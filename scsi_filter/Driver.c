#include <ntddk.h>
#include <scsi.h>
#include <ntstrsafe.h>

#define IOCTL_GET_SCSI_DATA CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_TARGET_DRIVE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENABLE_TRACING CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DISABLE_TRACING CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_STATS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define SCSI_TRACE_TAG 'SCTR'
#define TRACE_BUFFER_SIZE 1024
#ifndef SENSE_BUFFER_SIZE
#define SENSE_BUFFER_SIZE 18 // 일반적인 Sense Buffer 크기
#endif

#pragma pack(push, 8) // 8바이트 단위로 정렬
typedef struct _SCSI_TRACE_DATA {
    UCHAR CdbLength;
    UCHAR ScsiStatus;
    UCHAR CdbData[16];
    ULONG DataTransferLength;
    ULONG SenseInfoLength;
    UCHAR SenseInfoBuffer[SENSE_BUFFER_SIZE];
} SCSI_TRACE_DATA, * PSCSI_TRACE_DATA;

typedef struct _SCSI_FILTER_STATS {
    ULONG TotalRequests;
    ULONG DroppedRequests;
    ULONG BufferUtilization;  // 버퍼 사용률 (백분율)
    BOOLEAN TracingEnabled;
} SCSI_FILTER_STATS, * PSCSI_FILTER_STATS;
#pragma pack(pop)

typedef struct _DEVICE_EXTENSION {
    PDEVICE_OBJECT PhysicalDeviceObject;
    PDEVICE_OBJECT LowerDevice;
    PDEVICE_OBJECT TargetDevice; // 선택된 PhysicalDrive의 DeviceObject
    KSPIN_LOCK TraceBufferLock;
    LIST_ENTRY ListEntry;
    SCSI_TRACE_DATA TraceBuffer[TRACE_BUFFER_SIZE];
    volatile ULONG TraceBufferHead;  // volatile로 캐시 일관성 보장
    volatile ULONG TraceBufferTail;  // volatile로 캐시 일관성 보장
    BOOLEAN IsAttached;
    BOOLEAN TracingEnabled;          // 트레이싱 활성화 플래그
    ULONG DroppedRequests;           // 드롭된 요청 수 (성능 모니터링용)
} DEVICE_EXTENSION, * PDEVICE_EXTENSION;

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
DRIVER_DISPATCH DispatchCreate, DispatchClose, DispatchDeviceControl, DispatchPassThrough, DispatchPnp, DispatchPower;
DRIVER_DISPATCH ScsiDispatchRoutine;

PDEVICE_OBJECT g_ControlDeviceObject = NULL;

LIST_ENTRY g_DeviceExtensionList;
KSPIN_LOCK g_DeviceExtensionListLock;

// 함수 선언
NTSTATUS AddDevice(_In_ PDRIVER_OBJECT DriverObject, _In_ PDEVICE_OBJECT PhysicalDeviceObject);
NTSTATUS CompleteIrp(_In_ PIRP Irp, _In_ NTSTATUS status, _In_ ULONG_PTR information);
VOID DetachFromTargetDevice(_In_ PDEVICE_EXTENSION deviceExtension);
VOID DeleteControlDevice(void);
NTSTATUS DispatchPassThrough(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
NTSTATUS ScsiDispatchRoutine(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
NTSTATUS ScsiCompletionRoutine(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp, _In_ PVOID Context);
NTSTATUS DispatchDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
NTSTATUS DispatchCreate(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
NTSTATUS DispatchClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
NTSTATUS DispatchPnp(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
NTSTATUS DispatchPower(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);

// AddDevice 함수
NTSTATUS AddDevice(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PDEVICE_OBJECT PhysicalDeviceObject
)
{
    NTSTATUS status;
    PDEVICE_OBJECT DeviceObject = NULL;
    PDEVICE_EXTENSION deviceExtension;
    KIRQL oldIrql;

    status = IoCreateDevice(DriverObject, sizeof(DEVICE_EXTENSION), NULL,
        FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);

    if (!NT_SUCCESS(status)) {
        DbgPrint("AddDevice: IoCreateDevice failed with status 0x%X\n", status);
        return status;
    }

    deviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
    RtlZeroMemory(deviceExtension, sizeof(DEVICE_EXTENSION));

    deviceExtension->PhysicalDeviceObject = PhysicalDeviceObject;
    deviceExtension->LowerDevice = IoAttachDeviceToDeviceStack(DeviceObject, PhysicalDeviceObject);

    if (deviceExtension->LowerDevice == NULL) {
        DbgPrint("AddDevice: IoAttachDeviceToDeviceStack failed.\n");
        IoDeleteDevice(DeviceObject);
        return STATUS_NO_SUCH_DEVICE;
    }

    // 리스트에 추가하기 전에 스핀락을 획득
    KeAcquireSpinLock(&g_DeviceExtensionListLock, &oldIrql);
    InsertTailList(&g_DeviceExtensionList, &deviceExtension->ListEntry);
    KeReleaseSpinLock(&g_DeviceExtensionListLock, oldIrql);

    DeviceObject->Flags |= DO_POWER_PAGABLE;
    DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    // 초기화 코드 추가
    deviceExtension->TraceBufferHead = 0;
    deviceExtension->TraceBufferTail = 0;
    KeInitializeSpinLock(&deviceExtension->TraceBufferLock);
    deviceExtension->IsAttached = TRUE;
    deviceExtension->TracingEnabled = TRUE;  // 기본적으로 트레이싱 활성화
    deviceExtension->DroppedRequests = 0;

    DbgPrint("AddDevice: Successfully attached to device.\n");

    return STATUS_SUCCESS;
}

// IRP 완료 함수
NTSTATUS CompleteIrp(
    _In_ PIRP Irp,
    _In_ NTSTATUS status,
    _In_ ULONG_PTR information
)
{
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// 디바이스 분리 함수
VOID DetachFromTargetDevice(_In_ PDEVICE_EXTENSION deviceExtension)
{
    if (deviceExtension->IsAttached && deviceExtension->LowerDevice) {
        IoDetachDevice(deviceExtension->LowerDevice);
        deviceExtension->LowerDevice = NULL;
        deviceExtension->IsAttached = FALSE;
    }
}

// 컨트롤 디바이스 삭제 함수
VOID DeleteControlDevice(void)
{
    if (g_ControlDeviceObject) {
        // Delete symbolic link before deleting device
        UNICODE_STRING symbolicLink;
        RtlInitUnicodeString(&symbolicLink, L"\\??\\SCSITraceControl");
        IoDeleteSymbolicLink(&symbolicLink);

        IoDeleteDevice(g_ControlDeviceObject);
        g_ControlDeviceObject = NULL;
    }
}

// DriverUnload 함수
VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    // 컨트롤 디바이스 객체 삭제
    DeleteControlDevice();

    // 필터 디바이스 객체들은 PnP에 의해 제거됩니다.
    DbgPrint("DriverUnload: Driver unloaded successfully.\n");
}

// 최적화된 PassThrough 핸들러
NTSTATUS DispatchPassThrough(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    PDEVICE_EXTENSION deviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

    // 빠른 검증 (브랜치 예측 최적화를 위한 순서)
    if (deviceExtension->IsAttached && deviceExtension->LowerDevice) {
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(deviceExtension->LowerDevice, Irp);
    }

    // 오류 상황 (덜 빈번한 경우)
    DbgPrint("DispatchPassThrough: Device not attached or LowerDevice is NULL\n");
    return CompleteIrp(Irp, STATUS_NO_SUCH_DEVICE, 0);
}

// 고성능 SCSI 완료 콜백 함수
NTSTATUS ScsiCompletionRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PVOID Context
)
{
    PDEVICE_EXTENSION deviceExtension = (PDEVICE_EXTENSION)Context;
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);

    UNREFERENCED_PARAMETER(DeviceObject);

    // 빠른 종료 조건들 - 브랜치 예측 최적화
    if (!deviceExtension->IsAttached || !deviceExtension->TracingEnabled) {
        goto complete_irp;
    }

    if (irpStack->MajorFunction != IRP_MJ_SCSI) {
        goto complete_irp;
    }

    PSCSI_REQUEST_BLOCK srb = irpStack->Parameters.Scsi.Srb;
    if (!srb) {
        goto complete_irp;
    }

    // 락프리 큐 체크 - 버퍼가 거의 가득 찬 경우 드롭
    ULONG currentTail = deviceExtension->TraceBufferTail;
    ULONG currentHead = deviceExtension->TraceBufferHead;
    ULONG nextTail = (currentTail + 1) % TRACE_BUFFER_SIZE;
    
    // 90% 이상 찬 경우 성능을 위해 드롭
    ULONG used = (currentTail >= currentHead) ? 
                 (currentTail - currentHead) : 
                 (TRACE_BUFFER_SIZE - currentHead + currentTail);
    
    if (used > (TRACE_BUFFER_SIZE * 9 / 10)) {
        InterlockedIncrement(&deviceExtension->DroppedRequests);
        goto complete_irp;
    }

    // 스핀락 시도 - 즉시 획득할 수 없으면 드롭 (성능 우선)
    KIRQL oldIrql;
    if (!KeTestSpinLock(&deviceExtension->TraceBufferLock)) {
        InterlockedIncrement(&deviceExtension->DroppedRequests);
        goto complete_irp;
    }

    KeAcquireSpinLock(&deviceExtension->TraceBufferLock, &oldIrql);

    // 다시 한번 체크 (락 획득 후)
    if (nextTail == deviceExtension->TraceBufferHead) {
        deviceExtension->TraceBufferHead = (deviceExtension->TraceBufferHead + 1) % TRACE_BUFFER_SIZE;
    }

    PSCSI_TRACE_DATA traceData = &deviceExtension->TraceBuffer[currentTail];
    
    // 중요한 정보만 빠르게 복사
    traceData->CdbLength = (srb->CdbLength > sizeof(traceData->CdbData)) ? 
                          sizeof(traceData->CdbData) : srb->CdbLength;
    
    // 메모리 복사 최적화 - 필수 데이터만
    RtlCopyMemory(traceData->CdbData, srb->Cdb, traceData->CdbLength);
    traceData->DataTransferLength = srb->DataTransferLength;
    traceData->ScsiStatus = srb->ScsiStatus;
    
    // Sense 정보는 오류가 있을 때만 복사 (성능 최적화)
    if (srb->ScsiStatus != 0 && srb->SenseInfoBuffer && srb->SenseInfoBufferLength > 0) {
        ULONG copyLength = (srb->SenseInfoBufferLength < SENSE_BUFFER_SIZE) ? 
                          srb->SenseInfoBufferLength : SENSE_BUFFER_SIZE;
        RtlCopyMemory(traceData->SenseInfoBuffer, srb->SenseInfoBuffer, copyLength);
        traceData->SenseInfoLength = copyLength;
    } else {
        traceData->SenseInfoLength = 0;
    }

    // 원자적 업데이트
    deviceExtension->TraceBufferTail = nextTail;

    KeReleaseSpinLock(&deviceExtension->TraceBufferLock, oldIrql);

complete_irp:
    // IRP 처리 계속
    if (Irp->PendingReturned) {
        IoMarkIrpPending(Irp);
    }

    return STATUS_SUCCESS;
}

// 최적화된 SCSI 핸들러
NTSTATUS ScsiDispatchRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    PDEVICE_EXTENSION deviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);

    // 빠른 패스스루 체크
    if (!deviceExtension->IsAttached || !deviceExtension->LowerDevice) {
        return CompleteIrp(Irp, STATUS_NO_SUCH_DEVICE, 0);
    }

    // SCSI 요청이 아니거나 트레이싱이 비활성화된 경우 바로 패스스루
    if (irpStack->MajorFunction != IRP_MJ_SCSI || !deviceExtension->TracingEnabled) {
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(deviceExtension->LowerDevice, Irp);
    }

    // 완료 콜백 설정 (최소한의 오버헤드)
    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp, ScsiCompletionRoutine, deviceExtension, TRUE, TRUE, TRUE);
    
    return IoCallDriver(deviceExtension->LowerDevice, Irp);
}

// DeviceControl 핸들러
NTSTATUS DispatchDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    PIO_STACK_LOCATION irpStack;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR information = 0;

    // IRP 스택 위치 가져오기
    irpStack = IoGetCurrentIrpStackLocation(Irp);

    if (DeviceObject == g_ControlDeviceObject) {
        // 컨트롤 디바이스에 대한 처리
        switch (irpStack->Parameters.DeviceIoControl.IoControlCode) {
        case IOCTL_GET_SCSI_DATA:
        {
            // SCSI 데이터 가져오기 처리
            DbgPrint("DispatchDeviceControl: IOCTL_GET_SCSI_DATA\n");

            // 사용자 버퍼 가져오기
            PSCSI_TRACE_DATA userBuffer = (PSCSI_TRACE_DATA)Irp->AssociatedIrp.SystemBuffer;
            if (userBuffer == NULL || irpStack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(SCSI_TRACE_DATA)) {
                status = STATUS_INVALID_PARAMETER;
                DbgPrint("DispatchDeviceControl: IOCTL_GET_SCSI_DATA invalid parameter.\n");
                break;
            }

            // Acquire list lock
            KIRQL oldIrql;
            KeAcquireSpinLock(&g_DeviceExtensionListLock, &oldIrql);

            PLIST_ENTRY entry = g_DeviceExtensionList.Flink;
            BOOLEAN dataFound = FALSE;

            while (entry != &g_DeviceExtensionList) {
                PDEVICE_EXTENSION deviceExtensionNew = CONTAINING_RECORD(entry, DEVICE_EXTENSION, ListEntry);

                KIRQL deviceOldIrql;
                KeAcquireSpinLock(&deviceExtensionNew->TraceBufferLock, &deviceOldIrql);

                if (deviceExtensionNew->TraceBufferHead != deviceExtensionNew->TraceBufferTail) {
                    PSCSI_TRACE_DATA traceData = &deviceExtensionNew->TraceBuffer[deviceExtensionNew->TraceBufferHead];
                    deviceExtensionNew->TraceBufferHead = (deviceExtensionNew->TraceBufferHead + 1) % TRACE_BUFFER_SIZE;

                    RtlCopyMemory(userBuffer, traceData, sizeof(SCSI_TRACE_DATA));
                    information = sizeof(SCSI_TRACE_DATA);
                    dataFound = TRUE;

                    KeReleaseSpinLock(&deviceExtensionNew->TraceBufferLock, deviceOldIrql);
                    DbgPrint("DispatchDeviceControl: IOCTL_GET_SCSI_DATA succeeded.\n");
                    break;
                }

                KeReleaseSpinLock(&deviceExtensionNew->TraceBufferLock, deviceOldIrql);
                entry = entry->Flink;
            }

            KeReleaseSpinLock(&g_DeviceExtensionListLock, oldIrql);

            if (!dataFound) {
                status = STATUS_NO_MORE_ENTRIES;
                DbgPrint("DispatchDeviceControl: IOCTL_GET_SCSI_DATA no data found.\n");
            }

            break;
        }
        case IOCTL_SET_TARGET_DRIVE:
        {
            // 타겟 드라이브 설정 처리
            DbgPrint("DispatchDeviceControl: IOCTL_SET_TARGET_DRIVE\n");

            // 사용자 버퍼 검증 (드라이브 경로 문자열을 기대)
            if (irpStack->Parameters.DeviceIoControl.InputBufferLength < sizeof(WCHAR)) {
                status = STATUS_INVALID_PARAMETER;
                DbgPrint("DispatchDeviceControl: IOCTL_SET_TARGET_DRIVE invalid buffer length.\n");
                break;
            }

            // 사용자 버퍼에서 드라이브 경로 가져오기
            PWCHAR drivePathBuffer = (PWCHAR)Irp->AssociatedIrp.SystemBuffer;
            if (drivePathBuffer == NULL) {
                status = STATUS_INVALID_PARAMETER;
                DbgPrint("DispatchDeviceControl: IOCTL_SET_TARGET_DRIVE NULL buffer.\n");
                break;
            }

            // 문자열 길이 계산 및 검증
            ULONG pathLength = irpStack->Parameters.DeviceIoControl.InputBufferLength / sizeof(WCHAR);
            if (pathLength == 0 || pathLength > 256) {
                status = STATUS_INVALID_PARAMETER;
                DbgPrint("DispatchDeviceControl: IOCTL_SET_TARGET_DRIVE invalid path length.\n");
                break;
            }

            // 널 종료 문자열 보장
            if (drivePathBuffer[pathLength - 1] != L'\0') {
                if (pathLength < 256) {
                    drivePathBuffer[pathLength] = L'\0';
                } else {
                    status = STATUS_INVALID_PARAMETER;
                    DbgPrint("DispatchDeviceControl: IOCTL_SET_TARGET_DRIVE string not null-terminated.\n");
                    break;
                }
            }

            DbgPrint("DispatchDeviceControl: Target drive path: %ws\n", drivePathBuffer);

            // 현재는 간단히 성공 반환 (실제 구현에서는 드라이브 경로로 디바이스 객체를 찾아야 함)
            // TODO: 드라이브 경로를 사용하여 해당하는 Physical Device Object를 찾는 로직 구현
            
            // Acquire list lock
            KIRQL oldIrql;
            KeAcquireSpinLock(&g_DeviceExtensionListLock, &oldIrql);

            PLIST_ENTRY entry = g_DeviceExtensionList.Flink;
            BOOLEAN deviceFound = FALSE;

            // 현재 구현에서는 첫 번째 디바이스를 타겟으로 설정 (임시)
            if (entry != &g_DeviceExtensionList) {
                PDEVICE_EXTENSION deviceExtensionNew = CONTAINING_RECORD(entry, DEVICE_EXTENSION, ListEntry);
                deviceExtensionNew->TargetDevice = deviceExtensionNew->PhysicalDeviceObject;
                deviceFound = TRUE;
                DbgPrint("DispatchDeviceControl: IOCTL_SET_TARGET_DRIVE succeeded (using first device).\n");
            }

            KeReleaseSpinLock(&g_DeviceExtensionListLock, oldIrql);

            if (!deviceFound) {
                status = STATUS_NO_SUCH_DEVICE;
                DbgPrint("DispatchDeviceControl: IOCTL_SET_TARGET_DRIVE no devices available.\n");
            }

            break;
        }
        case IOCTL_ENABLE_TRACING:
        {
            DbgPrint("DispatchDeviceControl: IOCTL_ENABLE_TRACING\n");
            
            // 모든 장치에서 트레이싱 활성화
            KIRQL oldIrql;
            KeAcquireSpinLock(&g_DeviceExtensionListLock, &oldIrql);

            PLIST_ENTRY entry = g_DeviceExtensionList.Flink;
            while (entry != &g_DeviceExtensionList) {
                PDEVICE_EXTENSION deviceExtensionNew = CONTAINING_RECORD(entry, DEVICE_EXTENSION, ListEntry);
                deviceExtensionNew->TracingEnabled = TRUE;
                entry = entry->Flink;
            }

            KeReleaseSpinLock(&g_DeviceExtensionListLock, oldIrql);
            status = STATUS_SUCCESS;
            break;
        }
        case IOCTL_DISABLE_TRACING:
        {
            DbgPrint("DispatchDeviceControl: IOCTL_DISABLE_TRACING\n");
            
            // 모든 장치에서 트레이싱 비활성화
            KIRQL oldIrql;
            KeAcquireSpinLock(&g_DeviceExtensionListLock, &oldIrql);

            PLIST_ENTRY entry = g_DeviceExtensionList.Flink;
            while (entry != &g_DeviceExtensionList) {
                PDEVICE_EXTENSION deviceExtensionNew = CONTAINING_RECORD(entry, DEVICE_EXTENSION, ListEntry);
                deviceExtensionNew->TracingEnabled = FALSE;
                entry = entry->Flink;
            }

            KeReleaseSpinLock(&g_DeviceExtensionListLock, oldIrql);
            status = STATUS_SUCCESS;
            break;
        }
        case IOCTL_GET_STATS:
        {
            DbgPrint("DispatchDeviceControl: IOCTL_GET_STATS\n");

            PSCSI_FILTER_STATS statsBuffer = (PSCSI_FILTER_STATS)Irp->AssociatedIrp.SystemBuffer;
            if (statsBuffer == NULL || irpStack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(SCSI_FILTER_STATS)) {
                status = STATUS_INVALID_PARAMETER;
                DbgPrint("DispatchDeviceControl: IOCTL_GET_STATS invalid parameter.\n");
                break;
            }

            // 통계 정보 수집
            KIRQL oldIrql;
            KeAcquireSpinLock(&g_DeviceExtensionListLock, &oldIrql);

            ULONG totalDropped = 0;
            ULONG totalUtilization = 0;
            ULONG deviceCount = 0;
            BOOLEAN anyTracingEnabled = FALSE;

            PLIST_ENTRY entry = g_DeviceExtensionList.Flink;
            while (entry != &g_DeviceExtensionList) {
                PDEVICE_EXTENSION deviceExtensionNew = CONTAINING_RECORD(entry, DEVICE_EXTENSION, ListEntry);
                
                totalDropped += deviceExtensionNew->DroppedRequests;
                
                ULONG used = (deviceExtensionNew->TraceBufferTail >= deviceExtensionNew->TraceBufferHead) ? 
                            (deviceExtensionNew->TraceBufferTail - deviceExtensionNew->TraceBufferHead) : 
                            (TRACE_BUFFER_SIZE - deviceExtensionNew->TraceBufferHead + deviceExtensionNew->TraceBufferTail);
                totalUtilization += (used * 100) / TRACE_BUFFER_SIZE;
                
                if (deviceExtensionNew->TracingEnabled) {
                    anyTracingEnabled = TRUE;
                }
                
                deviceCount++;
                entry = entry->Flink;
            }

            KeReleaseSpinLock(&g_DeviceExtensionListLock, oldIrql);

            // 통계 정보 반환
            statsBuffer->DroppedRequests = totalDropped;
            statsBuffer->BufferUtilization = (deviceCount > 0) ? (totalUtilization / deviceCount) : 0;
            statsBuffer->TracingEnabled = anyTracingEnabled;
            
            information = sizeof(SCSI_FILTER_STATS);
            status = STATUS_SUCCESS;
            break;
        }
        default:
            // 지원하지 않는 IOCTL 코드
            status = STATUS_INVALID_DEVICE_REQUEST;
            DbgPrint("DispatchDeviceControl: Unsupported IOCTL code 0x%X\n", irpStack->Parameters.DeviceIoControl.IoControlCode);
            break;
        }

        // IRP 완료
        Irp->IoStatus.Status = status;
        Irp->IoStatus.Information = information;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        return status;
    }
    else {
        // 필터 디바이스에 대한 처리
        PDEVICE_EXTENSION deviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(deviceExtension->LowerDevice, Irp);
    }
}

// Create 핸들러
NTSTATUS DispatchCreate(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    DbgPrint("DispatchCreate: Create IRP received.\n");
    return CompleteIrp(Irp, STATUS_SUCCESS, 0);
}

// Close 핸들러
NTSTATUS DispatchClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    DbgPrint("DispatchClose: Close IRP received.\n");
    return CompleteIrp(Irp, STATUS_SUCCESS, 0);
}

// PnP 핸들러
NTSTATUS DispatchPnp(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    PDEVICE_EXTENSION deviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;

    switch (irpStack->MinorFunction) {
    case IRP_MN_START_DEVICE:
    {
        DbgPrint("DispatchPnp: IRP_MN_START_DEVICE received.\n");

        // START_DEVICE는 동기적으로 처리해야 함
        IoCopyCurrentIrpStackLocationToNext(Irp);
        status = IoCallDriver(deviceExtension->LowerDevice, Irp);

        if (NT_SUCCESS(status)) {
            deviceExtension->IsAttached = TRUE;
        }

        return status; // 여기서 바로 반환
    }
    case IRP_MN_REMOVE_DEVICE:
    {
        DbgPrint("DispatchPnp: IRP_MN_REMOVE_DEVICE received.\n");
        
        // 먼저 IsAttached를 FALSE로 설정하여 새로운 SCSI IRP 처리를 중단
        deviceExtension->IsAttached = FALSE;
        
        // 진행 중인 IRP들이 완료될 때까지 잠시 대기 (간단한 방법)
        // 실제 운영 환경에서는 더 정교한 동기화가 필요할 수 있음
        KeStallExecutionProcessor(1000); // 1ms 대기
        
        DetachFromTargetDevice(deviceExtension);

        // 리스트에서 제거하기 전에 스핀락을 획득
        KIRQL oldIrql;
        KeAcquireSpinLock(&g_DeviceExtensionListLock, &oldIrql);
        RemoveEntryList(&deviceExtension->ListEntry);
        KeReleaseSpinLock(&g_DeviceExtensionListLock, oldIrql);

        IoSkipCurrentIrpStackLocation(Irp);
        status = IoCallDriver(deviceExtension->LowerDevice, Irp);
        IoDeleteDevice(DeviceObject);
        return status; // 여기서 바로 반환
    }
    default:
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(deviceExtension->LowerDevice, Irp);
    }
}

// Power 핸들러
NTSTATUS DispatchPower(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    PDEVICE_EXTENSION deviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
    PoStartNextPowerIrp(Irp);
    IoSkipCurrentIrpStackLocation(Irp);
    return PoCallDriver(deviceExtension->LowerDevice, Irp);
}

// DriverEntry 함수
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status;
    ULONG i;

    // 드라이버 디스패치 함수 설정
    DriverObject->DriverUnload = DriverUnload;
    DriverObject->DriverExtension->AddDevice = AddDevice;

    for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
        DriverObject->MajorFunction[i] = DispatchPassThrough;
    }

    // 특정 MajorFunction 핸들러 설정
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
    DriverObject->MajorFunction[IRP_MJ_PNP] = DispatchPnp;
    DriverObject->MajorFunction[IRP_MJ_POWER] = DispatchPower;
    DriverObject->MajorFunction[IRP_MJ_SCSI] = ScsiDispatchRoutine;

    // 전역 리스트 초기화
    InitializeListHead(&g_DeviceExtensionList);
    KeInitializeSpinLock(&g_DeviceExtensionListLock);

    // 컨트롤 디바이스 생성
    UNICODE_STRING deviceName;
    RtlInitUnicodeString(&deviceName, L"\\Device\\SCSITraceControl");

    status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &g_ControlDeviceObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("DriverEntry: IoCreateDevice for control device failed with status 0x%X\n", status);
        return status;
    }

    // 컨트롤 디바이스 설정
    g_ControlDeviceObject->Flags |= DO_BUFFERED_IO;
    g_ControlDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    // 컨트롤 디바이스에 심볼릭 링크 생성
    UNICODE_STRING symbolicLink;
    RtlInitUnicodeString(&symbolicLink, L"\\??\\SCSITraceControl");
    status = IoCreateSymbolicLink(&symbolicLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("DriverEntry: IoCreateSymbolicLink failed with status 0x%X\n", status);
        IoDeleteDevice(g_ControlDeviceObject);
        return status;
    }

    DbgPrint("DriverEntry: Control device created successfully.\n");

    return STATUS_SUCCESS;
}
