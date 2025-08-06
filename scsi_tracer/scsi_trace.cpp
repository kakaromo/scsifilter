#define UNICODE
#define _UNICODE
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <conio.h>  // _kbhit(), _getch() 함수용

#define IOCTL_GET_SCSI_DATA CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_TARGET_DRIVE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENABLE_TRACING CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DISABLE_TRACING CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_STATS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MAX_TRACE_DATA 1000
#define MAX_DRIVES 32
#define MAX_PATH_LENGTH 256
#define SENSE_BUFFER_SIZE 18  // 드라이버와 일치시킴

#pragma pack(push, 8) // 드라이버와 동일한 정렬
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

// 전역 변수
SCSI_TRACE_DATA* traceDataBuffer = NULL;
int traceDataBufferIndex = 0;
wchar_t** drives = NULL;
HANDLE hControlDevice = INVALID_HANDLE_VALUE;
BOOL tracingEnabled = TRUE;
DWORD lastStatsTime = 0;
ULONG lastDroppedCount = 0;

// 함수 선언
BOOL ConsoleHandler(DWORD signal);
void SaveTraceDataToCSV(const wchar_t* filename);
void GetPhysicalDrives(wchar_t** drives, int* driveCount);
void PrintDriveList(wchar_t** drives, int driveCount);
int SelectDrive(wchar_t** drives, int driveCount);
BOOL SetTargetDrive(HANDLE hDevice, int driveIndex);
void PrintScsiTraceData(const SCSI_TRACE_DATA* traceData);
void CleanupResources();
BOOL EnableTracing(HANDLE hDevice);
BOOL DisableTracing(HANDLE hDevice);
BOOL GetDriverStats(HANDLE hDevice, SCSI_FILTER_STATS* stats);
void PrintDriverStats(const SCSI_FILTER_STATS* stats);
void ShowMenu();
BOOL ProcessUserInput();

void CleanupResources() {
    if (hControlDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(hControlDevice);
        hControlDevice = INVALID_HANDLE_VALUE;
    }
    
    if (drives) {
        for (int i = 0; i < MAX_DRIVES; ++i) {
            if (drives[i]) {
                free(drives[i]);
            }
        }
        free(drives);
        drives = NULL;
    }
    
    if (traceDataBuffer) {
        free(traceDataBuffer);
        traceDataBuffer = NULL;
    }
}

BOOL ConsoleHandler(DWORD signal) {
    if (signal == CTRL_C_EVENT) {
        wprintf(L"\nCtrl+C detected. Saving trace data to CSV...\n");
        SaveTraceDataToCSV(L"scsi_trace_data.csv");
        CleanupResources();
        exit(0);
    }
    return TRUE;
}

void SaveTraceDataToCSV(const wchar_t* filename) {
    FILE* outFile;
    errno_t err = _wfopen_s(&outFile, filename, L"w");
    if (err != 0) {
        wprintf(L"Failed to open file: %s (Error: %d)\n", filename, err);
        return;
    }

    // UTF-8 BOM 추가 (Excel 등에서 한글 표시 개선)
    fputwc(0xFEFF, outFile);
    
    // CSV 헤더
    fwprintf(outFile, L"CDB Length,SCSI Status,CDB Data,Data Transfer Length,Sense Info Length,Sense Info Data\n");

    // 데이터 저장
    for (int i = 0; i < traceDataBufferIndex; i++) {
        SCSI_TRACE_DATA traceData = traceDataBuffer[i];
        fwprintf(outFile, L"%d,", traceData.CdbLength);
        fwprintf(outFile, L"0x%02x,", traceData.ScsiStatus);

        // CDB 데이터 출력 (16진수 문자열로)
        wchar_t cdbStr[64] = L"";
        for (int j = 0; j < traceData.CdbLength && j < 16; j++) {
            wchar_t temp[4];
            swprintf(temp, 4, L"%02x", traceData.CdbData[j]);
            wcscat_s(cdbStr, 64, temp);
            if (j < traceData.CdbLength - 1) {
                wcscat_s(cdbStr, 64, L" ");
            }
        }
        fwprintf(outFile, L"\"%s\",", cdbStr);

        fwprintf(outFile, L"%lu,", traceData.DataTransferLength);
        fwprintf(outFile, L"%lu,", traceData.SenseInfoLength);

        // Sense 정보 출력 (16진수 문자열로)
        wchar_t senseStr[128] = L"";
        for (ULONG j = 0; j < traceData.SenseInfoLength && j < SENSE_BUFFER_SIZE; j++) {
            wchar_t temp[4];
            swprintf(temp, 4, L"%02x", traceData.SenseInfoBuffer[j]);
            wcscat_s(senseStr, 128, temp);
            if (j < traceData.SenseInfoLength - 1) {
                wcscat_s(senseStr, 128, L" ");
            }
        }
        fwprintf(outFile, L"\"%s\"\n", senseStr);
    }

    fclose(outFile);
    
    // 통계 정보도 함께 출력
    wprintf(L"Trace data saved to %s (%d records)\n", filename, traceDataBufferIndex);
    
    // 최종 드라이버 통계 표시
    if (hControlDevice != INVALID_HANDLE_VALUE) {
        SCSI_FILTER_STATS finalStats;
        if (GetDriverStats(hControlDevice, &finalStats)) {
            wprintf(L"\n=== Final Statistics ===\n");
            PrintDriverStats(&finalStats);
        }
    }
}

void GetPhysicalDrives(wchar_t** drives, int* driveCount) {
    *driveCount = 0;
    for (int i = 0; i < MAX_DRIVES; ++i) {
        wchar_t drivePath[MAX_PATH_LENGTH];
        if (swprintf(drivePath, MAX_PATH_LENGTH, L"\\\\.\\PhysicalDrive%d", i) < 0) {
            continue;
        }
        
        HANDLE hDevice = CreateFileW(drivePath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (hDevice != INVALID_HANDLE_VALUE) {
            wcsncpy_s(drives[*driveCount], MAX_PATH_LENGTH, drivePath, _TRUNCATE);
            (*driveCount)++;
            CloseHandle(hDevice);
            
            // 너무 많은 드라이브를 검색하지 않도록 제한
            if (*driveCount >= MAX_DRIVES) {
                break;
            }
        }
        else {
            // 연속된 실패가 몇 개 있으면 검색 중단 (성능 향상)
            DWORD error = GetLastError();
            if (error == ERROR_FILE_NOT_FOUND && i > 10) {
                break;
            }
        }
    }
}

void PrintDriveList(wchar_t** drives, int driveCount) {
    wprintf(L"Available Physical Drives:\n");
    for (int i = 0; i < driveCount; ++i) {
        wprintf(L"%d: %s\n", i, drives[i]);
    }
}

int SelectDrive(wchar_t** drives, int driveCount) {
    PrintDriveList(drives, driveCount);
    int choice;
    wprintf(L"Select a PhysicalDrive by entering the index: ");
    
    if (wscanf_s(L"%d", &choice) != 1 || choice < 0 || choice >= driveCount) {
        fwprintf(stderr, L"Invalid choice. Exiting...\n");
        return -1;
    }
    
    wprintf(L"You selected: %d (%s)\n", choice, drives[choice]);
    return choice;
}

BOOL SetTargetDrive(HANDLE hDevice, int driveIndex) {
    DWORD bytesReturned;
    
    // 드라이브 경로 문자열을 전송하여 드라이버가 해당 디바이스를 찾을 수 있도록 함
    wchar_t drivePath[MAX_PATH_LENGTH];
    if (swprintf(drivePath, MAX_PATH_LENGTH, L"\\Device\\Harddisk%d\\DR%d", driveIndex, driveIndex) < 0) {
        fwprintf(stderr, L"Failed to format drive path\n");
        return FALSE;
    }
    
    if (!DeviceIoControl(hDevice, IOCTL_SET_TARGET_DRIVE, drivePath, wcslen(drivePath) * sizeof(wchar_t), NULL, 0, &bytesReturned, NULL)) {
        fwprintf(stderr, L"Failed to set target drive. Error: %lu\n", GetLastError());
        return FALSE;
    }
    return TRUE;
}

void PrintScsiTraceData(const SCSI_TRACE_DATA* traceData) {
    wprintf(L"CDB Length: %d\n", traceData->CdbLength);
    wprintf(L"SCSI Status: 0x%02x\n", traceData->ScsiStatus);
    wprintf(L"CDB Data: ");
    for (int i = 0; i < traceData->CdbLength && i < 16; i++) {
        wprintf(L"%02x ", traceData->CdbData[i]);
    }
    wprintf(L"\n");
    wprintf(L"Data Transfer Length: %lu\n", traceData->DataTransferLength);
    wprintf(L"Sense Info Length: %lu\n", traceData->SenseInfoLength);
    if (traceData->SenseInfoLength > 0) {
        wprintf(L"Sense Info Data: ");
        for (ULONG i = 0; i < traceData->SenseInfoLength && i < SENSE_BUFFER_SIZE; i++) {
            wprintf(L"%02x ", traceData->SenseInfoBuffer[i]);
        }
        wprintf(L"\n");
    }
    wprintf(L"\n");
}

BOOL EnableTracing(HANDLE hDevice) {
    DWORD bytesReturned;
    if (!DeviceIoControl(hDevice, IOCTL_ENABLE_TRACING, NULL, 0, NULL, 0, &bytesReturned, NULL)) {
        fwprintf(stderr, L"Failed to enable tracing. Error: %lu\n", GetLastError());
        return FALSE;
    }
    tracingEnabled = TRUE;
    wprintf(L"Tracing enabled\n");
    return TRUE;
}

BOOL DisableTracing(HANDLE hDevice) {
    DWORD bytesReturned;
    if (!DeviceIoControl(hDevice, IOCTL_DISABLE_TRACING, NULL, 0, NULL, 0, &bytesReturned, NULL)) {
        fwprintf(stderr, L"Failed to disable tracing. Error: %lu\n", GetLastError());
        return FALSE;
    }
    tracingEnabled = FALSE;
    wprintf(L"Tracing disabled\n");
    return TRUE;
}

BOOL GetDriverStats(HANDLE hDevice, SCSI_FILTER_STATS* stats) {
    DWORD bytesReturned;
    if (!DeviceIoControl(hDevice, IOCTL_GET_STATS, NULL, 0, stats, sizeof(SCSI_FILTER_STATS), &bytesReturned, NULL)) {
        fwprintf(stderr, L"Failed to get driver statistics. Error: %lu\n", GetLastError());
        return FALSE;
    }
    return TRUE;
}

void PrintDriverStats(const SCSI_FILTER_STATS* stats) {
    wprintf(L"\n=== Driver Performance Statistics ===\n");
    wprintf(L"Tracing Status: %s\n", stats->TracingEnabled ? L"Enabled" : L"Disabled");
    wprintf(L"Dropped Requests: %lu\n", stats->DroppedRequests);
    wprintf(L"Buffer Utilization: %lu%%\n", stats->BufferUtilization);
    
    // 드롭률 계산 및 경고
    if (stats->DroppedRequests > lastDroppedCount) {
        ULONG newDrops = stats->DroppedRequests - lastDroppedCount;
        wprintf(L"⚠️  New drops since last check: %lu\n", newDrops);
        if (stats->BufferUtilization > 80) {
            wprintf(L"💡 High buffer utilization detected. Consider:\n");
            wprintf(L"   - Disabling tracing temporarily\n");
            wprintf(L"   - Reducing I/O load\n");
        }
    }
    lastDroppedCount = stats->DroppedRequests;
    wprintf(L"=====================================\n\n");
}

void ShowMenu() {
    wprintf(L"\n=== SCSI Tracer Control Menu ===\n");
    wprintf(L"[SPACE] - Toggle tracing on/off\n");
    wprintf(L"[S]     - Show driver statistics\n");
    wprintf(L"[C]     - Clear screen\n");
    wprintf(L"[ESC]   - Save and exit\n");
    wprintf(L"[H]     - Show this help\n");
    wprintf(L"===============================\n");
}

BOOL ProcessUserInput() {
    if (_kbhit()) {
        int ch = _getch();
        switch (ch) {
        case ' ': // Space - Toggle tracing
            if (tracingEnabled) {
                DisableTracing(hControlDevice);
            } else {
                EnableTracing(hControlDevice);
            }
            return TRUE;
            
        case 's':
        case 'S': // Show statistics
        {
            SCSI_FILTER_STATS stats;
            if (GetDriverStats(hControlDevice, &stats)) {
                PrintDriverStats(&stats);
            }
            return TRUE;
        }
        
        case 'c':
        case 'C': // Clear screen
            system("cls");
            ShowMenu();
            return TRUE;
            
        case 27: // ESC - Exit
            wprintf(L"\nExiting... Saving trace data to CSV...\n");
            SaveTraceDataToCSV(L"scsi_trace_data.csv");
            return FALSE;
            
        case 'h':
        case 'H': // Help
            ShowMenu();
            return TRUE;
        }
    }
    return TRUE;
}

int wmain() {
    if (!SetConsoleCtrlHandler((PHANDLER_ROUTINE)ConsoleHandler, TRUE)) {
        fwprintf(stderr, L"Unable to set console control handler\n");
        return 1;
    }

    // 메모리 할당
    traceDataBuffer = (SCSI_TRACE_DATA*)malloc(MAX_TRACE_DATA * sizeof(SCSI_TRACE_DATA));
    if (traceDataBuffer == NULL) {
        fwprintf(stderr, L"Failed to allocate memory for trace data buffer\n");
        return 1;
    }

    drives = (wchar_t**)malloc(MAX_DRIVES * sizeof(wchar_t*));
    if (drives == NULL) {
        fwprintf(stderr, L"Failed to allocate memory for drives\n");
        CleanupResources();
        return 1;
    }
    
    for (int i = 0; i < MAX_DRIVES; ++i) {
        drives[i] = (wchar_t*)malloc(MAX_PATH_LENGTH * sizeof(wchar_t));
        if (drives[i] == NULL) {
            fwprintf(stderr, L"Failed to allocate memory for drive path\n");
            CleanupResources();
            return 1;
        }
    }

    int driveCount;
    GetPhysicalDrives(drives, &driveCount);
    wprintf(L"Found %d physical drives\n", driveCount);

    if (driveCount == 0) {
        fwprintf(stderr, L"No physical drives found. Exiting...\n");
        CleanupResources();
        return 1;
    }

    int driveIndex = SelectDrive(drives, driveCount);
    if (driveIndex == -1) {
        CleanupResources();
        return 1;
    }

    // 드라이버의 컨트롤 디바이스에 연결
    hControlDevice = CreateFileW(L"\\\\.\\SCSITraceControl", 
                                GENERIC_READ | GENERIC_WRITE, 
                                0, NULL, OPEN_EXISTING, 
                                FILE_ATTRIBUTE_NORMAL, NULL);
    if (hControlDevice == INVALID_HANDLE_VALUE) {
        fwprintf(stderr, L"Failed to open SCSI trace control device. Error: %lu\n", GetLastError());
        fwprintf(stderr, L"Make sure the scsi_filter driver is loaded.\n");
        CleanupResources();
        return 1;
    }
    
    wprintf(L"Connected to SCSI trace control device successfully\n");
    
    if (!SetTargetDrive(hControlDevice, driveIndex)) {
        CleanupResources();
        return 1;
    }
    wprintf(L"Target drive set to %s\n", drives[driveIndex]);

    // 초기 통계 표시
    SCSI_FILTER_STATS initialStats;
    if (GetDriverStats(hControlDevice, &initialStats)) {
        wprintf(L"\nInitial driver status:\n");
        PrintDriverStats(&initialStats);
    }

    // 사용자 안내
    ShowMenu();

    DWORD bytesReturned;
    SCSI_TRACE_DATA traceData;
    DWORD lastAutoStatsTime = GetTickCount();
    DWORD traceCount = 0;

    wprintf(L"Starting SCSI trace... Use menu options above for control.\n\n");
    
    while (1) {
        // 사용자 입력 처리
        if (!ProcessUserInput()) {
            break; // ESC 키로 종료
        }

        // 자동 통계 표시 (30초마다)
        DWORD currentTime = GetTickCount();
        if (currentTime - lastAutoStatsTime > 30000) {
            SCSI_FILTER_STATS autoStats;
            if (GetDriverStats(hControlDevice, &autoStats)) {
                wprintf(L"\n--- Periodic Statistics (30s) ---\n");
                PrintDriverStats(&autoStats);
            }
            lastAutoStatsTime = currentTime;
        }

        // SCSI 데이터 수집 (트레이싱이 활성화된 경우에만)
        if (tracingEnabled) {
            if (DeviceIoControl(hControlDevice, IOCTL_GET_SCSI_DATA, NULL, 0, &traceData, sizeof(SCSI_TRACE_DATA), &bytesReturned, NULL)) {
                if (bytesReturned == sizeof(SCSI_TRACE_DATA)) {
                    traceCount++;
                    wprintf(L"[%lu] ", traceCount);
                    PrintScsiTraceData(&traceData);
                    
                    if (traceDataBufferIndex < MAX_TRACE_DATA) {
                        traceDataBuffer[traceDataBufferIndex++] = traceData;
                    }
                    else {
                        fwprintf(stderr, L"Trace data buffer is full. Saving data to CSV...\n");
                        SaveTraceDataToCSV(L"scsi_trace_data.csv");
                        traceDataBufferIndex = 0;
                    }
                }
            }
            else {
                DWORD error = GetLastError();
                if (error == ERROR_NO_MORE_ITEMS || 
                    error == ERROR_EMPTY || 
                    error == ERROR_NO_MORE_FILES ||
                    error == ERROR_INSUFFICIENT_BUFFER ||
                    error == ERROR_MORE_DATA) {
                    // 데이터가 없는 경우 잠시 대기
                    Sleep(10);
                    continue;
                }
                // 실제 오류인 경우
                fwprintf(stderr, L"DeviceIoControl failed. Error: %lu\n", error);
                if (error == ERROR_INVALID_HANDLE) {
                    fwprintf(stderr, L"Control device handle is invalid. Driver may have been unloaded.\n");
                } else if (error == ERROR_FILE_NOT_FOUND) {
                    fwprintf(stderr, L"Control device not found. Make sure the driver is loaded.\n");
                }
                break;
            }
        } else {
            // 트레이싱이 비활성화된 경우 더 오래 대기
            Sleep(100);
        }
        
        // CPU 사용률을 줄이기 위한 짧은 대기
        Sleep(1);
    }

    CleanupResources();
    return 0;
}