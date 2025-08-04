#define UNICODE
#define _UNICODE
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IOCTL_GET_SCSI_DATA CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_TARGET_DRIVE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

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
#pragma pack(pop)

// 전역 변수
SCSI_TRACE_DATA* traceDataBuffer = NULL;
int traceDataBufferIndex = 0;
wchar_t** drives = NULL;
HANDLE hControlDevice = INVALID_HANDLE_VALUE;

// 함수 선언
BOOL ConsoleHandler(DWORD signal);
void SaveTraceDataToCSV(const wchar_t* filename);
void GetPhysicalDrives(wchar_t** drives, int* driveCount);
void PrintDriveList(wchar_t** drives, int driveCount);
int SelectDrive(wchar_t** drives, int driveCount);
BOOL SetTargetDrive(HANDLE hDevice, int driveIndex);
void PrintScsiTraceData(const SCSI_TRACE_DATA* traceData);
void CleanupResources();

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

    fwprintf(outFile, L"CDB Length,SCSI Status,CDB Data,Data Transfer Length,Sense Info Length,Sense Info Data\n");

    for (int i = 0; i < traceDataBufferIndex; i++) {
        SCSI_TRACE_DATA traceData = traceDataBuffer[i];
        fwprintf(outFile, L"%d,", traceData.CdbLength);
        fwprintf(outFile, L"0x%02x,", traceData.ScsiStatus);

        // CDB 데이터 출력
        for (int j = 0; j < traceData.CdbLength && j < 16; j++) {
            fwprintf(outFile, L"%02x", traceData.CdbData[j]);
            if (j < traceData.CdbLength - 1) {
                fwprintf(outFile, L" ");
            }
        }

        fwprintf(outFile, L",%lu,", traceData.DataTransferLength);
        fwprintf(outFile, L"%lu,", traceData.SenseInfoLength);

        // Sense 정보 출력
        for (ULONG j = 0; j < traceData.SenseInfoLength && j < SENSE_BUFFER_SIZE; j++) {
            fwprintf(outFile, L"%02x", traceData.SenseInfoBuffer[j]);
            if (j < traceData.SenseInfoLength - 1) {
                fwprintf(outFile, L" ");
            }
        }

        fwprintf(outFile, L"\n");
    }

    fclose(outFile);
    wprintf(L"Trace data saved to %s (%d records)\n", filename, traceDataBufferIndex);
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
    
    // 드라이버 인덱스를 전송 (드라이브 포인터가 아닌 인덱스)
    if (!DeviceIoControl(hDevice, IOCTL_SET_TARGET_DRIVE, &driveIndex, sizeof(int), NULL, 0, &bytesReturned, NULL)) {
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

    DWORD bytesReturned;
    SCSI_TRACE_DATA traceData;

    wprintf(L"Starting SCSI trace... Press Ctrl+C to stop and save data.\n");
    
    while (1) {
        if (DeviceIoControl(hControlDevice, IOCTL_GET_SCSI_DATA, NULL, 0, &traceData, sizeof(SCSI_TRACE_DATA), &bytesReturned, NULL)) {
            if (bytesReturned == sizeof(SCSI_TRACE_DATA)) {
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
            if (error == ERROR_NO_MORE_ITEMS || error == ERROR_EMPTY || error == ERROR_NO_MORE_FILES) {
                // 데이터가 없는 경우 잠시 대기
                Sleep(10);
                continue;
            }
            fwprintf(stderr, L"DeviceIoControl failed. Error: %lu\n", error);
            break;
        }
        
        // CPU 사용률을 줄이기 위한 짧은 대기
        Sleep(1);
    }

    CleanupResources();
    return 0;
}
