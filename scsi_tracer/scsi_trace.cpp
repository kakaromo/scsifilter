#define UNICODE
#define _UNICODE
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <conio.h>  // _kbhit(), _getch() 함수용
#include <Shlobj.h> // IsUserAnAdmin 함수용
#include <vector>   // std::vector 사용용

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
    LONG DroppedRequests;        // 드라이버와 일치시킴
    ULONG BufferUtilization;     // 버퍼 사용률 (백분율)
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
LONG lastDroppedCount = 0;  // LONG 타입으로 변경

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
BOOL CheckDriverStatus();
void ShowDriverInstallationGuide();
void RunDiagnostics();
bool AutoRegisterFilterDriver();
bool CheckFilterRegistration();
bool UninstallFilterDriver();
// 필터 드라이버 자동 등록 함수
bool AutoRegisterFilterDriver() {
    printf("자동 필터 드라이버 등록을 시도합니다...
");
    
    // 1. 드라이버 서비스가 실행 중인지 확인
    if (!CheckDriverStatus()) {
        printf("드라이버 서비스가 실행되지 않았습니다. 먼저 드라이버를 시작하세요.
");
        return false;
    }
    
    // 2. 관리자 권한 확인
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    
    if (!isAdmin) {
        printf("관리자 권한이 필요합니다. 관리자로 실행하세요.
");
        return false;
    }
    
    // 3. 레지스트리를 통한 필터 등록
    HKEY hKey;
    LONG result = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                               L"SYSTEM\CurrentControlSet\Control\Class\{4D36E967-E325-11CE-BFC1-08002BE10318}",
                               0, KEY_READ | KEY_WRITE, &hKey);
    
    if (result != ERROR_SUCCESS) {
        printf("디스크 클래스 레지스트리 키를 열 수 없습니다. (Error: %ld)
", result);
        return false;
    }
    
    // 4. 기존 LowerFilters 값 읽기
    DWORD dataType;
    DWORD dataSize = 0;
    result = RegQueryValueEx(hKey, L"LowerFilters", NULL, &dataType, NULL, &dataSize);
    
    std::vector<wchar_t> newFilterData;
    
    if (result == ERROR_SUCCESS && dataType == REG_MULTI_SZ) {
        // 기존 필터 목록이 있는 경우
        std::vector<wchar_t> existingData(dataSize / sizeof(wchar_t));
        result = RegQueryValueEx(hKey, L"LowerFilters", NULL, &dataType, 
                                 (LPBYTE)existingData.data(), &dataSize);
        
        if (result == ERROR_SUCCESS) {
            // scsi_filter가 이미 등록되어 있는지 확인
            const wchar_t* currentFilter = existingData.data();
            bool alreadyExists = false;
            
            while (*currentFilter) {
                if (wcscmp(currentFilter, L"scsi_filter") == 0) {
                    alreadyExists = true;
                    break;
                }
                currentFilter += wcslen(currentFilter) + 1;
            }
            
            if (alreadyExists) {
                printf("scsi_filter가 이미 LowerFilters에 등록되어 있습니다.
");
                RegCloseKey(hKey);
                return true;
            }
            
            // 새로운 필터 목록 생성 (기존 + scsi_filter)
            newFilterData = existingData;
            newFilterData.resize(newFilterData.size() - 1); // 마지막 널 제거
            
            // scsi_filter 추가
            const wchar_t* filterName = L"scsi_filter";
            newFilterData.insert(newFilterData.end(), filterName, filterName + wcslen(filterName) + 1);
            newFilterData.push_back(L'\0'); // 마지막 널 종료 추가
        }
    } else if (result == ERROR_FILE_NOT_FOUND) {
        // LowerFilters 값이 없는 경우 - 새로 생성
        const wchar_t* filterName = L"scsi_filter";
        newFilterData.assign(filterName, filterName + wcslen(filterName) + 1);
        newFilterData.push_back(L'\0'); // 마지막 널 종료 추가
    } else {
        printf("LowerFilters 값을 읽는데 실패했습니다. (Error: %ld)
", result);
        RegCloseKey(hKey);
        return false;
    }
    
    // 5. 새로운 필터 목록을 레지스트리에 저장
    result = RegSetValueEx(hKey, L"LowerFilters", 0, REG_MULTI_SZ,
                           (LPBYTE)newFilterData.data(),
                           (DWORD)(newFilterData.size() * sizeof(wchar_t)));
    
    RegCloseKey(hKey);
    
    if (result == ERROR_SUCCESS) {
        printf("scsi_filter가 성공적으로 LowerFilters에 등록되었습니다.
");
        printf("변경사항을 적용하려면 시스템을 재부팅하세요.
");
        return true;
    } else {
        printf("LowerFilters 값을 설정하는데 실패했습니다. (Error: %ld)
", result);
        return false;
    }
}

// 필터 드라이버 제거 함수
bool UninstallFilterDriver() {
    printf("SCSI 필터 드라이버를 제거합니다...\n");
    
    // 1. 관리자 권한 확인
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    
    if (!isAdmin) {
        printf("관리자 권한이 필요합니다. 관리자로 실행하세요.\n");
        return false;
    }
    
    bool success = true;
    
    // 2. 드라이버 서비스 중지 및 삭제
    printf("드라이버 서비스를 중지하고 삭제합니다...\n");
    SC_HANDLE scManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scManager != NULL) {
        SC_HANDLE service = OpenService(scManager, L"scsi_filter", SERVICE_ALL_ACCESS);
        if (service != NULL) {
            // 서비스 중지
            SERVICE_STATUS status;
            if (ControlService(service, SERVICE_CONTROL_STOP, &status)) {
                printf("✓ 드라이버 서비스가 중지되었습니다.\n");
                // 서비스가 완전히 중지될 때까지 대기
                Sleep(2000);
            } else {
                DWORD error = GetLastError();
                if (error == ERROR_SERVICE_NOT_ACTIVE) {
                    printf("✓ 드라이버 서비스가 이미 중지되어 있습니다.\n");
                } else {
                    printf("⚠️  드라이버 서비스 중지 실패 (Error: %ld)\n", error);
                }
            }
            
            // 서비스 삭제
            if (DeleteService(service)) {
                printf("✓ 드라이버 서비스가 삭제되었습니다.\n");
            } else {
                printf("✗ 드라이버 서비스 삭제 실패 (Error: %ld)\n", GetLastError());
                success = false;
            }
            
            CloseServiceHandle(service);
        } else {
            DWORD error = GetLastError();
            if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
                printf("✓ 드라이버 서비스가 이미 삭제되어 있습니다.\n");
            } else {
                printf("✗ 드라이버 서비스에 접근할 수 없습니다 (Error: %ld)\n", error);
                success = false;
            }
        }
        CloseServiceHandle(scManager);
    } else {
        printf("✗ Service Control Manager에 접근할 수 없습니다.\n");
        success = false;
    }
    
    // 3. 레지스트리에서 필터 제거
    printf("레지스트리에서 필터를 제거합니다...\n");
    HKEY hKey;
    LONG result = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                               L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E967-E325-11CE-BFC1-08002BE10318}",
                               0, KEY_READ | KEY_WRITE, &hKey);
    
    if (result == ERROR_SUCCESS) {
        DWORD dataType;
        DWORD dataSize = 0;
        result = RegQueryValueEx(hKey, L"LowerFilters", NULL, &dataType, NULL, &dataSize);
        
        if (result == ERROR_SUCCESS && dataType == REG_MULTI_SZ) {
            std::vector<wchar_t> existingData(dataSize / sizeof(wchar_t));
            result = RegQueryValueEx(hKey, L"LowerFilters", NULL, &dataType, 
                                     (LPBYTE)existingData.data(), &dataSize);
            
            if (result == ERROR_SUCCESS) {
                // scsi_filter를 제거한 새로운 필터 목록 생성
                std::vector<wchar_t> newFilterData;
                const wchar_t* currentFilter = existingData.data();
                bool removed = false;
                
                while (*currentFilter) {
                    if (wcscmp(currentFilter, L"scsi_filter") != 0) {
                        // scsi_filter가 아닌 필터들만 새 목록에 추가
                        size_t filterLen = wcslen(currentFilter);
                        newFilterData.insert(newFilterData.end(), currentFilter, currentFilter + filterLen + 1);
                    } else {
                        removed = true;
                    }
                    currentFilter += wcslen(currentFilter) + 1;
                }
                
                if (removed) {
                    if (newFilterData.empty()) {
                        // 다른 필터가 없으면 LowerFilters 값 삭제
                        if (RegDeleteValue(hKey, L"LowerFilters") == ERROR_SUCCESS) {
                            printf("✓ LowerFilters 값이 삭제되었습니다.\n");
                        } else {
                            printf("✗ LowerFilters 값 삭제 실패\n");
                            success = false;
                        }
                    } else {
                        // 다른 필터가 있으면 업데이트
                        newFilterData.push_back(L'\0'); // 마지막 널 종료 추가
                        
                        result = RegSetValueEx(hKey, L"LowerFilters", 0, REG_MULTI_SZ,
                                               (LPBYTE)newFilterData.data(),
                                               (DWORD)(newFilterData.size() * sizeof(wchar_t)));
                        
                        if (result == ERROR_SUCCESS) {
                            printf("✓ scsi_filter가 LowerFilters에서 제거되었습니다.\n");
                        } else {
                            printf("✗ LowerFilters 업데이트 실패 (Error: %ld)\n", result);
                            success = false;
                        }
                    }
                } else {
                    printf("✓ scsi_filter가 LowerFilters에 등록되어 있지 않았습니다.\n");
                }
            }
        } else if (result == ERROR_FILE_NOT_FOUND) {
            printf("✓ LowerFilters 값이 존재하지 않습니다.\n");
        } else {
            printf("✗ LowerFilters 값을 읽을 수 없습니다 (Error: %ld)\n", result);
            success = false;
        }
        
        RegCloseKey(hKey);
    } else {
        printf("✗ 디스크 클래스 레지스트리 키에 접근할 수 없습니다 (Error: %ld)\n", result);
        success = false;
    }
    
    // 4. INF 파일을 통해 설치된 경우 제거 시도
    printf("INF 파일을 통해 설치된 드라이버를 제거합니다...\n");
    wchar_t cmdLine[512];
    swprintf(cmdLine, 512, L"pnputil /delete-driver scsi_filter.inf /uninstall /force");
    
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    if (CreateProcess(NULL, cmdLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 10000); // 10초 대기
        
        DWORD exitCode;
        if (GetExitCodeProcess(pi.hProcess, &exitCode)) {
            if (exitCode == 0) {
                printf("✓ INF 드라이버가 제거되었습니다.\n");
            } else {
                printf("⚠️  INF 드라이버 제거 실패 또는 설치되지 않았음 (Exit code: %ld)\n", exitCode);
            }
        }
        
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        printf("⚠️  pnputil 실행 실패. 수동으로 제거해야 할 수 있습니다.\n");
    }
    
    if (success) {
        printf("\n✅ 드라이버 제거가 완료되었습니다.\n");
        printf("변경사항을 완전히 적용하려면 시스템을 재부팅하세요.\n");
    } else {
        printf("\n⚠️  일부 제거 과정에서 오류가 발생했습니다.\n");
        printf("수동으로 다음을 확인해주세요:\n");
        printf("1. 서비스: sc delete scsi_filter\n");
        printf("2. 레지스트리: LowerFilters 값에서 scsi_filter 제거\n");
        printf("3. INF: pnputil /delete-driver scsi_filter.inf /uninstall\n");
    }
    
    return success;
}
    
    if (result != ERROR_SUCCESS) {
        printf("디스크 클래스 레지스트리 키를 열 수 없습니다.
");
        return false;
    }
    
    DWORD dataType;
    DWORD dataSize = 0;
    result = RegQueryValueEx(hKey, L"LowerFilters", NULL, &dataType, NULL, &dataSize);
    
    if (result == ERROR_FILE_NOT_FOUND) {
        printf("LowerFilters 값이 설정되지 않았습니다.
");
        RegCloseKey(hKey);
        return false;
    }
    
    if (result != ERROR_SUCCESS || dataType != REG_MULTI_SZ) {
        printf("LowerFilters 값을 읽을 수 없습니다.
");
        RegCloseKey(hKey);
        return false;
    }
    
    std::vector<wchar_t> filterData(dataSize / sizeof(wchar_t));
    result = RegQueryValueEx(hKey, L"LowerFilters", NULL, &dataType, 
                             (LPBYTE)filterData.data(), &dataSize);
    
    RegCloseKey(hKey);
    
    if (result != ERROR_SUCCESS) {
        printf("LowerFilters 값을 읽는데 실패했습니다.
");
        return false;
    }
    
    // scsi_filter가 등록되어 있는지 확인
    const wchar_t* currentFilter = filterData.data();
    bool found = false;
    
    printf("현재 등록된 Lower Filters:
");
    while (*currentFilter) {
        printf("  - %ws
", currentFilter);
        if (wcscmp(currentFilter, L"scsi_filter") == 0) {
            found = true;
        }
        currentFilter += wcslen(currentFilter) + 1;
    }
    
    if (found) {
        printf("✓ scsi_filter가 LowerFilters에 등록되어 있습니다.
");
    } else {
        printf("✗ scsi_filter가 LowerFilters에 등록되지 않았습니다.
");
    }
    
    return found;
}

bool TryConnectToDriver(HANDLE& hDevice) {

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
    wprintf(L"Dropped Requests: %ld\n", stats->DroppedRequests);  // %ld로 변경
    wprintf(L"Buffer Utilization: %lu%%\n", stats->BufferUtilization);
    
    // 드롭률 계산 및 경고
    if (stats->DroppedRequests > lastDroppedCount) {
        LONG newDrops = stats->DroppedRequests - lastDroppedCount;
        wprintf(L"⚠️  New drops since last check: %ld\n", newDrops);  // %ld로 변경
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
    wprintf(L"[D]     - Run diagnostics\n");
    wprintf(L"[U]     - Uninstall driver\n");
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
        
        case 'd':
        case 'D': // Diagnostics
            RunDiagnostics();
            return TRUE;
            
        case 'u':
        case 'U': // Uninstall driver
        {
            wprintf(L"\n⚠️  드라이버를 제거하시겠습니까? (Y/N): ");
            int confirm = _getch();
            if (confirm == 'Y' || confirm == 'y') {
                wprintf(L"Y\n");
                wprintf(L"드라이버를 제거합니다...\n");
                if (UninstallFilterDriver()) {
                    wprintf(L"드라이버 제거가 완료되었습니다. 프로그램을 종료합니다.\n");
                    SaveTraceDataToCSV(L"scsi_trace_data.csv");
                    return FALSE; // 프로그램 종료
                } else {
                    wprintf(L"드라이버 제거 중 오류가 발생했습니다.\n");
                }
            } else {
                wprintf(L"N\n드라이버 제거가 취소되었습니다.\n");
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

BOOL CheckDriverStatus() {
    SC_HANDLE scManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (scManager == NULL) {
        wprintf(L"Failed to open Service Control Manager. Error: %lu\n", GetLastError());
        return FALSE;
    }
    
    SC_HANDLE service = OpenService(scManager, L"scsi_filter", SERVICE_QUERY_STATUS);
    if (service == NULL) {
        DWORD error = GetLastError();
        CloseServiceHandle(scManager);
        
        if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
            wprintf(L"❌ SCSI Filter driver service is not installed.\n");
            ShowDriverInstallationGuide();
        } else {
            wprintf(L"Failed to open scsi_filter service. Error: %lu\n", error);
        }
        return FALSE;
    }
    
    SERVICE_STATUS status;
    if (!QueryServiceStatus(service, &status)) {
        wprintf(L"Failed to query service status. Error: %lu\n", GetLastError());
        CloseServiceHandle(service);
        CloseServiceHandle(scManager);
        return FALSE;
    }
    
    CloseServiceHandle(service);
    CloseServiceHandle(scManager);
    
    switch (status.dwCurrentState) {
    case SERVICE_RUNNING:
        wprintf(L"✅ SCSI Filter driver is running.\n");
        return TRUE;
    case SERVICE_STOPPED:
        wprintf(L"⚠️  SCSI Filter driver is installed but stopped.\n");
        wprintf(L"Run: sc start scsi_filter (as Administrator)\n");
        return FALSE;
    case SERVICE_PAUSED:
        wprintf(L"⚠️  SCSI Filter driver is paused.\n");
        return FALSE;
    default:
        wprintf(L"⚠️  SCSI Filter driver is in state: %lu\n", status.dwCurrentState);
        return FALSE;
    }
}

void ShowDriverInstallationGuide() {
    wprintf(L"\n=== SCSI 필터 드라이버 설치 가이드 ===\n\n");
    
    wprintf(L"방법 1: INF 파일을 사용한 설치 (권장)\n");
    wprintf(L"---------------------------------------\n");
    wprintf(L"1. 관리자 권한으로 명령 프롬프트를 실행하세요\n");
    wprintf(L"2. 드라이버 디렉토리로 이동: cd \"드라이버_경로\"\n");
    wprintf(L"3. INF 파일 설치: pnputil /add-driver scsi_filter.inf /install\n");
    wprintf(L"4. 드라이버 서비스 시작: sc start scsi_filter\n");
    wprintf(L"5. 시스템 재부팅\n\n");
    
    wprintf(L"방법 2: 레지스트리를 통한 수동 등록\n");
    wprintf(L"----------------------------------\n");
    wprintf(L"1. 관리자 권한으로 레지스트리 편집기(regedit) 실행\n");
    wprintf(L"2. 다음 경로로 이동:\n");
    wprintf(L"   HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Class\\\n");
    wprintf(L"   {4D36E967-E325-11CE-BFC1-08002BE10318}\n");
    wprintf(L"3. 'LowerFilters' 값을 찾거나 새로 생성 (형식: REG_MULTI_SZ)\n");
    wprintf(L"4. 값 데이터에 'scsi_filter' 추가\n");
    wprintf(L"5. 드라이버 서비스 등록:\n");
    wprintf(L"   sc create scsi_filter binPath= \"C:\\path\\to\\scsi_filter.sys\" type= kernel start= system\n");
    wprintf(L"6. 드라이버 서비스 시작: sc start scsi_filter\n");
    wprintf(L"7. 시스템 재부팅\n\n");
    
    wprintf(L"방법 3: DevCon 도구 사용 (고급 사용자)\n");
    wprintf(L"-------------------------------------\n");
    wprintf(L"1. Windows SDK에서 devcon.exe 다운로드\n");
    wprintf(L"2. 관리자 권한으로 실행:\n");
    wprintf(L"   devcon install scsi_filter.inf *\n");
    wprintf(L"3. 시스템 재부팅\n\n");
    
    wprintf(L"중요 참고사항:\n");
    wprintf(L"- 필터 드라이버는 시스템 재부팅 후에 활성화됩니다\n");
    wprintf(L"- 디지털 서명되지 않은 드라이버의 경우 테스트 모드 활성화가 필요할 수 있습니다\n");
    wprintf(L"- 테스트 모드: bcdedit /set testsigning on (재부팅 필요)\n");
    wprintf(L"- 시스템 복원 지점을 미리 생성하는 것을 권장합니다\n\n");
    
    wprintf(L"문제 해결:\n");
    wprintf(L"- 드라이버 로드 실패: 로그를 확인하고 서명 문제를 점검하세요\n");
    wprintf(L"- 장치 인식 실패: 디바이스 매니저에서 드라이버 상태를 확인하세요\n");
    wprintf(L"- 성능 문제: 시스템 이벤트 로그를 모니터링하세요\n\n");
    
    wprintf(L"드라이버 제거 방법:\n");
    wprintf(L"------------------\n");
    wprintf(L"1. 앱에서 [U] 키를 누르면 자동 제거\n");
    wprintf(L"2. 수동 제거:\n");
    wprintf(L"   - 서비스 삭제: sc delete scsi_filter\n");
    wprintf(L"   - 레지스트리에서 LowerFilters 값의 scsi_filter 제거\n");
    wprintf(L"   - INF 제거: pnputil /delete-driver scsi_filter.inf /uninstall\n");
    wprintf(L"   - 시스템 재부팅\n");
    wprintf(L"=============================================\n\n");
}

BOOL TryConnectToDriver() {
    // 여러 가능한 디바이스 경로 시도
    const wchar_t* devicePaths[] = {
        L"\\\\.\\SCSITraceControl",
        L"\\\\.\\Global\\SCSITraceControl",
        L"\\Device\\SCSITraceControl"
    };
    
    for (int i = 0; i < 3; i++) {
        HANDLE testHandle = CreateFileW(devicePaths[i], 
                                       GENERIC_READ | GENERIC_WRITE, 
                                       0, NULL, OPEN_EXISTING, 
                                       FILE_ATTRIBUTE_NORMAL, NULL);
        if (testHandle != INVALID_HANDLE_VALUE) {
            wprintf(L"✅ Connected to: %s\n", devicePaths[i]);
            if (hControlDevice == INVALID_HANDLE_VALUE) {
                hControlDevice = testHandle;
                return TRUE;
            }
            CloseHandle(testHandle);
            return TRUE;
        }
        wprintf(L"❌ Failed to connect to %s (Error: %lu)\n", devicePaths[i], GetLastError());
    }
    return FALSE;
}

void RunDiagnostics() {
    wprintf(L"\n=== SCSI Filter Driver Diagnostics ===\n");
    
    // 1. 관리자 권한 확인
    wprintf(L"1. Checking administrator privileges...\n");
    if (IsUserAnAdmin()) {
        wprintf(L"   ✅ Running with administrator privileges\n");
    } else {
        wprintf(L"   ⚠️  Not running as administrator\n");
        wprintf(L"   Some operations may require elevated privileges\n");
    }
    
    // 2. 드라이버 서비스 상태 확인
    wprintf(L"\n2. Checking driver service status...\n");
    BOOL driverRunning = CheckDriverStatus();
    
    // 3. 디바이스 경로 테스트
    wprintf(L"\n3. Testing device paths...\n");
    BOOL deviceAccessible = TryConnectToDriver();
    
    // 4. 시스템 정보
    wprintf(L"\n4. System Information...\n");
    OSVERSIONINFO osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    if (GetVersionEx(&osvi)) {
        wprintf(L"   OS Version: %lu.%lu Build %lu\n", 
                osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
    }
    
    // 5. 권장사항
    wprintf(L"\n=== Diagnosis Results ===\n");
    if (!driverRunning && !deviceAccessible) {
        wprintf(L"❌ Driver is not installed or not running\n");
        wprintf(L"💡 Recommendation: Install driver using INF file method\n");
        wprintf(L"   This ensures proper filter driver registration.\n");
    } else if (driverRunning && !deviceAccessible) {
        wprintf(L"⚠️  Driver is running but control device is not accessible\n");
        wprintf(L"💡 Recommendation: Check driver logs in Event Viewer\n");
    } else if (!driverRunning && deviceAccessible) {
        wprintf(L"⚠️  Unexpected state: Device accessible but service not running\n");
    } else {
        wprintf(L"✅ Driver appears to be working correctly\n");
    }
    
    wprintf(L"=====================================\n\n");
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

    // 드라이버 상태 확인
    wprintf(L"\nChecking SCSI Filter driver status...\n");
    if (!CheckDriverStatus()) {
        wprintf(L"Driver is not loaded. Please install and start the driver first.\n");
        wprintf(L"Press [D] to run full diagnostics or see installation guide above.\n");
        CleanupResources();
        return 1;
    }

    // 필터 등록 상태 확인
    wprintf(L"\nChecking filter registration status...\n");
    bool filterRegistered = CheckFilterRegistration();
    
    if (!filterRegistered) {
        wprintf(L"\nSCSI 필터가 시스템에 등록되지 않았습니다.\n");
        wprintf(L"옵션을 선택하세요:\n");
        wprintf(L"[A] 자동 필터 등록 시도\n");
        wprintf(L"[M] 수동 설치 가이드 보기\n");
        wprintf(L"[C] 등록 없이 계속 진행 (제한된 기능)\n");
        wprintf(L"[Q] 종료\n");
        wprintf(L"선택: ");
        
        wchar_t choice = getwchar();
        choice = towupper(choice);
        
        switch (choice) {
            case L'A':
                if (AutoRegisterFilterDriver()) {
                    wprintf(L"필터 등록이 완료되었습니다. 재부팅 후 다시 실행하세요.\n");
                } else {
                    wprintf(L"자동 등록에 실패했습니다. 수동 설치를 시도하세요.\n");
                    ShowDriverInstallationGuide();
                }
                CleanupResources();
                return 0;
                
            case L'M':
                ShowDriverInstallationGuide();
                CleanupResources();
                return 0;
                
            case L'C':
                wprintf(L"등록 없이 계속 진행합니다...\n");
                break;
                
            case L'Q':
            default:
                CleanupResources();
                return 0;
        }
    } else {
        wprintf(L"✓ SCSI 필터가 시스템에 등록되어 있습니다.\n");
        wprintf(L"옵션을 선택하세요:\n");
        wprintf(L"[C] 계속 진행\n");
        wprintf(L"[U] 드라이버 제거\n");
        wprintf(L"[Q] 종료\n");
        wprintf(L"선택: ");
        
        wchar_t choice = getwchar();
        choice = towupper(choice);
        
        switch (choice) {
            case L'C':
                wprintf(L"드라이버와 연결을 진행합니다...\n");
                break;
                
            case L'U':
                if (UninstallFilterDriver()) {
                    wprintf(L"드라이버 제거가 완료되었습니다. 재부팅 후 변경사항이 적용됩니다.\n");
                } else {
                    wprintf(L"드라이버 제거 중 오류가 발생했습니다. 로그를 확인하세요.\n");
                }
                CleanupResources();
                return 0;
                
            case L'Q':
            default:
                CleanupResources();
                return 0;
        }
    }

    // 드라이버의 컨트롤 디바이스에 연결 시도
    wprintf(L"Attempting to connect to SCSI filter driver...\n");
    
    if (!TryConnectToDriver()) {
        fwprintf(stderr, L"Failed to connect to SCSI trace control device.\n");
        fwprintf(stderr, L"Please run diagnostics ([D] key) for detailed information.\n");
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