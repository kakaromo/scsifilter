# SCSI Filter Driver

Windows 커널 모드 SCSI 필터 드라이버로 디스크 장치의 SCSI 명령을 모니터링하고 추적합니다.

## 프로젝트 구조

```
scsifilter/
├── scsi_filter/          # 커널 모드 필터 드라이버
├── scsi_tracer/          # 사용자 모드 제어 애플리케이션
├── inf scsi_filter/      # 드라이버 설치 파일
└── README.md
```

## 기능

### 드라이버 기능
- **SCSI 명령 모니터링**: 모든 SCSI I/O 요청 실시간 추적
- **성능 최적화**: 
  - 적응형 드롭 메커니즘으로 시스템 부하 최소화
  - Volatile 변수와 InterlockedIncrement 사용
  - 효율적인 버퍼 관리
- **Lower Filter**: 디스크 장치 스택의 하위 레벨에서 동작
- **다중 IOCTL 지원**: 트레이싱 제어 및 통계 수집

### 사용자 애플리케이션 기능
- **대화형 제어**: 실시간 트레이싱 on/off
- **자동 필터 등록**: 레지스트리를 통한 원클릭 설치
- **드라이버 제거**: 완전한 언인스톨 기능
- **진단 도구**: 드라이버 상태 및 시스템 호환성 확인
- **CSV 내보내기**: 수집된 데이터 분석용 파일 생성
- **실시간 통계**: 성능 모니터링 및 알림

## 설치 방법

### 1. INF 파일을 이용한 설치 (권장)

관리자 권한으로 명령 프롬프트를 열고:

```cmd
# 드라이버 설치
pnputil /add-driver scsi_filter.inf /install

# 드라이버 시작
sc start scsi_filter

# 시스템 재부팅 (필수)
shutdown /r /t 0
```

### 2. 자동 설치 (애플리케이션 사용)

1. `scsi_tracer.exe`를 관리자 권한으로 실행
2. 필터가 등록되지 않은 경우 **[A] 자동 필터 등록** 선택
3. 시스템 재부팅

### 3. 수동 레지스트리 설치

1. 관리자 권한으로 레지스트리 편집기 실행
2. 다음 경로로 이동:
   ```
   HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\
   {4D36E967-E325-11CE-BFC1-08002BE10318}
   ```
3. `LowerFilters` 값 (REG_MULTI_SZ) 생성 또는 수정
4. 값 데이터에 `scsi_filter` 추가
5. 드라이버 서비스 등록:
   ```cmd
   sc create scsi_filter binPath= "C:\path\to\scsi_filter.sys" type= kernel start= system
   ```
6. 시스템 재부팅

## 사용법

### 기본 사용법

1. 관리자 권한으로 `scsi_tracer.exe` 실행
2. 모니터링할 물리 드라이브 선택
3. 실시간 SCSI 명령 추적 시작

### 제어 명령

- **[SPACE]**: 트레이싱 on/off 토글
- **[S]**: 드라이버 통계 표시
- **[D]**: 진단 실행
- **[U]**: 드라이버 제거
- **[C]**: 화면 지우기
- **[ESC]**: 데이터 저장 후 종료
- **[H]**: 도움말 표시

### 출력 데이터

수집된 SCSI 추적 데이터는 다음 정보를 포함합니다:

- **CDB Length**: SCSI 명령 길이
- **SCSI Status**: 명령 실행 상태
- **CDB Data**: SCSI 명령 데이터 (16바이트)
- **Data Transfer Length**: 전송 데이터 크기
- **Sense Info**: 오류 정보 (있는 경우)

## 드라이버 제거

### 자동 제거 (애플리케이션 사용)

1. `scsi_tracer.exe` 실행
2. **[U]** 키를 눌러 제거 메뉴 진입
3. **Y** 확인 후 자동 제거 진행

### 수동 제거

```cmd
# 서비스 중지 및 삭제
sc stop scsi_filter
sc delete scsi_filter

# INF 드라이버 제거
pnputil /delete-driver scsi_filter.inf /uninstall

# 레지스트리에서 LowerFilters의 scsi_filter 제거
# 시스템 재부팅
```

## 시스템 요구사항

- **OS**: Windows 10/11 (64-bit)
- **권한**: 관리자 권한 필수
- **아키텍처**: x64
- **테스트 모드**: 서명되지 않은 드라이버의 경우 필요

### 테스트 모드 활성화

```cmd
# 테스트 모드 활성화
bcdedit /set testsigning on

# 재부팅 후 적용
shutdown /r /t 0

# 테스트 모드 비활성화 (필요시)
bcdedit /set testsigning off
```

## 개발 정보

### 빌드 환경

- **IDE**: Visual Studio 2019/2022
- **WDK**: Windows Driver Kit (최신 버전)
- **SDK**: Windows 10/11 SDK
- **언어**: C/C++

### 아키텍처

```
User Application (scsi_tracer.exe)
        ↓ DeviceIoControl
Control Device (\Device\SCSITraceControl)
        ↓
SCSI Filter Driver (scsi_filter.sys)
        ↓ Lower Filter
Disk Class Driver (disk.sys)
        ↓
Port Driver (storport.sys)
        ↓
Hardware (Physical Disk)
```

### 주요 구성 요소

- **Driver.c**: 메인 드라이버 로직 및 필터 처리
- **Device.c**: 디바이스 관리 및 I/O 처리
- **Queue.c**: 데이터 버퍼링 및 큐 관리
- **scsi_trace.cpp**: 사용자 인터페이스 및 제어

## 문제 해결

### 일반적인 문제

1. **드라이버 로드 실패**
   - 디지털 서명 확인 (테스트 모드 필요시)
   - 관리자 권한으로 실행 확인
   - 시스템 이벤트 로그 확인

2. **장치 연결 실패 (-2 오류)**
   - 드라이버 서비스 상태 확인: `sc query scsi_filter`
   - 필터 등록 상태 확인: 애플리케이션에서 [D] 진단 실행
   - 시스템 재부팅 후 재시도

3. **성능 문제**
   - 통계 모니터링: [S] 키로 드롭 요청 확인
   - 트레이싱 일시 중지: [SPACE] 키
   - 버퍼 사용률 80% 초과시 주의

### 로그 확인

- **시스템 이벤트**: 이벤트 뷰어 → Windows 로그 → 시스템
- **드라이버 디버그**: DebugView 도구 사용
- **애플리케이션 로그**: 콘솔 출력 확인

## 보안 고려사항

- 커널 모드 드라이버로 시스템 권한 필요
- 프로덕션 환경에서는 코드 서명 필수
- 시스템 복원 지점 생성 권장
- 바이러스 스캐너 예외 설정 필요할 수 있음

## 라이센스

이 프로젝트는 개발 및 교육 목적으로 제공됩니다.

## 기여

버그 리포트 및 기능 개선 제안을 환영합니다.

## 업데이트 이력

### v1.0.0 (2024-01-01)
- 초기 릴리스
- SCSI 명령 모니터링 기능
- 기본 필터 드라이버 구현

### v1.1.0 (현재)
- 성능 최적화 (적응형 드롭 메커니즘)
- 자동 필터 등록 기능
- 드라이버 제거 기능
- 향상된 진단 도구
- 실시간 통계 모니터링
- CSV 데이터 내보내기
- 사용자 인터페이스 개선
