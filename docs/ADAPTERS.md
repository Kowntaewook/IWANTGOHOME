# 선택 도구와 호스트 어댑터

## Android 정적 분석

android 프로필은 Androguard 4.1.4, JADX 1.5.6, apktool 3.0.3, Debian aapt/aapt2/apksigner를 설치하도록 구성했습니다. JADX는 안전하게 읽은 APK/AAB의 임시 사본에 고정 인자(리소스 제외, 단일 스레드, 사용자 설정 제외)를 사용합니다. 생성된 소스는 정적 결과로 요약한 뒤 임시 폴더를 정리합니다. 앱을 설치하거나 실행하지 않습니다.

apktool/aapt/apksigner는 선택 이미지의 유틸리티이며 임의 인자 MCP는 없습니다. android_certificate_info는 인증서 메타데이터입니다. APK v2/v3/v4 서명 검증을 수행한 것으로 해석하면 안 됩니다. 합성 DEX/APK의 실제 JADX 디컴파일은 Linux 호스트에서 검증했고 이미지 전체 빌드는 미검증입니다.

## Ghidra

binary 프로필은 LIEF 1.0.0, Ghidra 12.1.3, Temurin JDK 21을 사용합니다. ghidra_analyze는 입력 크기/포맷 검사 후 새 임시 프로젝트와 저장소의 FinderMetadata.java만 사용합니다. 임의 postScript, 기존 프로젝트 또는 대상 실행을 받지 않습니다.

ghidra_functions/ghidra_symbols는 분석 record_id를 받아 저장된 결과를 읽습니다. 자동 분석 timeout은 partial_analysis입니다. 기본 파일 16 MiB/30초, 운영자 설정 상한 64 MiB/120초, Java heap 768 MiB, worker 주소 공간 8 GiB, Docker 메모리 3 GiB로 제한했습니다. 합성 ELF의 Ghidra 실행과 PE/ELF/Mach-O의 LIEF 파싱을 검증했습니다. Ghidra의 모든 포맷/실제 앱 호환성은 미검증입니다.

기존 ghidra-projects를 읽거나 덮어쓰지 않습니다. 함수 경계/심볼은 런타임 증거가 아닙니다.

## Burp MCP

FINDER_PROFILES=burp로 선택하고 호스트의 Burp/MCP 확장은 사용자가 준비합니다.

| 변수 | 의미 |
|---|---|
| BURP_MCP_URL | 실제 host MCP URL; SSE는 호스트가 제공한 /sse 경로 |
| BURP_MCP_TOKEN | 호스트가 요구하는 경우 Bearer token; 모델/결과에 출력하지 않음 |
| BURP_MCP_TRANSPORT | sse(기본) 또는 streamable-http |

burp_capabilities는 실제 initialize/tools/list를 호출합니다. 읽기 도구도 매번 지원 스키마를 확인합니다.

| 로컬 MCP | 검토한 원격 이름 |
|---|---|
| burp_proxy_history | get_proxy_http_history |
| burp_saved_requests | get_organizer_items |
| burp_websocket_history | get_proxy_websocket_history |

최대 20개, offset 10,000, 연결 전체 12초/수신 2 MiB입니다. 같은 origin의 MCP 전송만 허용하고 리다이렉트는 따라가지 않습니다. 원문/노트/자격증명 값은 결과에서 제외하며 알 수 없는 형식은 감춥니다.

원격 compare/OpenAPI/GraphQL 기능은 가정하지 않습니다. 기존 compare_records와 로컬 OpenAPI/GraphQL 도구를 사용합니다. Burp가 없어도 시스템은 정상 작동합니다. 실제 Burp 대신 로컬 합성 MCP의 SSE/Streamable HTTP를 검증했습니다.

## Android host/device

FINDER_PROFILES=android-dynamic으로 선택합니다. USB/emulator/ADB/Frida 서버는 호스트가 관리합니다.

| 변수 | 예시 |
|---|---|
| FINDER_ADB_ENDPOINT | host.docker.internal:5037 |
| FINDER_FRIDA_ENDPOINT | host.docker.internal:27042 |

Compose는 host.docker.internal을 host-gateway에 연결합니다. 호스트 서비스의 바인딩/접근 설정은 운영자가 관리하며 자동 변경하지 않습니다.

- adb_devices: 이미 연결된 장치의 opaque ID/상태. 원본 serial은 출력하지 않음.
- adb_package_info: 선택한 장치/package의 일부 dumpsys 선언.
- adb_logcat_snapshot: 선택한 실행 중 package의 단일 PID, 최대 200행. 메시지 전체를 숨기고 level/tag/secret indicator만 반환.
- frida_devices / frida_process_list: 구성된 endpoint와 최소 process 목록. attach/spawn/hooks/임의 JS 없음.

연결/장치/클라이언트가 없으면 HOST_ADAPTER_REQUIRED이며 package PID가 없으면 별도의 제한 상태를 반환할 수 있습니다. worker 전체 15초 상한입니다. 실제 장치는 없었고 고정 명령 계약/최소화만 mock으로 검증했습니다.

## iOS 및 기타 경계

Linux에서는 IPA/Info.plist/제공된 entitlement/ATS/scheme/framework/Mach-O 정적 정보만 제공합니다. codesign/keychain/iOS 기기·simulator/암호화 코드 분석은 지원하지 않습니다. 펌웨어 에뮬레이션, live capture, 클라우드 API 권한 검증도 제공하지 않습니다.
