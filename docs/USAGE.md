# something-finder · ChatGPT Codex 연구 환경

ChatGPT 계정으로 로그인한 **Codex CLI**와 고정 목적 MCP 도구로 허가된 파일·소스·앱과 정상 웹 동작을 검토합니다. 기존 Python/FastMCP, Docker, 로그인, 기록 구조를 확장한 0.3.0 작업본입니다.

## 기존 작업과 기록

현재 기준은 사용자가 복원한 **/workspace/something_finder**입니다. 이전 ZIP을 구현 원본으로 사용하지 않습니다. 기존 Compose 프로젝트 `something-finder-codex`, `codex-state-v1` 인증/대화, `evidence-v1` 증거 볼륨을 유지하고 `browser-sessions-v1`만 추가했습니다. 종료 명령은 `stop`이며 데이터 초기화/볼륨 삭제 명령은 없습니다. 저장된 Codex 설정도 덮어쓰지 않습니다.

## Mac에서 실행

Docker Desktop/Compose와 호스트 Python 3.11 이상이 필요합니다. 프로젝트 폴더에서 한 번 설치합니다.

```sh
./scripts/finder.sh install
# 새 터미널을 열거나 설치기가 출력한 PATH 명령 실행
IWANTTOGOHOME build
IWANTTOGOHOME login
IWANTTOGOHOME
```

설치기는 `~/.local/bin/IWANTTOGOHOME`에서 현재 finder.sh를 호출하고 기존 `~/.zshrc`를 유지한 채 PATH를 추가합니다. 같은 이름의 다른 명령은 덮어쓰지 않습니다. 프로젝트를 이동하면 명령의 경로도 갱신해야 합니다. **실제 Mac 홈에 설치한 상태는 아니며 임시 디렉터리에서 설치/재실행을 검증했습니다.**

기존 `./scripts/finder.sh build|login|run`도 유지합니다. Windows는 `scripts/finder.ps1`과 Linux 컨테이너를 사용합니다.

`login`은 공식 `codex login --device-auth`를 실행합니다. 표시된 공식 URL과 일회용 코드로 로그인하며 API 키 입력은 필요하지 않습니다. 실제 계정/워크스페이스의 허용 설정이 적용됩니다. [공식 인증 문서](https://learn.chatgpt.com/docs/auth)

| 명령 | 동작 |
|---|---|
| 인자 없음 / run | 선택 서비스와 Codex 실행 |
| build | 기본 및 선택 프로필 이미지 빌드 |
| login / logout / switch | 전용 Codex 볼륨의 로그인/로그아웃/계정 변경 |
| resume | 마지막 Codex 대화 재개 |
| status / doctor | 자격증명을 출력하지 않는 진단 |
| stop | 현재 프로젝트 정지, 볼륨 보존 |
| approve PLAN.json / revoke GRANT_ID | 호스트에서 관찰 계획 검토·승인/철회 |
| session-import user_a STATE.json | 브라우저 저장 상태 초기 1회 가져오기 |
| test | 테스트 이미지 빌드 후 합성 테스트 |
| install | 셸 명령 설치 |

status는 원격 계정 권한까지 보장하지 않습니다. 모델은 고정하지 않았으며 필요한 경우 계정에서 지원하는 이름을 FINDER_MODEL에 지정합니다. switch도 대화/증거를 삭제하지 않습니다.

## 입력과 선택 프로필

```sh
export FINDER_INPUT_DIR=/absolute/path/to/authorized-files
export FINDER_PROFILES=web,android,binary
IWANTTOGOHOME build
IWANTTOGOHOME
```

| 논리 프로필 | 구성 |
|---|---|
| default 또는 미지정 | analysis + Codex; 로컬 API/소스/의존성 분석 |
| web | Chromium, 독립 persistent profiles, 승인 관찰 |
| android | Androguard, JADX, apktool, apksigner, aapt/aapt2 |
| android-dynamic | 명시한 호스트의 ADB/Frida 메타데이터 |
| binary | LIEF + Ghidra headless |
| burp | 호스트 Burp MCP의 기존 기록 읽기 |
| 기존 platform | Android/LIEF 메타데이터 호환 프로필 |

default는 선택 프로필 없이 시작하는 논리 이름입니다. 기존 FINDER_WEB=1, FINDER_PLATFORM=1도 유지하고 FINDER_ANDROID, FINDER_ANDROID_DYNAMIC, FINDER_BINARY, FINDER_BURP를 사용할 수 있습니다. 새 MCP 등록은 실행 옵션으로 적용하여 이전 설정 파일을 보존합니다.

기본 입력은 합성 예제입니다. 선택 입력은 읽기 전용이며 UID 1000의 읽기 권한이 필요합니다. 소유권을 자동 변경하지 않습니다. 기본 이미지에는 Java/JADX/Ghidra/Chromium/Frida를 설치하지 않습니다.

## 정상 웹·SPA 관찰

1. examples/session-plan.json을 복사해 identity, 시작 URL, 정확한 허용/제외 URL을 작성합니다. API/script/iframe/resource와 리다이렉트 목적지도 직접 선택합니다.
2. 로컬/사설망은 allow_private_targets: true와 정확한 private_cidrs가 함께 필요합니다. 기본은 차단입니다. Docker의 127.0.0.1은 컨테이너 자신이며 Mac 호스트는 선택한 host.docker.internal URL과 실제 목적지 CIDR이 필요합니다.
3. 인증이 필요한 경우 호스트에서 준비한 Playwright storage-state 파일을 가져옵니다.

```sh
IWANTTOGOHOME session-import user_a /absolute/path/state-a.json
IWANTTOGOHOME session-import user_b /absolute/path/state-b.json
IWANTTOGOHOME approve /absolute/path/session-plan.json
```

토큰/쿠키 파일 내용은 Codex에 전달하지 않습니다. 승인 계획을 읽고 TTY 확인 문구를 입력하면 15분 유효한 일회용 grant_id를 받습니다. Codex에서 observe_session을 호출하고 web_status의 완료/부분 실패 및 감사 기록을 확인합니다.

anonymous/user_a/user_b는 별도 0700 디렉터리와 잠금으로 분리됩니다. 쿠키/localStorage는 재실행 후 유지하고 결과에는 자격증명 존재 여부와 요청/응답 구조만 남깁니다. 초기 가져오기는 1회만 지원하며 만료된 프로필의 자동 재로그인은 없습니다.

관찰 범위는 **초기 정상 페이지 로드와 그 SPA 활동**입니다. navigation, fetch, XHR, GraphQL 구조, iframe/script/resource origin, WebSocket opening handshake, 제한된 SSE snapshot을 기록합니다. WebSocket 프레임/계속되는 SSE 스트림, 자동 클릭·폼·로그인은 지원하지 않습니다. POST는 호스트가 검토한 정확한 body SHA-256만 허용하고 GraphQL mutation/remote introspection은 차단합니다.

기존 observe_web의 read(GET), browser(스크립트 없는 문서)는 유지합니다.

| 세션 예산 | 기본 | 상한 |
|---|---:|---:|
| max_requests_per_minute | 30 | 120 |
| max_concurrent_requests | 2 | 4 |
| max_total_requests_per_session | 60 | 300 |
| max_download_bytes | 8 MiB | 32 MiB |
| max_response_bytes | 2 MiB | 8 MiB |
| max_runtime_seconds | 45초 | 120초 |

현재 전송은 직렬 처리하므로 동시 요청 설정은 상한입니다. research_pause는 후속 전송을 멈추고 시간 예산은 계속 흐릅니다. research_resume는 같은 승인과 잔여 예산을 재개합니다. research_abort는 worker 종료를 확인한 뒤 응답합니다. 이미 전송한 요청은 되돌릴 수 없습니다.

compare_session_observations는 저장된 user_a/user_b 구조만 비교하여 FACTS / DIFFERENCES / POSSIBLE_SECURITY_RELEVANCE / MISSING_EVIDENCE를 반환합니다. 같은 정상 행동인지, 의도된 역할 정책이 무엇인지는 사용자가 확인해야 합니다.

## 선택 호스트 어댑터

Burp는 호스트에서 실행합니다. BURP_MCP_URL, 선택적인 BURP_MCP_TOKEN, BURP_MCP_TRANSPORT=sse 또는 streamable-http를 지정합니다. 실제 tools/list로 확인한 proxy/organizer/WebSocket history만 읽습니다. 없는 원격 기능을 가정하지 않으며 비교/OpenAPI/GraphQL에는 기존 로컬 도구를 사용합니다.

Android는 FINDER_ADB_ENDPOINT=host.docker.internal:5037 또는 FINDER_FRIDA_ENDPOINT=host.docker.internal:27042처럼 이미 구성한 서버를 선택합니다. 연결/장치가 없으면 HOST_ADAPTER_REQUIRED입니다. 임의 shell/Frida JS/attach/앱 설치·실행 도구는 없습니다. [어댑터 상세](ADAPTERS.md)

## 분석·스킬·증거

고유 MCP 이름은 **107개**, 역할 스킬은 **18개**입니다. [도구/스킬 목록](TOOLS.md)과 실제 SDK에서 생성한 [스키마](tool-schemas.json)를 참고하세요.

Python AST + ripgrep + 고정 규칙으로 소스를 검토합니다. Semgrep은 연동하지 않았습니다. 새 기록에는 UTC·해시(가능한 경우)·버전·identity·결과 경로·redaction 상태를 추가하며 이전 기록은 재작성하지 않습니다. 후보 상태 8개를 지원하고 자동 CONFIRMED는 거부합니다. 스킬은 역할 지침이며 다중 에이전트 실행기가 아닙니다.

## 로컬 검증과 실행 한계

```sh
python3 -m venv .venv
.venv/bin/pip install -c constraints.txt '.[platform,browser,device,test]'
.venv/bin/python -m playwright install --with-deps chromium
.venv/bin/python -m pytest -q
python3 scripts/check_codex.py
```

선택 native 도구가 없으면 실제 JADX/Ghidra 테스트 두 개는 skip합니다. 설치된 경우 FINDER_TOOL_ROOT=/path/to/finder-tools로 지정합니다. Linux용 scripts/install_optional_tools.py는 고정 URL/크기/SHA-256을 확인합니다. [버전과 출처](RESEARCH_SOURCES.md)

테스트는 합성 파일과 로컬 mock 서버만 사용합니다. **Docker build/up/run, 실제 ChatGPT 로그인, Mac 명령 실행, 실제 Burp/Android 장치 연결은 미검증**입니다. [검증 결과](VALIDATION.md), [기능별 상태](CAPABILITY_MATRIX.md), [보안 모델](SECURITY_MODEL.md), [20개 요구사항 점검](UPGRADE_PROGRESS.md)을 확인하세요.

기존 입력·인증·증거는 이동/삭제하지 않았고 외부 push도 하지 않았습니다. 소스 패키징은 기존 scripts/package_source.py와 명시적 release-files.txt를 유지합니다.
