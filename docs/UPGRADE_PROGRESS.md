# 20개 요구사항 최종 점검

기준: 사용자가 복원한 **/workspace/something_finder**. ZIP은 이전 백업이며 사용하지 않았습니다. 기존 Python/MCP/Docker/로그인/기록 구조를 확장했습니다.

| # | 요구사항 | 구현·근거 | 검증/제한 |
|---|---|---|---|
| 1 | 분리 persistent sessions | sessions.py, browser_sessions.py, browser-sessions-v1 | 실제 Chromium 3 identity·재시작; 실제 계정 미검증 |
| 2 | SPA 관찰 | navigation/fetch/XHR/WS/SSE/GraphQL/iframe/resource 구조 | 실제 로컬 서버; 초기 로드, WS handshake/SSE snapshot 범위 |
| 3 | A/B 비교 | compare_session_observations의 4개 구획 | 저장된 구조 비교만, 요청 재전송 없음 |
| 4 | Scope guard | 정확한 URL/제외 우선/DNS IP/redirect/origin, explicit private | 실제 차단 테스트; OS 방화벽 아님 |
| 5 | 6개 예산/제어 | research_policy/control, pause/resume/abort | rate/concurrency/총량/bytes/runtime, abort 후 전송 차단 |
| 6 | Burp optional | URL/token, 실제 tools/list, history 3종 | 실제 mock SSE/HTTP; host 미연결, 없는 remote 기능 가정 안 함 |
| 7 | Android profile | 11개 MCP, Androguard/JADX + 이미지 apktool/apksigner/aapt/aapt2 | 실제 합성 JADX; Docker 빌드/서명 검증 미실행 |
| 8 | Android dynamic | 5개 고정 host metadata MCP, HOST_ADAPTER_REQUIRED | mock/미연결만 검증; 실제 기기 없음 |
| 9 | Binary/Ghidra | 8개 MCP, LIEF/고정 Ghidra, 파일/시간 상한 | PE/ELF/Mach-O LIEF + 실제 Ghidra ELF; 대상 실행 없음 |
| 10 | iOS 7 views | IPA/plist/entitlement/scheme/ATS/framework/Mach-O | 합성 파싱·내부 executable 검사; Mac/device 없음 |
| 11 | API | OpenAPI 5, GraphQL 3, 로컬 AST | 합성 문서/비교/값 제외; remote introspection 없음 |
| 12 | Source 7 tools | 기존 parser + Python AST/ripgrep/고정 규칙 | source escape/no-hooks 검사; **Semgrep 미연동** |
| 13 | Dependency/Container/IaC | 8개 도구, CI 규칙, CycloneDX 생성 | 합성 입력; CVE match/전체 SBOM/exploitability 증명 아님 |
| 14 | Provenance | 새 records의 8개 필드, 이전 기록 보존 | hash 불가 시 null, source manifest 해시 구분 |
| 15 | Candidate 상태 | 8개 uppercase + 기존 lowercase 호환 | CONFIRMED 거부, 불변 record 테스트 |
| 16 | Skills | 기존 11개 역할 확장/이름 정리 + 7개, 총18개 | quick_validate/실제 registry/Codex 발견 통과 |
| 17 | Profiles | logical default/web/android/android-dynamic/binary/burp; legacy platform | 공식 Compose config 10 services; build/up 미검증 |
| 18 | IWANTTOGOHOME | 기존 finder.sh + Python installer + install-command.sh | 다른 cwd/공백 경로/보존/초기 no-arg 동작 계약; 실제 Mac 미실행 |
| 19 | tmpfs 회귀 | 모든 옵션 문자열 quoted YAML 유지 | YAML과 실제 Compose 해석의 옵션 문자열 검사 |
| 20 | 기존/신규 테스트 | 기존109 모두 유지, 전체153 + 추가 iOS1 통과 | 로컬 fixture/mock만, 미검증 사항은 VALIDATION에 별도 기록 |

전체 변경 파일은 [CHANGES.md](CHANGES.md), 실제 실행 결과는 [VALIDATION.md](VALIDATION.md), 운영 방법은 [USAGE.md](USAGE.md)에 있습니다. README는 사용자가 지정한 설치/실행 내용 그대로 유지했습니다.

현재 구현 범위의 확장은 완료했습니다. 위 표의 실제 Docker/계정/장치 검증 한계와 조건부 Semgrep 미연동을 완료한 기능으로 표시하지 않습니다. 기존 사용자 인증/증거/볼륨을 삭제하지 않았고 push하지 않았습니다.
