# 기능별 구현과 실제 검증 범위

2026-09-15 Linux arm64 호스트의 합성 입력 기준입니다. 구현, mock 검증, 실제 서비스 검증을 구분합니다. 명령/최종 결과는 [VALIDATION](VALIDATION.md)에 있습니다.

| 기능 | 실제 검증 | 한계 |
|---|---|---|
| MCP initialize/list/call | 공식 SDK stdio·HTTP, 기존/new roles | 실제 Docker MCP 네트워크 미검증 |
| persistent profiles | 실제 Chromium, 세 identity, 재시작 쿠키/localStorage, 중복 Set-Cookie | 장기 실제 계정 만료/재로그인 미검증 |
| SPA | 실제 로컬 navigation/fetch/XHR/GraphQL/iframe/script/SSE/WS handshake | 초기 로드만; WS frames·무한 SSE·클릭/폼 없음 |
| A/B 비교 | 저장된 user_a/user_b 구조와 4개 결과 구획 | 정상 행동/역할 일치 여부는 사용자 확인, 순서/시간 차이 가능 |
| scope/private/redirect | 로컬 서버가 받은 경로로 차단 검증; DNS IP 고정 기존 테스트 | OS 목적지 방화벽 아님 |
| 6개 예산/제어 | 실제 요청/응답 byte 제한, rate/concurrency 단위 검증, pause/resume/abort 후 전송 차단 | in-flight 회수 불가, 전송은 현재 직렬 |
| Burp | 실제 로컬 mock MCP의 SSE/Streamable HTTP, discovery·history·민감값 제외 | 실제 host Burp 미연결 |
| Android 정적 | 합성 APK/AAB·AXML/protobuf·malformed, 실제 JADX의 자체 Java→DEX→APK 디컴파일 | 전체 앱/리소스 ID/서명 검증 아님 |
| apktool/aapt/aapt2/apksigner | 버전/설치 구성과 공식 출처 확인 | Docker 설치/전체 실행 미검증 |
| ADB/Frida | 고정 명령/최소화 mock 및 실제 MCP의 HOST_ADAPTER_REQUIRED | 실제 장치/emulator 미검증, attach/hooks 없음 |
| LIEF binary | 합성 PE/ELF/Mach-O, imported/exported/string metadata, 크기 제한 | target 실행 없음 |
| Ghidra | 실제 합성 ELF와 고정 HeadlessScript, 함수/심볼 결과, optional/path/size 검사 | 실제 앱/모든 포맷의 Ghidra 실행 미검증 |
| iOS | IPA/plist/entitlement/ATS/scheme/framework, malformed, Mach-O view | Linux 정적 범위; device/codesign/simulator 없음 |
| OpenAPI/GraphQL | 로컬 계약/버전 비교, AST 문서/operation/schema, 값 제외 | external refs·remote introspection 없음 |
| Source | Python AST, literal search, secret locations, path escape, no execution | 다른 언어는 lexical hints; Semgrep/전체 taint 미연동 |
| Dependency/Container/CI/IaC | 기존 형식 + CI/HCL 선언, CycloneDX 생성 | build-derived 전체 SBOM/CVE exploitability/배포 검증 아님 |
| Provenance/후보 | 불변 records, SHA/UTC/identity, 8개 상태, CONFIRMED 거부 | null hash 가능; WORM/관리자 변조 방지 서명 없음 |
| 18 Skills | quick_validate 18개, 실제 tools registry, Codex skills/list | 실제 모델 선택/보고 품질 평가 미실행 |
| Codex | CLI 0.154.0 strict config/mcp list/skills list | 실제 ChatGPT login/모델 계정 권한 미검증 |
| Compose | 공식 Compose 5.5.1 전체 profile config, tmpfs 옵션 회귀 | Docker daemon/build/up/run 없음 |
| IWANTTOGOHOME | 공백 경로/다른 cwd/기존 설정 보존/재설치 테스트 | 실제 Mac 홈 설치와 Docker lifecycle 미실행 |
| 기존 데이터 보존 | 기존 auth/session 합성 바이트, volumes/stop 불변식, source allowlist | 실제 Docker 볼륨 지속성 실행 미검증 |
| Scout pipeline | 6개 domain Scout + temporal Scout, outcome feedback, evidence graph, minimal experiment planner, 구조 우선 dedup, cheap triage, seeded portfolio, guarded promotion, SQLite 재구축, CLI/MCP | 실제 외부 대상 요청 없음; proposal/score/feedback/plan은 finding·severity·authorization 아님 |
| 악용/공격/자동제출 | 제공하지 않음 | 고정 목적 관찰·정적 검토 범위 |
