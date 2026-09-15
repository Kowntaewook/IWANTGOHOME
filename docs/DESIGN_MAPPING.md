# 복원된 작업본의 변경 매핑

이번 확장의 기준은 **2026-09-15 사용자가 복원한 /workspace/something_finder**입니다. ZIP은 이전 백업이며 이번 구현/비교의 입력으로 사용하지 않았습니다. 복원된 폴더에는 .git이 없습니다. 기존 release-files.txt의 소스 89개를 /tmp/finder-upgrade-baseline에 작업 전 스냅샷으로 보관했습니다.

| 유지한 구조 | 이번 확장 |
|---|---|
| Python ctf_mcp, 공식 FastMCP/worker | 고정 분석 view와 선택 native/host adapter |
| ChatGPT Codex device-code 로그인 | 기존 auth/config/session 보존; 실행 옵션으로 새 MCP 등록 |
| something-finder-codex Compose 프로젝트 | android/android-dynamic/binary/burp 프로필 |
| codex-state-v1 / evidence-v1 | 이름/마운트 유지; browser-sessions-v1 추가 |
| 기존 web read/browser와 host grant | persistent SPA, identity, 6개 예산, 제어 도구 |
| source/API/platform 파서 | 기존 파서 재사용 + GraphQL/Python AST/ripgrep/JADX/Ghidra |
| UUID 불변 기록/후보/보고 | provenance, 8개 상태; 이전 레코드 재작성 없음 |
| 11개 역할 스킬 | 이름/역할 정리와 7개 추가, 총 18개 |
| finder.sh / PowerShell | IWANTTOGOHOME 설치 helper |
| 기존 109개 테스트 | 범위 유지, 버전/스킬 수/추가 볼륨 기대값 갱신, 새 통합/경계 테스트 |
| 수정된 tmpfs | 전체 프로필의 옵션 문자열/Compose config 회귀 검증 |
| 명시적 배포 목록 | 새 소스/문서만 추가, 사용자 데이터 자동 수집 없음 |

이전 원본 조사/Claude→Codex 교체 출처는 sources.lock.json의 역사 항목입니다. 이번에 ZIP 기준으로 복원하거나 기존 기록을 이전한 것을 뜻하지 않습니다.

현재 /workspace는 Mac 폴더의 마운트로 확인했습니다. 프로젝트는 공유 경로에서 직접 수정했으며 실제 Mac Docker lifecycle/홈 셸 설치는 실행하지 않았습니다.
