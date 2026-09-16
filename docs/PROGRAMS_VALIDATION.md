# Program profile 검증

2026-09-16, `/workspace/IWANTGOHOME`, Linux arm64 / Python 3.14.6.

최종 전체 suite: **227 passed, 2 skipped**, 61.73초. JUnit 결과: `/tmp/iwant-program-final.xml`. 기존 테스트 파일은 수정하지 않았습니다. 새 테스트는 정책 검증 64개와 프로그램 통합 11개입니다. 기존 154개 중 152개 통과, 선택적 도구 2개 스킵이며 총 229개 case를 수집했습니다.

중간 검사: 정책·기존 승인/증거 78 passed → 전체 214 passed/2 skipped → 프로그램 통합 9 passed. 이후 승인 중 변경·취소, legacy 경고, DRAFT/REVOKED 사전 차단 검사를 보강한 최종 결과가 위 227 passed입니다.

실제 MCP registry로 `docs/tool-schemas.json`을 갱신했습니다. role별 도구 수는 analysis 57, platform 35, observer 18, android 27, android-dynamic 14, binary 24, burp 13입니다. 배포 manifest 133개 파일의 존재·중복/비공개 경로 제외, Python AST, shell syntax, 공개 예제 validation을 확인했고 `pip check`도 통과했습니다. 프로그램 코드·scripts·Skills·config·공개 예제에서 특정 실제 프로그램명/도메인 하드코딩은 검색되지 않았습니다.

모든 HTTP 대상은 테스트가 생성한 127.0.0.1 서버입니다. 합성 example.com scope 검사는 오프라인으로 수행합니다. 외부 버그바운티 대상에는 요청하지 않았고 실제 사용자 프로그램 승인, Git push, 인증·증거·볼륨 삭제를 수행하지 않았습니다.

## 실행한 명령

```sh
python3 -m venv /tmp/iwant-program-checks
/tmp/iwant-program-checks/bin/pip install -e '/workspace/IWANTGOHOME[test,browser,platform]'
/tmp/iwant-program-checks/bin/python -m playwright install chromium
/tmp/iwant-program-checks/bin/python -m playwright install-deps chromium
/tmp/iwant-program-checks/bin/python -m pytest -q /workspace/IWANTGOHOME/tests/test_programs.py /workspace/IWANTGOHOME/tests/test_safety_records.py /workspace/IWANTGOHOME/tests/test_skills_lifecycle.py
/tmp/iwant-program-checks/bin/python -m pytest -q /workspace/IWANTGOHOME/tests --junitxml=/tmp/iwant-program-full-first.xml
/tmp/iwant-program-checks/bin/python -m pytest -q /workspace/IWANTGOHOME/tests/test_program_integration.py
/tmp/iwant-program-checks/bin/python -m pytest -q /workspace/IWANTGOHOME/tests --junitxml=/tmp/iwant-program-final.xml
/tmp/iwant-program-checks/bin/python /tmp/iwant_program_audit.py
/tmp/iwant-program-checks/bin/pip check
/tmp/iwant-program-checks/bin/python -m pytest -q /workspace/IWANTGOHOME/tests/test_distribution.py
```

최종 문서 정리 후 배포 검사 2개를 추가로 실행해 0.12초에 통과했습니다. 이후 source audit에서도 133개 manifest 파일·스키마·문법·예제 검증이 통과했습니다.

첫 번째 기존 회귀 검사에서 worker가 poll 사이에 종료되면 짧은 deadline을 놓치는 경우가 발견됐습니다. 종료 후 deadline도 검증하도록 수정했고 해당 기존 테스트를 포함한 suite가 통과했습니다.

## 검증 범위

- profile schema/defaults, JSON/YAML malformed/duplicate/alias/custom-tag/크기 제한, traversal/symlink 거부.
- exact/wildcard/nested/apex/confusion, exclusion 우선, scheme/port/path/method 경계, private default deny/explicit allow, DNS private/link-local 차단.
- DRAFT/APPROVED/ACTIVE/REVOKED, 실제 CLI TTY 승인, 원본 변경 및 재승인 ID 교체, program A grant의 program B 사용 거부.
- 프로그램과 세션의 이중 제한, 정확한 URL만 plan 생성, 추가 리소스는 네트워크 없이 검토 후보로 표시.
- 실제 Chromium: 프로그램별 user_a/user_b 및 재시작 후 저장소, 다른 프로그램의 동일 identity에 credential 공유 없음, 진행 중 revoke/edit/switch 후 요청 중단.
- 프로그램 증거·보고서 metadata, PROGRAM_EXCLUDED annotation, optional template, 다른 프로그램 증거 연결·비교 거부.
- 실제 MCP stdio initialize/list/call 및 읽기 전용 scope tools; 승인 mutation 도구 없음.
- 기존 전체 suite 유지, 기존 3개 named volume 및 Codex mount 유지, 프로그램 볼륨은 서비스 read-only/operator write.

## 요구사항별 최종 점검

| # | 요구사항 | 현재 구현·검증 근거 |
|---|---|---|
| 1 | 로컬 Program Profile / 공개 예제 / 비공개 저장 | program_store.py, .gitignore, .dockerignore, manifest; 배포/volume 검사 |
| 2 | schema 및 보수적 기본값 | programs.py validate_profile; defaults/invalid fields/JSON/YAML 테스트 |
| 3 | wildcard/apex/제외 우선/scheme/port/path | scope_decision; 18개 URL 경계와 exact/path/port/method 테스트 |
| 4 | program CLI 8개 | program_cli.py, control.py; 실제 subprocess 및 TTY, 8개 Docker 명령 전달 검사 |
| 5 | DRAFT/APPROVED/ACTIVE/REVOKED, canonical/hash/승인 정보 | ProgramStore; 상태·해시·재승인·취소·검토 중 변경 테스트 |
| 6 | 좁은 session plan / 리소스 후보 | create_plan, scope_candidates; 실제 Chromium에서 start URL만 서버에 도달함 확인 |
| 7 | 별도 plan approve와 기존 grant 통합 | cli.approve/Grant; 실제 CLI TTY plan 승인, 1회 사용, legacy 경고/새 plan의 결합 강제 |
| 8 | 읽기 전용 MCP 5개 | program_tools.py; 실제 stdio initialize/list/call, 승인 mutation 없음, offline scope 검사 |
| 9 | generic scope-gate 및 신뢰 경계 | scope-gate, policy read-only mounts, 기존 Skills schema/tool 검증 |
| 10 | 프로그램별 Finding Policy | Records.candidate, PROGRAM_EXCLUDED annotation; excluded category 테스트 |
| 11 | reporter metadata 및 template | Records.report; 필드 연결·고정 placeholder·미지원 표현식 미실행·cross-program evidence 거부 |
| 12 | 실제 프로그램 하드코딩 없음 | src/scripts/Skills/config/example 검색; 예제는 example.com만 사용 |
| 13 | private/local explicit opt-in | address_allowed/Grant.addresses; local profile 실제 Chromium + DNS/private/link-local 검사 |
| 14 | 기존 테스트 유지 및 신규 경계 | 최종 227 passed/2 optional skipped; 외부 대상 요청 없음 |
| 15 | backwards compatible / 데이터 보존 | optional programs_root, legacy CLI/MCP 경고, 기존 3 named volume 및 Codex mount 유지, legacy 세션 바이트 보존 테스트 |
| 16 | README / PROGRAMS.md / 예제 | 공개 배포 manifest 포함, 예제 parser 검증 |
| 17 | 실제 구현 및 테스트 / 최종 전달 | CLI·loader·validation·store·matcher·MCP·session 연결과 위 실행 결과 |

Markdown/text 파싱 및 observe convenience command는 선택 사항이므로 추가하지 않았습니다. JSON/YAML과 명시적인 plan 생성·승인 흐름을 지원합니다.

## 수정 파일

신규 9개:

- `src/ctf_mcp/programs.py`, `program_store.py`, `program_cli.py`, `program_tools.py`
- `tests/test_programs.py`, `tests/test_program_integration.py`
- `docs/PROGRAMS.md`, `docs/PROGRAMS_VALIDATION.md`, `examples/program.example.json`

기존 25개:

- `src/ctf_mcp/browser_sessions.py`, `cli.py`, `config.py`, `engine.py`, `records.py`, `research_policy.py`, `server.py`, `sessions.py`, `web.py`, `worker.py`
- `scripts/control.py`, `IWANTGOHOME`
- `config/analysis.json`, `config/browser.json`, `Dockerfile`, `docker-compose.yml`
- `.agents/skills/{scope-gate,attack-surface-map,skeptical-retest,report-writing}/SKILL.md`
- `README.md`, `docs/tool-schemas.json`, `release-files.txt`, `.gitignore`, `.dockerignore`

## 환경상 미검증

Docker CLI/daemon이 없어 이미지 build/up와 실제 Docker named volume 지속성은 실행하지 못했습니다. YAML/명령 생성/로컬 Python·Chromium 검증으로 이를 실행했다고 간주하지 않습니다. 실제 계정 로그인·갱신, 외부 프로그램·Burp·기기, Windows/macOS runtime도 테스트하지 않았습니다. 선택적 JADX/Ghidra 실행 테스트 2개는 현재 환경에 도구가 없어 스킵됐습니다.

`.git` 메타데이터가 없는 작업 디렉터리여서 git diff/status 기반 검증은 불가능했습니다. 수정 전 소스 SHA-256 snapshot을 `/tmp/iwant-program-baseline.json`에 기록하여 파일 변경을 비교합니다. 기존 사용자 runtime 데이터는 snapshot 대상에서도 제외했습니다.
