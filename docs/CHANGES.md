# 복원본 대비 변경 파일

## Scout 후속 확장

기존 Scout 앞단에 `scout_feedback.py`, `scout_graph.py`, `scout_experiments.py`, `scouts/temporal.py`를 추가했습니다. 기존 candidate의 `proposal_id` 연결을 유지해 결과 피드백을 만들고, minimized evidence graph와 비실행 최소 실험 계획을 불변 record로 저장합니다. CLI에는 feedback/graph/experiment/explain을, MCP에는 대응하는 읽기 전용 조회 4개를 추가했습니다. 기존 승인·scope·session grant·bounded runner는 변경하지 않았습니다.

/tmp/finder-upgrade-baseline의 작업 전 소스 89개와 현재 명시적 배포 파일을 비교했습니다. 사용자 입력/인증/증거/ZIP은 비교 또는 배포 대상으로 읽지 않았습니다. 삭제 목록의 11개 스킬은 요청한 새 역할 이름으로 정리한 것입니다.

수정 32개 · 추가 45개 · 이전 스킬 경로 정리 11개.

## 수정

- [.dockerignore](../.dockerignore)
- [.gitignore](../.gitignore)
- [Dockerfile](../Dockerfile)
- [README.md](../README.md)
- [config/codex.toml](../config/codex.toml)
- [constraints.txt](../constraints.txt)
- [docker-compose.yml](../docker-compose.yml)
- [docker/runtime.py](../docker/runtime.py)
- [docs/ADAPTERS.md](../docs/ADAPTERS.md)
- [docs/CAPABILITY_MATRIX.md](../docs/CAPABILITY_MATRIX.md)
- [docs/DESIGN_MAPPING.md](../docs/DESIGN_MAPPING.md)
- [docs/RESEARCH_SOURCES.md](../docs/RESEARCH_SOURCES.md)
- [docs/SECURITY_MODEL.md](../docs/SECURITY_MODEL.md)
- [docs/TOOLS.md](../docs/TOOLS.md)
- [docs/VALIDATION.md](../docs/VALIDATION.md)
- [docs/tool-schemas.json](../docs/tool-schemas.json)
- [docs/validation-results.json](../docs/validation-results.json)
- [pyproject.toml](../pyproject.toml)
- [release-files.txt](../release-files.txt)
- [scripts/check_codex.py](../scripts/check_codex.py)
- [scripts/control.py](../scripts/control.py)
- [sources.lock.json](../sources.lock.json)
- [src/ctf_mcp/cli.py](../src/ctf_mcp/cli.py)
- [src/ctf_mcp/config.py](../src/ctf_mcp/config.py)
- [src/ctf_mcp/engine.py](../src/ctf_mcp/engine.py)
- [src/ctf_mcp/records.py](../src/ctf_mcp/records.py)
- [src/ctf_mcp/safety.py](../src/ctf_mcp/safety.py)
- [src/ctf_mcp/server.py](../src/ctf_mcp/server.py)
- [src/ctf_mcp/web.py](../src/ctf_mcp/web.py)
- [src/ctf_mcp/worker.py](../src/ctf_mcp/worker.py)
- [tests/test_analysis.py](../tests/test_analysis.py)
- [tests/test_skills_lifecycle.py](../tests/test_skills_lifecycle.py)

## 추가

- [.agents/skills/android-dynamic-review/SKILL.md](../.agents/skills/android-dynamic-review/SKILL.md)
- [.agents/skills/android-static-review/SKILL.md](../.agents/skills/android-static-review/SKILL.md)
- [.agents/skills/api-review/SKILL.md](../.agents/skills/api-review/SKILL.md)
- [.agents/skills/attack-surface-map/SKILL.md](../.agents/skills/attack-surface-map/SKILL.md)
- [.agents/skills/authenticated-session-review/SKILL.md](../.agents/skills/authenticated-session-review/SKILL.md)
- [.agents/skills/authz-comparison/SKILL.md](../.agents/skills/authz-comparison/SKILL.md)
- [.agents/skills/binary-review/SKILL.md](../.agents/skills/binary-review/SKILL.md)
- [.agents/skills/business-logic-review/SKILL.md](../.agents/skills/business-logic-review/SKILL.md)
- [.agents/skills/dependency-review/SKILL.md](../.agents/skills/dependency-review/SKILL.md)
- [.agents/skills/evidence-capture/SKILL.md](../.agents/skills/evidence-capture/SKILL.md)
- [.agents/skills/ios-static-review/SKILL.md](../.agents/skills/ios-static-review/SKILL.md)
- [.agents/skills/privacy-review/SKILL.md](../.agents/skills/privacy-review/SKILL.md)
- [.agents/skills/prompt-injection-defense/SKILL.md](../.agents/skills/prompt-injection-defense/SKILL.md)
- [.agents/skills/report-writing/SKILL.md](../.agents/skills/report-writing/SKILL.md)
- [.agents/skills/scope-gate/SKILL.md](../.agents/skills/scope-gate/SKILL.md)
- [.agents/skills/skeptical-retest/SKILL.md](../.agents/skills/skeptical-retest/SKILL.md)
- [.agents/skills/source-review/SKILL.md](../.agents/skills/source-review/SKILL.md)
- [.agents/skills/web-observation/SKILL.md](../.agents/skills/web-observation/SKILL.md)
- [config/browser.json](../config/browser.json)
- [config/tool-downloads.json](../config/tool-downloads.json)
- [docker/apktool.sh](../docker/apktool.sh)
- [docs/CHANGES.md](../docs/CHANGES.md)
- [docs/UPGRADE_PROGRESS.md](../docs/UPGRADE_PROGRESS.md)
- [docs/USAGE.md](../docs/USAGE.md)
- [examples/session-plan.json](../examples/session-plan.json)
- [scripts/install-command.sh](../scripts/install-command.sh)
- [scripts/install_command.py](../scripts/install_command.py)
- [scripts/install_optional_tools.py](../scripts/install_optional_tools.py)
- [src/ctf_mcp/api_analysis.py](../src/ctf_mcp/api_analysis.py)
- [src/ctf_mcp/browser_sessions.py](../src/ctf_mcp/browser_sessions.py)
- [src/ctf_mcp/burp_adapter.py](../src/ctf_mcp/burp_adapter.py)
- [src/ctf_mcp/device_adapter.py](../src/ctf_mcp/device_adapter.py)
- [src/ctf_mcp/extended.py](../src/ctf_mcp/extended.py)
- [src/ctf_mcp/ghidra_scripts/FinderMetadata.java](../src/ctf_mcp/ghidra_scripts/FinderMetadata.java)
- [src/ctf_mcp/native_tools.py](../src/ctf_mcp/native_tools.py)
- [src/ctf_mcp/platform_views.py](../src/ctf_mcp/platform_views.py)
- [src/ctf_mcp/research_control.py](../src/ctf_mcp/research_control.py)
- [src/ctf_mcp/research_policy.py](../src/ctf_mcp/research_policy.py)
- [src/ctf_mcp/sessions.py](../src/ctf_mcp/sessions.py)
- [src/ctf_mcp/source_analysis.py](../src/ctf_mcp/source_analysis.py)
- [tests/test_burp_adapter.py](../tests/test_burp_adapter.py)
- [tests/test_device_adapter.py](../tests/test_device_adapter.py)
- [tests/test_optional_native.py](../tests/test_optional_native.py)
- [tests/test_persistent_sessions.py](../tests/test_persistent_sessions.py)
- [tests/test_upgrade_offline.py](../tests/test_upgrade_offline.py)

## 이전 스킬 경로

- `.agents/skills/finder-android/SKILL.md`
- `.agents/skills/finder-binary/SKILL.md`
- `.agents/skills/finder-counterreview/SKILL.md`
- `.agents/skills/finder-ios/SKILL.md`
- `.agents/skills/finder-privacy/SKILL.md`
- `.agents/skills/finder-report/SKILL.md`
- `.agents/skills/finder-scope/SKILL.md`
- `.agents/skills/finder-source/SKILL.md`
- `.agents/skills/finder-supply-chain/SKILL.md`
- `.agents/skills/finder-untrusted/SKILL.md`
- `.agents/skills/finder-web/SKILL.md`
