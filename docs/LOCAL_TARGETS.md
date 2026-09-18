# Local Target Harness

Local Target Harness는 사용자가 소유하거나 실행을 허가받은 self-hosted OSS를 로컬에서 재현하기 위한 host-side 기능이다. 분석 MCP나 Codex 컨테이너에는 Docker socket, 임의 shell, 임의 compose, 임의 URL 요청 권한을 주지 않는다.

현재 adapter는 `mattermost` 하나이며 다음 revision으로 고정된다.

```text
repository: https://github.com/mattermost/mattermost
revision: d283cc6301368f6e3dc0fa6be0a1537a9677750b
```

## 구조와 신뢰 경계

`scripts/control.py`가 `local` subcommand를 host에서 처리하고 `LocalTargetAdapter`의 고정 action만 호출한다. manifest는 target ID, repository, revision, health URL만 담으며 command array나 URL override를 받지 않는다. adapter의 repository와 revision 상수도 manifest와 독립적으로 일치해야 한다.

```text
IWANTGOHOME local <fixed action>
  -> scripts/control.py (host)
  -> ctf_mcp.local_targets.MattermostAdapter
  -> fixed git/docker/go argv + fixed localhost API paths
```

모든 subprocess는 argv list와 `shell=False`를 사용한다. Git은 `.operator/targets/` 내부에서만 실행되고 hook 경로를 비활성화한다. Mattermost checkout은 분석 input으로 자동 mount되지 않는다.

Host 파일은 다음과 같이 분리된다.

```text
.operator/inputs/mattermost/          imported analysis input
.operator/targets/mattermost/         pinned upstream checkout
.operator/local-runtime/mattermost/   compose, PID state, Go cache, app data
.operator/local-secrets/mattermost/   passwords and local config (0700 directory, 0600 files)
.operator/local-evidence/mattermost/  immutable Records documents
```

`.operator/` 전체는 Git에서 제외된다. local target에는 Codex auth, program approval, Scout ledger, browser sessions, 기존 evidence volume이 mount되지 않는다.

## CLI

```bash
FINDER_TARGET=mattermost IWANTGOHOME local prepare
FINDER_TARGET=mattermost IWANTGOHOME local up
FINDER_TARGET=mattermost IWANTGOHOME local status
FINDER_TARGET=mattermost IWANTGOHOME local bootstrap
FINDER_TARGET=mattermost IWANTGOHOME local validate S12
FINDER_TARGET=mattermost IWANTGOHOME local validate S13
FINDER_TARGET=mattermost IWANTGOHOME local validate S15
FINDER_TARGET=mattermost IWANTGOHOME local validate
FINDER_TARGET=mattermost IWANTGOHOME local stop
FINDER_TARGET=mattermost IWANTGOHOME local reset
```

허용되지 않은 target, action, candidate는 각각 `invalid_local_target`, `invalid_local_action`, `unknown_local_candidate`로 종료된다.

## Source acquisition

`prepare`는 target directory가 없을 때 고정 GitHub repository를 partial clone하고 고정 commit을 detached checkout한다. 기존 directory가 있으면 origin을 먼저 확인하고 commit object가 없을 때만 고정 origin에서 fetch한다. 마지막에 origin, `git rev-parse HEAD`, pristine worktree를 다시 확인한다. active hook/filter/include/credential Git config는 거절하며, 강제 reset이나 user checkout 삭제는 하지 않는다.

이 Git 동작은 외부 target checkout에만 적용된다. IWANTGOHOME repository 자체에는 Git 동작을 수행하지 않는다.

## Runtime and networking

`up`은 source를 다시 검증한 뒤 harness-owned Compose 파일로 `postgres:15`만 시작한다. PostgreSQL은 host process인 Mattermost가 접근해야 하므로 `127.0.0.1:55432`에만 publish된다. Mattermost server는 pinned checkout의 `server/`에서 `go run ./cmd/mattermost`로 실행되며 listen address는 `127.0.0.1:8065`로 고정된다. Go module/cache와 Mattermost data/config는 upstream checkout 밖에 둔다.

Health gate는 `http://127.0.0.1:8065/api/v4/system/ping`의 `status == OK`만 인정한다. 2초 간격, 최대 150회로 5분에 종료된다. `status`는 clone이나 build를 시작하지 않으며 secret을 읽어 출력하지 않는다.

observer용 주소는 모든 OS에서 `http://host.docker.internal:8065`이다. Docker Desktop은 내장 mapping을 사용하고 Linux Compose는 `host-gateway` mapping을 사용한다. 외부 interface나 외부 IP는 선택하지 않는다.

## Stop and reset

`local stop`은 server process와 PostgreSQL container만 정지한다. PostgreSQL volume, source, runtime data, secrets, immutable evidence, approval/auth/Scout 자료를 보존한다.

`local reset`만 PostgreSQL volume과 synthetic runtime state/secrets를 제거한다. source와 immutable evidence는 유지한다. reset은 사용자가 이 explicit action을 호출했을 때만 실행된다.

## Requirements and failure codes

Host에는 Python 3.11+, Git, Go, Docker Engine + Compose v2가 필요하다. 주요 오류는 `SOURCE_NOT_PREPARED`, `REPOSITORY_MISMATCH`, `REVISION_MISMATCH`, `SOURCE_DIRTY`, `DOCKER_UNAVAILABLE`, `DEPENDENCY_START_FAILED`, `TARGET_START_FAILED`, `HEALTH_TIMEOUT`, `BOOTSTRAP_FAILED`, `ROLE_UNAVAILABLE`, `VALIDATION_BLOCKED`로 구분된다.

Mattermost 전체 build/start는 일반 pytest에서 실행하지 않는다. 허가된 Docker host에서 `FINDER_RUN_LOCAL_TARGET_INTEGRATION=1`을 설정하면 opt-in prepare/status integration test를 실행할 수 있다.
