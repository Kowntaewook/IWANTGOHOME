# Local Target Harness

Local Target Harness는 사용자가 소유하거나 실행을 허가받은 self-hosted OSS를 로컬에서 재현하기 위한 host-side 기능이다. 분석 MCP나 Codex 컨테이너에는 Docker socket, 임의 shell, 임의 compose, 임의 URL 요청 권한을 주지 않는다.

현재 adapter는 `mattermost`와 `gitea`이며 각 adapter가 repository, revision, health URL, candidate allowlist를 코드에서 독립적으로 고정한다.

```text
repository: https://github.com/mattermost/mattermost
revision: d283cc6301368f6e3dc0fa6be0a1537a9677750b
version: 12.0.0
enterprise image: mattermostdevelopment/mattermost-enterprise-edition:d283cc6
digest: sha256:3c11c93b5f75b4e9bc407711d6ad345c0072cff520e34ffc0e99238a507daeb1
platform: linux/amd64
```

```text
target: gitea
repository: https://github.com/go-gitea/gitea
revision: 146cc3eec57174711eac0e0a0c7b38670c6e3922
rootless image: docker.gitea.com/gitea:1.27.3-rootless
digest: sha256:1c17ecaead42eb3b5391553d8708103a4beb0e86edf5b9ebc1eb269c318845f2
```

## 구조와 신뢰 경계

`scripts/control.py`가 `local` subcommand를 host에서 처리하고 `LocalTargetAdapter`의 고정 action만 호출한다. manifest는 target ID, repository, revision, health URL만 담으며 command array나 URL override를 받지 않는다. adapter의 repository와 revision 상수도 manifest와 독립적으로 일치해야 한다.

```text
IWANTGOHOME local <fixed action>
  -> scripts/control.py (host)
  -> explicit registry: MattermostAdapter | GiteaAdapter
  -> adapter-owned fixed git/docker argv + fixed localhost API paths
```

모든 subprocess는 argv list와 `shell=False`를 사용한다. Git은 `.operator/targets/` 내부에서만 실행되고 hook 경로를 비활성화한다. Mattermost checkout은 분석 input으로 자동 mount되지 않는다.

Host 파일은 다음과 같이 분리된다.

```text
.operator/inputs/<target>/          imported analysis input
.operator/targets/<target>/         pinned upstream checkout
.operator/local-runtime/<target>/   compose and bootstrap state
.operator/local-secrets/<target>/   passwords and local config (0700 directory, 0600 files)
.operator/local-evidence/<target>/  immutable Records documents
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
FINDER_TARGET=mattermost IWANTGOHOME local hunt --full
FINDER_TARGET=mattermost IWANTGOHOME local stop
FINDER_TARGET=mattermost IWANTGOHOME local reset
```

```bash
FINDER_TARGET=gitea IWANTGOHOME local prepare
FINDER_TARGET=gitea IWANTGOHOME local up
FINDER_TARGET=gitea IWANTGOHOME local status
FINDER_TARGET=gitea IWANTGOHOME local bootstrap
FINDER_TARGET=gitea IWANTGOHOME local validate G01
FINDER_TARGET=gitea IWANTGOHOME local validate G02
FINDER_TARGET=gitea IWANTGOHOME local validate G03
FINDER_TARGET=gitea IWANTGOHOME local validate
FINDER_TARGET=gitea IWANTGOHOME local hunt
FINDER_TARGET=gitea IWANTGOHOME local hunt --full
FINDER_TARGET=gitea IWANTGOHOME local stop
FINDER_TARGET=gitea IWANTGOHOME local reset
```

허용되지 않은 target, action, candidate는 각각 `invalid_local_target`, `invalid_local_action`, `unknown_local_candidate`로 종료된다. Candidate는 선택된 adapter의 코드 고정 `supported_candidates`에서 검사한다. Mattermost의 S12/S13/S15와 Gitea의 G01~G08은 서로 교차 사용할 수 없다.

`hunt --full`은 target-neutral `ctf_mcp.full_hunt.FullHuntEngine`이 explicit registry에서 선택한 adapter를 실행한다. Registry에는 `gitea`와 `mattermost`가 등록된다. 두 adapter는 source 준비, 정적 후보 생성, 안전한 기존 validator 연결, 공개 중복 조사, 격리 version matrix, root-cause dedup과 공통 보고 형식을 사용한다. 제품별 endpoint, 권한 모델, fixture와 build recipe는 adapter에만 있다.

Mattermost full hunt는 pinned checkout의 `server/channels/api4/user.go`에서 route, handler, permission check와 data access call을 함께 확인해 MM-S12/MM-S13/MM-S15 후보를 만든다. Version은 같은 checkout의 `server/public/model/version.go`에서 읽고 revision commit과 별도 field로 기록한다. GET 기반 MM-S12와 MM-S13은 허용된 victim control body에서 fixture를 먼저 확인한 뒤 delegated probe body와 비교한다. PUT 기반 MM-S15는 read-only safety policy에 따라 `WEAK` scenario binding으로 생성 후 차단되고 `NEEDS_MANUAL_SCENARIO`로 유지된다. Pinned runtime은 `mattermost` namespace와 13100을 사용하고, version matrix의 latest/main endpoint는 13101/13102다. Main source는 `refs/heads/main`을 조회한 40자 SHA 아래 detached checkout하며 build recipe와 runtime configuration hash, local image ID를 cache identity로 사용한다. Enterprise fixture를 main public source build에서 신뢰할 수 없으면 `RETEST_BLOCKED`로 남는다.

Gitea upstream main은 `refs/heads/main`의 immutable commit을 `.operator/targets/gitea-main/<sha>/`에 분리하고, local rootless image와 `127.0.0.1:13002`의 전용 Compose/volume/bootstrap namespace로 SD-G04와 SD-G08만 재검증한다. 기존 `hunt`의 G01~G08 동작과 출력은 유지된다.

## Source acquisition

`prepare`는 target directory가 없을 때 선택한 adapter의 고정 GitHub repository를 partial clone하고 고정 commit을 detached checkout한다. 기존 directory가 있으면 origin을 먼저 확인하고 commit object가 없을 때만 고정 origin에서 fetch한다. 마지막에 origin, `git rev-parse HEAD`, pristine worktree를 다시 확인한다. 공통 Git 실행기는 target directory 밖 실행과 active hook/filter/include/credential/sshCommand 설정을 거절하며, 강제 reset이나 user checkout 삭제는 하지 않는다.

이 Git 동작은 외부 target checkout에만 적용된다. IWANTGOHOME repository 자체에는 Git 동작을 수행하지 않는다.

## Runtime and networking

Mattermost `up`은 source를 다시 검증한 뒤 adapter-owned Compose로 `postgres:15`, digest-pinned Enterprise image, digest-pinned HAProxy sidecar 세 service만 시작한다. 두 pinned image는 `linux/amd64`로 고정한다. 시작 전 local image의 repo digest/OS/architecture와 `/mattermost/bin/mattermost version`의 pinned build hash, `Build Enterprise Ready: true`를 검증한다. Host `go run`이나 `-tags enterprise` build fallback은 없다.

Mattermost container는 PostgreSQL에 `postgres:5432`로 접근한다. PostgreSQL과 Mattermost는 `internal: true` network에만 연결되고 host port를 publish하지 않는다. HAProxy sidecar만 internal network와 별도 published bridge에 연결되며 `127.0.0.1:13100:13100`을 publish한다. Sidecar의 read-only config는 TCP mode에서 `mattermost:8065` 하나만 upstream으로 허용하므로 method, path/query, headers, status와 body를 HTTP 해석 없이 전달한다. Runtime data는 `.operator/local-runtime/mattermost/data`를 `/mattermost/data`에 rw bind mount하며 다른 operator volume은 mount하지 않는다.

Health gate는 sidecar를 거친 `http://127.0.0.1:13100/api/v4/system/ping`의 HTTP 200과 body `status == OK`를 모두 요구한다. 2초 간격, 최대 150회로 5분에 종료된다. `status`는 Mattermost, PostgreSQL, local proxy container 상태를 각각 표시하며 clone이나 build를 시작하지 않고 secret을 읽어 출력하지 않는다.

observer용 주소는 모든 OS에서 `http://host.docker.internal:13100`이다. Docker Desktop은 내장 mapping을 사용하고 Linux Compose는 `host-gateway` mapping을 사용한다. 외부 interface나 외부 IP는 선택하지 않는다.

Gitea `up`은 `docker.gitea.com/gitea:1.27.3-rootless`의 exact index digest를 검사하고 한 개의 `gitea` service만 시작한다. SQLite database와 Gitea config는 Compose project 전용 named volume에 저장한다. 일반 bridge `local-target` network를 사용하며 `internal: true`, host network, privileged mode, Docker socket mount를 사용하지 않는다. HTTP는 `127.0.0.1:13000:3000`에만 publish하고 SSH는 비활성화하며 publish하지 않는다.

Gitea container를 신뢰하기 전에 Compose project label, `gitea` service label, 실행 상태, pinned image reference와 image ID를 검사한다. 실행 중 container 안에서 `gitea --version`을 호출해 `1.27.3`을 확인한다. Health는 `GET http://127.0.0.1:13000/api/healthz`의 HTTP 200, `status=pass`, 정상 JSON shape를 요구하고, 그 listener가 검증한 owned container에 속할 때만 healthy로 인정한다.

## Stop and reset

`local stop`은 선택한 Compose project의 명시된 service만 정지한다. Named volume, source, runtime data, secrets, immutable evidence, approval/auth/Scout 자료를 보존한다.

`local reset`만 선택한 target의 named volume과 synthetic bootstrap state/secrets를 제거한다. source와 immutable evidence는 유지한다. reset은 사용자가 이 explicit action을 호출했을 때만 실행된다.

## Requirements and failure codes

Local adapter에는 Python 3.11+, Git, Docker Engine + Compose v2가 필요하며 host Go toolchain은 필요하지 않다. 주요 오류는 `SOURCE_NOT_PREPARED`, `REPOSITORY_MISMATCH`, `REVISION_MISMATCH`, `SOURCE_DIRTY`, `DOCKER_UNAVAILABLE`, `IMAGE_MISMATCH`, `ENTERPRISE_RUNTIME_REQUIRED`, `DEPENDENCY_START_FAILED`, `TARGET_START_FAILED`, `HEALTH_TIMEOUT`, `BOOTSTRAP_FAILED`, `VALIDATION_BLOCKED`로 구분된다. Mattermost delegated capability 실패는 bootstrap state와 candidate blocker에 `ROLE_LOOKUP_FAILED`, `ROLE_TOO_PRIVILEGED`, `REQUIRED_ROLE_PERMISSIONS_MISSING`, `ROLE_ASSIGNMENT_FAILED`, `ROLE_ASSIGNMENT_NOT_EFFECTIVE`로 기록한다.

Enterprise-ready image는 license를 자동 제공하지 않는다. Harness는 license/trial을 우회하거나 위조하지 않는다. Delegated Granular Administration capability를 사용할 수 없으면 Mattermost bootstrap은 일반 fixture를 보존한 `PARTIAL` 상태가 된다.

Mattermost 전체 build/start는 일반 pytest에서 실행하지 않는다. 허가된 Docker host에서 `FINDER_RUN_LOCAL_TARGET_INTEGRATION=1`을 설정하면 opt-in prepare/status integration test를 실행할 수 있다.
