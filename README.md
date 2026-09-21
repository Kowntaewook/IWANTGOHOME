# IWANTGOHOME

## 설치

처음 한 번만 아래 명령어를 실행하세요.

```bash
git clone https://github.com/Kowntaewook/IWANTGOHOME.git && cd IWANTGOHOME && chmod +x scripts/install-command.sh && ./scripts/install-command.sh
```

## 실행

설치가 끝난 뒤에는 어디서든 아래 명령어만 입력하면 됩니다.

```bash
IWANTTOGOHOME
```

프로그램 정책을 등록·검토한 뒤 승인된 범위만 조사합니다.

```bash
IWANTTOGOHOME program import policy.json
IWANTTOGOHOME program approve my-program
IWANTTOGOHOME program use my-program
```

관찰 전 세션 계획도 별도로 승인해야 합니다. [프로그램·세션 사용법](docs/PROGRAMS.md)과 [합성 예제](examples/program.example.json)를 참고하세요.

승인된 프로그램의 기존 불변 evidence와 observation에서 검토 후보를 찾고 우선순위를 정할 수 있습니다.

```bash
IWANTTOGOHOME program use example
IWANTTOGOHOME scout run
IWANTTOGOHOME scout proposals
IWANTTOGOHOME scout portfolio
IWANTTOGOHOME scout feedback
IWANTTOGOHOME scout graph
```

Scout는 자동 공격 도구가 아닙니다. 외부 요청을 보내지 않고 승인된 기존 자료와 이전 revision에서 `CandidateProposal`을 만듭니다. 검증 결과 피드백과 evidence graph는 순위 예측만 보정합니다. 최소 실험 계획도 권한이나 실행권을 만들지 않으며, 명시적 승격 때 기존 승인·scope·evidence 검증을 다시 통과한 후보만 `DISCOVERED` candidate로 전달합니다. 자세한 흐름과 보안 경계는 [Scout pipeline](docs/SCOUT_PIPELINE.md)과 [Scout security model](docs/SCOUT_SECURITY_MODEL.md)을 참고하세요.

성능 상태와 동일 입력 cold/warm benchmark를 확인할 수 있습니다.

```bash
IWANTTOGOHOME perf status
IWANTTOGOHOME perf benchmark
IWANTTOGOHOME perf compare
```

개발 중에는 `IWANTTOGOHOME test fast`, 통합 경계는 `test integration`, 기존 전체 검증은 `test full`을 사용합니다. 역할별 tool schema는 필요할 때만 `FINDER_AGENT_ROLE=Scout|Triage|Portfolio|Investigator|Verifier|Reporter`로 제한하며, 이 필터는 승인·scope·session grant를 대신하지 않습니다. 자세한 측정법은 [Performance](docs/PERFORMANCE.md), 설계와 cache/model routing은 [Optimization](docs/OPTIMIZATION.md)을 참고하세요.

허가된 self-hosted Mattermost 또는 Gitea pinned revision을 host에서 준비하고 localhost-only validation을 실행할 수 있습니다.

```bash
FINDER_TARGET=mattermost IWANTGOHOME local prepare
FINDER_TARGET=mattermost IWANTGOHOME local up
FINDER_TARGET=mattermost IWANTGOHOME local bootstrap
FINDER_TARGET=mattermost IWANTGOHOME local validate S12
FINDER_TARGET=mattermost IWANTGOHOME local hunt --full
FINDER_TARGET=mattermost IWANTGOHOME local status
FINDER_TARGET=mattermost IWANTGOHOME local stop
```

Gitea는 공식 rootless 이미지와 SQLite로 한 서비스만 실행하며 G01/G02/G03 권한 control을 제공합니다.

```bash
FINDER_TARGET=gitea IWANTGOHOME local prepare
FINDER_TARGET=gitea IWANTGOHOME local up
FINDER_TARGET=gitea IWANTGOHOME local bootstrap
FINDER_TARGET=gitea IWANTGOHOME local validate G01
FINDER_TARGET=gitea IWANTGOHOME local validate G02
FINDER_TARGET=gitea IWANTGOHOME local validate G03
FINDER_TARGET=gitea IWANTGOHOME local hunt
FINDER_TARGET=gitea IWANTGOHOME local hunt --full
FINDER_TARGET=gitea IWANTGOHOME local status
FINDER_TARGET=gitea IWANTGOHOME local stop
FINDER_TARGET=gitea IWANTGOHOME local reset
```

Docker와 local process는 host CLI의 fixed action만 실행합니다. Codex/analysis 컨테이너에는 Docker socket이나 실행 tool이 추가되지 않습니다. 자세한 구조는 [Local Target Harness](docs/LOCAL_TARGETS.md), candidate 조건과 evidence 형식은 [Local Validation](docs/LOCAL_VALIDATION.md)을 참고하세요.

Mattermost pinned source의 release version은 `12.0.0`, revision commit은 `d283cc6301368f6e3dc0fa6be0a1537a9677750b`입니다. `d283cc6`은 image tag와 화면 표시용 short SHA이며 version으로 기록하지 않습니다. Mattermost와 PostgreSQL은 outbound가 차단된 internal network에만 연결됩니다. Digest-pinned HAProxy TCP sidecar가 고정 upstream `mattermost:8065`만 `127.0.0.1:13100`으로 전달하며, Mattermost와 PostgreSQL 자체에는 host port가 없습니다. Delegated role bootstrap은 built-in `system_user_manager`를 변경하지 않고 필요한 권한을 조회해 확인합니다. 해당 capability를 사용할 수 없어도 일반 fixture는 생성되며 bootstrap은 `PARTIAL`로 기록됩니다.

Gitea runtime은 `docker.gitea.com/gitea:1.27.3-rootless@sha256:1c17ecaead42eb3b5391553d8708103a4beb0e86edf5b9ebc1eb269c318845f2`만 사용하고 `127.0.0.1:13000`에만 publish합니다. SSH port는 publish하지 않습니다.

`local hunt --full`은 pinned source에서 route, middleware, handler, query 연결을 추적해 후보를 생성하고 기존 G01~G08 control/probe로 안전하게 검증할 수 있는 후보만 자동 실행합니다. 로컬 재현 뒤 공개 GitHub/GHSA/NVD/release/PR 자료에서 중복을 조사합니다. Latest는 13001에서 digest-pinned image로, upstream main은 조회 시점의 commit을 고정하고 rootless image를 직접 build한 뒤 13002에서 격리 재검증합니다. Main build/runtime/control을 신뢰할 수 없으면 구체적인 `MAIN_*` reason을 포함한 `RETEST_BLOCKED`로 기록하며 임의 외부 서버를 대신 시험하지 않습니다.

Full-hunt pipeline은 target-neutral engine과 registry, schema, duplicate research, version/runtime, scenario synthesis, clustering, reporting 모듈로 구성됩니다. Gitea와 Mattermost adapter가 같은 Core를 사용하고, 제품별 route, fixture, 판정 규칙은 adapter에 남습니다. Mattermost는 pinned source에서 MM-S12/MM-S13/MM-S15 trace를 만들고 read-only validator만 자동 실행합니다. Gitea JSON에는 공통 outcome schema와 기존 호환 field가 함께 기록됩니다.

`NEEDS_MANUAL_SCENARIO` 후보는 source assertion과 adapter capability가 충분할 때만 adapter의 reviewed fixture-route binding을 통해 localhost 전용 control/probe plan으로 바뀝니다. Core는 body/count, direct/collection, visibility-boundary pattern만 알고 제품 route와 fixture는 알지 못합니다. `EXACT`와 `STRONG` binding만 실행할 수 있고 `WEAK`는 생성 후 차단됩니다. Core safety gate는 `finder-local-*` fixture, GET/HEAD, 고정 request budget, loopback final URL과 control 성공을 강제합니다. 근거가 부족하거나 mutation이 필요한 후보는 manual 상태로 남고, 각 결과는 report의 `scenarios/` 아래에서 확인할 수 있습니다.
