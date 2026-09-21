# Local Target Harness

Local Target Harness는 사용자가 소유하거나 실행을 허가받은 self-hosted target을 격리된 host 환경에서 재현하기 위한 lifecycle interface다. 공개 Core는 target 이름, repository, API route, fixture, image와 build 방법을 포함하지 않는다. 대상 구현은 [Target SDK](TARGET_SDK.md)의 Python entry point로 설치한다.

## Trust boundary

`scripts/control.py`는 `local` subcommand를 host에서 처리하고 선택된 `TargetAdapter`의 고정 method만 호출한다.

```text
FINDER_TARGET=<id> IWANTGOHOME local <fixed action>
  -> scripts/control.py
  -> TargetRegistry
  -> selected installed entry point
  -> adapter-owned fixed source/runtime/API operations
```

Registry는 installed package metadata만 탐색한다. 임의 directory, current working directory, recursive module scan, `PYTHONPATH` 후보 검색을 수행하지 않는다. `target list`와 `target info`는 target module을 import하지 않는다. `target doctor`는 선택된 module의 API version과 interface만 확인하고 lifecycle method나 network validation을 실행하지 않는다.

Adapter는 source checkout, runtime과 secret/evidence namespace를 target ID 아래에서 분리해야 한다.

```text
.operator/targets/<target>/
.operator/local-runtime/<target>/
.operator/local-secrets/<target>/
.operator/local-evidence/<target>/
```

`.operator/` data는 public source package에 포함되지 않는다. Adapter는 Codex auth, program approval, browser session, 다른 target secret과 Docker socket을 target container에 mount하면 안 된다.

## CLI

```bash
IWANTGOHOME target list
IWANTGOHOME target info <target>
IWANTGOHOME target doctor <target>

FINDER_TARGET=<target> IWANTGOHOME local prepare
FINDER_TARGET=<target> IWANTGOHOME local up
FINDER_TARGET=<target> IWANTGOHOME local status
FINDER_TARGET=<target> IWANTGOHOME local bootstrap
FINDER_TARGET=<target> IWANTGOHOME local validate <candidate>
FINDER_TARGET=<target> IWANTGOHOME local hunt --full
FINDER_TARGET=<target> IWANTGOHOME local stop
FINDER_TARGET=<target> IWANTGOHOME local reset
```

허용되지 않은 action과 candidate는 실행 전에 거절한다. Exact candidate allowlist, source identity, runtime ownership, API destination과 method/path 범위는 adapter가 고정한다.

## Adapter responsibilities

Adapter는 다음 항목을 제공하고 검증한다.

- immutable source revision과 repository identity
- isolated runtime identity와 localhost endpoint
- idempotent synthetic bootstrap
- candidate별 control/probe와 request budget
- secret-free append-only evidence
- deterministic cleanup과 owned-resource reset
- full-hunt discovery, duplicate research와 version provider capability

Core의 `FullHuntEngine`은 제품 route나 credential 형식을 알지 않는다. Version boundary search도 source checkout, build cache, bootstrap과 validation을 adapter provider에 위임한다.

## Stop and reset

`stop`은 선택된 target의 owned service만 정지해야 한다. Source, volume, secrets, immutable evidence와 승인 자료를 자동 삭제하지 않는다. `reset`은 사용자가 명시적으로 호출한 경우에만 adapter가 소유한 synthetic state를 제거한다.

## Failure isolation

Plugin discovery/load/API incompatibility는 `DUPLICATE_TARGET_ID`, `INVALID_TARGET_PLUGIN`, `INCOMPATIBLE_TARGET_PLUGIN`으로 구분한다. Source, runtime, bootstrap, validation 오류는 adapter가 body, command, credential을 포함하지 않는 stable code로 반환한다.

