# Target SDK

IWANTGOHOME Core는 target별 API, fixture, build 방법을 알지 않는다. 설치된 Python package가 `iwantgohome.targets` entry point로 host-side adapter를 제공한다. 임의 plugin directory, 현재 directory 재귀 검색, `PYTHONPATH` 탐색은 사용하지 않는다.

## API version과 lifecycle

현재 `TARGET_API_VERSION`은 `1`이다. Adapter는 다음 필드를 제공한다.

```text
target_id
target_api_version
supported_candidates
```

필수 lifecycle method는 다음과 같다.

```text
prepare()
up(progress=...)
status()
bootstrap()
validate(candidate_id)
stop()
reset()
```

기존 `FullHuntTargetAdapter` schema와 scenario binding을 그대로 사용할 수 있다. `full_hunt`, `hunt`, `version_provider`, `scenario_bindings`, `release_provider`, `regression_capabilities`, `run_regression`은 optional capability다. Release provider는 기존 version provider의 revision resolution과 lifecycle을 재사용할 수 있다. Local adapter와 full-hunt adapter가 서로 다른 역할을 담당하므로 Core protocol을 복제하지 않는다.

## Package registration

외부 package의 `pyproject.toml`에 entry point를 추가한다. Entry point name은 adapter의 exact `target_id`다.

```toml
[project.entry-points."iwantgohome.targets"]
sample = "sample_target.adapter:create_adapter"
```

Factory는 명시적인 `root` keyword를 받고 adapter를 반환한다. 선택된 target code 안에서 API version을 선언한다.

```python
from ctf_mcp.targets import TARGET_API_VERSION

def create_adapter(*, root, runner=None):
    return SampleAdapter(
        root=root,
        runner=runner,
        target_api_version=TARGET_API_VERSION,
    )
```

`target list`는 entry point name과 distribution metadata만 읽으며 target module을 import하지 않는다. `target info`도 metadata-only다. `target doctor`와 실제 target 선택 때만 해당 entry point를 load한다.

```bash
IWANTTOGOHOME target list
IWANTTOGOHOME target info sample
IWANTTOGOHOME target doctor sample
FINDER_TARGET=sample IWANTTOGOHOME local status
```

Doctor는 plugin load, API version, target ID, 필수 method와 optional capability 존재 여부만 확인한다. Lifecycle method를 호출하지 않으며 외부 server에 접속하거나 validation을 시작하지 않는다.

## 오류와 충돌

동일한 entry point name이 둘 이상이면 어떤 target도 실행하지 않고 `DUPLICATE_TARGET_ID`를 반환한다. Import/factory/ID가 잘못되면 `INVALID_TARGET_PLUGIN`, API version이나 필수 interface가 맞지 않으면 `INCOMPATIBLE_TARGET_PLUGIN`이다. Registry instance는 공유 mutable registration state를 사용하지 않는다.

Target lookup은 `TargetRegistry` 하나를 source of truth로 사용한다. `FullHuntRegistry` type은 isolated factory collection이 필요한 embedding 호환용이며 CLI나 local/full-hunt target lookup에는 사용되지 않는다.
