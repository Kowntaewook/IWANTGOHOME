# Local Validation

Local validation은 선택한 installed target adapter와 adapter가 만든 synthetic resource만 대상으로 한다. 외부 임의 target, 발견한 URL, production account로 validation 범위를 넓히지 않는다.

## Required gates

Adapter는 validation 전에 다음을 확인한다.

- source assertion과 immutable revision identity
- owned isolated runtime과 loopback destination
- synthetic fixture identity와 expected control body
- candidate별 method/path allowlist
- bounded request count
- read-only probe 또는 명시적으로 허용된 defensive action
- secret-free evidence destination

Control이 실패하거나 fixture/source assertion이 맞지 않으면 candidate를 검증된 것으로 판정하지 않는다. Status code 하나, empty response 또는 404만으로 visibility나 authorization 위반을 확정하지 않는다. Destructive mutation, credential guessing, arbitrary command와 외부 redirect는 차단한다.

## Evidence

Local evidence는 target, immutable source/runtime identity, candidate ID, identity label, fixed method/path, expected observation, response shape, control/probe assertion, request count와 assessment만 보존한다. 다음 값은 저장하지 않는다.

```text
password
token
cookie
authorization header
raw credentialed response
personal data
local absolute path
```

Evidence와 reassessment는 append-only artifact로 만들며 scanner severity나 model confidence만으로 `CONFIRMED`를 생성하지 않는다.

## Full hunt and scenarios

Core의 `ScenarioPlan`은 identity/resource 요구사항, fixture capability, control/probe, invariant, request budget, source assertion과 cleanup 조건만 표현한다. 제품별 route와 object mapping은 adapter가 제공한다.

Source fact가 부족하면 `SCENARIO_NOT_GENERATABLE`, capability나 runtime이 없으면 `SCENARIO_BLOCKED`, safety rule을 어기면 `SCENARIO_UNSAFE`다. Control 성공과 deterministic body-based invariant가 모두 확인된 결과만 local verification으로 전달한다.

Duplicate research와 version retest는 local verification 뒤에 실행한다. `NO_PUBLIC_DUPLICATE_FOUND`는 novelty confirmation이 아니다. Version bisect의 `BLOCKED`와 `INCONCLUSIVE` revision은 safe/fixed로 취급하지 않는다.

## Disclosure boundary

Local validation, full hunt, bisect와 disclosure pack 생성은 자동 vendor submission 권한을 만들지 않는다. Email, issue, advisory와 vendor API 제출은 제공하지 않는다. 생성된 보고서와 checklist를 사람이 검토하고 별도의 disclosure 정책과 공개 시점을 결정한다.

