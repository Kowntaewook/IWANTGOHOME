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

범용 full-hunt 기능은 [외부 대상 모듈 연결](docs/TARGET_SDK.md), [버전 경계 자동 탐색](docs/VERSION_BISECT.md), [사람 검토용 제보 보고서 묶음 생성](docs/DISCLOSURE_PACK.md)을 지원합니다. 대상별 API와 fixture는 외부 target package가 제공하며 Core에는 들어가지 않습니다.

- 새 stable 버전과 patch revision 추적
- 검증된 후보의 안전한 local 자동 재검증
- 수정, 영향 지속, 회귀 상태와 선언형 regression 항목 확인

사용법과 판정 조건은 [Release monitoring](docs/RELEASE_MONITORING.md)과 [Regression testing](docs/REGRESSION_TESTING.md)을 참고하세요.

설치된 target package는 명시적으로 선택된 경우에만 host-side lifecycle과 localhost validation을 제공합니다.

```bash
IWANTTOGOHOME target list
IWANTTOGOHOME target doctor sample
FINDER_TARGET=sample IWANTGOHOME local status
```

Docker와 local process는 선택된 adapter의 fixed action만 실행합니다. Codex/analysis 컨테이너에는 Docker socket이나 임의 실행 tool이 추가되지 않습니다. 자세한 구조는 [Target SDK](docs/TARGET_SDK.md), [Local Target Harness](docs/LOCAL_TARGETS.md), [Local Validation](docs/LOCAL_VALIDATION.md)을 참고하세요.

Full-hunt pipeline은 target-neutral engine과 schema, duplicate research, version/runtime, scenario synthesis, clustering, reporting 모듈로 구성됩니다. 제품별 route, fixture, 권한 모델, build recipe와 판정 규칙은 설치된 adapter가 제공합니다.

`NEEDS_MANUAL_SCENARIO` 후보는 source assertion과 adapter capability가 충분할 때만 adapter의 reviewed fixture-route binding을 통해 localhost 전용 control/probe plan으로 바뀝니다. Core는 body/count, direct/collection, visibility-boundary pattern만 알고 제품 route와 fixture는 알지 못합니다. `EXACT`와 `STRONG` binding만 실행할 수 있고 `WEAK`는 생성 후 차단됩니다. Core safety gate는 `finder-local-*` fixture, GET/HEAD, 고정 request budget, loopback final URL과 control 성공을 강제합니다. 근거가 부족하거나 mutation이 필요한 후보는 manual 상태로 남고, 각 결과는 report의 `scenarios/` 아래에서 확인할 수 있습니다.
