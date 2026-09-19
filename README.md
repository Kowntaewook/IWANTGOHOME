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

허가된 self-hosted Mattermost pinned revision을 host에서 준비하고 localhost-only A/B validation을 실행할 수 있습니다.

```bash
FINDER_TARGET=mattermost IWANTGOHOME local prepare
FINDER_TARGET=mattermost IWANTGOHOME local up
FINDER_TARGET=mattermost IWANTGOHOME local bootstrap
FINDER_TARGET=mattermost IWANTGOHOME local validate S12
FINDER_TARGET=mattermost IWANTGOHOME local status
FINDER_TARGET=mattermost IWANTGOHOME local stop
```

Docker와 local process는 host CLI의 fixed action만 실행합니다. Codex/analysis 컨테이너에는 Docker socket이나 실행 tool이 추가되지 않습니다. 자세한 구조는 [Local Target Harness](docs/LOCAL_TARGETS.md), candidate 조건과 evidence 형식은 [Local Validation](docs/LOCAL_VALIDATION.md)을 참고하세요.

Mattermost runtime은 `mattermostdevelopment/mattermost-enterprise-edition:d283cc6` (`linux/amd64`) digest-pinned image만 사용하며 host source-build fallback을 사용하지 않습니다. Delegated role bootstrap에는 유효한 Enterprise license 또는 공식 trial이 별도로 필요합니다.
