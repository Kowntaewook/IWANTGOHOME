# Version bisect

Version bisect는 검증 가능한 candidate의 최초 영향 revision 또는 최초 수정 revision을 immutable revision 사이에서 좁힌다. Core는 tag 형식, source checkout, image build, bootstrap route를 알지 않으며 binary search와 결과 검증만 담당한다.

## 실행 조건

Provider는 candidate마다 다음 capability를 모두 확인해야 한다.

```text
deterministic_validation
source_assertions
immutable_revisions
revision_ordering
safety_gate
```

Revision은 40자 commit SHA, source/image identity, version과 stable order key를 포함한다. Floating branch나 tag 문자열만으로는 실행할 수 없다. Provider가 ordered revisions, source/build/runtime cache, isolated bootstrap, control/probe validation과 cleanup을 책임진다. 기존 source checkout과 build cache를 provider에서 그대로 재사용할 수 있다.

```bash
FINDER_TARGET=sample IWANTTOGOHOME bisect CAND-001 \
  --mode introduced --from v1.0.0 --to v2.0.0

FINDER_TARGET=sample IWANTTOGOHOME bisect CAND-001 \
  --mode fixed --from v2.0.0 --to main-commit
```

## 판정

Revision observation은 `UNAFFECTED`, `AFFECTED`, `BLOCKED`, `INCONCLUSIVE` 중 하나다. Control이 성공하지 않은 observation은 영향/비영향 판정에 사용하지 않는다.

최종 상태는 다음과 같다.

```text
FIRST_AFFECTED_FOUND
FIRST_FIXED_FOUND
BISECT_BLOCKED
NON_MONOTONIC
BOUNDARY_NOT_FOUND
```

Core는 양 끝점을 먼저 검사한다. `introduced`는 `UNAFFECTED → AFFECTED`, `fixed`는 `AFFECTED → UNAFFECTED` 조건이 맞아야 binary search를 시작한다. 중간 build/bootstrap/control이 막히면 safe나 fixed로 간주하지 않는다. Boundary 전후 최대 2개 revision을 추가 검사하며 모순은 `NON_MONOTONIC`으로 남긴다. 같은 immutable identity는 한 run에서 한 번만 실행된다.

## Artifacts

결과는 다음 위치에 private artifact로 기록한다.

```text
.operator/bisect/<target>/<candidate>/<run-id>/
  bisect.json
  bisect.md
  version-matrix.json
  observations/*.json
```

Bisect도 기존 localhost, approved environment, secret redaction, read-only/destructive validation gate를 우회하지 않는다.

