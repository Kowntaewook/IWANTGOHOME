# Disclosure pack

Disclosure pack은 기존 local report를 사람이 개발사 제보 전에 검토할 수 있는 파일 묶음으로 정리한다. Network client, email sender, issue/advisory 생성기, vendor destination 선택 기능은 제공하지 않는다.

## 실행 gate

기본적으로 `NEW_SECURITY_CANDIDATE`만 build할 수 있다. 다른 상태는 outcome에 `review_status=READY_FOR_HUMAN_REVIEW`와 `human_approved=true`가 모두 있는 경우에만 허용한다. `DISCOVERED`, `NEEDS_LOCAL_VALIDATION`, `NEEDS_MANUAL_SCENARIO` 상태를 자동 승격하지 않는다.

```bash
FINDER_TARGET=sample IWANTTOGOHOME disclosure build CAND-001
FINDER_TARGET=sample IWANTTOGOHOME disclosure inspect CAND-001
FINDER_TARGET=sample IWANTTOGOHOME disclosure list
```

`build`는 최신 local full-hunt report와 존재하는 최신 bisect result를 읽는다. `inspect`는 manifest hash와 local file 존재만 확인한다.

## 생성 파일

```text
.operator/disclosure-packs/<target>/<candidate>/<run-id>/
  summary.md
  technical-report.md
  reproduction.md
  version-impact.md
  duplicate-research.md
  evidence-manifest.json
  report.json
  human-review-checklist.md
  public-redacted.md
  release-monitor.md      # optional
  regression-status.md    # optional
```

local monitor state나 regression spec이 있으면 두 optional 파일과 `report.json`의 `release_monitor`, `latest_retest`, `regression` 참조를 추가한다. 해당 state가 없어도 기존 pack은 같은 방식으로 생성된다. `--ai-use-disclosure`를 명시하면 편집 가능한 `ai-use-disclosure.md`도 만든다. `public-redacted.md`는 공개 승인이 아니며 release timing 항목을 사람이 확인해야 한다.

## Redaction과 해석 제한

Pack 생성 전에 secret key/value, authorization/cookie/token pattern, email, local absolute path와 private note를 제거한다. Public draft에서는 synthetic local username도 일반 placeholder로 바꾼다. Heuristic redaction은 사람의 secret/PoC 검토를 대체하지 않는다.

Duplicate 결과가 `NO_PUBLIC_DUPLICATE_FOUND`여도 다음 의미를 유지한다.

> No public duplicate was found in the reviewed sources. This is not novelty confirmation.

Version matrix와 bisect result가 없거나 모순되면 `unknown/inconclusive`로 기록한다. `human-review-checklist.md`의 모든 항목은 사람이 확인해야 한다. 모든 artifact에는 `external_submission_performed=false`가 유지된다.
