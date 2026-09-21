# Local Validation

Local validation은 선택한 pinned target과 `finder-local-` synthetic resource만 대상으로 한다. Mattermost HTTP destination은 `127.0.0.1:8065`, Gitea는 `127.0.0.1:13000`으로 고정되고 각 adapter의 candidate별 method/path 정규식 allowlist를 통과한 요청만 보낸다. 로그인 요청과 deterministic setup은 validation request budget에서 제외되지만 같은 localhost 제한을 적용한다.

## Synthetic bootstrap

`local bootstrap`은 다음 identity와 resource를 생성하거나 동일 marker의 기존 항목을 재사용한다.

```text
system_admin
delegated_admin
victim
normal_user

team_a
private_channel_a
private_channel_b
DM victim <-> normal_user
```

실제 username과 resource name에는 `finder-local-` prefix가 붙는다. `private_channel_a`에는 victim과 normal_user가 들어가며 delegated_admin은 bootstrap 때 명시적으로 제거된다. victim이 `PRIVATE_S12_TEST_MESSAGE` root post를 만들고 DM variant용 별도 synthetic root도 만든다.

비밀번호는 host에서 무작위 생성해 `.operator/local-secrets/mattermost/`에만 저장한다. API login body와 process memory 외에는 전달하지 않으며 stdout, command argv, immutable evidence에 저장하지 않는다. session token도 memory에만 있고 evidence에는 SHA-256 기반 16자리 `session_fingerprint`만 남는다.

Delegated role은 Mattermost의 built-in `system_user_manager`를 공식 role API로 조회·patch·assign한다. 검증 전 다음 조건을 모두 확인한다.

```text
system_admin == false
edit_other_users == true
view_team == true
manage_system == false
read_channel_content == false
target_channel_member == false
```

지원되는 API로 이 조합을 만들 수 없으면 bootstrap은 `ROLE_UNAVAILABLE`로 종료하고 각 candidate에 `BLOCKED_BY_LOCAL_SETUP`, `reason=required_supported_role_not_constructible` immutable reassessment를 추가한다. DB를 직접 수정하지 않는다.

Enterprise runtime 검증과 license entitlement는 별개다. `local up`은 Enterprise-ready build만 인정하지만, delegated role bootstrap은 유효한 Enterprise/Enterprise Advanced license 또는 공식 trial이 적용되지 않으면 `ROLE_UNAVAILABLE`로 중단한다.

## S12

Budget은 최대 8 requests이며 현재 private-channel flow는 2 requests, 조건이 성립하면 DM control 1 request를 추가한다.

```text
control:   GET /api/v4/users/{victim}/teams/{team}/threads/{thread_id}
candidate: GET /api/v4/users/{victim}/teams/{team}/threads?per_page=100&extended=true
```

Delegated user가 system admin/channel member가 아니고 content-read permission도 없으며, control은 거절되고 bulk는 성공하며 exact synthetic marker를 반환할 때만 `VERIFIED_CANDIDATE`다. 이 경우에만 DM single-thread control과 bulk response의 DM marker를 한 번 비교한다. 이 상태도 `CONFIRMED`로 자동 승격하지 않는다.

## S13

Budget은 최대 5 requests이며 현재 2 requests를 사용한다.

```text
control:   GET /api/v4/users/{victim}/teams/{team}/channels/members?page=0&per_page=100
candidate: GET /api/v4/users/{victim}/channel_members?page=0&per_page=100
```

status, channel IDs, roles, message/mention counts, notify metadata, team metadata의 shape와 presence를 비교한다. Pinned source의 candidate handler는 `edit_other_users`를 요구하고 requester 기준 sanitize를 수행하므로 정상 성공은 `INTENDED_BEHAVIOR`로 기록한다. 예상과 다른 실패나 shape는 `NEEDS_MORE_EVIDENCE`다.

## S15

Budget은 최대 5 requests이며 현재 before/control/candidate/after 4 requests를 사용한다. 먼저 normal_user가 synthetic reply를 추가해 victim thread state를 갱신한다.

```text
before:    GET victim threads
control:   PUT /api/v4/users/{victim}/teams/{team}/threads/{thread}/read/{timestamp}
candidate: PUT /api/v4/users/{victim}/teams/{team}/threads/read
after:     GET victim threads
```

Delegated user가 resource를 읽지 못하고 single mutation이 거절되며 bulk mutation은 성공하고 victim의 `last_viewed_at`/unread state가 실제로 변한 경우에만 `VERIFIED_CANDIDATE`다.

## Immutable evidence and reassessment

각 validation은 `Records.save`를 사용해 `.operator/local-evidence/mattermost/`에 새 `local_validation`과 `candidate_reassessment` JSON을 atomic create한다. 원래 S12/S13/S15 record는 읽거나 수정하지 않는다.

Evidence에는 target/commit/candidate/source record, identity, role summary, method/path/expected/status code/response shape, marker boolean, request count, timestamp, session fingerprint만 저장한다. Raw response body, password, token, cookie, secret path는 저장하지 않는다.

Reassessment 상태는 `VERIFIED_CANDIDATE`, `INTENDED_BEHAVIOR`, `FALSE_POSITIVE`, `NEEDS_MORE_EVIDENCE`, `BLOCKED_BY_LOCAL_SETUP` 중 하나이며 자동 `CONFIRMED`는 생성하지 않는다.

## Gitea synthetic bootstrap

Gitea bootstrap은 owned container에서 고정된 `gitea admin user create` argv를 사용해 다음 네 synthetic identity를 생성하거나 기존 항목을 인증해 재사용한다.

```text
finder-local-system-admin   site admin
finder-local-repo-owner    normal user
finder-local-collaborator  normal user
finder-local-outsider      normal user
```

비밀번호는 `.operator/local-secrets/gitea/secrets.json`에만 0600으로 저장하고 상위 directory는 0700으로 유지한다. Bootstrap state와 evidence에는 password, Basic Authorization header, token을 기록하지 않는다.

`finder-local-repo-owner/finder-local-private-repo` private repository를 만들고 description에도 `finder-local` marker를 둔다. Collaborator에는 read permission만 부여하고 outsider collaboration은 제거한다. 같은 bootstrap을 반복하면 기존 synthetic user/repository를 검증하고 재사용한다.

## G01

Budget은 1 request다. Membership이 없는 authenticated outsider가 아래 private repository metadata를 요청한다.

```text
GET /api/v1/repos/finder-local-repo-owner/finder-local-private-repo
```

401/403/404이면 `INTENDED_BEHAVIOR`다. Exact synthetic private repository가 200으로 반환되고 owner가 확인한 outsider membership이 없을 때만 실제 unexpected authorization으로 `VERIFIED_CANDIDATE`가 될 수 있다.

## G02

Budget은 1 request다. Owner API로 read collaboration을 먼저 확인한 뒤 collaborator가 같은 metadata endpoint를 요청한다. Exact synthetic repository가 200으로 반환되면 `INTENDED_BEHAVIOR`, 그 외에는 `NEEDS_MORE_EVIDENCE`다.

## G03

Budget은 1 request다. Read collaborator가 owner/admin 권한이 필요한 repository edit endpoint에 빈 JSON object를 보낸다.

```text
PATCH /api/v1/repos/finder-local-repo-owner/finder-local-private-repo
{}
```

빈 patch는 field를 변경하거나 repository를 삭제하지 않는다. 401/403/404이면 `INTENDED_BEHAVIOR`다. Exact repository가 200으로 반환될 때만 unexpected authorization으로 `VERIFIED_CANDIDATE`가 될 수 있다.

Gitea evidence는 identity, fixed method/path, expected result, status code, response shape, exact synthetic repository marker boolean, request count와 assessment만 저장한다. Raw response body와 credential은 저장하지 않는다.

## Gitea deterministic hunt

`FINDER_TARGET=gitea IWANTGOHOME local hunt`는 healthy local target의 bootstrap 상태를 확인하고, 필요할 때만 idempotent bootstrap을 수행한 뒤 G01~G08을 모두 실행한다. G04~G08은 candidate별 boolean assertion을 코드 고정 규칙으로 판정한다. Fixture/control 실패는 `BLOCKED_BY_LOCAL_SETUP`, 정상 보안 동작은 `INTENDED_BEHAVIOR`, 불완전한 관찰은 `NEEDS_MORE_EVIDENCE`, 모든 필수 assertion을 만족한 로컬 재현은 `VERIFIED_LOCAL`이다.

`VERIFIED_LOCAL`은 pinned local target에서의 재현 상태이며 외부 제품 취약점 확정이나 disclosure 승인이 아니다. Hunt는 외부 요청이나 제출을 수행하지 않는다. 결과는 매 실행마다 새로운 `.operator/reports/gitea/<run-id>/` 아래 JSON, Markdown, localhost 고정 GET-only PoC로 저장된다. Report에는 status, count, marker와 evidence ID만 포함하며 credential과 raw response body는 포함하지 않는다.

Verified candidate는 source helper 기준 `root_cause_cluster`로만 묶는다. G06/G07은 shared user/organization repository count path, G08은 team repository count path로 별도 취급한다. 사람은 생성된 최종 report를 검토한 뒤 외부 disclosure 여부를 결정한다.

## Gitea full hunt

`FINDER_TARGET=gitea IWANTGOHOME local hunt --full`은 manifest의 pinned source가 없으면 공식 저장소에서 고정 commit을 준비한다. Go source를 정해진 파일·용량 한도 안에서 읽고 route registration, 상속 middleware, handler, helper/model query 호출을 연결한다. Keyword 한 개만으로 후보를 통과시키지 않으며 각 후보에 source file SHA-256과 다음 boolean fact를 남긴다.

```text
route_exists
handler_resolved
model_query_resolved
trace_edges_resolved
authorization_middleware_present
viewer_binding_present
owner_repo_binding_present
response_refilter_present
visibility_helper_present
count_before_filter
candidate_pattern_observed
```

정적 상태는 `REJECTED_STATIC`, `NEEDS_LOCAL_VALIDATION`, `BLOCKED_STATIC`이다. Actions run/job처럼 repository ID binding이 handler에서 확인되면 정적으로 reject한다. 안전한 G04~G08 GET control/probe에 정확히 연결되는 후보만 자동 시나리오를 만들며 그 외 후보는 `NEEDS_MANUAL_SCENARIO`로 남긴다. 자동 시나리오는 `127.0.0.1:13000`, `finder-local-*`, bootstrap-only mutation, DB 직접 수정 금지와 고정 request budget을 강제한다.

로컬에서 `VERIFIED_LOCAL`인 후보만 공개 duplicate research 대상으로 삼는다. 외부 연결은 credential 없는 GET으로 `api.github.com`과 `services.nvd.nist.gov`에만 허용하며 GitHub issues, merged PR 검색 결과, public advisories, Gitea releases와 NVD를 조회한다. Endpoint와 source function/query fact가 함께 맞아야 duplicate match가 된다. `NO_PUBLIC_DUPLICATE_FOUND`는 신규 취약점 확정으로 취급하지 않는다.

Latest/main 재검증은 pinned runtime과 다른 loopback endpoint 및 runtime ID를 가진 evidence만 인정한다. 현재 supported latest stable인 1.27.3은 immutable image digest를 별도 Compose project와 `127.0.0.1:13001`에서 실행하고 별도 bootstrap, secret store, evidence directory를 사용한다. Version, commit, image digest, control 결과가 모두 있어야 affected/fixed 판정을 만들 수 있다. 검증된 immutable main image와 HEAD commit 쌍이 없거나 격리 runtime을 시작할 수 없으면 `RETEST_BLOCKED`이고, 외부 Gitea instance를 대신 테스트하지 않는다.

Full report는 새 `.operator/reports/gitea/<run-id>/`에 다음 구조로 append-only 생성된다.

```text
report.md
report.json
findings/RCxx.md
findings/RCxx.json
poc/RCxx.py
duplicate-research.json
version-matrix.json
```

`NEW_SECURITY_CANDIDATE`는 deterministic local reproduction, 성공한 control, latest 또는 main 영향, 완료된 공개 검색에서 일치 없음, report evidence가 모두 있는 경우에만 사용한다. Vendor-confirmed vulnerability를 뜻하지 않으며 외부 제출은 수행하지 않는다.
