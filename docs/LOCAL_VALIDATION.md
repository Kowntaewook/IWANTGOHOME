# Local Validation

Local validation은 Mattermost pinned revision과 `FINDER_LOCAL_*` synthetic resource만 대상으로 한다. HTTP destination은 `127.0.0.1:8065`로 고정되고 각 candidate의 method/path 정규식 allowlist를 통과한 요청만 보낸다. 로그인 요청과 deterministic setup은 validation request budget에서 제외되지만 같은 localhost 제한을 적용한다.

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
