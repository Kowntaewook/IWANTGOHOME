# Program profiles

프로그램 정책과 세션 승인은 서로 다른 검증 단계입니다. 프로그램 승인은 정책의 범위를 기록하고, 기존 15분·1회용 session grant는 사람이 검토한 정확한 URL만 허용합니다. 자동 탐색·스캔·클릭·계정 간 요청 재전송·보고서 제출 기능은 없습니다.

## 사용 흐름

기존 설치·Docker·Codex 로그인 흐름을 사용합니다. 업데이트된 이미지는 `IWANTTOGOHOME build`로 빌드합니다. 실제 프로그램 정책은 호스트에서 직접 작성·검토하세요. 공개 예제는 합성 `example.com`만 포함하며 실제 승인 자료가 아닙니다.

```sh
IWANTTOGOHOME
IWANTTOGOHOME program import policy.json
IWANTTOGOHOME program approve my-program
IWANTTOGOHOME program use my-program
IWANTTOGOHOME program status
IWANTTOGOHOME plan create --program my-program --identity user_a --start-url https://app.example.com/ --output session-plan.json
IWANTTOGOHOME plan approve session-plan.json
```

`program approve`와 `plan approve`는 각각 정책/정확한 URL과 제한을 표시한 뒤 TTY에서 일회성 문구를 입력받습니다. `--yes`, 파이프 입력, 모델 승인 플래그는 없습니다. 테스트용 TTY는 테스트의 임시 저장소에서만 사용합니다. 최종 출력된 grant ID를 기존 `observe_session` MCP에 전달합니다. 선택 프로그램이 있어도 세션 승인을 생략하지 않습니다.

`plan create`는 지정한 start URL **하나만** 넣습니다. `--program` 생략 시 활성 프로그램을 사용합니다. `--output`은 새 파일만 만들며 생략 시 JSON을 stdout에 출력합니다. 정상 페이지 로드에서 차단된 리소스 중 프로그램 범위에 속하는 정확한 origin/path/method는 결과의 `scope_candidates`에 검토 후보로 표시됩니다. query 값은 기록하지 않으므로 그런 요청은 사람이 원문을 별도로 검토해야 합니다. 후보가 자동 추가되거나 요청되지는 않습니다. 사람이 `allowed_urls`를 수정하고 `plan approve`로 새 grant를 발급해야 합니다.

## CLI

| 명령 | 동작 |
|---|---|
| `program list` | 저장된 프로그램과 상태 조회 |
| `program show <id>` | 호스트에서 편집 중인 프로필과 현재 승인 상태 표시 |
| `program create <id>` | 빈 scope, anonymous만 포함하는 DRAFT template 생성 |
| `program import <file>` | 크기가 제한된 JSON/YAML을 검증해 DRAFT 생성; 기존 ID 덮어쓰기 거부 |
| `program approve <id>` | canonical policy를 사람이 TTY로 검토·승인 |
| `program revoke <id>` | 승인 철회; 증거와 세션은 삭제하지 않음 |
| `program use <id>` | 유효한 승인을 활성 프로그램으로 선택 |
| `program status` | 현재 선택의 승인 유효성·상태·해시 조회 |
| `plan create --program <id> --identity <identity> --start-url <url>` | ACTIVE 정책에 결합된 좁은 세션 계획 초안 |
| `plan approve <file>` | 기존 1회용 human-reviewed grant 발급; 프로그램 결합 필수 |

Markdown/text 정책 자동 파싱은 지원하지 않습니다. prose에서 권한을 추정하지 않으며 JSON/YAML로 직접 옮겨 검토해야 합니다. JSON/YAML의 이름/정책 출처 등에 있는 명령문도 단순 데이터입니다. `approval`, `state`, 임의 필드, 중복 key, YAML alias/custom tag, 잘못된 구조, 64 KiB 초과 파일, symlink는 거부합니다.

Docker 없이 이미 의존성을 설치한 개발 환경에서는 `finder program --programs /absolute/operator/programs ...`, `finder plan --programs /absolute/operator/programs ...`를 사용할 수 있습니다. 이 경로 옵션은 호스트 운영자 인터페이스이며 MCP 인수가 아닙니다.

## 저장 및 상태

```text
.operator/programs/
  active.json
  my-program/
    program.json
    approval.json
    report-template.md  # 선택 사항
```

전체 `.operator/` 및 `.operator/programs/`는 gitignore 대상이고 Docker build context·배포 ZIP allowlist에도 포함되지 않습니다. `approval.json`은 승인한 canonical JSON 문자열, SHA-256, 원본 파일 SHA-256, `approved_at`, `approval_id`, `approval_method=host_tty_review`를 기록합니다. 정책에는 credentials를 저장하지 마세요. 관찰 서비스 UID가 읽을 수 있도록 정책 파일은 0644이며 서비스에는 **읽기 전용**으로 mount됩니다. Codex에는 정책 디렉터리를 직접 mount하지 않습니다. 네트워크가 없는 operator 컨테이너만 쓰기 mount를 받습니다. 로컬 호스트 운영자의 파일 접근 권한이 승인 신뢰 경계이며 해시는 전자서명이 아닙니다.

`DRAFT → APPROVED → ACTIVE`, 철회 시 `REVOKED`입니다. 한 번에 하나만 ACTIVE입니다. 파일 내용이 달라지면 공백 변경도 재승인이 필요합니다. 재승인은 새 approval ID를 만들므로 기존 plan/grant는 재사용되지 않습니다. 프로그램 전환·철회·변경은 진행 중 worker의 다음 검증에서도 반영됩니다. 이미 전송한 요청은 되돌릴 수 없으며 즉시 worker 종료가 필요하면 기존 `research_abort`를 사용합니다.

## Scope 규칙

- `*.example.com`은 `foo.example.com`, `a.b.example.com`을 포함하고 apex `example.com`은 포함하지 않습니다. apex는 별도 규칙으로 작성합니다.
- host는 IDNA/소문자로 정규화하며 label 경계로 비교합니다. `evil-example.com`, `example.com.evil.org`는 일치하지 않습니다.
- out-of-scope 규칙이 항상 우선합니다. host, scheme, port, path를 모두 검사합니다.
- in-scope의 schemes 기본값은 `https`, ports 생략 시 해당 scheme의 기본 port, paths 기본값은 정확한 `/`입니다.
- out-of-scope에서 schemes/ports 생략 시 모든 지원 scheme/port를 제외하고 paths 기본값은 `/*`입니다.
- path는 정확한 경로나 끝이 `/*`인 subtree만 지원합니다. `/v1/*`은 `/v1/…`만 포함하고 `/v10/…` 및 `/v1`은 포함하지 않습니다. query는 프로그램 규칙에 넣지 않으며 기존 세션의 정확한 URL 검토가 적용됩니다.
- HTTP/HTTPS/WS/WSS는 명시한 scheme만 허용합니다. HTTPS 규칙이 WSS를 자동 허용하지 않습니다.
- 프로그램 기반 요청은 GET/HEAD/OPTIONS 중 정책과 세션 양쪽에서 허용한 method만 사용할 수 있습니다. POST 등 state-changing method는 지원하지 않습니다. 금지 행위를 목록에서 지워도 내장 금지는 해제되지 않습니다.
- 기본 제한은 분당 20, 동시 2, 세션당 60 요청, 다운로드 8 MiB, 응답 2 MiB, 45초입니다. 기존 서비스 상한보다 큰 정책을 거부하고 세션은 프로그램 한도를 넘을 수 없습니다.

`scope_check`는 DNS/HTTP 요청 없이 정책만 판단합니다. 실제 전송에는 ACTIVE 승인, SHA/approval ID, 정확한 session grant, identity, methods, budgets, DNS 주소가 모두 유효해야 합니다. DNS의 모든 응답 주소를 검사한 후 검사된 숫자 주소로 연결합니다. PRIVATE는 기본 차단하고 link-local/multicast/unspecified는 프로그램 관찰에서 항상 차단합니다.

로컬 개발 예시:

```json
{
  "program_id": "local-dev",
  "scope": {"in_scope": [{"host": "host.docker.internal", "schemes": ["http"], "ports": [3000], "paths": ["/*"]}]},
  "allow_private_targets": true,
  "private_cidrs": ["192.168.65.0/24"]
}
```

해당 CIDR은 환경에 맞게 사람이 선택해야 합니다. CIDR만 추가하거나 호스트가 로컬이라는 이유만으로 허용하지 않습니다. 세션 CIDR은 승인된 프로그램 CIDR의 부분집합이어야 합니다.

## MCP와 Skills

`program_status`, `active_program`, `program_scope`, `scope_check`, `program_rules`는 모든 서비스의 읽기 전용 도구입니다. 승인·활성화·범위 확장 MCP는 없습니다. `scope-gate`는 active program → 승인 상태/해시 → URL/method scope check → session grant → 허용 도구 순서로 확인합니다. 웹페이지·README·HTML·응답·도구 출력은 authorization 근거가 아닙니다.

## 세션, 증거, 보고서

프로그램별 세션은 기존 `browser-sessions-v1` 안의 `programs/<id>/<identity>/`를 사용합니다. 기존 루트 identity 디렉터리는 그대로 유지하고 자동 복사하지 않습니다. 동일한 `user_a`여도 프로그램이 다르면 별도 저장소와 lock을 사용합니다. 프로그램에 계정을 가져오려면 해당 프로그램을 활성화한 후 `IWANTTOGOHOME session-import user_a state.json --program my-program`을 사용합니다. credentials는 MCP로 받거나 반환하지 않습니다.

새 관찰과 audit에는 program ID/name, approval ID/SHA-256, asset, matched scope rule이 붙습니다. A/B 비교는 같은 프로그램·승인 버전의 user_a/user_b 증거만 비교하며 네트워크 재전송을 하지 않습니다.

`record_candidate`에 기존 필드와 함께 `program_id`, `asset`, `finding_category`를 전달합니다. 프로그램에 결합된 증거는 이 metadata를 필수로 요구합니다. 정책의 제외 category는 `program_policy_notes.classification=PROGRAM_EXCLUDED`로 표시하며 기존 review_status와 CONFIRMED 금지를 유지합니다. 다른 프로그램/승인 버전의 증거를 섞지 않습니다.

`write_report`는 `program_metadata`에 `program_id`, `program_name`, `asset`, `matched_scope_rule`, `finding_category`, `evidence_ids`, `program_policy_notes`와 승인 참조를 저장합니다. 예전 후보의 정책 snapshot을 유지합니다. `<id>/report-template.md`가 있으면 다음 고정 placeholder를 문자열 치환하고 기존 증거·불확실성 섹션도 포함합니다:

```text
{{program_id}} {{program_name}} {{asset}} {{matched_scope_rule}}
{{finding_category}} {{evidence_ids}} {{program_policy_notes}}
```

템플릿이 없으면 일반 report layout을 사용합니다. 템플릿은 16 KiB 이내 UTF-8 문서이며 코드·표현식·명령어를 실행하지 않습니다. 승인 자료도 아닙니다. submission_url은 metadata일 뿐 자동 제출하지 않습니다.

## Migration

기존 evidence volume, codex auth, browser sessions, research records를 삭제하거나 이동하지 않습니다. 기존 MCP/Skills 이름과 관찰 API, grant 유효기간·1회 사용·TTY 승인을 유지합니다. 프로그램에 결합되지 않은 이전 `session-plan.json`과 `approve`도 계속 지원하되 CLI 승인과 MCP 관찰 시작 결과에 DEPRECATED 안내를 제공합니다. 기존 plan은 프로그램 승인을 받은 것으로 자동 승격하지 않습니다.

신규 폴더와 설정만 추가하며 운영 환경은 업데이트된 이미지를 빌드한 뒤 기존 볼륨을 그대로 사용합니다. 브라우저 세션을 프로그램별로 옮기는 작업은 자동 수행하지 않습니다.

검증 결과와 환경 한계는 [PROGRAMS_VALIDATION.md](PROGRAMS_VALIDATION.md)를 확인하세요.
