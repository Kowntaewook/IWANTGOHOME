# 도구·스킬·증거 형식

현재 실제 FastMCP registry에서 생성한 [tool-schemas.json](tool-schemas.json)이 입출력 형식의 기준입니다. 고유 이름은 92개이며 공통 도구가 서비스별로 중복됩니다. 기존 30개 이름을 유지하고 62개를 추가했습니다.

| 서비스 | 도구 수 |
|---|---:|
| analysis | 52 |
| platform | 30 |
| observer | 13 |
| android | 22 |
| android-dynamic | 9 |
| binary | 19 |
| burp | 8 |

## analysis

`compose_review`, `dependency_inventory`, `dependency_lockfile_summary`, `dockerfile_review`, `github_actions_review`, `graphql_document_summary`, `graphql_operations_from_file`, `graphql_schema_summary`, `ios_ats_config`, `ios_entitlements`, `ios_frameworks`, `ios_info_plist`, `ios_package_info`, `ios_url_schemes`, `kubernetes_manifest_review`, `openapi_auth_schemes`, `openapi_operations`, `openapi_sensitive_operations`, `openapi_summary`, `sbom_generate`, `source_dependency_map`, `source_diff_review`, `source_entrypoints`, `source_secret_indicators`, `source_security_scan`, `source_tree`, `terraform_review`, `source_search`, `openapi_compare_versions`, `health`, `read_record`, `list_records`, `compare_records`, `inventory`, `review_source`, `review_source_tree`, `read_source_context`, `analyze_har`, `analyze_http_log`, `review_openapi`, `analyze_source_map`, `review_diff`, `review_dependencies`, `review_infrastructure`, `review_ios`, `review_entitlements`, `review_crash`, `packet_metadata`, `archive_inventory`, `record_candidate`, `resume_research`, `write_report`

## platform

`android_certificate_info`, `android_exported_components`, `android_find_deeplinks`, `android_find_urls`, `android_find_webviews`, `android_manifest`, `android_network_security`, `android_package_info`, `android_permissions`, `binary_exports`, `binary_identify`, `binary_imports`, `binary_strings`, `ios_macho_info`, `android_search_code`, `android_decompile_summary`, `ghidra_analyze`, `ghidra_functions`, `ghidra_symbols`, `health`, `read_record`, `list_records`, `compare_records`, `inventory`, `review_source`, `review_source_tree`, `read_source_context`, `review_android`, `binary_metadata`, `certificate_metadata`

## observer

`health`, `read_record`, `list_records`, `compare_records`, `observe_web`, `observe_session`, `research_pause`, `research_resume`, `research_abort`, `compare_session_observations`, `web_status`, `stop_web`, `write_regression_test`

## android

`android_certificate_info`, `android_exported_components`, `android_find_deeplinks`, `android_find_urls`, `android_find_webviews`, `android_manifest`, `android_network_security`, `android_package_info`, `android_permissions`, `android_search_code`, `android_decompile_summary`, `health`, `read_record`, `list_records`, `compare_records`, `inventory`, `review_source`, `review_source_tree`, `read_source_context`, `review_android`, `binary_metadata`, `certificate_metadata`

## android-dynamic

`health`, `read_record`, `list_records`, `compare_records`, `adb_devices`, `adb_package_info`, `adb_logcat_snapshot`, `frida_devices`, `frida_process_list`

## binary

`binary_exports`, `binary_identify`, `binary_imports`, `binary_strings`, `ios_macho_info`, `ghidra_analyze`, `ghidra_functions`, `ghidra_symbols`, `health`, `read_record`, `list_records`, `compare_records`, `inventory`, `review_source`, `review_source_tree`, `read_source_context`, `review_android`, `binary_metadata`, `certificate_metadata`

## burp

`health`, `read_record`, `list_records`, `compare_records`, `burp_capabilities`, `burp_proxy_history`, `burp_saved_requests`, `burp_websocket_history`

## 호출 형식

대부분 로컬 분석 도구는 `path`(읽기 전용 입력 기준 상대 경로)를 받습니다. source_search/android_search_code는 `query`(literal), openapi_compare_versions는 `before_path`, `after_path`를 받습니다. ghidra_functions/ghidra_symbols는 기존 `record_id`를 받습니다.

observe_session은 `grant_id`만 받습니다. research_pause/resume/abort 및 web_status는 `job_id`입니다. compare_session_observations는 `user_a_record_id`, `user_b_record_id`로 저장된 결과만 비교합니다. Burp는 `count`(1~20), `offset`(0~10000)이며 주소/token은 환경 설정에만 있습니다. 장치 API는 schema의 opaque device_id와 검증된 package를 사용합니다.

실패는 MCP isError=true와 정제된 error.code를 반환합니다. 연결/도구 부재는 HOST_ADAPTER_REQUIRED 또는 OPTIONAL_TOOL_REQUIRED 같은 구조화된 상태일 수 있습니다. 저장된 result.error, partial status, blocked_or_incomplete도 확인해야 합니다. record가 있다는 것만으로 성공이라고 판단하지 마세요.

## Provenance

새 기록의 provenance 필드: analysis_id, timestamp_utc, input_sha256, analyzer, analyzer_version, identity_label, tool_result_path, redaction_status. 파이프라인 버전은 0.3.0입니다. 실제 native/parser 버전은 result/health에도 제공합니다. 입력 해시가 없으면 null이며 source view는 ordered_file_manifest 해시일 수 있습니다. 이전 기록은 재작성하지 않습니다.

## 후보

record_candidate의 candidate 필수 필드는 project, title, facts, concerns, assumptions, counterarguments, missing_evidence, review_status, remediation, evidence_ids입니다. 텍스트 필드는 문자열, evidence_ids는 실제 analysis ID 1~20개입니다. skill의 보고 구조는 이 API 입력과 별도입니다.

상태: DISCOVERED, VALIDATING, NEEDS_MORE_EVIDENCE, REJECTED, BLOCKED_SCOPE, DUPLICATE, NOT_SECURITY_RELEVANT, READY_FOR_HUMAN_REVIEW. 이전 lowercase 상태는 호환을 위해 유지합니다. CONFIRMED는 거부합니다. 수정은 새 record를 추가하며 write_report에는 기존 후보도 포함되므로 중복/대체 관계를 검토하세요.

write_report와 write_regression_test는 Markdown/Python payload를 저장합니다. 파일 자동 덮어쓰기나 외부 제출/재요청은 하지 않습니다. finder export는 사용자 선택 새 파일로만 내보냅니다.

## 18개 스킬

기존 11개 역할을 확장·이름 정리하고 7개를 추가했습니다. 각각 trigger/prerequisites/실제 tool dependencies/process/evidence/false positives/stop/output JSON schema/references를 포함합니다. 역할 전환은 독립 에이전트 실행을 뜻하지 않습니다.

- [android-dynamic-review](../.agents/skills/android-dynamic-review/SKILL.md)
- [android-static-review](../.agents/skills/android-static-review/SKILL.md)
- [api-review](../.agents/skills/api-review/SKILL.md)
- [attack-surface-map](../.agents/skills/attack-surface-map/SKILL.md)
- [authenticated-session-review](../.agents/skills/authenticated-session-review/SKILL.md)
- [authz-comparison](../.agents/skills/authz-comparison/SKILL.md)
- [binary-review](../.agents/skills/binary-review/SKILL.md)
- [business-logic-review](../.agents/skills/business-logic-review/SKILL.md)
- [dependency-review](../.agents/skills/dependency-review/SKILL.md)
- [evidence-capture](../.agents/skills/evidence-capture/SKILL.md)
- [ios-static-review](../.agents/skills/ios-static-review/SKILL.md)
- [privacy-review](../.agents/skills/privacy-review/SKILL.md)
- [prompt-injection-defense](../.agents/skills/prompt-injection-defense/SKILL.md)
- [report-writing](../.agents/skills/report-writing/SKILL.md)
- [scope-gate](../.agents/skills/scope-gate/SKILL.md)
- [skeptical-retest](../.agents/skills/skeptical-retest/SKILL.md)
- [source-review](../.agents/skills/source-review/SKILL.md)
- [web-observation](../.agents/skills/web-observation/SKILL.md)
