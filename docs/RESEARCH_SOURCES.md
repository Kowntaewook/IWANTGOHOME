# 조사 자료와 채택 근거

확인 날짜: **2026-09-15**. 공식 문서·원본 저장소·실제 설치된 배포판을 확인했습니다. 상세 버전·해시·라이선스 메타데이터는 `sources.lock.json`, Python 해석 환경은 `constraints.txt`에 있습니다.

제3자 스킬/설치 스크립트를 자동 설치하지 않았습니다. Trail of Bits의 원본 스킬과 라이선스를 읽고 변경분·근거·반론 검토 방식만 참고했습니다. upstream 스킬, 공격 절차, Bash 권한, 에이전트 위임 설정은 복사하지 않았습니다.

| 자료 | 확인한 버전/경로 | 채택/미채택 및 포함 형태 | 라이선스·재배포 확인 |
|---|---|---|---|
| [Codex authentication](https://learn.chatgpt.com/docs/auth) | /docs/auth | Device-code ChatGPT login, file credential store, separate CODEX_HOME and expiry/access guidance.  [design_only] | Official documentation; text not redistributed. Codex package license handled separately. |
| [Codex configuration](https://learn.chatgpt.com/docs/config-file/config-reference) | /docs/config-file/config-reference and config-schema.json | Verified configuration keys and strict app-server config parsing; no assumed model.  [design_only] | Official docs/schema; not vendored. |
| [Codex MCP](https://learn.chatgpt.com/docs/extend/mcp) | /docs/extend/mcp | HTTP MCP server tables, explicit optional-service enablement, real CLI registration inspection.  [design_only] | Official docs; not redistributed. |
| [Codex skill discovery](https://learn.chatgpt.com/docs/build-skills) | /docs/build-skills | .agents/skills repository layout; /etc/codex/skills image layout; actual skills/list check.  [design_only] | Official docs; not redistributed. |
| [Codex CLI](https://registry.npmjs.org/@openai/codex/0.154.0) | 0.154.0 | Pinned CLI for ChatGPT-backed agent. Version/help/config/skill discovery executed.  [build_dependency_not_vendored] | Apache-2.0 per npm metadata; preserve package notices in images. |
| [MCP Python SDK v1](https://py.sdk.modelcontextprotocol.io/v1/) | mcp 1.30.0; v1 maintenance-line documentation | Retain original FastMCP framework with typed tools, structured responses, bounded HTTP body, official stdio and HTTP clients.  [python_dependency_not_vendored] | MIT; retain dependency license/notice. |
| [MCP security advisories](https://github.com/modelcontextprotocol/python-sdk/security/advisories) | advisory API snapshot 2026-09-15 | Checked six published SDK advisories; selected 1.30.0 beyond listed patched versions; no experimental tasks/WebSocket MCP.  [design_only] | Advisory reference only. |
| [MCP security guidance](https://modelcontextprotocol.io/docs/draft/tutorials/security/security_best_practices) | draft security_best_practices | Separate authority from tool output, avoid credential passthrough, validate destinations and origins.  [design_only] | Reference only; no documentation redistribution. |
| [OWASP WSTG](https://owasp.github.io/www-project-web-security-testing-guide/) | project page; v4.2 referenced by official page | Evidence-backed review structure and explicit coverage; no active-testing payload catalog adopted.  [design_only] | Project license must be checked before copying text; attempted LICENSE.md URL was unavailable. No text copied. |
| [OWASP API Security](https://api-security.owasp.org/editions/2023/en/0x11-t10/) | 2023 Top 10; OWASP/API-Security LICENSE read | Distinguish declared API authentication from observed credentials and actual enforcement.  [design_only] | CC BY-SA 4.0 (repository LICENSE); attribution/share-alike review needed for derived redistributed material. |
| [OWASP MASVS](https://mas.owasp.org/MASVS/) | MASVS web documentation | Mobile storage/network/platform review categories, not runtime compliance certification.  [design_only] | Reference only; verify current project licensing before redistribution. No text copied. |
| [Trail of Bits security skills](https://github.com/trailofbits/skills) | 027bc47a69a276c340717bafdc3708263094b9a4; plugins/differential-review/skills/differential-review/SKILL.md and LICENSE | Changed-line evidence, caller/context review, explicit counterarguments and report artifacts. Did not install the plugin, Bash tool permissions or adversarial automation. Original narrowly scoped skills written here. [design_only] | CC-BY-SA-4.0 in inspected commit; no upstream skill files or implementation copied. |
| [Android manifest docs](https://developer.android.com/guide/topics/manifest/manifest-intro) | manifest-intro | SDK/permission/exported declarations and platform-dependent defaults.  [design_only] | Android documentation terms; reference only. |
| [Android network security config](https://developer.android.com/privacy-and-security/security-config) | security-config | Review cleartext/trust-anchor/pin declarations with source context.  [design_only] | Android documentation terms; reference only. |
| [Androguard AXML documentation](https://androguard.readthedocs.io/en/latest/intro/axml.html) | page identifies old 3.4.0 docs; runtime 4.1.4 API inspected separately | Use a real AXML parser; current import path androguard.core.axml verified in installed 4.1.4.  [design_only] | Apache-2.0 project; no documentation copied. |
| [AAPT2 Resources.proto](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/tools/aapt2/Resources.proto) | tools/aapt2/Resources.proto at checked main; content hash recorded | XmlNode/XmlElement/XmlAttribute/Item/Primitive wire field numbers decoded with Google protobuf.  [design_only] | AOSP Apache-2.0 header. Original field projection; no full upstream generated code vendored. |
| [Apple ATS](https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity) | NSAppTransportSecurity | ATS key review; no device/signature/encrypted-code claims.  [design_only] | Apple documentation terms; reference only. |
| [LIEF documentation](https://lief.re/doc/latest/intro.html) | documentation introduction; installed LIEF 1.0.0 | PE/ELF/Mach-O metadata through parser API rather than arbitrary reverse-engineering commands.  [design_only] | Apache-2.0; retain dependency notices. |
| [Playwright network documentation](https://playwright.dev/python/docs/network) | Python network routing docs; installed 1.62.0 | Intercept requests and fulfill from a bounded pinned-IP fetcher; service workers/JS/WebSockets disabled.  [design_only] | Apache-2.0; Chromium bundles have additional third-party licenses. |
| [Python AST documentation](https://docs.python.org/3/library/ast.html) | 3.14 docs ast | Reviewed as possible structural-analysis option; no target imports. Current cross-language rules are lexical; no AST/taint-analysis capability claimed. [design_only] | PSF documentation license; reference only. |
| [Compose specification](https://docs.docker.com/reference/compose-file/) | Compose file reference; CLI v5.5.1 config verification | Named state volumes, read-only bind mounts, internal network, non-root services and optional profiles.  [design_only] | Docs reference only; Compose CLI Apache-2.0. |
| [SPDX SBOM format](https://spdx.github.io/spdx-spec/v2.3/) | v2.3 | Read name/versionInfo inventory only; no full schema-conformance claim.  [design_only] | Specification terms must be checked before text redistribution; no text copied. |
| [CycloneDX SBOM schema](https://github.com/CycloneDX/specification/blob/1.6/schema/bom-1.6.schema.json) | 1.6 schema/bom-1.6.schema.json and LICENSE | Read components name/version inventory; no full BOM-validation claim.  [design_only] | Apache-2.0 schema; referenced but not vendored. |
| [mcp distribution](https://pypi.org/project/mcp/1.30.0/) | 1.30.0 | Pinned base dependency; imported and exercised in local tests.  [python_dependency_not_vendored] | MIT; installed license metadata recorded; retain and review distribution notices before redistribution. |
| [defusedxml distribution](https://pypi.org/project/defusedxml/0.7.1/) | 0.7.1 | Pinned base dependency; imported and exercised in local tests.  [python_dependency_not_vendored] | PSF-2.0; installed license metadata recorded; retain and review distribution notices before redistribution. |
| [PyYAML distribution](https://pypi.org/project/PyYAML/6.0.3/) | 6.0.3 | Pinned base dependency; imported and exercised in local tests.  [python_dependency_not_vendored] | MIT; installed license metadata recorded; retain and review distribution notices before redistribution. |
| [androguard distribution](https://pypi.org/project/androguard/4.1.4/) | 4.1.4 | Pinned platform dependency; imported and exercised in local tests.  [python_dependency_not_vendored] | Apache-2.0; installed license metadata recorded; retain and review distribution notices before redistribution. |
| [lief distribution](https://pypi.org/project/lief/1.0.0/) | 1.0.0 | Pinned platform dependency; imported and exercised in local tests.  [python_dependency_not_vendored] | Apache-2.0; installed license metadata recorded; retain and review distribution notices before redistribution. |
| [cryptography distribution](https://pypi.org/project/cryptography/50.0.1/) | 50.0.1 | Pinned platform dependency; imported and exercised in local tests.  [python_dependency_not_vendored] | Apache-2.0 OR BSD-3-Clause; installed license metadata recorded; retain and review distribution notices before redistribution. |
| [protobuf distribution](https://pypi.org/project/protobuf/7.36.1/) | 7.36.1 | Pinned platform dependency; imported and exercised in local tests.  [python_dependency_not_vendored] | BSD-3-Clause; installed license metadata recorded; retain and review distribution notices before redistribution. |
| [playwright distribution](https://pypi.org/project/playwright/1.62.0/) | 1.62.0 | Pinned web dependency; imported and exercised in local tests.  [python_dependency_not_vendored] | Apache-2.0; installed license metadata recorded; retain and review distribution notices before redistribution. |
| [pytest distribution](https://pypi.org/project/pytest/9.1.1/) | 9.1.1 | Pinned test dependency; imported and exercised in local tests.  [python_dependency_not_vendored] | MIT; installed license metadata recorded; retain and review distribution notices before redistribution. |
| [python Docker base](https://hub.docker.com/_/python) | 3.12.12-slim-bookworm@sha256:593bd06efe90efa80dc4eee3948be7c0fde4134606dd40d8dd8dbcade98e669c | Pinned multi-architecture base manifest verified through registry; Docker build not executed.  [container_build_reference] | Official image contains multiple packages/licenses; full image license/SBOM review still required before public redistribution. |
| [node Docker base](https://hub.docker.com/_/node) | 24.19.0-bookworm-slim@sha256:a9f5f7c91a432850b2a8a7797adf5eadb6c733ceed61167806cee7ea7fbc29df | Pinned multi-architecture base manifest verified through registry; Docker build not executed.  [container_build_reference] | Official image contains multiple packages/licenses; full image license/SBOM review still required before public redistribution. |
| [Compose validation executable](https://github.com/docker/compose/releases/download/v5.5.1/docker-compose-linux-aarch64) | v5.5.1 sha256:732e3a84c1a0f67256ce80bc2598a24546b10ca05f9faa97efceb1171ece2ef7 | Standalone compose config validation; no Docker daemon/build/start performed.  [validation_only] | Apache-2.0; binary used from /tmp and not distributed. |

## 검토 한계

- X/Twitter 게시물을 자료로 사용하지 않았습니다.
- CycloneDX 문서 페이지 접근 실패 후 원본 GitHub 1.6 스키마를 확인했습니다.
- WSTG/MASTG의 시도한 raw 라이선스 경로는 읽지 못했습니다. 문서 원문을 재배포하지 않습니다.
- MCP 최신 주 버전은 2.x입니다. 기존 FastMCP 구조를 유지하기 위해 보안 수정이 유지되는 1.x의 1.30.0을 고정했습니다. 확인한 6개 SDK 권고의 패치 버전보다 높습니다. 향후 권고까지 안전하다는 보장이 아닙니다.
- Androguard ReadTheDocs 페이지는 오래된 3.4.0 예시입니다. 실제 4.1.4의 import/API와 AXML 처리는 설치본 및 합성 바이너리로 검증했습니다.
- 배포 ZIP에는 설치된 의존성/브라우저/이미지/제3자 스킬을 포함하지 않습니다. 이미지 공개 배포 전 의존성 및 기존 원본 소스의 재배포 권한을 별도로 확인해야 합니다.
- 컨테이너 이미지의 전체 패키지 라이선스 목록, Python 3.12/다른 아키텍처의 설치 결과는 아직 검증하지 않았습니다.

## 0.3.0 추가 조사

기존 조사 항목은 유지하며 이번 복원본 확장의 출처를 추가했습니다. 도구 배포물은 저장소에 넣지 않고 고정 URL/크기/SHA-256을 config/tool-downloads.json으로 관리합니다. JDK/JADX/apktool/Ghidra 다운로드 해시는 실제 확인했습니다. Docker 이미지 자체는 빌드하지 않았습니다.

| 항목 | 버전 | 채택/검증 |
|---|---|---|
| [JADX](https://github.com/skylot/jadx/releases/tag/v1.5.6) | 1.5.6 | Fixed snapshot decompilation; actual own synthetic DEX/APK executed. |
| [apktool](https://github.com/iBotPeaches/Apktool/releases/tag/v3.0.3) | 3.0.3 | Optional image utility, no arbitrary MCP runner; downloaded/hash verified on host. |
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.3_build) | 12.1.3 | Fixed HeadlessScript on a fresh project; actual synthetic ELF execution. |
| [Temurin JDK](https://github.com/adoptium/temurin21-binaries/releases/tag/jdk-21.0.12.1%2B1) | 21.0.12.1+1 | Official reviewed Linux arm64/x64 assets; host arm64 installed and executed. |
| [Burp MCP tool declarations](https://github.com/PortSwigger/mcp-server/blob/642e6fa31c63db3886a353fcd7ed62037e0ceed5/src/main/kotlin/net/portswigger/mcp/tools/Tools.kt) | 642e6fa31c63db3886a353fcd7ed62037e0ceed5 | Reviewed history schemas; actual tools/list gate; local mocks only, no host Burp. |
| [GraphQL core](https://pypi.org/project/graphql-core/3.2.12/) | 3.2.12 | Local parse only; argument/default values omitted; remote introspection absent. |
| [Frida](https://pypi.org/project/frida/17.18.0/) | 17.18.0 | Optional minimal host device/process metadata; installed host client, no device validation. |
| [Debian aapt/aapt2](https://packages.debian.org/bookworm/arm64/aapt/filelist) | 1:10.0.0+r36-10 | Optional Android image; verified both executable paths, build not executed. Distro version, not latest Android SDK. |
| [Debian apksigner](https://packages.debian.org/bookworm/apksigner) | 31.0.2-1 | Pinned optional image utility; signature verification not exposed or tested. |
| [Debian adb](https://packages.debian.org/bookworm/adb) | 1:29.0.6-28 | Pinned optional image client to configured host server; no actual device validation. |
| [Playwright persistent context](https://playwright.dev/python/docs/api/class-browsertype#browser-type-launch-persistent-context) | 1.62.0 | Independent persistent profiles; real Chromium local tests. |
| [Playwright WebSocket routing](https://playwright.dev/python/docs/api/class-browsercontext#browser-context-route-web-socket) | 1.62.0 | Fixed bounded opening handshake only; no frames forwarded. |

JADX/apktool/Ghidra의 공식 안정 release와 라이선스를 확인했습니다. Android SDK 도구는 Debian bookworm 패키지 버전이며 최신 Google SDK로 표시하지 않습니다. apktool의 Apache-2.0 선언은 [태그 LICENSE.md](https://github.com/iBotPeaches/Apktool/blob/v3.0.3/LICENSE.md)에서 확인했습니다.

Semgrep은 연동하지 않았습니다. 현재 source 도구는 Python AST, ripgrep literal search, 고정 정적 규칙을 사용합니다. 전체 taint/reachability 분석으로 해석하지 않습니다.
