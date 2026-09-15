# 합성 예제

`make_fixtures.py`가 만든 `synthetic/`만 테스트/배포에 사용합니다. APK/AAB의 DEX와
PE/ELF/Mach-O payload는 실행 가능한 프로그램 테스트가 아니며 도구는 실행하지 않습니다.
독립 생성한 AXML/protobuf/컨테이너 헤더의 파싱과 메타데이터 추출을 검증합니다.
파일 재생성은 다른 내용의 기존 파일을 덮어쓰지 않습니다.

기본 Compose 입력은 `examples/`입니다. 따라서 MCP 경로는
`synthetic/sample.har`, `synthetic/sample.apk`, `synthetic/sample.ipa`,
`synthetic/sample.exe`, `synthetic/review.js` 등입니다.

`web-plan.json`은 네이티브 루프백 예시로 자동 승인이 아닙니다. 실제 로컬 mock
서버와 승인/차단 테스트는 `tests/test_web.py`에서 임시 디렉터리를 사용합니다.
외부 사이트나 기존 사용자 연구 데이터는 테스트에 사용하지 않습니다.
