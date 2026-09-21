# IWANTGOHOME

IWANTGOHOME은 **소스코드를 기반으로 보안 취약점 후보를 탐색하고, 허가된 환경에서 자동으로 검증하는 범용 보안 분석 도구**입니다.

소스코드에서 보안상 의심되는 부분을 찾고, 검증 시나리오를 구성한 뒤 안전한 환경에서 재현하여 결과와 근거를 정리합니다.

## 주요 기능

- 소스코드 기반 취약점 후보 탐색
- 정적 분석 및 후보 분류
- 자동 검증 시나리오 생성
- 정상 동작과 의심 동작 비교
- 기존 공개 취약점 중복 확인
- 버전별 재검증
- 원인별 후보 분류
- 검증 결과 및 근거 저장
- Markdown / JSON 보고서 생성
- 대상별 모듈을 통한 기능 확장

## 설치

처음 한 번만 아래 명령어를 실행합니다.

    git clone https://github.com/Kowntaewook/IWANTGOHOME.git
    cd IWANTGOHOME
    chmod +x scripts/install-command.sh
    ./scripts/install-command.sh

한 줄로 설치하려면:

    git clone https://github.com/Kowntaewook/IWANTGOHOME.git && cd IWANTGOHOME && chmod +x scripts/install-command.sh && ./scripts/install-command.sh

## 실행

설치가 끝난 뒤에는 다음 명령어로 실행할 수 있습니다.

    IWANTTOGOHOME

특정 분석 대상은 별도의 대상 모듈을 연결하여 사용할 수 있습니다.

자동 분석 결과는 확정된 취약점이 아닌 **검토가 필요한 보안 연구 후보**입니다.
