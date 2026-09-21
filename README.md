# IWANTGOHOME

IWANTGOHOME은 **허가된 로컬 또는 자체 구축 환경에서 오픈소스 소프트웨어의 보안 취약점 후보를 자동으로 탐색하고 검증하기 위한 범용 보안 분석 도구**입니다.

소스코드를 분석해 보안상 의심되는 부분을 찾고, 로컬 Docker 환경에서 안전하게 재현한 뒤 중복 여부 확인, 버전별 재검증, 원인 분류, 결과 보고서 생성을 수행합니다.

현재 **Gitea**와 **Mattermost**를 지원합니다.

주요 기능:

- 소스코드 기반 취약점 후보 탐색
- 정적 분석 및 후보 분류
- 로컬 환경에서 안전한 검증
- 정상 동작과 의심 동작 비교
- 자동 검증 시나리오 생성
- 공개 자료를 이용한 기존 취약점 중복 확인
- 원인별 후보 묶음 처리
- 고정 버전 / 최신 버전 / 개발 중 버전 재검증
- 검증 근거 및 버전별 결과 기록
- Markdown / JSON 형식의 보고서 생성
- 대상별 모듈 구조를 이용한 여러 오픈소스 지원

> 실제 보안 검증은 사용 권한이 있는 로컬 또는 자체 구축 환경에서만 수행하도록 설계되어 있습니다.

---

## 설치

처음 한 번만 아래 명령어를 실행합니다.

```bash
git clone https://github.com/Kowntaewook/IWANTGOHOME.git
cd IWANTGOHOME
chmod +x scripts/install-command.sh
./scripts/install-command.sh
