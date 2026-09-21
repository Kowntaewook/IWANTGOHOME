# IWANTGOHOME

IWANTGOHOME은 **허가된 로컬·Self-hosted 환경에서 OSS 보안 취약점을 자동으로 탐색하고 검증하기 위한 범용 Vulnerability Hunting Framework**입니다.

소스코드에서 보안 후보를 탐색하고, 로컬 Docker 환경에서 안전하게 재현한 뒤 중복 조사, 버전 재검증, Root Cause 분류 및 보고서 생성을 수행합니다.

현재 **Gitea**와 **Mattermost**를 지원하며, 각 제품은 동일한 Generic Full-Hunt Engine 위에서 Target Adapter 형태로 동작합니다.

주요 기능:

- Source 기반 취약점 후보 자동 탐색
- Static Triage
- localhost 전용 안전한 Local Validation
- Control / Probe 기반 취약점 검증
- 자동 Scenario Synthesis
- 공개 자료 기반 Duplicate Research
- Root Cause Clustering
- Pinned / Latest / Upstream Main 재검증
- Version Matrix 및 Evidence 생성
- Markdown / JSON 보고서 생성
- Target Adapter 기반 다중 OSS 지원

> 실제 보안 검증은 승인된 로컬 또는 Self-hosted 환경에서만 수행하도록 설계되어 있습니다.

---

## 설치

처음 한 번만 아래 명령어를 실행합니다.

```bash
git clone https://github.com/Kowntaewook/IWANTGOHOME.git
cd IWANTGOHOME
chmod +x scripts/install-command.sh
./scripts/install-command.sh
