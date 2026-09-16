# 실제 검증 결과

## 2026-09-16 launcher 권한과 noexec 구분

현재 작업본: `/workspace/IWANTGOHOME`. 이번 변경은 `scripts/install_command.py`, `tests/test_upgrade_offline.py`와 이 검증 기록입니다.

기존 installer는 **새 파일에 이미 0755를 설정**하고 있었습니다. 실제 `/dev/shm` 재현 파일도 `stat.S_IMODE=0755`, owner X bit가 설정된 상태였지만 `os.access(path, os.X_OK)=False`였습니다. 읽기 전용으로 확인한 `/proc/mounts`는 다음과 같았습니다:

```text
shm /dev/shm tmpfs rw,nosuid,nodev,noexec,relatime,size=65536k 0 0
```

`os.statvfs`로도 `/dev/shm`의 noexec=True, `/tmp`의 noexec=False를 확인했습니다. 따라서 이 재현의 직접 exec 실패는 파일 mode 누락이 아니라 파일시스템의 noexec였습니다. [noexec 옵션 설명](https://docs.docker.com/engine/storage/tmpfs/#options-for---tmpfs).

별도의 결함으로 동일 내용인 기존 launcher에는 chmod가 적용되지 않아, 복사·복원 후 실행 비트가 사라진 경우 재설치로 복구하지 못했습니다. POSIX에서 새 파일은 0755, 동일 내용의 기존 파일은 기존 mode에 owner execute만 추가하도록 수정했습니다. 예: 0640 → 0740. 복구 후에도 noexec 경로의 X_OK는 False이며 보안 정책은 유지됩니다. 다른 내용의 명령은 내용·mode 모두 보존한 채 거부합니다. .zshrc 내용과 PATH 중복 방지 로직은 변경하지 않았습니다.

권한 검사와 직접 실행 검사를 분리했습니다. 권한 검사는 pytest의 원래 tmp_path에서 mode와 X_OK를 검사합니다. 직접 실행 검사는 mount 상태를 읽어 확인한 별도의 실행 가능한 임시 디렉터리에서 **새 fixture 프로젝트와 새 launcher**를 만들고 subprocess로 직접 실행합니다. 기존 noexec 파일을 인터프리터로 실행하거나 mount를 변경하지 않습니다. 적절한 실행 디렉터리가 없으면 테스트를 실패시키며 skip하지 않습니다. Windows 분기에서는 POSIX chmod를 수행하지 않는다는 mock 검증도 추가했습니다. 실제 Windows 실행 검증은 아닙니다.

### 실행 결과

| 검사 | 결과 |
|---|---|
| 수정 전 기존 단일 테스트, 일반 /tmp | 1 passed |
| 수정 전 같은 테스트, /dev/shm basetemp | PermissionError 재현; 실제 mode 0755 및 noexec 확인 |
| 수정 후 사용자 지정 단일 테스트 | **1 passed**, 0.20초 |
| 수정 후 /dev/shm에서 분리된 권한/실행/Windows 분기 검사 | **3 passed**, 22 deselected, 0.16초 |
| 수정 후 로컬 전체 suite | **229 passed, 2 skipped, 0 failed**, 62.54초 |

스킵 2개는 기존 선택적 JADX/Ghidra 실행 도구가 없는 경우입니다. 이번 변경에서 기존 테스트를 삭제하거나 skip 처리하지 않았습니다. 전체 JUnit 기록은 `/tmp/iwant-launcher-final.xml`입니다.

실행한 pytest 명령:

```sh
/tmp/iwant-program-checks/bin/python -m pytest /workspace/IWANTGOHOME/tests/test_upgrade_offline.py::test_installed_command_works_from_unrelated_directory_without_overwrite -q
/tmp/iwant-program-checks/bin/python -m pytest /workspace/IWANTGOHOME/tests/test_upgrade_offline.py::test_installed_command_works_from_unrelated_directory_without_overwrite -q --basetemp=/dev/shm/iwant-launcher-noexec-repro-856422dc
/tmp/iwant-program-checks/bin/python -m pytest /workspace/IWANTGOHOME/tests/test_upgrade_offline.py -q -k 'installed_command or non_posix_permission or docker_test_tmpfs' --tb=short
/tmp/iwant-program-checks/bin/python -m pytest /workspace/IWANTGOHOME/tests/test_upgrade_offline.py::test_installed_command_works_from_unrelated_directory_without_overwrite -q
/tmp/iwant-program-checks/bin/python -m pytest /workspace/IWANTGOHOME/tests/test_upgrade_offline.py -q -k 'installed_command or installer_permissions or non_posix_permission' --basetemp=/dev/shm/iwant-launcher-noexec-check-856422dc --tb=short
/tmp/iwant-program-checks/bin/python -m pytest -q /workspace/IWANTGOHOME/tests --junitxml=/tmp/iwant-launcher-final.xml
```

중간 회귀 검사는 수정 전 누락을 확인하기 위해 3개 실패를 확인했습니다. 이때 준비했던 Docker exec mount 기대 검사는 사용자의 보안 설정 유지 지시에 따라 적용하지 않았고, 권한/직접 실행을 분리하는 검사로 대체했습니다. Dockerfile/docker-compose와 mount 옵션은 이번 작업에서 변경하지 않았습니다. 사용자의 수정 지시에 따라 Docker 실행은 생략했습니다.

Docker CLI unavailable in this environment; host validation required

Git push와 인증/증거/볼륨 삭제는 수행하지 않았습니다.

## 이전 검증 기록

검증일: **2026-09-15**, Linux arm64, Python 3.14.6. 기준 작업본은 /workspace/something_finder입니다. 이전 ZIP을 사용하지 않았습니다.

## 테스트

| 실행 | 결과 |
|---|---|
| 복원 직후 기존 테스트 | **109 passed**, 21.56초 |
| 전체 회귀 + 새 기능 테스트 | **153 passed**, 64.80초 |
| 이후 추가한 IPA 내부 Mach-O view 테스트 | **1 passed**, 1.19초 |
| 서로 다른 통과 case 합계 | **154개**, 기존 109개 모두 유지 |

전체 suite는 아래 명령으로 실행했습니다. 마지막 iOS 검사는 별도 실행이므로 전체 suite 한 번에서 154개가 실행됐다고 표시하지 않습니다.

```sh
FINDER_TOOL_ROOT=/tmp/finder-tools /tmp/finder-venv/bin/python -m pytest -q --junitxml=/tmp/finder-upgrade-final.xml
/tmp/finder-venv/bin/python -m pytest -q tests/test_upgrade_offline.py -k ios_macho --junitxml=/tmp/finder-ios-macho-final.xml
```

개별 case/time, 환경 버전, 테스트한 구현 파일 해시는 [validation-results.json](validation-results.json)에 저장했습니다.

## 실제 실행한 경계·통합 검증

- 공식 MCP SDK initialize/tools/list/call: stdio/HTTP, analysis/platform/observer 및 android/binary/android-dynamic/burp 역할.
- 실제 Chromium: anonymous/user_a/user_b 분리, 재시작 후 cookies/localStorage, 여러 Set-Cookie 유지, 자격증명/본문 값 제외.
- 로컬 SPA: navigation, fetch/XHR, GraphQL 구조, iframe/script, SSE snapshot, WebSocket opening handshake.
- 서버가 실제 받은 경로 확인: 범위/제외 우선, redirect 차단, private 기본 차단, origin 간 credential 제거, 미승인 POST 차단.
- 세션 요청 수/응답 바이트, rate/concurrency/runtime 예산, pause/resume, abort 완료 후 후속 전송 차단.
- Burp 대체 로컬 MCP: **SSE와 Streamable HTTP**, 실제 discovery/history, 부재/미지원 기능, 비밀값 제외.
- Android malformed APK/AAB, iOS malformed IPA/plist, binary oversized/세 포맷, source path/symlink escape.
- 실제 JADX 1.5.6: 테스트가 작성한 고정 Java만 javac/D8로 DEX화해 합성 APK 생성 후 디컴파일. 제출된 프로젝트 코드는 빌드/실행하지 않았습니다.
- 실제 Ghidra 12.1.3: 합성 ELF, 고정 HeadlessScript의 format/function/symbol/timeout metadata. 대상 실행 없음.
- ADB/Frida는 고정 명령/최소화 mock과 미연결 HOST_ADAPTER_REQUIRED. **실제 장치 검증이 아닙니다.**
- 기존 불변 기록, 8개 후보 상태/CONFIRMED 거부, 배포 allowlist와 기존 설정/인증 합성 바이트 보존.

## 추가 검증

| 항목 | 실행/결과 |
|---|---|
| Codex 0.154.0 | scripts/check_codex.py: strict config, 7 MCP 등록, 실제 skills/list로 18개 발견 |
| Skill 형식 | skill-creator quick_validate 18개 통과; registry와 실제 tool dependency 대조 |
| Compose 5.5.1 | /tmp/finder-compose --profile '*' config --format json, 10개 서비스 해석; tmpfs 옵션 확인 |
| README 설치 진입점 | scripts/install-command.sh를 임시 bin/셸 설정에 두 번 실행, 기존 내용과 PATH 1회 추가 확인 |
| 셸/소스 문법 | sh -n으로 scripts/docker .sh 검사, 배포 Python 파일 AST 파싱 |
| Python 설치/의존성 | 현재 0.3.0 editable 설치, pip check 통과 |
| 소스 비교 | 복원본의 89개 파일 스냅샷과 비교; .git이 없어 git diff check를 실행했다고 주장하지 않음 |

editable 설치 첫 시도는 --no-build-isolation 환경에 setuptools가 없어 실패했습니다. pyproject의 고정 build dependencies를 사용하는 기본 build isolation으로 다시 설치해 성공했습니다. 최종 의존성 검사는 통과했습니다.

최종 문서/배포 목록 정리 후 distribution/skills 7개를 다시 실행해 0.96초에 통과했습니다. README는 사용자 지정 문자열과 정확히 일치하고, 스키마는 현재 registry와 같으며 테스트한 구현 파일 해시도 일치합니다.

## 실행하지 않은 것

Docker CLI/daemon이 없어 **이미지 build/up/run과 실제 named volume 지속성**은 검증하지 못했습니다. 실제 ChatGPT 로그인/갱신/계정 모델 권한, Mac/Windows 명령 실행, 실제 Burp, Android 장치/emulator/Frida 서버 연결, 실제 모델의 스킬 선택/보고 품질 평가도 실행하지 않았습니다.

제3자 대상 사이트 테스트, 대상 실행파일/앱 실행, 공격 재현, 외부 push/보고 제출은 수행하지 않았습니다. 위의 mock/파서/설정 검증으로 이를 대신 검증했다고 주장하지 않습니다.
