# IWANTGOHOME

## 설치

처음 한 번만 아래 명령어를 실행하세요.

```bash
git clone https://github.com/Kowntaewook/IWANTGOHOME.git && cd IWANTGOHOME && chmod +x scripts/install-command.sh && ./scripts/install-command.sh
```

설치 후 `IWANTTOGOHOME` 명령어가 바로 인식되지 않는 경우 아래 명령어를 한 번 실행하세요.

```bash
export PATH="$HOME/.local/bin:$PATH"
```

macOS의 zsh에서 새 터미널을 열어도 자동으로 인식되게 하려면:

```bash
grep -qxF 'export PATH="$HOME/.local/bin:$PATH"' ~/.zshrc || echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

설치 확인:

```bash
which IWANTTOGOHOME
```

정상적으로 설치되었다면 다음과 같이 표시됩니다.

```text
/Users/<username>/.local/bin/IWANTTOGOHOME
```

## 실행

설치가 끝난 뒤에는 어디서든 아래 명령어만 입력하면 됩니다.

```bash
IWANTTOGOHOME
```
