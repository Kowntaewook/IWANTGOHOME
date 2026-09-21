# Base image tags/digests are recorded in sources.lock.json. Docker build unverified here.
FROM python:3.12.12-slim-bookworm@sha256:593bd06efe90efa80dc4eee3948be7c0fde4134606dd40d8dd8dbcade98e669c AS runtime-deps
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /opt/finder

# Dependency metadata changes invalidate installs; ordinary src changes do not.
COPY pyproject.toml README.md constraints.txt ./
RUN python -c "import subprocess,sys,tomllib; p=tomllib.load(open('pyproject.toml','rb')); subprocess.check_call([sys.executable,'-m','pip','install','--no-cache-dir','-c','constraints.txt','setuptools==80.9.0','wheel==0.45.1',*p['project']['dependencies']])" \
    && apt-get update && apt-get install -y --no-install-recommends ripgrep \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 analyst \
    && mkdir -p /inputs /results /grants /browser-state /programs \
    && chown analyst:analyst /results /grants /browser-state

FROM runtime-deps AS analysis
COPY src ./src
RUN pip install --no-cache-dir --no-deps --no-build-isolation .
COPY config/analysis.json /etc/finder/config.json
COPY config/browser.json /etc/finder/browser.json
ENV FINDER_CONFIG=/etc/finder/config.json
USER analyst
ENTRYPOINT ["finder-mcp"]
CMD ["--role", "analysis", "--transport", "streamable-http", "--host", "0.0.0.0"]

FROM runtime-deps AS platform-deps
RUN python -c "import subprocess,sys,tomllib; p=tomllib.load(open('pyproject.toml','rb')); subprocess.check_call([sys.executable,'-m','pip','install','--no-cache-dir','-c','constraints.txt',*p['project']['optional-dependencies']['platform']])"

FROM platform-deps AS platform
COPY src ./src
RUN pip install --no-cache-dir --no-deps --no-build-isolation .
COPY config/analysis.json /etc/finder/config.json
COPY config/browser.json /etc/finder/browser.json
ENV FINDER_CONFIG=/etc/finder/config.json
USER analyst
ENTRYPOINT ["finder-mcp"]
CMD ["--role", "platform", "--transport", "streamable-http", "--host", "0.0.0.0"]

FROM platform-deps AS java-tools
USER root
COPY scripts/install_optional_tools.py ./scripts/install_optional_tools.py
COPY config/tool-downloads.json ./config/tool-downloads.json
RUN apt-get update && apt-get install -y --no-install-recommends bash ca-certificates fontconfig libfreetype6 \
    && rm -rf /var/lib/apt/lists/* \
    && python scripts/install_optional_tools.py java
ENV JAVA_HOME=/opt/finder-tools/java PATH=/opt/finder-tools/java/bin:/usr/local/bin:/usr/bin:/bin

FROM java-tools AS android
RUN python scripts/install_optional_tools.py jadx \
    && python scripts/install_optional_tools.py apktool \
    && apt-get update && apt-get install -y --no-install-recommends aapt=1:10.0.0+r36-10 apksigner=31.0.2-1 \
    && rm -rf /var/lib/apt/lists/*
COPY docker/apktool.sh /usr/local/bin/apktool
RUN chmod +x /usr/local/bin/apktool
COPY src ./src
RUN pip install --no-cache-dir --no-deps --no-build-isolation .
COPY config/analysis.json /etc/finder/config.json
COPY config/browser.json /etc/finder/browser.json
ENV FINDER_CONFIG=/etc/finder/config.json
ENV PATH=/opt/finder-tools/jadx/bin:/opt/finder-tools/java/bin:/usr/local/bin:/usr/bin:/bin
USER analyst
ENTRYPOINT ["finder-mcp"]
CMD ["--role", "android", "--transport", "streamable-http", "--host", "0.0.0.0"]

FROM java-tools AS binary
RUN python scripts/install_optional_tools.py ghidra
COPY src ./src
RUN pip install --no-cache-dir --no-deps --no-build-isolation .
COPY config/analysis.json /etc/finder/config.json
COPY config/browser.json /etc/finder/browser.json
ENV FINDER_CONFIG=/etc/finder/config.json
USER analyst
ENTRYPOINT ["finder-mcp"]
CMD ["--role", "binary", "--transport", "streamable-http", "--host", "0.0.0.0"]

FROM runtime-deps AS device-deps
RUN python -c "import subprocess,sys,tomllib; p=tomllib.load(open('pyproject.toml','rb')); subprocess.check_call([sys.executable,'-m','pip','install','--no-cache-dir','-c','constraints.txt',*p['project']['optional-dependencies']['device']])" \
    && apt-get update && apt-get install -y --no-install-recommends adb=1:29.0.6-28 \
    && rm -rf /var/lib/apt/lists/*

FROM device-deps AS android-dynamic
COPY src ./src
RUN pip install --no-cache-dir --no-deps --no-build-isolation .
COPY config/analysis.json /etc/finder/config.json
COPY config/browser.json /etc/finder/browser.json
ENV FINDER_CONFIG=/etc/finder/config.json
USER analyst
ENTRYPOINT ["finder-mcp"]
CMD ["--role", "android-dynamic", "--transport", "streamable-http", "--host", "0.0.0.0"]

FROM analysis AS burp
CMD ["--role", "burp", "--transport", "streamable-http", "--host", "0.0.0.0"]

FROM runtime-deps AS browser-deps
USER root
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/playwright
RUN python -c "import subprocess,sys,tomllib; p=tomllib.load(open('pyproject.toml','rb')); subprocess.check_call([sys.executable,'-m','pip','install','--no-cache-dir','-c','constraints.txt',*p['project']['optional-dependencies']['browser']])" \
    && python -m playwright install --with-deps chromium \
    && chmod -R a+rX /opt/playwright && rm -rf /var/lib/apt/lists/*

FROM browser-deps AS browser
COPY src ./src
RUN pip install --no-cache-dir --no-deps --no-build-isolation .
COPY config/analysis.json /etc/finder/config.json
COPY config/browser.json /etc/finder/browser.json
ENV FINDER_CONFIG=/etc/finder/browser.json
USER analyst
ENTRYPOINT ["finder-mcp"]
CMD ["--role", "observer", "--transport", "streamable-http", "--host", "0.0.0.0"]

FROM browser-deps AS test-deps
RUN python -c "import subprocess,sys,tomllib; p=tomllib.load(open('pyproject.toml','rb')); extras=p['project']['optional-dependencies']; subprocess.check_call([sys.executable,'-m','pip','install','--no-cache-dir','-c','constraints.txt',*extras['platform'],*extras['test']])"

FROM test-deps AS test
COPY src ./src
RUN pip install --no-cache-dir --no-deps --no-build-isolation .
# .dockerignore is an allowlist; the test image also verifies the source ZIP manifest.
COPY . .
COPY config/analysis.json /etc/finder/config.json
COPY config/browser.json /etc/finder/browser.json
USER analyst
ENV PYTEST_ADDOPTS="-p no:cacheprovider"
ENTRYPOINT ["python", "-m", "pytest"]
CMD ["-q", "tests"]

FROM node:24.19.0-bookworm-slim@sha256:a9f5f7c91a432850b2a8a7797adf5eadb6c733ceed61167806cee7ea7fbc29df AS codex
RUN apt-get update && apt-get install -y --no-install-recommends python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && npm install --global @openai/codex@0.154.0 \
    && npm cache clean --force
COPY config/codex.toml /opt/finder/config/codex.toml
COPY docker/entrypoint.sh /usr/local/bin/finder-entrypoint
COPY docker/runtime.py /opt/finder/docker/runtime.py
COPY .agents/skills /etc/codex/skills
COPY AGENTS.md /work/AGENTS.md
COPY prompts /work/prompts
RUN chmod +x /usr/local/bin/finder-entrypoint && mkdir -p /home/node/.codex \
    && chown node:node /home/node/.codex
ENV CODEX_HOME=/home/node/.codex RUST_LOG=off
USER node
WORKDIR /work
ENTRYPOINT ["finder-entrypoint"]
CMD ["run"]
