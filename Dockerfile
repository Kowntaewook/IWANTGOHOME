# Base image tags/digests are recorded in sources.lock.json. Docker build unverified here.
FROM python:3.12.12-slim-bookworm@sha256:593bd06efe90efa80dc4eee3948be7c0fde4134606dd40d8dd8dbcade98e669c AS analysis
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /opt/finder
COPY pyproject.toml README.md constraints.txt ./
COPY src ./src
RUN pip install --no-cache-dir -c constraints.txt . && useradd --create-home --uid 1000 analyst \
    && mkdir -p /inputs /results /grants /browser-state && chown analyst:analyst /results /grants /browser-state
COPY config/analysis.json /etc/finder/config.json
COPY config/browser.json /etc/finder/browser.json
USER root
RUN apt-get update && apt-get install -y --no-install-recommends ripgrep \
    && rm -rf /var/lib/apt/lists/*
ENV FINDER_CONFIG=/etc/finder/config.json
USER analyst
ENTRYPOINT ["finder-mcp"]
CMD ["--role", "analysis", "--transport", "streamable-http", "--host", "0.0.0.0"]

FROM analysis AS platform
USER root
RUN pip install --no-cache-dir -c constraints.txt '.[platform]'
USER analyst
CMD ["--role", "platform", "--transport", "streamable-http", "--host", "0.0.0.0"]

FROM platform AS java-tools
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
ENV PATH=/opt/finder-tools/jadx/bin:/opt/finder-tools/java/bin:/usr/local/bin:/usr/bin:/bin
USER analyst
CMD ["--role", "android", "--transport", "streamable-http", "--host", "0.0.0.0"]

FROM java-tools AS binary
RUN python scripts/install_optional_tools.py ghidra
USER analyst
CMD ["--role", "binary", "--transport", "streamable-http", "--host", "0.0.0.0"]

FROM analysis AS android-dynamic
USER root
RUN pip install --no-cache-dir -c constraints.txt '.[device]' \
    && apt-get update && apt-get install -y --no-install-recommends adb=1:29.0.6-28 \
    && rm -rf /var/lib/apt/lists/*
USER analyst
CMD ["--role", "android-dynamic", "--transport", "streamable-http", "--host", "0.0.0.0"]

FROM analysis AS burp
CMD ["--role", "burp", "--transport", "streamable-http", "--host", "0.0.0.0"]

FROM analysis AS browser
USER root
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/playwright
RUN pip install --no-cache-dir -c constraints.txt '.[browser]' && python -m playwright install --with-deps chromium \
    && chmod -R a+rX /opt/playwright && rm -rf /var/lib/apt/lists/*
USER analyst
ENV FINDER_CONFIG=/etc/finder/browser.json
CMD ["--role", "observer", "--transport", "streamable-http", "--host", "0.0.0.0"]

FROM browser AS test
USER root
RUN pip install --no-cache-dir -c constraints.txt '.[platform,test]'
# .dockerignore is an allowlist; the test image also verifies the source ZIP manifest.
COPY . .
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
