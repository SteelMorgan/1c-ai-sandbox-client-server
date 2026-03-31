##
## 1C-enabled devcontainer image.
## - Downloads 1C platform installer at build time (BuildKit secrets)
## - Installs full client + admin tools (ibcmd/ibsrv)
## - Provides headless execution via xvfb-run
## - Adds community activation script
##

FROM sleemp/onec-installer-downloader:latest AS downloader

ARG ONEC_VERSION
# Fallback: read ONEC_VERSION from infra/vm/.env if arg is not passed (Dev Containers build).
COPY infra/vm/.env /tmp/infra.env
RUN set -eux; \
  if [ -z "${ONEC_VERSION:-}" ]; then \
    ONEC_VERSION="$(grep -E '^ONEC_VERSION=' /tmp/infra.env | head -n1 | cut -d= -f2- | tr -d '\r' || true)"; \
  fi; \
  : "${ONEC_VERSION:?ONEC_VERSION is required (pass build arg or set infra/vm/.env)}"; \
  printf "%s" "$ONEC_VERSION" >/tmp/ONEC_VERSION

# Prefer local installer if present, else download via BuildKit secrets.
# Local path (inside build context): .devcontainer/distr/setup-full-${ONEC_VERSION}*.run
# Output (regular FS): /tmp/out/Platform83/${ONEC_VERSION}
RUN --mount=type=bind,source=.devcontainer/distr,target=/tmp/local-distr,readonly \
    --mount=type=secret,id=onec_username,required=false \
    --mount=type=secret,id=onec_password,required=false \
    --mount=type=cache,target=/tmp/downloads \
    set -eux; \
    ONEC_VERSION="$(cat /tmp/ONEC_VERSION)"; \
    mkdir -p "/tmp/out/Platform83/${ONEC_VERSION}"; \
    if ls "/tmp/local-distr/setup-full-${ONEC_VERSION}"*.run >/dev/null 2>&1; then \
      echo "[INFO] Using local installer from .devcontainer/distr"; \
      cp -a "/tmp/local-distr/setup-full-${ONEC_VERSION}"*.run "/tmp/out/Platform83/${ONEC_VERSION}/"; \
    else \
      echo "[INFO] Local installer not found. Downloading from releases.1c.ru"; \
      test -f /run/secrets/onec_username && test -f /run/secrets/onec_password; \
      export YARD_RELEASES_USER="$(cat /run/secrets/onec_username)"; \
      export YARD_RELEASES_PWD="$(cat /run/secrets/onec_password)"; \
      /app/downloader.sh server "${ONEC_VERSION}"; \
      # IMPORTANT: /tmp/downloads is a cache mount -> copy artifacts into image FS
      cp -a "/tmp/downloads/Platform83/${ONEC_VERSION}/." "/tmp/out/Platform83/${ONEC_VERSION}/"; \
    fi

FROM mcr.microsoft.com/devcontainers/base:ubuntu-24.04

USER root
ARG DEBIAN_FRONTEND=noninteractive
ARG ONEC_VERSION
ENV ONESCRIPT_VERSION="2.0.0" \
    VANESSAEXT_VERSION="1.3.9.95" \
    ALLURE_VERSION="2.37.0" \
    IMAGEMAGICK_VERSION="7.1.2-15"

# Base sandbox tooling (keep aligned with .devcontainer/Dockerfile)
RUN apt-get update \
  -o Acquire::ForceIPv4=true -o Acquire::Retries=3 \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    openssh-client \
    gnupg \
    sudo \
    python3 \
    python3-pip \
    python3-venv \
    nodejs \
    tmux \
    npm \
    unzip \
  && rm -rf /var/lib/apt/lists/*

# Passwordless sudo for vscode (enabled only when container is started without no-new-privileges).
RUN echo "vscode ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/vscode \
  && chmod 0440 /etc/sudoers.d/vscode

# GitHub CLI (gh)
RUN set -eux; \
  mkdir -p /etc/apt/keyrings; \
  curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
    | gpg --dearmor -o /etc/apt/keyrings/githubcli-archive-keyring.gpg; \
  chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg; \
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
    > /etc/apt/sources.list.d/github-cli.list; \
  apt-get update -o Acquire::ForceIPv4=true -o Acquire::Retries=3; \
  apt-get install -y --no-install-recommends gh; \
  rm -rf /var/lib/apt/lists/*

# Docker CLI (client only). Required if we mount docker.sock into the sandbox.
RUN set -eux; \
  mkdir -p /etc/apt/keyrings; \
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg; \
  chmod a+r /etc/apt/keyrings/docker.gpg; \
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
    > /etc/apt/sources.list.d/docker.list; \
  apt-get update -o Acquire::ForceIPv4=true -o Acquire::Retries=3; \
  apt-get install -y --no-install-recommends \
    docker-ce-cli \
    docker-compose-plugin \
    docker-buildx-plugin; \
  rm -rf /var/lib/apt/lists/*

# 1C runtime deps + headless display
RUN apt-get update \
  -o Acquire::ForceIPv4=true -o Acquire::Retries=3 \
  && echo "ttf-mscorefonts-installer msttcorefonts/accepted-mscorefonts-eula select true" | debconf-set-selections \
  && apt-get install -y --no-install-recommends \
    locales \
    net-tools \
    iproute2 \
    openjdk-21-jdk \
    openjdk-17-jdk \
    gradle \
    xvfb \
    x11vnc \
    novnc \
    websockify \
    dbus-x11 \
    xauth \
    ffmpeg \
    ghostscript \
    wmctrl \
    x11-utils \
    libglib2.0-0 \
    libgsf-1-114 \
    libwebkit2gtk-4.1-0 \
    libfontconfig1 \
    libfreetype6 \
    libcups2 \
    libsm6 \
    libx11-6 \
    libxext6 \
    libxrender1 \
    libxtst6 \
    libxi6 \
    libxinerama1 \
    libxrandr2 \
    libatk1.0-0 \
    libgtk-3-0 \
    libglu1-mesa \
    libodbc2 \
    fonts-dejavu \
    fonts-liberation \
    ttf-mscorefonts-installer \
  && fc-cache -f \
  && locale-gen ru_RU.UTF-8 \
  && update-locale LANG=ru_RU.UTF-8 LC_ALL=ru_RU.UTF-8 LC_CTYPE=ru_RU.UTF-8 LANGUAGE=ru_RU:ru \
  && rm -rf /var/lib/apt/lists/*

# Lightweight QA tooling that does not depend on OneScript.
RUN set -eux; \
  apt-get update -o Acquire::ForceIPv4=true -o Acquire::Retries=3; \
  apt-get install -y --no-install-recommends \
    xdotool; \
  mkdir -p "/opt/vanessaext/${VANESSAEXT_VERSION}"; \
  curl -fsSLo /tmp/AddIn.zip \
    "https://github.com/lintest/VanessaExt/releases/download/${VANESSAEXT_VERSION}/AddIn.zip"; \
  unzip -q /tmp/AddIn.zip -d "/opt/vanessaext/${VANESSAEXT_VERSION}"; \
  curl -fsSLo "/opt/vanessaext/${VANESSAEXT_VERSION}/VanessaExt.epf" \
    "https://github.com/lintest/VanessaExt/releases/download/${VANESSAEXT_VERSION}/VanessaExt.epf"; \
  curl -fsSLo /tmp/allure.deb \
    "https://github.com/allure-framework/allure2/releases/download/${ALLURE_VERSION}/allure_${ALLURE_VERSION}-1_all.deb"; \
  apt-get install -y --no-install-recommends /tmp/allure.deb; \
  rm -rf /tmp/AddIn.zip /tmp/allure.deb; \
  rm -rf /var/lib/apt/lists/*; \
  allure --version; \
  xdotool --version; \
  find /opt/vanessaext -maxdepth 2 -type f | sort

# For Gradle builds inside the container.
ENV JAVA_HOME="/usr/lib/jvm/java-21-openjdk-amd64" \
    JAVA_HOME_21="/usr/lib/jvm/java-21-openjdk-amd64" \
    JAVA_HOME_17="/usr/lib/jvm/java-17-openjdk-amd64"

# Prepare distribution payload (copy whole Platform83 tree to avoid relying on ARG expansion)
COPY --from=downloader /tmp/out/Platform83/ /tmp/downloads/Platform83/

# Install platform (client_full + server_admin for ibcmd/ibsrv)
COPY ./onec-client/scripts/onec-install.sh /onec-install.sh
COPY infra/vm/.env /tmp/infra.env
RUN set -eux; \
  if [ -z "${ONEC_VERSION:-}" ]; then \
    ONEC_VERSION="$(grep -E '^ONEC_VERSION=' /tmp/infra.env | head -n1 | cut -d= -f2- | tr -d '\r' || true)"; \
  fi; \
  : "${ONEC_VERSION:?ONEC_VERSION is required (pass build arg or set infra/vm/.env)}"; \
  cd "/tmp/downloads/Platform83/${ONEC_VERSION}"; \
  sed -i 's/\r$//' /onec-install.sh \
  && chmod +x /onec-install.sh \
  && installer_type=client nls=false /onec-install.sh \
  && rm -f /onec-install.sh \
  && rm -rf /tmp/downloads

# Create /opt/1cv8/current symlink to simplify PATH
RUN set -eux; \
  if [ -d "/opt/1cv8/x86_64" ]; then arch_dir="x86_64"; \
  elif [ -d "/opt/1cv8/amd64" ]; then arch_dir="amd64"; \
  else arch_dir="$(ls -1 /opt/1cv8 | grep -E 'x86_64|amd64' | head -n1 || true)"; fi; \
  [ -n "${arch_dir:-}" ]; \
  ver="${ONEC_VERSION:-}"; \
  if [ -z "${ver:-}" ] && [ -f /tmp/infra.env ]; then \
    ver="$(grep -E '^ONEC_VERSION=' /tmp/infra.env | head -n1 | cut -d= -f2- | tr -d '\r' || true)"; \
  fi; \
  if [ -z "${ver:-}" ]; then \
    ver="$(ls -1 "/opt/1cv8/${arch_dir}" 2>/dev/null | sort -V | tail -n1 || true)"; \
  fi; \
  : "${ver:?Failed to determine installed 1C version}"; \
  ln -sfn "/opt/1cv8/${arch_dir}/${ver}" /opt/1cv8/current

ENV LANG="ru_RU.UTF-8" \
    LC_ALL="ru_RU.UTF-8" \
    LC_CTYPE="ru_RU.UTF-8" \
    LANGUAGE="ru_RU:ru"

ENV PATH="/opt/1cv8/current:${PATH}"

# Ensure standard 1C user/group exist (activation scripts use them)
RUN set -eux; \
  if ! getent group grp1cv8 >/dev/null 2>&1; then groupadd -r grp1cv8 --gid 1001; fi; \
  if ! id -u usr1cv8 >/dev/null 2>&1; then useradd -r -g grp1cv8 --uid 1001 -m --home-dir /home/usr1cv8 --shell /bin/bash usr1cv8; fi; \
  mkdir -p /home/usr1cv8/.1cv8 /var/1C/licenses; \
  chown -R usr1cv8:grp1cv8 /home/usr1cv8 /var/1C/licenses || true

# Community activation payload + script
COPY ./onec-client/ActivateCommunity.epf /opt/onec-client/ActivateCommunity.epf
COPY ./.devcontainer/onec-activate-community.sh /usr/local/bin/onec-activate-community.sh
RUN sed -i 's/\r$//' /usr/local/bin/onec-activate-community.sh \
  && chmod +x /usr/local/bin/onec-activate-community.sh

# AI CLI agents for agent workflows inside the sandbox.
# Files are organised under cli-agents/{claude,codex,gemini}/ in the repo.
RUN npm install -g @anthropic-ai/claude-code
RUN npm install -g @openai/codex
RUN npm install -g @google/gemini-cli

# Grant vscode ownership of global npm/node directories so it can update packages without sudo.
# Paths differ by Node install (e.g. /usr/local/lib/node_modules vs /usr/lib/node_modules) — chown only if present.
RUN usermod -aG staff,root vscode \
  && for d in /usr/lib/node_modules /usr/local/lib/node_modules \
      /usr/local/lib /usr/local/bin /usr/local/share /usr/local/include /usr/local; do \
    [ -d "$d" ] && chown -R vscode:vscode "$d" || true; \
  done

# Bootstrap scripts live in image (workspace is a volume and may be empty at first start)
RUN mkdir -p /usr/local/share/agent-sandbox/cli-agents/claude/tools \
             /usr/local/share/agent-sandbox/cli-agents/codex \
             /usr/local/share/agent-sandbox/cli-agents/gemini
COPY ./.devcontainer/postCreateCommand.sh           /usr/local/share/agent-sandbox/postCreateCommand.sh
COPY ./.devcontainer/entrypoint.sh                  /usr/local/share/agent-sandbox/entrypoint.sh
COPY ./.devcontainer/sync-onec-infra-hosts.sh       /usr/local/share/agent-sandbox/sync-onec-infra-hosts.sh
COPY ./.devcontainer/gh-auth-bootstrap.sh            /usr/local/share/agent-sandbox/gh-auth-bootstrap.sh
COPY ./.devcontainer/cli-agents/claude/helper.mjs            /usr/local/share/agent-sandbox/cli-agents/claude/helper.mjs
COPY ./.devcontainer/cli-agents/claude/bootstrap.sh          /usr/local/share/agent-sandbox/cli-agents/claude/bootstrap.sh
COPY ./.devcontainer/cli-agents/claude/tools/claude-safe.sh  /usr/local/share/agent-sandbox/cli-agents/claude/tools/claude-safe.sh
COPY ./.devcontainer/cli-agents/claude/tools/statusline.js   /usr/local/share/agent-sandbox/cli-agents/claude/tools/statusline.js
COPY ./.devcontainer/cli-agents/codex/bootstrap.sh           /usr/local/share/agent-sandbox/cli-agents/codex/bootstrap.sh
COPY ./.devcontainer/cli-agents/codex/model-map.json         /usr/local/share/agent-sandbox/cli-agents/codex/model-map.json
COPY ./.devcontainer/cli-agents/codex/model-overrides.json   /usr/local/share/agent-sandbox/cli-agents/codex/model-overrides.json
COPY ./.devcontainer/cli-agents/gemini/bootstrap.sh          /usr/local/share/agent-sandbox/cli-agents/gemini/bootstrap.sh
COPY ./.devcontainer/bin/agent-new-branch      /usr/local/bin/agent-new-branch
COPY ./.devcontainer/bin/agent-task-branch     /usr/local/bin/agent-task-branch
COPY ./.devcontainer/bin/agent-merge-to-agent  /usr/local/bin/agent-merge-to-agent
COPY ./.devcontainer/bin/agent-open-pr         /usr/local/bin/agent-open-pr
RUN sed -i 's/\r$//' \
      /usr/local/share/agent-sandbox/postCreateCommand.sh \
      /usr/local/share/agent-sandbox/entrypoint.sh \
      /usr/local/share/agent-sandbox/sync-onec-infra-hosts.sh \
      /usr/local/share/agent-sandbox/gh-auth-bootstrap.sh \
      /usr/local/share/agent-sandbox/cli-agents/claude/bootstrap.sh \
      /usr/local/share/agent-sandbox/cli-agents/codex/bootstrap.sh \
      /usr/local/share/agent-sandbox/cli-agents/gemini/bootstrap.sh \
      /usr/local/share/agent-sandbox/cli-agents/claude/tools/claude-safe.sh \
      /usr/local/share/agent-sandbox/cli-agents/claude/tools/statusline.js \
      /usr/local/bin/agent-new-branch \
      /usr/local/bin/agent-task-branch \
      /usr/local/bin/agent-merge-to-agent \
      /usr/local/bin/agent-open-pr \
  && chmod 0555 \
      /usr/local/bin/agent-new-branch \
      /usr/local/bin/agent-task-branch \
      /usr/local/bin/agent-merge-to-agent \
      /usr/local/bin/agent-open-pr \
  && chmod +x \
      /usr/local/share/agent-sandbox/postCreateCommand.sh \
      /usr/local/share/agent-sandbox/entrypoint.sh \
      /usr/local/share/agent-sandbox/sync-onec-infra-hosts.sh \
      /usr/local/share/agent-sandbox/gh-auth-bootstrap.sh \
      /usr/local/share/agent-sandbox/cli-agents/claude/bootstrap.sh \
      /usr/local/share/agent-sandbox/cli-agents/codex/bootstrap.sh \
      /usr/local/share/agent-sandbox/cli-agents/gemini/bootstrap.sh \
      /usr/local/share/agent-sandbox/cli-agents/claude/tools/claude-safe.sh

ENTRYPOINT ["/usr/local/share/agent-sandbox/entrypoint.sh"]
USER root
CMD ["sleep", "infinity"]
