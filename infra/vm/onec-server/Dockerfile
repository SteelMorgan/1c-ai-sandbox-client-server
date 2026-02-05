##
## 1C server image (cluster + RAS) built from local installer when available.
## - Prefers local installer from .devcontainer/distr (setup-full-${ONEC_VERSION}*.run)
## - Installs server + admin tools (rac) for automation
## - Includes community activation script (optional; no-op if secrets not provided)
##

FROM sleemp/onec-installer-downloader:latest AS downloader

ARG ONEC_VERSION
RUN : "${ONEC_VERSION:?ONEC_VERSION argument is required}"

# Prefer local installer if present, else download via BuildKit secrets.
# Local path (inside build context): .devcontainer/distr/setup-full-${ONEC_VERSION}*.run
# Output (regular FS): /tmp/out/Platform83/${ONEC_VERSION}
RUN --mount=type=bind,source=.devcontainer/distr,target=/tmp/local-distr,readonly \
    --mount=type=secret,id=onec_username,required=false \
    --mount=type=secret,id=onec_password,required=false \
    --mount=type=cache,target=/tmp/downloads \
    set -eux; \
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

FROM ubuntu:24.04 AS server
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

USER root
ARG DEBIAN_FRONTEND=noninteractive
ARG ONEC_VERSION
ENV ONEC_VERSION="${ONEC_VERSION}"

# Runtime deps + tools for automation/healthchecks
RUN apt-get update -o Acquire::ForceIPv4=true -o Acquire::Retries=3 \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    locales \
    net-tools \
    iproute2 \
    procps \
    python3 \
    python3-minimal \
    bash \
    curl \
    xvfb \
    dbus-x11 \
    xauth \
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
  && locale-gen ru_RU.UTF-8 && update-locale LANG=ru_RU.UTF-8 \
  && rm -rf /var/lib/apt/lists/*

ENV LANG=ru_RU.UTF-8
ENV LC_ALL=ru_RU.UTF-8
ENV LANGUAGE=ru_RU:ru

# Bring installer payload
ENV distrPath=/tmp/downloads/Platform83/${ONEC_VERSION}
WORKDIR ${distrPath}
COPY --from=downloader /tmp/out/Platform83/${ONEC_VERSION} /tmp/downloads/Platform83/${ONEC_VERSION}

# Install platform (server + admin tools)
COPY ./onec-client/scripts/onec-install.sh /onec-install.sh
ENV installer_type=server
ENV nls=false
RUN sed -i 's/\r$//' /onec-install.sh \
  && chmod +x /onec-install.sh \
  && /onec-install.sh \
  && rm -f /onec-install.sh \
  && rm -rf /tmp/downloads

# Create /opt/1cv8/current symlink to simplify PATH
RUN set -eux; \
  if [ -d "/opt/1cv8/x86_64" ]; then arch_dir="x86_64"; \
  elif [ -d "/opt/1cv8/amd64" ]; then arch_dir="amd64"; \
  else arch_dir="$(ls -1 /opt/1cv8 | grep -E 'x86_64|amd64' | head -n1 || true)"; fi; \
  [ -n "${arch_dir:-}" ]; \
  ln -sfn "/opt/1cv8/${arch_dir}/${ONEC_VERSION}" /opt/1cv8/current

ENV PATH="/opt/1cv8/current:${PATH}"

# Ensure standard 1C user/group exist
RUN set -eux; \
  if ! getent group grp1cv8 >/dev/null 2>&1; then groupadd -r grp1cv8 --gid 1001; fi; \
  if ! id -u usr1cv8 >/dev/null 2>&1; then useradd -r -g grp1cv8 --uid 1001 -m --home-dir /home/usr1cv8 --shell /bin/bash usr1cv8; fi; \
  mkdir -p /home/usr1cv8/.1cv8 /var/1C/licenses /var/log/onec /var/lib/onec; \
  chown -R usr1cv8:grp1cv8 /home/usr1cv8 /var/1C/licenses /var/log/onec /var/lib/onec || true

# Community activation payload + script (optional)
COPY ./onec-client/ActivateCommunity.epf /opt/onec-client/ActivateCommunity.epf
COPY ./.devcontainer/onec-activate-community.sh /usr/local/bin/onec-activate-community.sh
RUN sed -i 's/\r$//' /usr/local/bin/onec-activate-community.sh \
  && chmod +x /usr/local/bin/onec-activate-community.sh

# Runtime scripts
COPY ./infra/vm/onec-server/entrypoint.sh /usr/local/bin/onec-server-entrypoint.sh
COPY ./infra/vm/onec-server/init-infobases.sh /usr/local/bin/onec-init-infobases.sh
RUN sed -i 's/\r$//' /usr/local/bin/onec-server-entrypoint.sh /usr/local/bin/onec-init-infobases.sh \
  && chmod +x /usr/local/bin/onec-server-entrypoint.sh /usr/local/bin/onec-init-infobases.sh

# Volumes: licenses + cluster data
VOLUME ["/var/1C/licenses", "/var/lib/onec", "/var/log/onec"]

# 1C default ports (work-process range is configured via ragent -range):
# - 1540: ragent
# - 1541: regport (rmngr)
# - 1545: RAS
EXPOSE 1540 1541 1545

ENTRYPOINT ["/usr/local/bin/onec-server-entrypoint.sh"]

##
## Apache web publication image (web client + HTTP services)
## - Uses the same installed 1C payload (component ws) from the server image
## - Runs Apache in foreground and manages publications via /usr/local/bin/onec-webinst.sh
##
FROM server AS web

# Apache runtime
RUN apt-get update -o Acquire::ForceIPv4=true -o Acquire::Retries=3 \
  && apt-get install -y --no-install-recommends \
    apache2 \
    apache2-utils \
    libapache2-mod-fcgid \
  && a2enmod headers rewrite \
  && rm -rf /var/lib/apt/lists/*

# Persist publications + webinst-managed Apache fragment
ENV APACHE_LISTEN_PORT=8080
ENV ONEC_WEB_ROOT=/var/lib/onec-web
ENV ONEC_WEB_WWW=/var/lib/onec-web/www
ENV ONEC_WEB_APACHE_FRAGMENT=/var/lib/onec-web/apache/onec.conf

VOLUME ["/var/lib/onec-web"]

COPY ./infra/vm/onec-web/onec-publications.conf /etc/apache2/conf-available/onec-publications.conf
COPY ./infra/vm/onec-web/entrypoint.sh /usr/local/bin/onec-web-entrypoint.sh
COPY ./infra/vm/onec-web/onec-webinst.sh /usr/local/bin/onec-webinst.sh
RUN sed -i 's/\r$//' /etc/apache2/conf-available/onec-publications.conf /usr/local/bin/onec-web-entrypoint.sh /usr/local/bin/onec-webinst.sh \
  && chmod +x /usr/local/bin/onec-web-entrypoint.sh /usr/local/bin/onec-webinst.sh \
  && a2enconf onec-publications

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/onec-web-entrypoint.sh"]

