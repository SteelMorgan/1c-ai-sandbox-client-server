ARG DOWNLOADER_REGISTRY_URL=sleemp
ARG DOWNLOADER_IMAGE=onec-installer-downloader
ARG DOWNLOADER_TAG=latest

FROM ${DOWNLOADER_REGISTRY_URL}/${DOWNLOADER_IMAGE}:${DOWNLOADER_TAG} AS downloader

ARG ONEC_VERSION
# Fallback: read ONEC_VERSION from infra/vm/.env if arg is not passed.
COPY infra/vm/.env /tmp/infra.env
RUN set -eux; \
  if [ -z "${ONEC_VERSION:-}" ]; then \
    ONEC_VERSION="$(grep -E '^ONEC_VERSION=' /tmp/infra.env | head -n1 | cut -d= -f2- | tr -d '\r' || true)"; \
  fi; \
  : "${ONEC_VERSION:?ONEC_VERSION is required (pass build arg or set infra/vm/.env)}"; \
  printf "%s" "$ONEC_VERSION" >/tmp/ONEC_VERSION

WORKDIR /tmp

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

FROM ubuntu:24.04 AS base
ARG ONEC_VERSION

ENV DEBIAN_FRONTEND=noninteractive
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    locales \
    gosu \
    net-tools \
    iproute2 \
    # GUI stack (noVNC)
    xvfb \
    xfce4 \
    xfce4-terminal \
    dbus-x11 \
    x11vnc \
    novnc \
    websockify \
    # libs required by 1C
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
    libmagickwand-6.q16-7t64 \
    fonts-dejavu \
    fonts-liberation \
  && rm -rf /var/lib/apt/lists/*

RUN locale-gen ru_RU.UTF-8 && update-locale LANG=ru_RU.UTF-8
ENV LANG=ru_RU.UTF-8 LC_ALL=ru_RU.UTF-8 LANGUAGE=ru_RU:ru
ENV NO_AT_BRIDGE=1

ENV nls=false
ENV installer_type=client

COPY onec-client/scripts/onec-install.sh /onec-install.sh
COPY onec-client/scripts /opt/onec-client/scripts
COPY --from=downloader /tmp/out/Platform83/ /tmp/downloads/Platform83/
COPY infra/vm/.env /tmp/infra.env

RUN set -eux; \
  if [ -z "${ONEC_VERSION:-}" ]; then \
    ONEC_VERSION="$(grep -E '^ONEC_VERSION=' /tmp/infra.env | head -n1 | cut -d= -f2- | tr -d '\r' || true)"; \
  fi; \
  : "${ONEC_VERSION:?ONEC_VERSION is required (pass build arg or set infra/vm/.env)}"; \
  cd "/tmp/downloads/Platform83/${ONEC_VERSION}"; \
  chmod +x /onec-install.sh \
  && sed -i 's/\r$//' /onec-install.sh \
  && /onec-install.sh \
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

ENV PATH="/opt/1cv8/current:${PATH}"

# Create dedicated user
RUN set -eux; \
  if ! getent group grp1cv8 >/dev/null 2>&1; then groupadd -r grp1cv8 --gid 1001; fi; \
  if ! id -u usr1cv8 >/dev/null 2>&1; then useradd -r -g grp1cv8 --uid 1001 -m --home-dir /home/usr1cv8 --shell /bin/bash usr1cv8; fi; \
  mkdir -p /home/usr1cv8/.1cv8; \
  chown -R usr1cv8:grp1cv8 /home/usr1cv8

# Licenses dir (mounted)
RUN mkdir -p /var/1C/licenses \
  && chown -R usr1cv8:grp1cv8 /var/1C/licenses

COPY onec-client/ActivateCommunity.epf /opt/onec-client/ActivateCommunity.epf
COPY onec-client/scripts/entrypoint.sh /entrypoint.sh
COPY onec-client/scripts/license_activator.sh /opt/onec-client/scripts/license_activator.sh
COPY onec-client/scripts/license_expiring_soon.sh /opt/onec-client/scripts/license_expiring_soon.sh

RUN sed -i 's/\r$//' /entrypoint.sh /opt/onec-client/scripts/*.sh \
  && chmod +x /entrypoint.sh /opt/onec-client/scripts/*.sh

VOLUME /home/usr1cv8 /var/1C/licenses

EXPOSE 6080

ENTRYPOINT ["/entrypoint.sh"]

