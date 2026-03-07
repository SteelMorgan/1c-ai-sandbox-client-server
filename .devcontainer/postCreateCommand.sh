#!/usr/bin/env bash
set -eu

# Some environments/scripts end up with CRLF or non-bash shells in the chain.
# Enable pipefail only if supported and parsed correctly.
if (set -o pipefail) 2>/dev/null; then
  set -o pipefail
fi

# Workspace is a Docker volume and may be owned by root (755). If we can't chown
# (common on Docker Desktop), fall back to chmod to allow writes for vscode.
if [ -d "/workspaces/work" ] && [ ! -w "/workspaces/work" ]; then
  # With --security-opt=no-new-privileges, sudo is blocked. Permission fix is handled by entrypoint.
  echo "WARNING: /workspaces/work is not writable for current user."
  echo "If this persists, rebuild the container (entrypoint should chmod 0777)."
fi

echo "Devcontainer ready."
echo
echo "Next steps:"
echo "- Create/confirm Docker volume: agent-work-sandbox-1c"
echo "- Authenticate GitHub bot inside container (see docs/github-bot-setup.md)"
echo "- Work only on branches: agent/<task>-<yyyymmdd>"

# Make sure git doesn't complain about ownership in containerized volumes
if command -v git >/dev/null 2>&1; then
  git config --global --add safe.directory "*" >/dev/null 2>&1 || true
fi

# Python dependencies (idempotent, no rebuild required)
pip3 install --quiet --break-system-packages "python-xlib==0.33" "Pillow" "tiktoken" 2>/dev/null || pip3 install --quiet "python-xlib==0.33" "Pillow" "tiktoken" || true

# GitHub auth bootstrap (idempotent). Uses /run/secrets/github_token when present.
bash /usr/local/share/agent-sandbox/gh-auth-bootstrap.sh || true

# OneScript + Vanessa bootstrap (idempotent).
install_onescript_vanessa() {
  local onescript_version="2.0.0"
  local onescript_home="/opt/onescript/${onescript_version}"
  local onescript_zip="OneScript-${onescript_version}-linux-x64.zip"
  local onescript_url="https://github.com/EvilBeaver/OneScript/releases/download/v${onescript_version}/${onescript_zip}"
  local marker="${onescript_home}/.postcreate-installed"
  local log_dir="/workspaces/work/temp"
  local log_file="${log_dir}/onescript-postcreate.log"

  if command -v oscript >/dev/null 2>&1 \
    && command -v opm >/dev/null 2>&1 \
    && command -v vrunner >/dev/null 2>&1 \
    && [ -f "${marker}" ]; then
    echo "OneScript/Vanessa already installed. Skipping."
    return 0
  fi

  mkdir -p "${log_dir}" 2>/dev/null || true

  {
    echo "==> Installing OneScript and Vanessa tooling"
    sudo apt-get update
    sudo apt-get install -y --no-install-recommends curl unzip

    curl -fL --retry 3 --retry-delay 2 -o "/tmp/${onescript_zip}" "${onescript_url}"

    sudo mkdir -p "${onescript_home}"
    sudo unzip -oq "/tmp/${onescript_zip}" -d "${onescript_home}"
    sudo chmod 0755 \
      "${onescript_home}/bin/oscript" \
      "${onescript_home}/bin/opm" \
      "${onescript_home}/bin/createdump"

    sudo ln -sf "${onescript_home}/bin/oscript" /usr/local/bin/oscript

    printf '%s\n' \
      '#!/usr/bin/env bash' \
      "exec ${onescript_home}/bin/opm \"\$@\"" \
      | sudo tee /usr/local/bin/opm >/dev/null
    sudo chmod 0755 /usr/local/bin/opm

    sudo /usr/local/bin/opm install add
    sudo /usr/local/bin/opm install vanessa-runner
    sudo /usr/local/bin/opm install vanessa-automation-single
    sudo /usr/local/bin/opm app --app-name vrunner \
      "${onescript_home}/lib/vanessa-runner/src/main.os" \
      /usr/local/bin

    oscript --version
    opm --version
    vrunner version

    sudo touch "${marker}"
    sudo rm -f "/tmp/${onescript_zip}"
    echo "==> OneScript and Vanessa tooling installed"
  } 2>&1 | tee "${log_file}"
}

install_imagemagick7() {
  local imagemagick_version="7.1.2-15"
  local imagemagick_prefix="/opt/imagemagick/${imagemagick_version}"
  local marker="${imagemagick_prefix}/.postcreate-installed"
  local log_dir="/workspaces/work/temp"
  local log_file="${log_dir}/imagemagick-postcreate.log"

  if command -v magick >/dev/null 2>&1 \
    && magick --version 2>/dev/null | grep -q "ImageMagick ${imagemagick_version}" \
    && [ -f "${marker}" ]; then
    echo "ImageMagick ${imagemagick_version} already installed. Skipping."
    return 0
  fi

  mkdir -p "${log_dir}" 2>/dev/null || true

  {
    echo "==> Installing ImageMagick ${imagemagick_version}"
    sudo apt-get update
    sudo apt-get install -y --no-install-recommends \
      build-essential \
      pkg-config \
      libbz2-dev \
      libdjvulibre-dev \
      libfontconfig1-dev \
      libfreetype6-dev \
      libheif-dev \
      libjpeg-dev \
      liblcms2-dev \
      libltdl-dev \
      libopenjp2-7-dev \
      libpng-dev \
      libraw-dev \
      libtiff-dev \
      libwebp-dev \
      libx11-dev \
      libxml2-dev \
      libxt-dev

    curl -fsSLo /tmp/ImageMagick.tar.xz \
      "https://imagemagick.org/archive/releases/ImageMagick-${imagemagick_version}.tar.xz"
    rm -rf /tmp/imagemagick-src
    mkdir -p /tmp/imagemagick-src
    tar -xf /tmp/ImageMagick.tar.xz -C /tmp/imagemagick-src --strip-components=1
    cd /tmp/imagemagick-src
    ./configure \
      --prefix="${imagemagick_prefix}" \
      --disable-dependency-tracking \
      --disable-static \
      --with-modules \
      --without-magick-plus-plus \
      --without-perl
    make -j"$(nproc)"
    sudo make install
    echo "${imagemagick_prefix}/lib" | sudo tee /etc/ld.so.conf.d/imagemagick.conf >/dev/null
    sudo ldconfig
    sudo ln -sfn "${imagemagick_prefix}/bin/magick" /usr/local/bin/magick
    magick --version

    sudo touch "${marker}"
    sudo rm -rf /tmp/ImageMagick.tar.xz /tmp/imagemagick-src
    echo "==> ImageMagick ${imagemagick_version} installed"
  } 2>&1 | tee "${log_file}"
}

install_onescript_vanessa
install_imagemagick7

# ---------------------------------------------------------------------------
# Helper: run a cli-agent bootstrap script.
# Prefers workspace-local copy; falls back to image-baked copy.
# ---------------------------------------------------------------------------
run_bootstrap() {
  local rel="$1"   # e.g. cli-agents/codex/bootstrap.sh
  local ws="/workspaces/work/.devcontainer/${rel}"
  local img="/usr/local/share/agent-sandbox/${rel}"
  if [[ -f "${ws}" ]]; then
    bash "${ws}" || bash "${img}" || true
  else
    bash "${img}" || true
  fi
}

# ---------------------------------------------------------------------------
# Claude Code bootstrap (idempotent).
# Sets up custom backend, statusLine, cc alias / symlink.
# ---------------------------------------------------------------------------
run_bootstrap cli-agents/claude/bootstrap.sh

# ---------------------------------------------------------------------------
# Codex bootstrap (idempotent). Uses /run/secrets/cc_api_key when present.
# ---------------------------------------------------------------------------
run_bootstrap cli-agents/codex/bootstrap.sh

# ---------------------------------------------------------------------------
# Gemini CLI bootstrap (idempotent). Uses /run/secrets/cc_api_key when present.
# ---------------------------------------------------------------------------
run_bootstrap cli-agents/gemini/bootstrap.sh

# Global pre-push hook is installed by entrypoint (root-owned, locked-down).
# (Still bypassable by a determined user; this is an anti-footgun.)
