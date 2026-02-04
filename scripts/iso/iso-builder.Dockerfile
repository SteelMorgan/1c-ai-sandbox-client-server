FROM ubuntu:24.04

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ARG DEBIAN_FRONTEND=noninteractive

# Tools for ISO remastering and patching boot configs
RUN apt-get update -o Acquire::ForceIPv4=true -o Acquire::Retries=3 \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    xorriso \
    grub-pc-bin \
    grub-efi-amd64-bin \
    grub-efi-ia32-bin \
    mtools \
    dosfstools \
    rsync \
    sed \
    coreutils \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /work
ENTRYPOINT ["/bin/bash", "-lc"]

