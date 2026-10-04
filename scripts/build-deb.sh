#!/usr/bin/env bash
# Сборка vpn-panel_*.deb в чистом контейнере, том же, что у CI.
# Результат: dist/. Дерево монтируется только для чтения.
# Ставить пакет — только в одноразовой виртуальной машине, не на хосте.
set -euo pipefail

IMAGE=mcr.microsoft.com/devcontainers/go:1.26-bookworm
CACHE_VOLUME=vpn-panel-gocache
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$ROOT/dist"

docker run --rm \
  -v "$ROOT":/src:ro \
  -v "$ROOT/dist":/dist \
  -v "$CACHE_VOLUME":/gc -e GOMODCACHE=/gc/mod -e GOCACHE=/gc/build \
  "$IMAGE" bash -c '
    set -e
    export DEBIAN_FRONTEND=noninteractive
    apt-get -qq update >/dev/null
    apt-get -qq install -y debhelper lintian librsvg2-bin >/dev/null

    # Копия исходников без DEV-артефактов: в пакет не попадает ничего личного.
    mkdir /build
    tar -C /src --exclude=.git --exclude=storage --exclude=tmp \
        --exclude=dist --exclude=.env -cf - . | tar -C /build -xf -
    cd /build

    dpkg-buildpackage -us -uc -b -d
    lintian --fail-on error ../vpn-panel_*.deb || { echo "lintian errors"; exit 1; }
    lintian ../vpn-panel_*.deb || true   # предупреждения — в лог, не блокер

    cp ../vpn-panel_*.deb /dist/
    echo "OK: $(cd /dist && ls vpn-panel_*.deb)"
  '
