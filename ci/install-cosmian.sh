#!/usr/bin/env bash
# Installs the pinned Cosmian KMS server on an Ubuntu CI runner.
# Usage: ci/install-cosmian.sh [cache-dir]
set -euo pipefail

COSMIAN_VERSION=5.28.0
CACHE_DIR="${1:-$HOME/cosmian-deb}"
ARCH=$(dpkg --print-architecture)
DEB="cosmian-kms-server-non-fips-static-openssl_${COSMIAN_VERSION}_${ARCH}.deb"

mkdir -p "$CACHE_DIR"
if [ ! -f "$CACHE_DIR/$DEB" ]; then
  wget -q -O "$CACHE_DIR/$DEB.tmp" \
    "https://package.cosmian.com/kms/${COSMIAN_VERSION}/deb/${ARCH}/non-fips/static/${DEB}"
  mv "$CACHE_DIR/$DEB.tmp" "$CACHE_DIR/$DEB"
fi

sudo dpkg -i "$CACHE_DIR/$DEB"
# .deb ships binary + bundled legacy.so as 0500 root:root; CI runner is non-root.
sudo chmod 0755 /usr/sbin/cosmian_kms
sudo chmod 0755 /usr/local/cosmian/lib/ossl-modules/legacy.so
