#!/usr/bin/env bash
# Install nuclei binary and update templates.
# Safe to run multiple times — skips download if already installed.
set -e

if command -v nuclei &>/dev/null; then
    echo "[nuclei] already installed: $(nuclei -version 2>&1 | head -1)"
    echo "[nuclei] updating templates..."
    nuclei -update-templates -silent 2>/dev/null || true
    exit 0
fi

ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  ARCH_SLUG="amd64" ;;
    aarch64) ARCH_SLUG="arm64" ;;
    *)       echo "[nuclei] unsupported arch: $ARCH — skipping install"; exit 0 ;;
esac

echo "[nuclei] installing for linux_${ARCH_SLUG}..."
URL="https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_${ARCH_SLUG}.zip"
curl -sSL "$URL" -o /tmp/nuclei.zip
unzip -q -o /tmp/nuclei.zip nuclei -d /usr/local/bin/
chmod +x /usr/local/bin/nuclei
rm -f /tmp/nuclei.zip

echo "[nuclei] version: $(nuclei -version 2>&1 | head -1)"
echo "[nuclei] updating templates (~50 MB, one-time)..."
nuclei -update-templates -silent 2>/dev/null || true
echo "[nuclei] install complete"
