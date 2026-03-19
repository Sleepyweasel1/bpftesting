#!/usr/bin/env bash
#MISE description="install the latest bpftop release"
set -euo pipefail

api_url="https://api.github.com/repos/Netflix/bpftop/releases/latest"

arch="$(uname -m)"
case "$arch" in
  x86_64)
    asset_name="bpftop-x86_64-unknown-linux-gnu"
    ;;
  aarch64|arm64)
    asset_name="bpftop-aarch64-unknown-linux-gnu"
    ;;
  *)
    echo "Unsupported architecture: $arch"
    exit 1
    ;;
esac

json="$(curl -fsSL "$api_url")"
asset_url="$(printf '%s' "$json" | sed -n 's/.*"browser_download_url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | grep "/${asset_name}$" | head -n1)"

if [[ -z "$asset_url" ]]; then
  echo "Failed to resolve latest bpftop release asset: $asset_name"
  exit 1
fi

tmp_path="$(mktemp)"
cleanup() {
  rm -f "$tmp_path"
}
trap cleanup EXIT

echo "Downloading $asset_name from $asset_url"
curl -fL "$asset_url" -o "$tmp_path"

if [[ "${EUID}" -eq 0 ]]; then
  install -m 0755 "$tmp_path" /usr/local/bin/bpftop
else
  sudo install -m 0755 "$tmp_path" /usr/local/bin/bpftop
fi

echo "Installed bpftop to /usr/local/bin/bpftop"