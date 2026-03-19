#!/usr/bin/env bash
#MISE description="install the latest bpftool release"
set -euo pipefail

api_url="https://api.github.com/repos/libbpf/bpftool/releases/latest"

arch="$(uname -m)"
case "$arch" in
  x86_64)
    asset_arch="amd64"
    ;;
  aarch64|arm64)
    asset_arch="arm64"
    ;;
  *)
    echo "Unsupported architecture: $arch"
    exit 1
    ;;
esac

json="$(curl -fsSL "$api_url")"
tag="$(printf '%s' "$json" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
asset_name="bpftool-${tag}-${asset_arch}.tar.gz"
asset_url="$(printf '%s' "$json" | sed -n 's/.*"browser_download_url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | grep "/${asset_name}$" | head -n1)"

if [[ -z "$tag" || -z "$asset_url" ]]; then
  echo "Failed to resolve latest bpftool release asset for architecture: $asset_arch"
  exit 1
fi

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

archive_path="$tmp_dir/$asset_name"
echo "Downloading $asset_name from $asset_url"
curl -fL "$asset_url" -o "$archive_path"

tar -xzf "$archive_path" -C "$tmp_dir"

if [[ ! -f "$tmp_dir/bpftool" ]]; then
  echo "Archive did not contain expected bpftool binary"
  exit 1
fi

if [[ "${EUID}" -eq 0 ]]; then
  install -m 0755 "$tmp_dir/bpftool" /usr/local/bin/bpftool
else
  sudo install -m 0755 "$tmp_dir/bpftool" /usr/local/bin/bpftool
fi

echo "Installed bpftool $(/usr/local/bin/bpftool version | head -n1)"