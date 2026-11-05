#!/bin/sh
# Installs the latest hush CLI: curl -fsSL <this file's raw URL> | sh
# INSTALL_DIR picks the folder (default /usr/local/bin, else ~/.local/bin).
set -eu

repo=hushsecurity/hush-cli
os=$(uname -s | tr '[:upper:]' '[:lower:]')
case $(uname -m) in
x86_64 | amd64) arch=amd64 ;;
arm64 | aarch64) arch=arm64 ;;
*) echo "unsupported CPU: $(uname -m)" >&2 && exit 1 ;;
esac
archive="hush_${os}_${arch}.tar.gz"
url="https://github.com/$repo/releases/latest/download"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/$archive" "$url/$archive"
curl -fsSL -o "$tmp/checksums.txt" "$url/checksums.txt"
(cd "$tmp" && grep " $archive\$" checksums.txt | sha256sum -c - >/dev/null 2>&1 ||
	grep " $archive\$" checksums.txt | shasum -a 256 -c - >/dev/null 2>&1) ||
	{ echo "checksum mismatch for $archive" >&2 && exit 1; }
tar -xzf "$tmp/$archive" -C "$tmp" hush

dir=${INSTALL_DIR:-/usr/local/bin}
if [ -z "${INSTALL_DIR:-}" ] && [ ! -w "$dir" ]; then
	dir="$HOME/.local/bin"
fi
mkdir -p "$dir"
install -m 755 "$tmp/hush" "$dir/hush"
echo "Installed hush in $dir"
