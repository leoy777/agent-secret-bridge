#!/bin/sh
set -eu

source_binary=${1:-./asb}
install_directory=${ASB_INSTALL_DIR:-${HOME}/.local/bin}
destination=${install_directory}/asb

if [ ! -f "$source_binary" ]; then
  echo "ASB binary not found: $source_binary" >&2
  exit 1
fi

mkdir -p "$install_directory"
chmod 700 "$install_directory"
install -m 0755 "$source_binary" "$destination"
echo "Installed ASB to $destination"
echo "Run: asb --version"
