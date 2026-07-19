#!/bin/sh
set -eu

install_directory=${ASB_INSTALL_DIR:-${HOME}/.local/bin}
destination=${install_directory}/asb

if [ ! -f "$destination" ]; then
  echo "ASB is not installed at $destination"
  exit 0
fi

rm -i "$destination"
echo "Credential stores, configuration, and audit logs were left untouched."
