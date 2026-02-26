#!/usr/bin/env bash
set -euo pipefail

BIN_NAME="agent-burp"
TARGET_DIR="${TARGET_DIR:-/usr/local/bin}"
TARGET_PATH="${TARGET_DIR}/${BIN_NAME}"

if [[ -f "${TARGET_PATH}" ]]; then
  echo "Removing ${TARGET_PATH}..."
  sudo rm -f "${TARGET_PATH}"
  echo "Removed."
else
  echo "Nothing to remove at ${TARGET_PATH}."
fi
