#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_NAME="agent-burp"

TARGET_DIR="${TARGET_DIR:-/usr/local/bin}"
TARGET_PATH="${TARGET_DIR}/${BIN_NAME}"

echo "Building ${BIN_NAME}..."
(cd "${REPO_DIR}" && go build -o "${BIN_NAME}" ./cmd/agent-burp)

if [[ ! -d "${TARGET_DIR}" ]]; then
  echo "Creating ${TARGET_DIR}..."
  sudo mkdir -p "${TARGET_DIR}"
fi

echo "Installing to ${TARGET_PATH}..."
sudo install -m 0755 "${REPO_DIR}/${BIN_NAME}" "${TARGET_PATH}"

if ! echo "${PATH}" | tr ':' '\n' | grep -qx "${TARGET_DIR}"; then
  echo
  echo "Note: ${TARGET_DIR} is not currently on your PATH."
  echo "Add this to your shell profile (for zsh: ~/.zshrc):"
  echo "  export PATH=\"${TARGET_DIR}:\$PATH\""
fi

echo
echo "Installed successfully. Try:"
echo "  ${BIN_NAME} help"
