#!/usr/bin/env bash
# Cullis Connector — macOS installer.
#
# Double-click this file in Finder. It copies the bundled binary to
# ~/.local/bin, registers the dashboard as a login item, and opens the
# onboarding page in your default browser.
#
# To uninstall later:
#     ~/.local/bin/cullis-connector install-autostart --uninstall
#     rm ~/.local/bin/cullis-connector

set -e

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

BIN_DIR="${HOME}/.local/bin"
mkdir -p "${BIN_DIR}"

# The release zip drops one or two architecture-specific binaries next
# to this script. Prefer arm64 on Apple Silicon, x86_64 on Intel.
if [[ "$(uname -m)" == "arm64" ]] && [[ -f "cullis-connector-macos-arm64" ]]; then
    SOURCE="cullis-connector-macos-arm64"
elif [[ -f "cullis-connector-macos-x86_64" ]]; then
    SOURCE="cullis-connector-macos-x86_64"
else
    # Fall back to whatever single macOS binary was shipped.
    SOURCE="$(ls cullis-connector-macos-* 2>/dev/null | head -1 || true)"
fi
if [[ -z "${SOURCE:-}" ]] || [[ ! -f "${SOURCE}" ]]; then
    echo "error: could not find a macOS binary next to install.command"
    echo "       expected one of cullis-connector-macos-arm64 / -x86_64"
    read -p "Press Enter to close…"
    exit 1
fi

echo "Installing ${SOURCE} → ${BIN_DIR}/cullis-connector"
cp "${SOURCE}" "${BIN_DIR}/cullis-connector"
chmod +x "${BIN_DIR}/cullis-connector"

# macOS Gatekeeper quarantines anything downloaded by a browser. Strip
# the quarantine bit so the binary runs without a "cannot be opened"
# dialog — user already trusted us enough to launch the installer.
xattr -d com.apple.quarantine "${BIN_DIR}/cullis-connector" 2>/dev/null || true

echo "Registering autostart…"
"${BIN_DIR}/cullis-connector" install-autostart || true

echo "Starting the dashboard…"
"${BIN_DIR}/cullis-connector" dashboard &
sleep 2
open "http://127.0.0.1:7777" 2>/dev/null || true

echo ""
echo "=========================================================="
echo " Cullis Connector is running."
echo " Dashboard: http://127.0.0.1:7777"
echo ""
echo " If ~/.local/bin is not on your PATH, add this line to"
echo " your ~/.zshrc or ~/.bash_profile:"
echo '   export PATH="$HOME/.local/bin:$PATH"'
echo "=========================================================="

read -p "Press Enter to close this window…"
