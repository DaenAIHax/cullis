#!/usr/bin/env bash
# Cullis Connector — Linux installer.
#
# Run this script from the extracted zip:
#     ./install.sh
#
# It copies the bundled binary to ~/.local/bin, registers a systemd user
# service so the dashboard survives reboot, and opens the onboarding page
# in your default browser.
#
# To uninstall later:
#     ~/.local/bin/cullis-connector install-autostart --uninstall
#     rm ~/.local/bin/cullis-connector

set -e

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

BIN_DIR="${HOME}/.local/bin"
mkdir -p "${BIN_DIR}"

SOURCE="$(ls cullis-connector-linux-* 2>/dev/null | head -1 || true)"
if [[ -z "${SOURCE}" ]] || [[ ! -f "${SOURCE}" ]]; then
    echo "error: could not find a Linux binary next to install.sh"
    echo "       expected a cullis-connector-linux-* file"
    exit 1
fi

echo "Installing ${SOURCE} → ${BIN_DIR}/cullis-connector"
cp "${SOURCE}" "${BIN_DIR}/cullis-connector"
chmod +x "${BIN_DIR}/cullis-connector"

echo "Registering autostart (systemd user unit)…"
"${BIN_DIR}/cullis-connector" install-autostart || true

echo "Starting the dashboard in the background…"
"${BIN_DIR}/cullis-connector" dashboard >/dev/null 2>&1 &
sleep 2

if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "http://127.0.0.1:7777" >/dev/null 2>&1 &
fi

echo ""
echo "=========================================================="
echo " Cullis Connector is running."
echo " Dashboard: http://127.0.0.1:7777"
echo ""
echo " If ~/.local/bin is not on your PATH, add this line to"
echo " your shell's rc file (~/.bashrc, ~/.zshrc):"
echo '   export PATH="$HOME/.local/bin:$PATH"'
echo "=========================================================="
