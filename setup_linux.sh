#!/bin/bash
# First-time setup of Latency Checker on Linux from a git clone:
#
#   git clone <your-repo-url> ~/latency-checker
#   cd ~/latency-checker && ./setup_linux.sh
#
# Creates ./.venv, installs the logger as a systemd service that runs straight from
# this checkout (so ./update_linux.sh = git pull + restart keeps it current).
#   --viewer     also install the viewer's packages and an app-menu entry
#   --at-login   per-user service instead of a boot service (no sudo)
set -e
cd "$(dirname "$(readlink -f "$0")")"
VIEWER=0; MODE=""
for a in "$@"; do
  case "$a" in
    --viewer) VIEWER=1 ;;
    --at-login) MODE="--at-login" ;;
    *) echo "Unknown option: $a"; exit 2 ;;
  esac
done
hint="Debian/Ubuntu: sudo apt install python3 python3-venv iputils-ping
Fedora:        sudo dnf install python3 iputils
Arch:          sudo pacman -S python iputils"
command -v python3 >/dev/null || { echo "python3 is missing."; echo "$hint"; exit 1; }
python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))' || { echo "Python 3.9+ is required."; exit 1; }
command -v ping >/dev/null || echo "Warning: 'ping' is not installed — every target will show 'ping missing'."
command -v systemctl >/dev/null || { echo "systemd not found; run the logger with: .venv/bin/python latency_logger.py"; }

source ./venv_linux.sh
ensure_venv || { echo "$hint"; exit 1; }
.venv/bin/pip install -q --disable-pip-version-check -r requirements-logger.txt \
  || echo "Note: optional 'cryptography' not installed; remote access will use openssl instead."
if [ "$VIEWER" = 1 ]; then
  python3 -c "import tkinter" 2>/dev/null || { echo "Tkinter missing: sudo apt install python3-tk (Debian/Ubuntu)"; exit 1; }
  .venv/bin/pip install -q --disable-pip-version-check -r requirements.txt && touch .venv/.deps-ok
  ./install_desktop_linux.sh
fi

echo "Installing the logger service (runs from $(pwd))…"
if [ -n "$MODE" ]; then
  .venv/bin/python latency_logger.py install --in-place --at-login
else
  sudo .venv/bin/python latency_logger.py install --in-place
fi
echo
.venv/bin/python latency_logger.py status
echo
echo "To update later:  ./update_linux.sh"
