#!/bin/bash
# Install the Latency Checker logger as a systemd service that starts at boot.
#   ./install_service_linux.sh             at boot, system service (asks for sudo)
#   ./install_service_linux.sh --at-login  per-user service, no sudo
# In a git checkout this runs the service from the checkout's .venv (see setup_linux.sh);
# otherwise the logger is copied to ~/LatencyChecker/app.
cd "$(dirname "$(readlink -f "$0")")" || exit 1
command -v ping >/dev/null || echo "Note: 'ping' is not installed (Debian/Ubuntu: sudo apt install iputils-ping)."
if [ -d .git ]; then
  exec ./setup_linux.sh "$@"
fi
if [ "$1" = "--at-login" ]; then
  python3 latency_logger.py install --at-login
else
  sudo python3 latency_logger.py install
fi
echo; python3 latency_logger.py status
