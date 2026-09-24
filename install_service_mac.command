#!/bin/bash
# Double-click: install the Latency Checker logger as a background service that
# starts automatically when the Mac boots. Asks for your Mac password (sudo).
cd "$(dirname "$0")"
PY=python3; [ -x .venv/bin/python ] && PY=.venv/bin/python
echo "Installing the Latency Checker logger service (your password is needed once)…"
sudo "$PY" latency_logger.py install
echo; "$PY" latency_logger.py status
echo; read -n 1 -s -r -p "Press any key to close"
