#!/bin/bash
# Double-click: stop the Latency Checker logger service and remove the automatic start.
cd "$(dirname "$0")"
PY=python3; [ -x .venv/bin/python ] && PY=.venv/bin/python
sudo "$PY" latency_logger.py uninstall
echo; read -n 1 -s -r -p "Press any key to close"
