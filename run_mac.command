#!/bin/bash
# Double-click to open the Latency Checker viewer. The Terminal window closes by itself.
# (Tip: "Latency Checker.app" in this folder does the same without any Terminal window.)
cd "$(dirname "$0")"
if [ ! -d .venv ]; then
  echo "First run: setting up Python packages…"
  python3 -m venv .venv || { echo "Python 3 is required: https://www.python.org/downloads/"; read; exit 1; }
fi
if [ ! -f .venv/.deps-ok ] || [ requirements.txt -nt .venv/.deps-ok ]; then
  .venv/bin/pip install -q --disable-pip-version-check -r requirements.txt && touch .venv/.deps-ok
fi
# Start the viewer detached from this Terminal, then close this window.
nohup .venv/bin/python latency_viewer.py >/dev/null 2>&1 &
disown
( sleep 1; osascript -e 'tell application "Terminal" to close (every window whose name contains "run_mac.command")' >/dev/null 2>&1 ) &
disown
exit 0
