#!/bin/bash
# Builds, on a Mac:
#   dist/Latency Checker.app   – the viewer
#   dist/LatencyLogger         – the headless logger (install with: sudo dist/LatencyLogger install)
set -e
cd "$(dirname "$0")"
python3 -m venv .venv-build
.venv-build/bin/pip install -q -r requirements.txt pyinstaller
.venv-build/bin/pyinstaller --noconfirm --windowed --collect-data sv_ttk --name "Latency Checker" latency_viewer.py
.venv-build/bin/pyinstaller --noconfirm --onefile --name LatencyLogger latency_logger.py
echo "Done: dist/Latency Checker.app and dist/LatencyLogger"
