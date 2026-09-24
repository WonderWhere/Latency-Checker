@echo off
REM Double-click to open the Latency Checker viewer (installs/updates its packages as needed).
cd /d "%~dp0"
if not exist .venv (
  py -3 -m venv .venv || (echo Python 3 is required: https://www.python.org/downloads/ & pause & exit /b 1)
)
.venv\Scripts\pip install -q --disable-pip-version-check -r requirements.txt
start "" .venv\Scripts\pythonw.exe latency_viewer.py
