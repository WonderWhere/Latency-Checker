@echo off
REM Builds, on Windows:
REM   dist\LatencyChecker.exe  - the viewer
REM   dist\LatencyLogger.exe   - the headless logger (install from an admin prompt: LatencyLogger.exe install)
cd /d "%~dp0"
py -3 -m venv .venv-build
.venv-build\Scripts\pip install -q -r requirements.txt pyinstaller
.venv-build\Scripts\pyinstaller --noconfirm --windowed --onefile --collect-data sv_ttk --hidden-import latency_remote --hidden-import latency_sources --name LatencyChecker latency_viewer.py
.venv-build\Scripts\pyinstaller --noconfirm --onefile --hidden-import latency_remote --name LatencyLogger latency_logger.py
echo Done: dist\LatencyChecker.exe and dist\LatencyLogger.exe
pause
