@echo off
REM Double-click: install the Latency Checker logger so it starts automatically when Windows boots.
REM Re-launches itself as administrator (Windows will ask for permission).
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
cd /d "%~dp0"
set PY=py -3
if exist .venv\Scripts\python.exe set PY=.venv\Scripts\python.exe
%PY% latency_logger.py install
echo.
%PY% latency_logger.py status
echo.
pause
