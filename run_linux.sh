#!/bin/bash
# Opens the Latency Checker viewer on Linux (sets up .venv on first run).
# Works from a terminal or from the app-menu entry made by install_desktop_linux.sh.
cd "$(dirname "$(readlink -f "$0")")" || exit 1
LOGDIR="$HOME/LatencyChecker"; mkdir -p "$LOGDIR"; LOG="$LOGDIR/viewer-launch.log"
say() {   # message in the terminal, or as a desktop dialog/notification when there is none
  echo "$1"
  if [ ! -t 1 ]; then
    command -v zenity >/dev/null && zenity --error --title="Latency Checker" --text="$1" 2>/dev/null && return
    command -v kdialog >/dev/null && kdialog --error "$1" 2>/dev/null && return
    command -v notify-send >/dev/null && notify-send "Latency Checker" "$1"
  fi
}
hint="Debian/Ubuntu: sudo apt install python3-venv python3-tk
Fedora: sudo dnf install python3-tkinter
Arch: sudo pacman -S tk"
command -v python3 >/dev/null || { say "Python 3 is required.
$hint"; exit 1; }
python3 -c "import tkinter" 2>/dev/null || { say "Tkinter (the Python GUI toolkit) is missing.
$hint"; exit 1; }
source ./venv_linux.sh
ensure_venv >>"$LOG" 2>&1 || { say "Could not create a virtualenv.
$hint"; exit 1; }
if [ ! -f .venv/.deps-ok ] || [ requirements.txt -nt .venv/.deps-ok ]; then
  .venv/bin/pip install -q --disable-pip-version-check -r requirements.txt >>"$LOG" 2>&1 \
    && touch .venv/.deps-ok || { say "Installing packages failed — see $LOG"; exit 1; }
fi
# Detach from the terminal so it can be closed.
nohup .venv/bin/python latency_viewer.py >>"$LOG" 2>&1 &
disown
