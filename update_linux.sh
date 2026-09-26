#!/bin/bash
# Update Latency Checker from git and restart the logger service.
#   ./update_linux.sh
set -e
cd "$(dirname "$(readlink -f "$0")")"
[ -d .git ] || { echo "This folder is not a git checkout."; exit 1; }
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "You have local changes here — commit or stash them first (git status)."; exit 1
fi
before=$(git rev-parse --short HEAD)
git pull --ff-only
after=$(git rev-parse --short HEAD)

source ./venv_linux.sh
ensure_venv                                   # recreates .venv if a system Python upgrade broke it
.venv/bin/pip install -q --disable-pip-version-check -r requirements-logger.txt || true
if [ -f .venv/.deps-ok ]; then                # the viewer is used on this machine too
  .venv/bin/pip install -q --disable-pip-version-check -r requirements.txt && touch .venv/.deps-ok
fi

UNIT=latency-logger.service
if [ -f "/etc/systemd/system/$UNIT" ] || [ -f "$HOME/.config/systemd/user/$UNIT" ]; then
  unitfile="/etc/systemd/system/$UNIT"; [ -f "$unitfile" ] || unitfile="$HOME/.config/systemd/user/$UNIT"
  if ! grep -q "$(pwd)/latency_logger.py" "$unitfile"; then
    echo "The installed service doesn't run from this checkout (it uses a copied snapshot)."
    echo "Switch it over once with:  ./setup_linux.sh"
    exit 1
  fi
  if [ -f "/etc/systemd/system/$UNIT" ]; then
    sudo .venv/bin/python latency_logger.py restart
  else
    .venv/bin/python latency_logger.py restart
  fi
else
  echo "No logger service installed yet — run ./setup_linux.sh"
fi
[ "$before" = "$after" ] && echo "Already up to date ($after)." || echo "Updated $before → $after."
.venv/bin/python latency_logger.py status
