# Shared helper (sourced by setup_linux.sh / update_linux.sh / run_linux.sh).
# ensure_venv: make sure ./.venv exists and works; rebuild it if the system Python it
# points at was upgraded or removed (the classic "venv broke after an OS update").
ensure_venv() {
  if [ -x .venv/bin/python ] && .venv/bin/python -c "import sys, ssl, json" >/dev/null 2>&1; then
    return 0
  fi
  [ -d .venv ] && echo "Rebuilding .venv (the Python it was made with has changed)…"
  rm -rf .venv
  python3 -m venv .venv || { echo "Could not create .venv (install python3-venv)."; return 1; }
  .venv/bin/python -m pip install -q --disable-pip-version-check --upgrade pip >/dev/null 2>&1 || true
}
