#!/bin/bash
# Adds "Latency Checker" to your application menu (no root needed).
DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
APPS="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
mkdir -p "$APPS"
cat > "$APPS/latency-checker.desktop" <<DESK
[Desktop Entry]
Type=Application
Name=Latency Checker
Comment=Latency graphs for your targets, gateway and public IP
Exec="$DIR/run_linux.sh"
Path=$DIR
Icon=$DIR/assets/icon.png
Terminal=false
Categories=Network;Monitor;Utility;
DESK
chmod +x "$APPS/latency-checker.desktop" "$DIR/run_linux.sh"
command -v update-desktop-database >/dev/null && update-desktop-database "$APPS" >/dev/null 2>&1
echo "Added Latency Checker to your applications menu ($APPS/latency-checker.desktop)."
