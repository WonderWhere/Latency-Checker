# Latency Checker

Latency monitoring for macOS and Windows, split into two programs:

| | What it does | Needs |
|---|---|---|
| **Logger** (`latency_logger.py`) | Headless. Pings your targets and the current local gateway, looks up the public IP, and appends everything to daily CSV logs. Can run as a service that starts at boot. | Python 3.9+ only, no extra packages |
| **Viewer** (`latency_viewer.py`) | The window: live and historical graphs, stats, targets and settings. It doesn't ping anything; it reads the logs and follows today's file live. | Python + Tkinter + matplotlib |

Both share `~/LatencyChecker/`:

- `config.json` holds the targets and settings. The viewer edits it, and the logger re-reads it within one round.
- `logs/latency_YYYY-MM-DD.csv` holds the measurements.
- `status.json` is the logger's heartbeat, so the viewer knows whether the logger is running.
- `logger.log` is the logger's own diagnostic log: start and stop, config reloads, gateway and public-IP changes, errors.

## 1. Set up the logger as a service (starts at boot, runs headless)

**macOS:** double-click `install_service_mac.command` (first time: right-click → Open) and enter your Mac password.
Or in Terminal: `sudo python3 latency_logger.py install`.

- It installs a launchd **LaunchDaemon** (`/Library/LaunchDaemons/com.latencychecker.logger.plist`). It starts when the Mac boots, even before anyone logs in, and runs as *your* user so the logs belong to you. launchd restarts it if it ever stops.
- The logger is copied to `~/LatencyChecker/app/` and runs from there. macOS doesn't let boot-time services read `~/Documents`, so the service never depends on this project folder. **Run the installer again after updating the code.**

**Windows:** double-click `install_service_windows.bat` and accept the administrator prompt.
Or from an admin prompt: `py -3 latency_logger.py install`.

- It registers a **scheduled task** "LatencyChecker Logger". The task runs at system startup as SYSTEM (headless, before anyone logs in), with no time limit, and restarts every minute if it stops. It keeps writing to your `C:\Users\<you>\LatencyChecker` folder.
- As on macOS, the logger is copied to `LatencyChecker\app\`, so run the installer again after updating the code.

**Start at login instead of boot (no admin rights):** `python3 latency_logger.py install --at-login`.

**Check it:** `python3 latency_logger.py status` shows whether the service is installed, whether the logger is running, the last heartbeat, gateway and public IP.
**Remove it:** `uninstall_service_mac.command` / `uninstall_service_windows.bat`, or `latency_logger.py uninstall`.
**Linux:** `sudo python3 latency_logger.py install` sets up a systemd unit in the same way.

Only one logger runs at a time. If the service starts while you're running one by hand, it waits and takes over when that one stops.

## 2. Open the viewer

1. Install Python 3.9+ from python.org (includes Tkinter). Homebrew Python users: `brew install python-tk`.
2. Open it without any terminal window:
   - **macOS:** double-click **Latency Checker.app** in this folder. You can drag it to the Dock, but keep the app itself in this folder. The first time, right-click → Open, and allow access to the Documents folder if macOS asks.
   - **Windows:** double-click **Latency Checker (Windows).vbs**. You can make a shortcut to it on the desktop or in the Start menu.
   - `run_mac.command` and `run_windows.bat` still work too. The Terminal window now closes by itself once the viewer is open.

   On first run it creates a local `.venv` with matplotlib, the Sun Valley theme and dark-mode detection. That takes about a minute, and a notification tells you it's happening. Launch problems are written to `~/LatencyChecker/viewer-launch.log`.

The header shows whether the logger is running, and whether it runs as a service. It also shows the current gateway and public IP. If the logger isn't running, **Start logger** launches it in the background. That instance keeps going after you close the viewer, but it won't start at boot; use the service for that. You can also run it by hand in a terminal: `python3 latency_logger.py` (Ctrl+C stops it).

## Using the viewer

- Add a target (IP or hostname, optional name) and press **Add**. Select one or more rows and press **Remove** to drop them. The logger picks up the change on its next round.
- **Settings** (left panel): ping interval, timeout, the gateway and public-IP switches, and the log folder. These are all logger settings, saved to `config.json`.
- The ☀/☾ button switches between light and dark. By default the viewer follows your system's appearance.
- Timeouts show as small ticks along the bottom of the graph and count toward Loss.
- **Log scale** (toggle in the toolbar) switches the vertical axis to logarithmic (0.5 · 1 · 2 · 5 · 10 · 20 · 50 · 100 … ms). The gateway at ~1 ms, internet targets at 10–30 ms and occasional 800 ms spikes then all stay readable together, and nothing is clipped. The choice is remembered.

### Local gateway (auto-detected)

With **Auto-detect local gateway** ticked, the first row is always your current network's default gateway. It is re-detected every round, so when you switch Wi-Fi / Ethernet / hotspot it follows automatically:

- The row shows the gateway IP and interface, e.g. `192.168.1.1 (en0)`.
- The status bar announces the change, and the graph draws a dashed vertical line labelled with the new gateway IP (or "offline").
- The gateway keeps one continuous line on the graph across networks; each log row stores the actual IP it pinged, with `role = gateway`.
- VPN/tunnel interfaces (utun, tun, wg, ppp…) are skipped on macOS/Linux so you get the *local* router. On Windows the active default route with the lowest metric is used. Some VPNs take over that route, and then the VPN's gateway is shown instead.

### Public IP

With **Record public IP** switched on (Settings), every log row also stores your public (internet-facing) IPv4 address, so you can tell which connection or ISP a measurement came from.

- The app looks it up every 5 minutes and right after a network change. It asks a plain-text "what is my IP" service (api.ipify.org, with ifconfig.me, icanhazip.com and checkip.amazonaws.com as fallbacks). These services see your IP, as any website would.
- After a network switch the column stays blank until the new IP is confirmed, so an old IP is never logged against the new network.
- The header shows the current public IP, and the status bar tells you when it changes.

### Navigating history

- **Span buttons**: 15m · 1h · 6h · 12h · 24h · 7d · 30d.
- **Custom…** lets you pick any From/To range, with shortcuts for Today, Yesterday, This week and This month.
- **Drag across the graph** to zoom into exactly that span. **Double-click** zooms out.
- **‹ / ›** move one span back or forward, and **Live** returns to now.
- Up to 1 hour you see every sample. Longer spans show averages so the graph stays readable, sized to about 360 points: 1 min buckets for 6 h, 2 min for 12 h, 5 min for 24 h, 30 min for 7 d and 2 h for 30 d. The line is the average and the shaded band is the min–max; ticks mark buckets with ≥ 2 % loss.
- The stats table always covers the range on screen.
- Past days are read from the CSV logs. A 1-minute summary of each finished day is cached in `logs/.summary/`, so week and month views load quickly after the first time. The cache rebuilds itself if a log file changes, and you can delete it safely.

## Files

- Logs: `~/LatencyChecker/logs/latency_YYYY-MM-DD.csv` (one per day). Columns: `timestamp, host, label, latency_ms, status, role, public_ip` (`role` is `gateway` or `target`). Today's file from an older version gets the new header automatically, and your rows are kept. Change the folder with **Change log folder…**.
- Settings, targets, span and theme: `~/LatencyChecker/config.json` (shared by the logger and the viewer). Set `"theme"` to `"system"`, `"dark"` or `"light"`.

## Build standalone apps (no Python needed on the target machine)

- **macOS:** `./build_mac.sh` → `dist/Latency Checker.app` (viewer) and `dist/LatencyLogger` (logger). Install the service with `sudo dist/LatencyLogger install`.
- **Windows:** `build_windows.bat` → `dist\LatencyChecker.exe` and `dist\LatencyLogger.exe`. Install the service from an admin prompt with `LatencyLogger.exe install`.
- **Both at once:** push this folder to a GitHub repo; `.github/workflows/build.yml` builds everything and attaches it as workflow artifacts.

Keep `LatencyLogger` next to the viewer so **Start logger** can find it. PyInstaller can't cross-compile, so each build runs on its own OS. The builds are unsigned: on macOS, right-click → Open the first time; on Windows, SmartScreen may ask you to confirm with "More info → Run anyway".

## Troubleshooting

- **Viewer says "Logger not running":** run `latency_logger.py status`, then look at `~/LatencyChecker/logger.log` (and `logger.stdout.log` on macOS) for errors.
- **macOS: the gateway always times out while internet targets work:** macOS 15+ may block local-network access. Allow **Python** (or LatencyLogger) under System Settings › Privacy & Security › Local Network.
- **You updated the code:** run the service installer again so the copy in `~/LatencyChecker/app/` is refreshed.
