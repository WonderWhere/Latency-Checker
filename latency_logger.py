#!/usr/bin/env python3
"""
Latency Checker — headless logger
---------------------------------
Pings the configured targets (and the auto-detected local gateway) on an
interval and appends every result to the daily CSV logs. No window, no extra
packages: standard-library Python 3.9+ only.

    python3 latency_logger.py                 run in the foreground (Ctrl+C to stop)
    python3 latency_logger.py status          is it installed / running?
    sudo python3 latency_logger.py install    macOS/Linux: start automatically at boot (launchd / systemd)
    python  latency_logger.py install         Windows (from an admin prompt): same
    python3 latency_logger.py install --at-login   start at login instead (no admin needed)
    python3 latency_logger.py uninstall       remove the automatic start
    python3 latency_logger.py archive         compress finished daily logs now (safe while running)
    python3 latency_logger.py restart         restart the installed service

Finished daily logs are gzip-compressed automatically (at start-up and after each
midnight) to latency_YYYY-MM-DD.csv.gz; the viewer reads them transparently.

Settings come from ~/LatencyChecker/config.json and are re-read while running,
so changes made in the viewer apply within one round.
"""

import argparse
import logging
import logging.handlers
import os
import queue
import shutil
import signal
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime
from pathlib import Path

HERE = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
sys.path.insert(0, str(HERE))
import latency_core as core  # noqa: E402

SERVICE_LABEL = "com.latencychecker.logger"     # macOS launchd label
WIN_TASK = "LatencyChecker Logger"               # Windows Task Scheduler name
LINUX_UNIT = "latency-logger.service"            # systemd unit
FROZEN = getattr(sys, "frozen", False)

log = logging.getLogger("latency-logger")


# --------------------------------------------------------------------------- #
# Single instance (a service and a manual run must not log twice)
# --------------------------------------------------------------------------- #
class SingleInstance:
    def __init__(self, path: Path):
        self.path = path
        self.fh = None

    def acquire(self) -> bool:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.fh = open(self.path, "a+")
        try:
            if os.name == "nt":
                import msvcrt
                self.fh.seek(0)
                msvcrt.locking(self.fh.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.fh.close()
            self.fh = None
            return False
        self.fh.seek(0)
        self.fh.truncate()
        self.fh.write(str(os.getpid()))
        self.fh.flush()
        return True


# --------------------------------------------------------------------------- #
# The logger
# --------------------------------------------------------------------------- #
class LatencyLogger:
    def __init__(self, mode="manual"):
        self.mode = mode
        self.stop_event = threading.Event()
        self.pool = ThreadPoolExecutor(max_workers=32)
        self.results = queue.Queue()            # events from the public-IP watcher
        self.gateway = {"ip": None, "iface": None}
        self.public_ip = None
        self.last_public_ip = None
        self.last = {}
        self._first_gw = True
        self._cfg_mtime = object()
        self.csv = None
        self.started = datetime.now()
        self._archived_on = None
        self._archiving = False
        self.reload_config()
        self.pubwatch = core.PublicIPWatcher(self)

    # ---- config ---------------------------------------------------------- #
    def reload_config(self):
        m = core.config_mtime()
        if m == self._cfg_mtime:
            return
        first = not isinstance(self._cfg_mtime, (float, type(None)))
        self._cfg_mtime = m
        cfg = core.load_config()
        if m is None:                            # first run: create the file to edit
            try:
                core.save_config(cfg)
                self._cfg_mtime = core.config_mtime()
            except Exception as exc:
                log.warning("could not create %s: %s", core.CONFIG_PATH, exc)
        self.targets = cfg["targets"]
        self.interval_sec = max(1.0, float(cfg.get("interval_sec", 5)))
        self.timeout_ms = max(100, int(cfg.get("timeout_ms", 1000)))
        self.gateway_enabled = bool(cfg.get("auto_gateway", True))
        self.public_ip_enabled = bool(cfg.get("public_ip", True))
        self.compress = bool(cfg.get("compress_logs", True))
        self.compress_after = max(1, int(cfg.get("compress_after_days", 1)))
        log_dir = Path(cfg.get("log_dir") or core.APP_DIR / "logs")
        if self.csv is None or self.csv.log_dir != log_dir:
            self.csv = core.CsvLogger(log_dir)
        log.info("%s config: %d targets, every %gs, timeout %d ms, gateway %s, public IP %s, logs → %s",
                 "loaded" if first else "reloaded", len(self.targets), self.interval_sec,
                 self.timeout_ms, "on" if self.gateway_enabled else "off",
                 "on" if self.public_ip_enabled else "off", log_dir)

    # ---- one round ------------------------------------------------------- #
    def round(self):
        ts = datetime.now()
        jobs = [(t["host"], t["host"], t.get("label", ""), "target") for t in self.targets]
        if self.gateway_enabled or self.public_ip_enabled:
            gw, iface = core.detect_gateway()   # every round → follows network switches
            prev = self.gateway
            if (gw, iface) != (prev["ip"], prev["iface"]):
                self.gateway = {"ip": gw, "iface": iface}
                if gw:
                    log.info("local gateway: %s on %s%s", gw, iface,
                             f" (was {prev['ip']})" if prev["ip"] else "")
                else:
                    log.info("no local gateway — offline?")
                if not self._first_gw:
                    self.pubwatch.trigger()      # new network → new public IP?
            self._first_gw = False
            if self.gateway_enabled:
                jobs.insert(0, (core.GATEWAY_KEY, self.gateway["ip"], core.GATEWAY_LABEL,
                                "gateway"))
        public_ip = self.public_ip if self.public_ip_enabled else ""

        futures = [(self.pool.submit(core.ping, host, self.timeout_ms) if host else None,
                    key, host, label, role) for key, host, label, role in jobs]
        for fut, key, host, label, role in futures:
            if fut is None:
                latency, status = None, "no network"
            else:
                try:
                    latency, status = fut.result()
                except Exception as exc:  # pragma: no cover
                    latency, status = None, f"error: {exc}"
            try:
                self.csv.write(ts, host or "", label, latency, status, role, public_ip)
            except Exception as exc:
                log.error("could not write log: %s", exc)
            self.last[key] = [latency, status]

    def maybe_archive(self):
        """Once at start-up and once after every midnight: gzip finished days (in the background)."""
        today = date.today()
        if not self.compress or self._archived_on == today or self._archiving:
            return
        self._archived_on = today
        self._archiving = True

        def work():
            try:
                core.archive_old_logs(self.csv.log_dir, self.compress_after, log)
            except Exception:
                log.exception("archiving failed")
            finally:
                self._archiving = False
        threading.Thread(target=work, daemon=True, name="archive").start()

    def drain_events(self):
        while True:
            try:
                kind, ts, ip, prev = self.results.get_nowait()
            except queue.Empty:
                return
            if ip:
                log.info("public IP: %s%s", ip, f" (was {prev})" if prev and prev != ip else "")
            else:
                log.info("public IP lookup failed — will retry")

    def status(self, running=True):
        return {
            "version": core.VERSION, "pid": os.getpid(), "mode": self.mode,
            "running": running, "heartbeat": time.time(),
            "started": self.started.isoformat(timespec="seconds"),
            "interval_sec": self.interval_sec, "targets": len(self.targets),
            "gateway_enabled": self.gateway_enabled, "gateway": self.gateway,
            "public_ip_enabled": self.public_ip_enabled, "public_ip": self.public_ip,
            "log_dir": str(self.csv.log_dir), "last": self.last,
        }

    # ---- main loop ------------------------------------------------------- #
    def run(self):
        log.info("logger started (pid %d, %s mode, data in %s)", os.getpid(), self.mode, core.APP_DIR)
        self.pubwatch.start()
        while not self.stop_event.is_set():
            started = time.monotonic()
            try:
                self.reload_config()
                self.round()
                self.maybe_archive()
                self.drain_events()
                core.write_status(self.status())
            except Exception:
                log.exception("round failed")
            self.stop_event.wait(max(0.2, self.interval_sec - (time.monotonic() - started)))
        core.write_status(self.status(running=False))
        self.pool.shutdown(wait=False)
        log.info("logger stopped")

    def stop(self, *_):
        self.stop_event.set()


def setup_logging(quiet: bool):
    core.APP_DIR.mkdir(parents=True, exist_ok=True)
    log.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s  %(levelname)-7s %(message)s", "%Y-%m-%d %H:%M:%S")
    fh = logging.handlers.RotatingFileHandler(core.LOGGER_LOG, maxBytes=1_000_000,
                                              backupCount=3, encoding="utf-8")
    fh.setFormatter(fmt)
    log.addHandler(fh)
    if not quiet and sys.stderr:
        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        log.addHandler(sh)


def cmd_run(args):
    setup_logging(args.quiet)
    lock = SingleInstance(core.APP_DIR / "logger.lock")
    if not lock.acquire():
        msg = "Another Latency Checker logger is already running for " + str(core.APP_DIR)
        log.warning(msg)
        if not args.quiet:
            print(msg, file=sys.stderr)
            return 1
        # As a service: wait for the other one (e.g. started from the viewer) to stop,
        # instead of exiting and being restarted by the OS every few seconds.
        log.info("service will take over when it stops")
        while not lock.acquire():
            time.sleep(15)
    app = LatencyLogger(mode="service" if args.quiet else "manual")
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, app.stop)
        except (ValueError, OSError):
            pass
    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, app.stop)
    try:
        app.run()
    except KeyboardInterrupt:
        app.stop()
    return 0


# --------------------------------------------------------------------------- #
# Service installation
# --------------------------------------------------------------------------- #
def _target_user():
    """(user name, home) of the person installing — even when run through sudo."""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and os.name != "nt":
        import pwd
        pw = pwd.getpwnam(sudo_user)
        return sudo_user, Path(pw.pw_dir), pw.pw_uid, pw.pw_gid
    if os.name != "nt":
        import pwd
        pw = pwd.getpwuid(os.getuid())
        return pw.pw_name, Path(pw.pw_dir), pw.pw_uid, pw.pw_gid
    return os.environ.get("USERNAME", ""), Path.home(), None, None


def _base_python(windowless=False):
    """A Python interpreter outside any virtualenv/Documents folder (the logger needs no packages)."""
    if sys.prefix != sys.base_prefix:                   # running inside a venv
        if os.name == "nt":
            exe = Path(sys.base_prefix) / ("pythonw.exe" if windowless else "python.exe")
        else:
            v = f"python{sys.version_info.major}.{sys.version_info.minor}"
            exe = Path(sys.base_prefix) / "bin" / v
            if not exe.exists():
                exe = Path(sys.base_prefix) / "bin" / "python3"
    else:
        exe = Path(sys.executable)
        if os.name == "nt" and windowless and exe.name.lower() == "python.exe":
            w = exe.with_name("pythonw.exe")
            exe = w if w.exists() else exe
    return str(exe)


def _deploy(data_dir: Path):
    """Copy the logger into <data>/app so the service never depends on this folder.

    (On macOS a boot-time service may not read ~/Documents, ~/Desktop or ~/Downloads.)
    """
    app_dir = data_dir / "app"
    app_dir.mkdir(parents=True, exist_ok=True)
    if FROZEN:
        dst = app_dir / Path(sys.executable).name
        if Path(sys.executable).resolve() != dst.resolve():
            shutil.copy2(sys.executable, dst)
        return [str(dst)]
    for name in ("latency_core.py", "latency_logger.py"):
        shutil.copy2(HERE / name, app_dir / name)
    return [_base_python(windowless=True), str(app_dir / "latency_logger.py")]


def _chown_tree(path: Path, uid, gid):
    if uid is None or os.name == "nt" or os.geteuid() != 0:
        return
    for p in [path, *path.rglob("*")]:
        try:
            os.chown(p, uid, gid)
        except OSError:
            pass


def _sh(cmd, check=False):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed:\n{r.stdout}{r.stderr}")
    return r


def _mac_paths(at_login, home):
    if at_login:
        return home / "Library" / "LaunchAgents" / f"{SERVICE_LABEL}.plist", f"gui/{os.getuid()}"
    return Path("/Library/LaunchDaemons") / f"{SERVICE_LABEL}.plist", "system"


def install_macos(args, user, home, uid, gid, data):
    import plistlib
    if not args.at_login and os.geteuid() != 0:
        print("Starting at boot needs administrator rights. Run:\n"
              f"  sudo {sys.executable} {Path(__file__).name} install\n"
              "or use  install --at-login  to start when you log in (no admin needed).")
        return 1
    prog = _deploy(data) + ["run", "--home", str(data), "--quiet"]
    plist_path, domain = _mac_paths(args.at_login, home)
    plist = {
        "Label": SERVICE_LABEL,
        "ProgramArguments": prog,
        "RunAtLoad": True,
        "KeepAlive": True,                 # restart if it ever exits
        "ThrottleInterval": 10,
        "WorkingDirectory": str(data / "app"),
        "EnvironmentVariables": {"HOME": str(home), "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                                 "LATENCYCHECKER_HOME": str(data)},
        "StandardOutPath": str(data / "logger.stdout.log"),
        "StandardErrorPath": str(data / "logger.stdout.log"),
    }
    if not args.at_login:
        plist["UserName"] = user           # boot-time daemon, but running as you
    plist_path.parent.mkdir(parents=True, exist_ok=True)
    _sh(["launchctl", "bootout", f"{domain}/{SERVICE_LABEL}"])
    with open(plist_path, "wb") as fh:
        plistlib.dump(plist, fh)
    if not args.at_login:
        os.chown(plist_path, 0, 0)
        os.chmod(plist_path, 0o644)
    _chown_tree(data, uid, gid)
    _sh(["launchctl", "enable", f"{domain}/{SERVICE_LABEL}"])
    _sh(["launchctl", "bootstrap", domain, str(plist_path)], check=True)
    _sh(["launchctl", "kickstart", "-k", f"{domain}/{SERVICE_LABEL}"])
    when = "you log in" if args.at_login else "the Mac boots (even before anyone logs in)"
    print(f"Installed. The logger is running now and will start automatically when {when}.\n"
          f"  service file: {plist_path}\n  data:         {data}\n  its own log:  {data / 'logger.log'}")
    return 0


def uninstall_macos(args, home):
    removed = False
    for at_login in (False, True):
        plist_path, domain = _mac_paths(at_login, home)
        if plist_path.exists():
            if not at_login and os.geteuid() != 0:
                print(f"Removing {plist_path} needs sudo:\n  sudo {sys.executable} "
                      f"{Path(__file__).name} uninstall")
                return 1
            _sh(["launchctl", "bootout", f"{domain}/{SERVICE_LABEL}"])
            plist_path.unlink()
            removed = True
            print(f"Removed {plist_path}")
    if not removed:
        print("No Latency Checker service was installed.")
    return 0


def _ps_quote(s: str) -> str:
    return "'" + str(s).replace("'", "''") + "'"


def install_windows(args, user, home, data):
    import ctypes
    admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    if not args.at_login and not admin:
        print("Starting at boot needs an administrator prompt. Right-click "
              "install_service_windows.bat → Run as administrator, or use  install --at-login.")
        return 1
    prog = _deploy(data)
    exe, pre = prog[0], prog[1:]
    arguments = " ".join(f'"{a}"' for a in pre + ["run", "--home", str(data), "--quiet"])
    if args.at_login:
        trigger = "New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME"
        principal = "New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive"
    else:
        trigger = "New-ScheduledTaskTrigger -AtStartup"
        principal = "New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest"
    script = f"""
$ErrorActionPreference = 'Stop'
$a = New-ScheduledTaskAction -Execute {_ps_quote(exe)} -Argument {_ps_quote(arguments)} -WorkingDirectory {_ps_quote(data / 'app')}
$t = {trigger}
$p = {principal}
$s = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName {_ps_quote(WIN_TASK)} -Action $a -Trigger $t -Principal $p -Settings $s -Description 'Latency Checker headless logger' -Force | Out-Null
Start-ScheduledTask -TaskName {_ps_quote(WIN_TASK)}
"""
    r = _sh(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script])
    if r.returncode != 0:
        print("Could not register the scheduled task:\n" + r.stdout + r.stderr)
        return 1
    when = "you log in" if args.at_login else "Windows starts (before anyone logs in)"
    print(f"Installed as scheduled task '{WIN_TASK}'. It is running now and will start "
          f"automatically when {when}, restarting if it ever stops.\n"
          f"  data:        {data}\n  its own log: {data / 'logger.log'}")
    return 0


def uninstall_windows(args):
    script = (f"Stop-ScheduledTask -TaskName {_ps_quote(WIN_TASK)} -ErrorAction SilentlyContinue; "
              f"Unregister-ScheduledTask -TaskName {_ps_quote(WIN_TASK)} -Confirm:$false")
    r = _sh(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script])
    print("Removed the scheduled task." if r.returncode == 0 else
          "Could not remove the task (not installed, or run this from an administrator prompt):\n"
          + r.stderr)
    return 0 if r.returncode == 0 else 1


def _linux_unit_paths(home):
    """(system unit, user unit)."""
    return (Path("/etc/systemd/system") / LINUX_UNIT,
            home / ".config" / "systemd" / "user" / LINUX_UNIT)


def _systemctl_user(*a):
    return _sh(["systemctl", "--user", *a])


def install_linux(args, user, home, uid, gid, data):
    if shutil.which("systemctl") is None:
        print("systemd was not found. Run the logger from your init system or cron instead:\n"
              f"  {_base_python()} {HERE / 'latency_logger.py'} run --quiet")
        return 1
    if args.at_login and os.geteuid() == 0:
        print("A per-user service must be installed as you, not root. Run without sudo:\n"
              f"  {sys.executable} {Path(__file__).name} install --at-login")
        return 1
    if not args.at_login and os.geteuid() != 0:
        print("Starting at boot needs root. Run:\n"
              f"  sudo {sys.executable} {Path(__file__).name} install\n"
              "or use  install --at-login  for a per-user service (no root needed).")
        return 1
    prog = _deploy(data) + ["run", "--home", str(data), "--quiet"]
    exec_start = " ".join(f'"{p}"' for p in prog)
    system_path, user_path = _linux_unit_paths(home)
    if args.at_login:
        unit = f"""[Unit]
Description=Latency Checker logger (user)
After=network.target

[Service]
Environment=LATENCYCHECKER_HOME={data}
Environment=LC_ALL=C
ExecStart={exec_start}
Restart=always
RestartSec=10

[Install]
WantedBy=default.target
"""
        user_path.parent.mkdir(parents=True, exist_ok=True)
        user_path.write_text(unit)
        _systemctl_user("daemon-reload")
        r = _systemctl_user("enable", "--now", LINUX_UNIT)
        if r.returncode != 0:
            print("systemctl --user failed:\n" + r.stdout + r.stderr)
            return 1
        print(f"Installed {user_path}; running now and whenever you log in.\n"
              "Tip: to keep it running while you're logged out (and start it at boot) run\n"
              f"  sudo loginctl enable-linger {user}")
        return 0
    unit = f"""[Unit]
Description=Latency Checker logger
After=network.target

[Service]
User={user}
Environment=LATENCYCHECKER_HOME={data}
Environment=LC_ALL=C
ExecStart={exec_start}
Restart=always
RestartSec=10
Nice=5

[Install]
WantedBy=multi-user.target
"""
    system_path.write_text(unit)
    _chown_tree(data, uid, gid)
    _sh(["systemctl", "daemon-reload"], check=True)
    _sh(["systemctl", "enable", "--now", LINUX_UNIT], check=True)
    print(f"Installed {system_path}; the logger is running now and starts at every boot "
          f"(as {user}), restarting if it ever stops.\n"
          f"  data:        {data}\n  its own log: {data / 'logger.log'}\n"
          f"  journal:     journalctl -u {LINUX_UNIT}")
    return 0


def uninstall_linux(args, home):
    system_path, user_path = _linux_unit_paths(home)
    removed = False
    if user_path.exists():
        _systemctl_user("disable", "--now", LINUX_UNIT)
        user_path.unlink()
        _systemctl_user("daemon-reload")
        print(f"Removed {user_path}")
        removed = True
    if system_path.exists():
        if os.geteuid() != 0:
            print(f"Removing {system_path} needs root:\n  sudo {sys.executable} "
                  f"{Path(__file__).name} uninstall")
            return 1
        _sh(["systemctl", "disable", "--now", LINUX_UNIT])
        system_path.unlink()
        _sh(["systemctl", "daemon-reload"])
        print(f"Removed {system_path}")
        removed = True
    if not removed:
        print("No Latency Checker service was installed.")
    return 0


def cmd_install(args):
    user, home, uid, gid = _target_user()
    data = Path(args.home).expanduser() if args.home else home / "LatencyChecker"
    core.set_home(data)
    data.mkdir(parents=True, exist_ok=True)
    if not core.CONFIG_PATH.exists():
        core.save_config(core.load_config())
    if core.SYSTEM == "Darwin":
        return install_macos(args, user, home, uid, gid, data)
    if core.SYSTEM == "Windows":
        return install_windows(args, user, home, data)
    return install_linux(args, user, home, uid, gid, data)


def cmd_uninstall(args):
    user, home, uid, gid = _target_user()
    if core.SYSTEM == "Darwin":
        return uninstall_macos(args, home)
    if core.SYSTEM == "Windows":
        return uninstall_windows(args)
    return uninstall_linux(args, home)


def cmd_status(args):
    user, home, _, _ = _target_user()
    if not args.home and os.environ.get("SUDO_USER"):
        core.set_home(home / "LatencyChecker")
    print(f"Data folder: {core.APP_DIR}")
    if core.SYSTEM == "Darwin":
        found = False
        for at_login in (False, True):
            plist_path, domain = _mac_paths(at_login, home)
            if plist_path.exists():
                found = True
                r = _sh(["launchctl", "print", f"{domain}/{SERVICE_LABEL}"])
                state = next((ln.strip() for ln in r.stdout.splitlines()
                              if ln.strip().startswith("state =")), "state = unknown (try with sudo)")
                print(f"Service: installed ({'at login' if at_login else 'at boot'}), {state}")
        if not found:
            print("Service: not installed")
    elif core.SYSTEM == "Windows":
        r = _sh(["schtasks", "/Query", "/TN", WIN_TASK, "/FO", "LIST"])
        print("Service: " + ("installed\n" + r.stdout.strip() if r.returncode == 0 else "not installed"))
    else:
        system_path, user_path = _linux_unit_paths(home)
        found = False
        if system_path.exists():
            found = True
            r = _sh(["systemctl", "is-active", LINUX_UNIT])
            print(f"Service: installed (at boot), {r.stdout.strip() or 'unknown'}")
        if user_path.exists():
            found = True
            r = _systemctl_user("is-active", LINUX_UNIT)
            print(f"Service: installed (at login, user), {r.stdout.strip() or 'unknown'}")
        if not found:
            print("Service: not installed")
    st = core.read_status()
    if not st:
        print("Logger: has not run yet")
    else:
        age = time.time() - float(st.get("heartbeat", 0))
        alive = core.logger_alive(st)
        print(f"Logger: {'RUNNING' if alive else 'not running'} — last heartbeat {age:.0f}s ago, "
              f"pid {st.get('pid')}, {st.get('mode')} mode")
        gw = st.get("gateway") or {}
        print(f"  gateway {gw.get('ip') or '–'} ({gw.get('iface') or '–'}), "
              f"public IP {st.get('public_ip') or '–'}, {st.get('targets')} targets "
              f"every {st.get('interval_sec')}s")
        print(f"  logs: {st.get('log_dir')}")
    return 0


def cmd_archive(args):
    """Compress finished daily logs right now (works while the service is running)."""
    setup_logging(quiet=False)
    cfg = core.load_config()
    log_dir = Path(cfg.get("log_dir") or core.APP_DIR / "logs")
    keep = max(1, int(cfg.get("compress_after_days", 1)))
    n, before, after = core.archive_old_logs(log_dir, keep, log)
    if not n:
        print(f"Nothing to compress in {log_dir} (finished days are already .csv.gz).")
    else:
        print(f"Compressed {n} file(s) in {log_dir}: {core.fmt_bytes(before)} → {core.fmt_bytes(after)}")
    return 0


def cmd_restart(args):
    """Restart the installed service (it archives old logs again as it starts)."""
    user, home, _, _ = _target_user()
    if core.SYSTEM == "Darwin":
        for at_login in (False, True):
            plist_path, domain = _mac_paths(at_login, home)
            if plist_path.exists():
                if not at_login and os.geteuid() != 0:
                    print(f"Restarting the boot service needs sudo:\n  sudo {sys.executable} "
                          f"{Path(__file__).name} restart")
                    return 1
                r = _sh(["launchctl", "kickstart", "-k", f"{domain}/{SERVICE_LABEL}"])
                print("Restarted." if r.returncode == 0 else "Restart failed:\n" + r.stderr)
                return r.returncode
        print("No Latency Checker service is installed.")
        return 1
    if core.SYSTEM == "Windows":
        _sh(["schtasks", "/End", "/TN", WIN_TASK])
        time.sleep(2)
        r = _sh(["schtasks", "/Run", "/TN", WIN_TASK])
        print("Restarted." if r.returncode == 0 else
              "Restart failed (installed? run from an administrator prompt):\n" + r.stderr)
        return r.returncode
    system_path, user_path = _linux_unit_paths(home)
    if user_path.exists():
        r = _systemctl_user("restart", LINUX_UNIT)
    elif system_path.exists():
        if os.geteuid() != 0:
            print(f"Restarting the boot service needs root:\n  sudo {sys.executable} "
                  f"{Path(__file__).name} restart")
            return 1
        r = _sh(["systemctl", "restart", LINUX_UNIT])
    else:
        print("No Latency Checker service is installed.")
        return 1
    print("Restarted." if r.returncode == 0 else "Restart failed:\n" + r.stderr)
    return r.returncode


def main(argv=None):
    ap = argparse.ArgumentParser(description="Latency Checker headless logger")
    ap.add_argument("command", nargs="?", default="run",
                    choices=["run", "install", "uninstall", "status", "archive", "restart"])
    ap.add_argument("--home", help="data folder (default ~/LatencyChecker)")
    ap.add_argument("--quiet", action="store_true", help="no console output (used by the service)")
    ap.add_argument("--at-login", action="store_true",
                    help="install: start when you log in instead of at boot (no admin rights)")
    args = ap.parse_args(argv)
    if args.home:
        core.set_home(args.home)
    return {"run": cmd_run, "install": cmd_install, "uninstall": cmd_uninstall,
            "status": cmd_status, "archive": cmd_archive,
            "restart": cmd_restart}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
