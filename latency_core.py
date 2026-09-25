#!/usr/bin/env python3
"""
latency_core — shared code for the Latency Checker logger and viewer.

Standard library only, so the headless logger runs on any Python 3.9+ without
extra packages. Contains: ping + parsing, default-gateway detection, public-IP
lookup, the CSV log format, config/status files and the history aggregation
used by the viewer.
"""

import csv
import gzip
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import struct
import subprocess
import threading
import time
import urllib.request
from collections import OrderedDict
from datetime import date, datetime, timedelta
from pathlib import Path

APP_NAME = "Latency Checker"
SYSTEM = platform.system()  # "Darwin", "Windows", "Linux"
VERSION = "4.1"

# Data folder (config, status, logs). Override with LATENCYCHECKER_HOME or set_home().
APP_DIR = Path(os.environ.get("LATENCYCHECKER_HOME") or (Path.home() / "LatencyChecker"))
CONFIG_PATH = APP_DIR / "config.json"
STATUS_PATH = APP_DIR / "status.json"     # heartbeat written by the logger, read by the viewer
LOGGER_LOG = APP_DIR / "logger.log"       # the logger's own diagnostic log

DEFAULT_CONFIG = {
    "targets": [
        {"host": "1.1.1.1", "label": "Cloudflare DNS"},
        {"host": "8.8.8.8", "label": "Google DNS"},
    ],
    "interval_sec": 5,
    "timeout_ms": 1000,
    "log_dir": str(APP_DIR / "logs"),
    "auto_gateway": True,
    "public_ip": True,          # look up and log the public (internet-facing) IP
    "compress_logs": True,      # gzip finished daily logs (latency_YYYY-MM-DD.csv.gz)
    "compress_after_days": 1,   # 1 = every day before today; 2 = keep yesterday plain too
    # viewer-only settings
    "span_sec": 3600,
    "theme": "system",          # "system", "dark" or "light"
}


def set_home(path):
    """Point every data file at another folder (used by the service)."""
    global APP_DIR, CONFIG_PATH, STATUS_PATH, LOGGER_LOG
    APP_DIR = Path(path).expanduser().resolve()
    CONFIG_PATH = APP_DIR / "config.json"
    STATUS_PATH = APP_DIR / "status.json"
    LOGGER_LOG = APP_DIR / "logger.log"
    DEFAULT_CONFIG["log_dir"] = str(APP_DIR / "logs")


# --------------------------------------------------------------------------- #
# Config + status files (shared between the two apps)
# --------------------------------------------------------------------------- #
def _atomic_write(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + f".{os.getpid()}.tmp")
    tmp.write_text(text, encoding="utf-8")
    for _ in range(20):             # Windows: the reader may hold the file for a moment
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            time.sleep(0.05)
    os.replace(tmp, path)


def load_config():
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    raw = {}
    try:
        if CONFIG_PATH.exists():
            raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        raw = {}
    cfg.update(raw)
    if "span_sec" not in raw and "window" in raw:        # migrate the v1/v2 viewer setting
        legacy = {"5 min": 300, "15 min": 900, "1 hour": 3600, "6 hours": 21600,
                  "24 hours": 86400, "1 day": 86400, "1 week": 604800,
                  "1 month": 2592000, "All": 86400}
        cfg["span_sec"] = legacy.get(raw["window"], 3600)
    cfg.pop("window", None)
    cfg["targets"] = [t for t in cfg.get("targets", []) if t.get("host")]
    return cfg


def save_config(cfg: dict):
    _atomic_write(CONFIG_PATH, json.dumps(cfg, indent=2))


def config_mtime():
    try:
        return CONFIG_PATH.stat().st_mtime
    except OSError:
        return None


def write_status(status: dict):
    try:
        _atomic_write(STATUS_PATH, json.dumps(status, indent=1))
    except Exception:
        pass


def read_status():
    """The logger's last heartbeat, or None."""
    try:
        return json.loads(STATUS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return None


def logger_alive(status, now=None):
    """True if the logger wrote a heartbeat recently (≈ 3 rounds, at least 30 s)."""
    if not status:
        return False
    try:
        age = (now or time.time()) - float(status["heartbeat"])
        return age < max(30.0, 3 * float(status.get("interval_sec", 5)) + 10)
    except Exception:
        return False


GATEWAY_KEY = "@gateway"          # internal id of the auto-detected gateway target
GATEWAY_LABEL = "Local gateway"
# Tunnel / VPN interfaces are skipped so the *local* network's gateway is found.
_TUNNEL_PREFIXES = ("utun", "ipsec", "ppp", "tun", "tap", "wg", "gif", "stf", "zt")
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

RAW_MAX_SPAN = 3600      # windows up to 1 h show every sample; longer ones are averaged
TARGET_BUCKETS = 360     # aim for ~this many averaged points across the graph
BUCKET_SIZES = [60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400]
AGG_LOSS_MARK = 0.02     # averaged views mark a bucket with × when loss ≥ 2 %
RAW_DAY_CACHE = 3        # past days kept in memory at full resolution

MAX_POINTS_PER_TARGET = 200_000
COLORS = ["#3b82f6", "#f59e0b", "#10b981", "#ec4899", "#8b5cf6",
          "#06b6d4", "#ef4444", "#84cc16", "#f97316", "#64748b"]

# Matches "time=12.3 ms", "time<1ms", "tempo=12ms", "Zeit=4ms", etc.
_TIME_RE = re.compile(r"[=<]\s*([0-9]+(?:[.,][0-9]+)?)\s*ms", re.IGNORECASE)
_DNS_ERR = ("unknown host", "cannot resolve", "could not find host",
            "name or service not known", "temporary failure in name resolution")


# --------------------------------------------------------------------------- #
# Ping
# --------------------------------------------------------------------------- #
def parse_ping_output(text: str, returncode: int, system: str = SYSTEM):
    """Return (latency_ms | None, status) from ping output."""
    low = text.lower()
    if any(s in low for s in _DNS_ERR):
        return None, "dns error"
    if returncode != 0:
        return None, "timeout"
    # Windows can return 0 for "Destination host unreachable" – a real reply has TTL.
    if system == "Windows" and "ttl=" not in low:
        return None, "unreachable"
    for line in text.splitlines():
        if "ttl" in line.lower() or "bytes" in line.lower() or "time" in line.lower():
            m = _TIME_RE.search(line.split(":", 1)[-1])
            if m:
                return float(m.group(1).replace(",", ".")), "ok"
    m = _TIME_RE.search(text)
    if m:
        return float(m.group(1).replace(",", ".")), "ok"
    return None, "parse error"


# Tool output (ping, netstat, ip) in plain English/C locale on macOS and Linux, so the
# parsers work whatever language the system uses.
_TOOL_ENV = None if os.name == "nt" else {**os.environ, "LC_ALL": "C", "LANG": "C"}


def ping(host: str, timeout_ms: int):
    """Send one ICMP echo using the system ping command."""
    kwargs = {} if _TOOL_ENV is None else {"env": _TOOL_ENV}
    if SYSTEM == "Windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), host]
        kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW: no console flash
    elif SYSTEM == "Darwin":
        cmd = ["ping", "-c", "1", "-W", str(timeout_ms), host]  # -W in ms on macOS
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, round(timeout_ms / 1000))), host]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                              timeout=timeout_ms / 1000 + 3, **kwargs)
    except subprocess.TimeoutExpired:
        return None, "timeout"
    except FileNotFoundError:
        return None, "ping missing"      # Linux: install iputils-ping (Debian/Ubuntu)
    except Exception as exc:  # pragma: no cover
        return None, f"error: {exc}"
    return parse_ping_output(proc.stdout + proc.stderr, proc.returncode)


# --------------------------------------------------------------------------- #
# Default-gateway detection
# --------------------------------------------------------------------------- #
def _is_tunnel(iface: str) -> bool:
    return iface.lower().startswith(_TUNNEL_PREFIXES)


def parse_gateway_macos(netstat_out: str):
    """Parse `netstat -rn -f inet`. Returns (gateway, interface) or (None, None)."""
    for line in netstat_out.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0] == "default" and _IPV4_RE.match(parts[1]):
            iface = parts[3] if not parts[3].isdigit() else parts[-1]
            if not _is_tunnel(iface):
                return parts[1], iface
    return None, None


def parse_gateway_macos_route(route_out: str):
    """Fallback: parse `route -n get default`."""
    gw = iface = None
    for line in route_out.splitlines():
        k, _, v = line.strip().partition(":")
        if k == "gateway" and _IPV4_RE.match(v.strip()):
            gw = v.strip()
        elif k == "interface":
            iface = v.strip()
    return (gw, iface) if gw else (None, None)


def parse_gateway_windows(route_out: str):
    """Parse `route print -4 0.0.0.0`; picks the active default route with the lowest metric."""
    best = None
    for line in route_out.splitlines():
        p = line.split()
        # Active routes: dest netmask gateway interface metric  (5 columns, metric numeric)
        if (len(p) == 5 and p[0] == "0.0.0.0" and p[1] == "0.0.0.0"
                and _IPV4_RE.match(p[2]) and p[4].isdigit()):
            if best is None or int(p[4]) < best[2]:
                best = (p[2], p[3], int(p[4]))
    return (best[0], best[1]) if best else (None, None)


def parse_gateway_linux_proc(route_table: str):
    """Parse /proc/net/route (always present on Linux, no tools needed).

    Default route = destination 00000000 with the UP+GATEWAY flags; the gateway is a
    little-endian hex IPv4. The lowest metric wins; tunnel/VPN interfaces are skipped.
    """
    best = None
    for line in route_table.splitlines()[1:]:
        p = line.split()
        if len(p) < 8:
            continue
        iface, dest, gw, flags, metric, mask = p[0], p[1], p[2], p[3], p[6], p[7]
        try:
            if dest != "00000000" or mask != "00000000" or (int(flags, 16) & 0x3) != 0x3:
                continue
            ip = socket.inet_ntoa(struct.pack("<L", int(gw, 16)))
            m = int(metric)
        except (ValueError, struct.error):
            continue
        if ip != "0.0.0.0" and not _is_tunnel(iface) and (best is None or m < best[2]):
            best = (ip, iface, m)
    return (best[0], best[1]) if best else (None, None)


def parse_gateway_linux(ip_out: str):
    """Parse `ip -4 route show default`."""
    best = None
    for line in ip_out.splitlines():
        p = line.split()
        if "via" in p and "dev" in p:
            gw, iface = p[p.index("via") + 1], p[p.index("dev") + 1]
            metric = int(p[p.index("metric") + 1]) if "metric" in p else 0
            if _IPV4_RE.match(gw) and not _is_tunnel(iface):
                if best is None or metric < best[2]:
                    best = (gw, iface, metric)
    return (best[0], best[1]) if best else (None, None)


def _run(cmd):
    kwargs = {"creationflags": 0x08000000} if SYSTEM == "Windows" else {"env": _TOOL_ENV}
    return subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                          timeout=5, **kwargs).stdout


def detect_gateway():
    """Return (gateway_ip, interface) for the current local network, or (None, None)."""
    try:
        if SYSTEM == "Darwin":
            gw = parse_gateway_macos(_run(["netstat", "-rn", "-f", "inet"]))
            return gw if gw[0] else parse_gateway_macos_route(_run(["route", "-n", "get", "default"]))
        if SYSTEM == "Windows":
            return parse_gateway_windows(_run(["route", "print", "-4", "0.0.0.0"]))
        try:
            with open("/proc/net/route", encoding="ascii", errors="replace") as fh:
                gw = parse_gateway_linux_proc(fh.read())
            if gw[0]:
                return gw
        except OSError:
            pass
        return parse_gateway_linux(_run(["ip", "-4", "route", "show", "default"]))
    except Exception:
        return None, None


# --------------------------------------------------------------------------- #
# Public IP
# --------------------------------------------------------------------------- #
# Plain-text "what is my IP" services, tried in order until one answers.
PUBLIC_IP_SERVICES = ["https://api.ipify.org", "https://ifconfig.me/ip",
                      "https://icanhazip.com", "https://checkip.amazonaws.com"]
PUBLIC_IP_REFRESH = 300      # re-check every 5 min (and right after a network change)
PUBLIC_IP_RETRY = 30         # retry sooner when the lookup failed


def fetch_public_ip(timeout: float = 4.0):
    """Return the current public IP as a string, or None if no service answered."""
    for url in PUBLIC_IP_SERVICES:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "LatencyChecker/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                txt = resp.read(64).decode("ascii", "replace").strip()
            return str(ipaddress.ip_address(txt))
        except Exception:
            continue
    return None


class PublicIPWatcher(threading.Thread):
    """Keeps app.public_ip current. Runs on its own so a slow lookup never delays pings."""

    def __init__(self, app):
        super().__init__(daemon=True)
        self.app = app
        self.wake = threading.Event()

    def trigger(self):
        """Network changed: forget the old IP (so it isn't logged by mistake) and re-check."""
        if self.app.public_ip_enabled:
            self.app.public_ip = None
        self.wake.set()

    def run(self):
        while True:
            if self.app.public_ip_enabled:
                if self.wake.is_set():
                    self.wake.clear()
                    time.sleep(3)          # give a new network a moment to come up
                ip = fetch_public_ip()
                prev = self.app.public_ip
                if ip != prev and self.app.public_ip_enabled:
                    self.app.public_ip = ip
                    self.app.results.put(("pub", datetime.now(), ip, self.app.last_public_ip))
                    if ip:
                        self.app.last_public_ip = ip
                wait = PUBLIC_IP_REFRESH if ip else PUBLIC_IP_RETRY
            else:
                wait = 3600
            self.wake.wait(wait)


# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #
LOG_FIELDS = ["timestamp", "host", "label", "latency_ms", "status", "role", "public_ip"]


class CsvLogger:
    """Appends results to <log_dir>/latency_YYYY-MM-DD.csv (one file per day)."""

    def __init__(self, log_dir: Path):
        self.log_dir = Path(log_dir)
        self._lock = threading.Lock()
        self._checked = set()

    def path_for(self, day: datetime) -> Path:
        return self.log_dir / f"latency_{day:%Y-%m-%d}.csv"

    def _upgrade_header(self, path: Path):
        """A file started by an older version gets the current header (rows are kept)."""
        if path in self._checked:
            return
        self._checked.add(path)
        try:
            if not path.exists():
                return
            with open(path, newline="", encoding="utf-8") as fh:
                first = fh.readline()
            if not first.startswith("timestamp") or first.strip() == ",".join(LOG_FIELDS):
                return
            with open(path, newline="", encoding="utf-8") as fh:   # keep line endings as-is
                text = fh.read()
            eol = "\r\n" if first.endswith("\r\n") else "\n"
            body = text[len(first):]
            tmp = path.with_suffix(".tmp")
            with open(tmp, "w", newline="", encoding="utf-8") as fh:
                fh.write(",".join(LOG_FIELDS) + eol + body)
            os.replace(tmp, path)
        except Exception:
            pass

    def write(self, ts: datetime, host: str, label: str, latency, status: str,
              role: str = "target", public_ip: str = ""):
        with self._lock:
            self.log_dir.mkdir(parents=True, exist_ok=True)
            path = self.path_for(ts)
            self._upgrade_header(path)
            new = not path.exists()
            with open(path, "a", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                if new:
                    w.writerow(LOG_FIELDS)
                w.writerow([ts.isoformat(timespec="seconds"), host, label,
                            "" if latency is None else f"{latency:.2f}", status, role,
                            public_ip or ""])

    def read_since(self, since: datetime, keys):
        """Yield (ts, key, host, latency) from log files newer than `since`.

        `key` is the host for normal targets and GATEWAY_KEY for gateway rows.
        """
        day = since.date()
        today = date.today()
        while day <= today:
            for path in self.day_files(day):
                for ts, key, host, lat in iter_log_file(path):
                    if key in keys and ts >= since:
                        yield ts, key, host, lat
            day += timedelta(days=1)

    def day_files(self, day):
        """Existing files holding that day's rows: the archive first, then plain CSV."""
        base = self.log_dir / f"latency_{day:%Y-%m-%d}.csv"
        gz = base.with_name(base.name + ".gz")
        return [p for p in (gz, base) if p.exists()]


def open_log(path: Path):
    """Open a daily log for reading as text — plain .csv or gzip'd .csv.gz alike."""
    if path.name.endswith(".gz"):
        return gzip.open(path, "rt", newline="", encoding="utf-8", errors="replace")
    return open(path, newline="", encoding="utf-8", errors="replace")


def iter_log_rows(path: Path):
    """Yield (ts, key, host, latency, status, public_ip) for every row of a daily log."""
    if not path.exists():
        return
    try:
        with open_log(path) as fh:
            for row in csv.reader(fh):
                parsed = parse_row(row)
                if parsed:
                    yield parsed
    except (OSError, EOFError, gzip.BadGzipFile):
        return


def iter_log_file(path: Path):
    """Yield (ts, key, host, latency) for every row of one daily log (.csv or .csv.gz)."""
    for ts, key, host, lat, _status, _pub in iter_log_rows(path):
        yield ts, key, host, lat


# --------------------------------------------------------------------------- #
# Networks seen (public IPs + local gateways) and their user-given names
# --------------------------------------------------------------------------- #
def new_nets():
    return {"pub": {}, "gw": {}}      # ip -> [first_iso, last_iso, samples]


def nets_add(nets, kind, ip, ts_iso):
    if not ip:
        return
    e = nets[kind].get(ip)
    if e is None:
        nets[kind][ip] = [ts_iso, ts_iso, 1]
    else:
        if ts_iso < e[0]:
            e[0] = ts_iso
        if ts_iso > e[1]:
            e[1] = ts_iso
        e[2] += 1


def nets_merge(into, other):
    for kind in ("pub", "gw"):
        for ip, (a, b, n) in other.get(kind, {}).items():
            e = into[kind].get(ip)
            if e is None:
                into[kind][ip] = [a, b, n]
            else:
                e[0], e[1], e[2] = min(e[0], a), max(e[1], b), e[2] + n


def nets_from_rows(rows):
    """Inventory from (ts, key, host, latency, status, public_ip) rows."""
    nets = new_nets()
    for ts, key, host, _lat, _st, pub in rows:
        iso = ts.isoformat(timespec="seconds")
        nets_add(nets, "pub", pub, iso)
        if key == GATEWAY_KEY:
            nets_add(nets, "gw", host, iso)
    return nets


def log_days(log_dir):
    """Every date that has a daily log (plain or compressed), oldest first."""
    days = set()
    try:
        for p in Path(log_dir).iterdir():
            m = re.match(r"^latency_(\d{4}-\d{2}-\d{2})\.csv(\.gz)?$", p.name)
            if m:
                try:
                    days.add(date.fromisoformat(m.group(1)))
                except ValueError:
                    pass
    except OSError:
        pass
    return sorted(days)


def scan_networks(logger, progress=None):
    """All public IPs and local gateways found in the logs, with first/last seen.

    Past days come from the per-day summaries (fast); today is read directly.
    Uses its own HistoryStore, so it is safe to run in a background thread.
    """
    store = HistoryStore(logger)
    nets = new_nets()
    days = log_days(logger.log_dir)
    today = date.today()
    for i, d in enumerate(days):
        if d == today:
            rows = (r for p in logger.day_files(d) for r in iter_log_rows(p))
            nets_merge(nets, nets_from_rows(rows))
        else:
            nets_merge(nets, store.networks(d))
        if progress:
            progress(i + 1, len(days))
    return nets


def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def ip_label(ip, names, fallback="–"):
    """'Lisbon home (46.172.248.156)' when named, else the bare IP."""
    if not ip:
        return fallback
    name = (names or {}).get(ip)
    return f"{name} ({ip})" if name else ip


def lookup_ip_owner(ip: str, timeout: float = 5.0):
    """Best-effort 'ISP · City, Country' for a public IP (asks ipinfo.io). None on failure."""
    if not ip or is_private_ip(ip):
        return None
    try:
        req = urllib.request.Request(f"https://ipinfo.io/{ip}/json",
                                     headers={"User-Agent": "LatencyChecker/1.0",
                                              "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            info = json.loads(resp.read(4096).decode("utf-8", "replace"))
    except Exception:
        return None
    org = re.sub(r"^AS\d+\s+", "", info.get("org") or "").strip()
    place = ", ".join(x for x in (info.get("city"), info.get("country")) if x)
    return " · ".join(x for x in (org, place) if x) or None


def parse_row(row):
    """Positional parse of one CSV row (column order is the same in every version).

    Returns (ts, key, host, latency, status, public_ip) or None for header/bad rows.
    """
    if not row or row[0] == "timestamp":
        return None
    row = list(row) + [""] * (len(LOG_FIELDS) - len(row))
    try:
        ts = datetime.fromisoformat(row[0])
        lat = float(row[3]) if row[3] else None
    except ValueError:
        return None
    host, status, role, pub = row[1], row[4], row[5], row[6]
    key = GATEWAY_KEY if role == "gateway" else host
    return ts, key, host, lat, status, pub


class LogTail:
    """Follows today's log file and returns only rows appended since the last call.

    This is how the viewer gets live data from the separately running logger.
    Switches to the new file automatically after midnight.
    """

    def __init__(self, logger: CsvLogger):
        self.logger = logger
        self.path = None
        self.offset = 0

    def skip_to_end(self):
        self.path = self.logger.path_for(datetime.now())
        try:
            self.offset = self.path.stat().st_size
        except OSError:
            self.offset = 0

    def read_new(self):
        rows = []
        path = self.logger.path_for(datetime.now())
        if path != self.path:
            if self.path is not None:            # finish yesterday's file first
                rows += self._read(self.path)
            self.path, self.offset = path, 0
        rows += self._read(self.path)
        return rows

    def _read(self, path):
        try:
            size = path.stat().st_size
        except OSError:
            return []
        if size < self.offset:                   # file replaced / rewritten
            self.offset = 0
        if size == self.offset:
            return []
        with open(path, "rb") as fh:
            fh.seek(self.offset)
            chunk = fh.read()
        end = chunk.rfind(b"\n")
        if end < 0:                              # partial line — wait for the rest
            return []
        self.offset += end + 1
        text = chunk[:end + 1].decode("utf-8", "replace")
        out = []
        for row in csv.reader(text.splitlines()):
            parsed = parse_row(row)
            if parsed:
                out.append(parsed)
        return out


# --------------------------------------------------------------------------- #
# Archiving: gzip finished daily logs
# --------------------------------------------------------------------------- #
_DAY_RE = re.compile(r"^latency_(\d{4}-\d{2}-\d{2})\.csv(\.part)?$")


def _count_lines(fh, chunk=1 << 20):
    n = 0
    while True:
        b = fh.read(chunk)
        if not b:
            return n
        n += b.count(b"\n")


def fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def archive_old_logs(log_dir, keep_days: int = 1, log=None):
    """Compress daily logs older than `keep_days` into latency_YYYY-MM-DD.csv.gz.

    Safe to run while the logger and viewer are running:
      1. the .csv is renamed to .csv.part first (on Windows this fails while another
         program has it open → that day is simply retried next time);
      2. the .gz is written to a temp file (appending to an existing archive of the
         same day, if there is one), then decompressed again and line-counted;
      3. only then is it moved into place and the .part removed.
    Returns (files_compressed, bytes_before, bytes_after).
    """
    log_dir = Path(log_dir)
    say = (log.info if log else (lambda *a: None))
    warn = (log.warning if log else (lambda *a: None))
    if not log_dir.is_dir():
        return 0, 0, 0
    lock = log_dir / ".archive.lock"
    try:
        if lock.exists() and time.time() - lock.stat().st_mtime > 3600:
            lock.unlink()                               # stale lock from a crash
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.close(fd)
    except FileExistsError:
        say("archiving already in progress elsewhere — skipped")
        return 0, 0, 0
    except OSError as exc:
        warn("cannot archive in %s: %s", log_dir, exc)
        return 0, 0, 0

    cutoff = date.today() - timedelta(days=max(1, int(keep_days)) - 1)
    done, before, after = 0, 0, 0
    try:
        for src in sorted(log_dir.iterdir()):
            m = _DAY_RE.match(src.name)
            if not m:
                continue
            try:
                day = date.fromisoformat(m.group(1))
            except ValueError:
                continue
            if day >= cutoff:
                continue                                # today (and kept days) stay plain
            base = log_dir / f"latency_{m.group(1)}.csv"
            part = base.with_name(base.name + ".part")
            gz = base.with_name(base.name + ".gz")
            tmp = gz.with_name(gz.name + ".tmp")
            try:
                if not m.group(2):                      # claim the plain file
                    if part.exists():
                        continue                        # handled via the .part entry
                    os.replace(base, part)
                size_in = part.stat().st_size
                old_gz = gz.stat().st_size if gz.exists() else 0
                expected = 0
                with gzip.open(tmp, "wb", compresslevel=9) as out:
                    if gz.exists():                     # same day archived before: keep it
                        with gzip.open(gz, "rb") as old:
                            expected += _count_lines(old)
                        with gzip.open(gz, "rb") as old:
                            shutil.copyfileobj(old, out)
                    with open(part, "rb") as fh:
                        data = fh.read()
                    if gz.exists() and data.startswith(b"timestamp"):
                        data = data[data.find(b"\n") + 1:]   # one header is enough
                    if data and not data.endswith(b"\n"):
                        data += b"\n"
                    out.write(data)
                    expected += data.count(b"\n")
                with gzip.open(tmp, "rb") as chk:     # verify before replacing anything
                    got = _count_lines(chk)
                if got != expected:
                    raise IOError(f"verification failed ({got} != {expected} lines)")
                os.replace(tmp, gz)
                try:
                    part.unlink()
                except OSError:
                    pass
                size_out = gz.stat().st_size
                before += size_in + old_gz
                after += size_out
                done += 1
            except PermissionError:
                warn("%s is in use — will compress it next time", src.name)
                if not m.group(2) and part.exists() and not base.exists():
                    try:
                        os.replace(part, base)          # give it back untouched
                    except OSError:
                        pass
            except Exception as exc:
                warn("could not compress %s: %s", src.name, exc)
                try:
                    tmp.unlink()
                except OSError:
                    pass
                if part.exists() and not base.exists():
                    try:
                        os.replace(part, base)
                    except OSError:
                        pass
    finally:
        try:
            lock.unlink()
        except OSError:
            pass
    if done:
        say("compressed %d daily log%s: %s → %s", done, "" if done == 1 else "s",
            fmt_bytes(before), fmt_bytes(after))
    return done, before, after


# --------------------------------------------------------------------------- #
# Aggregation helpers (averaging for long time ranges)
# --------------------------------------------------------------------------- #
def new_acc():
    # [sum, ok_count, lost_count, min, max]
    return [0.0, 0, 0, float("inf"), float("-inf")]


def acc_add(acc, latency):
    if latency is None:
        acc[2] += 1
    else:
        acc[0] += latency
        acc[1] += 1
        acc[3] = min(acc[3], latency)
        acc[4] = max(acc[4], latency)


def acc_merge(acc, other):
    acc[0] += other[0]
    acc[1] += other[1]
    acc[2] += other[2]
    acc[3] = min(acc[3], other[3])
    acc[4] = max(acc[4], other[4])


def floor_ts(ts: datetime, secs: int) -> datetime:
    """Floor a timestamp to a bucket boundary aligned to local midnight."""
    midnight = ts.replace(hour=0, minute=0, second=0, microsecond=0)
    s = (ts - midnight).total_seconds()
    return midnight + timedelta(seconds=(s // secs) * secs)


def bucket_size_for(span_sec: float):
    """None → show raw samples; otherwise bucket length in seconds."""
    if span_sec <= RAW_MAX_SPAN + 1:
        return None
    want = span_sec / TARGET_BUCKETS
    for b in BUCKET_SIZES:
        if b >= want:
            return b
    return BUCKET_SIZES[-1]


def fmt_bucket(secs: int) -> str:
    if secs < 3600:
        return f"{secs // 60} min"
    if secs < 86400:
        return f"{secs // 3600} h"
    return f"{secs // 86400} day"


class HistoryStore:
    """Reads past days from the CSV logs on demand and caches them.

    Per day it keeps 1-minute aggregates for every key (small, kept for all
    loaded days) and the raw samples (large, only for the last few days used).
    """

    def __init__(self, logger: CsvLogger):
        self.logger = logger
        self._minutes = {}          # date -> {key: {minute_ts: acc}}
        self._gw = {}               # date -> [(ts, gateway_ip)]
        self._nets = {}             # date -> networks seen that day (see new_nets)
        self._raw = OrderedDict()   # date -> {key: [(ts, latency)]}

    def clear(self):
        self._minutes.clear()
        self._gw.clear()
        self._nets.clear()
        self._raw.clear()

    def _load(self, day: date):
        raw, mins, gw_events = {}, {}, []
        nets = new_nets()
        last_gw = None
        rows = (r for p in self.logger.day_files(day) for r in iter_log_rows(p))
        for ts, key, host, lat, _status, pub in rows:
            iso = ts.isoformat(timespec="seconds")
            nets_add(nets, "pub", pub, iso)
            if key == GATEWAY_KEY:
                nets_add(nets, "gw", host, iso)
            raw.setdefault(key, []).append((ts, lat))
            m = ts.replace(second=0, microsecond=0)
            acc = mins.setdefault(key, {}).get(m)
            if acc is None:
                acc = mins[key][m] = new_acc()
            acc_add(acc, lat)
            if key == GATEWAY_KEY:
                if last_gw is not None and host != last_gw:
                    gw_events.append((ts, host))
                last_gw = host
        self._minutes[day] = mins
        self._gw[day] = gw_events
        self._nets[day] = nets
        self._raw[day] = raw
        self._raw.move_to_end(day)
        while len(self._raw) > RAW_DAY_CACHE:
            self._raw.popitem(last=False)
        self._save_summary(day, mins, gw_events, nets)

    # Per-day summaries (1-minute averages) are cached on disk next to the logs,
    # so week/month views don't have to re-read every raw sample each time.
    def _summary_path(self, day: date) -> Path:
        return self.logger.log_dir / ".summary" / f"latency_{day:%Y-%m-%d}.json"

    def _src_sig(self, day: date):
        sig = []
        for p in self.logger.day_files(day):
            try:
                st = p.stat()
                sig.append([p.name, st.st_mtime, st.st_size])
            except OSError:
                pass
        return sig or None

    def _save_summary(self, day, mins, gw_events, nets=None):
        sig = self._src_sig(day)
        if sig is None or day >= date.today():
            return
        try:
            path = self._summary_path(day)
            path.parent.mkdir(parents=True, exist_ok=True)
            doc = {"src": sig,
                   "minutes": {k: [[m.isoformat(), *acc] for m, acc in v.items()]
                               for k, v in mins.items()},
                   "gw": [[ts.isoformat(), ip] for ts, ip in gw_events],
                   "nets": nets or new_nets()}
            path.write_text(json.dumps(doc), encoding="utf-8")
        except Exception:
            pass

    def _load_summary(self, day) -> bool:
        try:
            doc = json.loads(self._summary_path(day).read_text(encoding="utf-8"))
            if doc.get("src") != self._src_sig(day):
                return False
            self._minutes[day] = {
                k: {datetime.fromisoformat(r[0]): list(r[1:]) for r in rows}
                for k, rows in doc["minutes"].items()}
            self._gw[day] = [(datetime.fromisoformat(t), ip) for t, ip in doc["gw"]]
            if "nets" in doc:              # summaries written before v4.1 don't have it
                self._nets[day] = doc["nets"]
            return True
        except Exception:
            return False

    def minutes(self, day: date):
        if day not in self._minutes and not self._load_summary(day):
            self._load(day)
        return self._minutes[day]

    def raw(self, day: date):
        if day not in self._raw:
            self._load(day)
        else:
            self._raw.move_to_end(day)
        return self._raw[day]

    def networks(self, day: date):
        """Public IPs and local gateways seen on a past day."""
        if day not in self._nets:
            self._load_summary(day)
        if day not in self._nets:
            self._load(day)
        return self._nets[day]

    def gw_events(self, day: date):
        if day not in self._gw and not self._load_summary(day):
            self._load(day)
        return self._gw[day]
