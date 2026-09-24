#!/usr/bin/env python3
"""
latency_core — shared code for the Latency Checker logger and viewer.

Standard library only, so the headless logger runs on any Python 3.9+ without
extra packages. Contains: ping + parsing, default-gateway detection, public-IP
lookup, the CSV log format, config/status files and the history aggregation
used by the viewer.
"""

import csv
import ipaddress
import json
import os
import platform
import re
import subprocess
import threading
import time
import urllib.request
from collections import OrderedDict
from datetime import date, datetime, timedelta
from pathlib import Path

APP_NAME = "Latency Checker"
SYSTEM = platform.system()  # "Darwin", "Windows", "Linux"
VERSION = "4.0"

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


def ping(host: str, timeout_ms: int):
    """Send one ICMP echo using the system ping command."""
    kwargs = {}
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
        return None, "ping missing"
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
    kwargs = {"creationflags": 0x08000000} if SYSTEM == "Windows" else {}
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
            for ts, key, host, lat in iter_log_file(self.path_for(day)):
                if key in keys and ts >= since:
                    yield ts, key, host, lat
            day += timedelta(days=1)


def iter_log_file(path: Path):
    """Yield (ts, key, host, latency) for every row of one daily log file."""
    if not path.exists():
        return
    try:
        with open(path, newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                try:
                    # Files started by v1 have no "role" header; the value then
                    # lands under the None key.
                    role = row.get("role") or (row.get(None) or [""])[0]
                    host = row.get("host") or ""
                    key = GATEWAY_KEY if role == "gateway" else host
                    ts = datetime.fromisoformat(row["timestamp"])
                    lat = row.get("latency_ms") or ""
                    yield ts, key, host, (float(lat) if lat else None)
                except (ValueError, KeyError, TypeError):
                    continue
    except OSError:
        return


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
        self._raw = OrderedDict()   # date -> {key: [(ts, latency)]}

    def clear(self):
        self._minutes.clear()
        self._gw.clear()
        self._raw.clear()

    def _load(self, day: date):
        raw, mins, gw_events = {}, {}, []
        last_gw = None
        for ts, key, host, lat in iter_log_file(self.logger.path_for(day)):
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
        self._raw[day] = raw
        self._raw.move_to_end(day)
        while len(self._raw) > RAW_DAY_CACHE:
            self._raw.popitem(last=False)
        self._save_summary(day, mins, gw_events)

    # Per-day summaries (1-minute averages) are cached on disk next to the logs,
    # so week/month views don't have to re-read every raw sample each time.
    def _summary_path(self, day: date) -> Path:
        return self.logger.log_dir / ".summary" / f"latency_{day:%Y-%m-%d}.json"

    def _src_sig(self, day: date):
        try:
            st = self.logger.path_for(day).stat()
            return [st.st_mtime, st.st_size]
        except OSError:
            return None

    def _save_summary(self, day, mins, gw_events):
        sig = self._src_sig(day)
        if sig is None or day >= date.today():
            return
        try:
            path = self._summary_path(day)
            path.parent.mkdir(parents=True, exist_ok=True)
            doc = {"src": sig,
                   "minutes": {k: [[m.isoformat(), *acc] for m, acc in v.items()]
                               for k, v in mins.items()},
                   "gw": [[ts.isoformat(), ip] for ts, ip in gw_events]}
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

    def gw_events(self, day: date):
        if day not in self._gw and not self._load_summary(day):
            self._load(day)
        return self._gw[day]
