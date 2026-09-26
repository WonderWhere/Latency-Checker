#!/usr/bin/env python3
"""
latency_sources — the monitoring locations a viewer can show.

* LocalSource  – the logger on this computer (reads ~/LatencyChecker directly).
* RemoteSource – a logger on another machine, over the pinned-TLS API. Its log files
  are mirrored into ~/LatencyChecker/remote-cache/<id>/logs by a background thread
  (finished days once, today's file incrementally), so all history/averaging code
  works on the mirror exactly as on local files — and stays browsable offline.
* SourceData   – per-location data the viewer keeps in memory (recent samples,
  history cache, live tail, gateway changes). Compare mode holds several at once.
* Prefs        – viewer settings + paired locations (~/LatencyChecker/viewer.json,
  owner-only; it holds the access keys).

Times: each location's logs are in *that logger's* local time. A remote source knows
its offset to this computer (time zone + clock difference) from the logger's status,
so live views line up and compare mode can put all locations on one time axis.
"""

import json
import os
import shutil
import threading
import time
from collections import deque
from datetime import date, datetime, timedelta
from pathlib import Path

import latency_core as core
from latency_core import GATEWAY_KEY, MAX_POINTS_PER_TARGET, CsvLogger, HistoryStore, LogTail
from latency_core import acc_add, acc_merge, floor_ts, new_acc

VIEWER_PREF_KEYS = ("theme", "span_sec", "log_scale")


# --------------------------------------------------------------------------- #
# Viewer preferences + paired locations
# --------------------------------------------------------------------------- #
class Prefs:
    def __init__(self):
        self.path = core.APP_DIR / "viewer.json"
        self.data = {"sources": [], "selected": "local", "theme": "system",
                     "span_sec": 3600, "log_scale": False}
        try:
            self.data.update(json.loads(self.path.read_text(encoding="utf-8")))
        except FileNotFoundError:
            cfg = core.load_config()               # migrate from config.json (≤ v4.1)
            for k in VIEWER_PREF_KEYS:
                if k in cfg:
                    self.data[k] = cfg[k]
        except Exception:
            pass

    def get(self, k, default=None):
        return self.data.get(k, default)

    def set(self, **kw):
        self.data.update(kw)
        self.save()

    def save(self):
        import latency_remote
        latency_remote._secure_write(self.path, json.dumps(self.data, indent=1))

    @property
    def sources(self):
        return self.data.setdefault("sources", [])


# --------------------------------------------------------------------------- #
# Sources
# --------------------------------------------------------------------------- #
class LocalSource:
    kind = "local"
    id = "local"
    role = "admin"

    def __init__(self):
        self.error = None

    @property
    def name(self):
        cfg = core.load_config()
        return cfg.get("location_name") or "This computer"

    @property
    def log_dir(self):
        return Path(core.load_config().get("log_dir") or core.APP_DIR / "logs")

    reachable = True
    offset = timedelta(0)

    def now(self):
        return datetime.now()

    def today(self):
        return date.today()

    def read_status(self):
        return core.read_status()

    def get_config(self):
        return core.load_config()

    def config_version(self):
        return core.config_mtime()

    def save_config(self, updates: dict, on_done=None):
        cfg = core.load_config()
        cfg.update(updates)
        core.save_config(cfg)
        if on_done:
            on_done(None)

    def start(self):
        pass

    def stop(self):
        pass


class RemoteSource:
    kind = "remote"

    def __init__(self, entry: dict):
        import latency_remote as R
        self.R = R
        self.entry = entry
        self.id = entry["id"]
        self.client = R.RemoteClient(entry["host"], entry.get("port", R.DEFAULT_PORT),
                                     entry["fingerprint"], entry["token"], timeout=10)
        self.cache = core.APP_DIR / "remote-cache" / self.id
        self.mirror = self.cache / "logs"
        self.mirror.mkdir(parents=True, exist_ok=True)
        self.status = None
        self.config = None
        self._config_ver = 0
        self.offset = timedelta(0)
        self._offset_known = False
        self.reachable = False
        self.error = None
        self.last_ok = None
        self.syncing = False
        self.initial_sync_done = False
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread = None
        self._server_today = None
        self.data_version = 0        # bumps whenever mirrored past days change
        self._load_cached_meta()

    # --- identity / time ---
    @property
    def name(self):
        return self.entry.get("name") or f"{self.entry['host']}"

    @property
    def role(self):
        return (self.config or {}).get("_role") or self.entry.get("role", "admin")

    @property
    def log_dir(self):
        return self.mirror

    def now(self):
        return datetime.now() + self.offset

    def today(self):
        return self.now().date()

    # --- cached metadata (so the location opens offline too) ---
    def _load_cached_meta(self):
        try:
            meta = json.loads((self.cache / "meta.json").read_text(encoding="utf-8"))
            self.config = meta.get("config")
            self.status = meta.get("status")
            self.offset = timedelta(seconds=float(meta.get("offset", 0)))
            self._offset_known = "offset" in meta
        except Exception:
            pass

    def _save_cached_meta(self):
        try:
            self.cache.mkdir(parents=True, exist_ok=True)
            tmp = self.cache / "meta.json.tmp"
            tmp.write_text(json.dumps({"config": self.config, "status": self.status,
                                       "offset": self.offset.total_seconds()}), encoding="utf-8")
            os.replace(tmp, self.cache / "meta.json")
        except Exception:
            pass

    # --- what the viewer asks ---
    def read_status(self):
        """Logger status with the heartbeat moved onto this computer's clock."""
        if not self.status:
            return None
        st = dict(self.status)
        try:
            st["heartbeat"] = float(st["heartbeat"]) - float(st["server_time"]) + st["_recv"]
        except (KeyError, TypeError, ValueError):
            pass
        return st

    def get_config(self):
        cfg = core.load_config()                    # defaults for missing keys
        cfg.update(self.config or {})
        cfg["log_dir"] = str(self.mirror)
        return cfg

    def config_version(self):
        return self._config_ver

    def save_config(self, updates: dict, on_done=None):
        allowed = {k: v for k, v in updates.items() if k in self.R.EDITABLE_KEYS}

        def work():
            err = None
            try:
                self.config = self.client.json("PUT", "/api/config", allowed)
                self._save_cached_meta()
            except Exception as exc:
                err = str(exc)
            if on_done:
                on_done(err)
        threading.Thread(target=work, daemon=True).start()

    # --- background sync ---
    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name=f"sync-{self.id}")
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._wake.set()
        self.client.close()

    def wake(self):
        self._wake.set()

    def _run(self):
        last_days = last_cfg = 0.0
        while not self._stop.is_set():
            try:
                self._poll_status()
                if time.time() - last_cfg > 15 or self.config is None:
                    self._poll_config()
                    last_cfg = time.time()
                if time.time() - last_days > 60 or not self.initial_sync_done:
                    self.syncing = True
                    self._sync_days()
                    self.initial_sync_done = True
                    self.syncing = False
                    last_days = time.time()
                else:
                    self._tail_today()
                self.reachable = True
                self.error = None
                self.last_ok = time.time()
            except self.R.FingerprintMismatch as exc:
                self.reachable, self.error = False, str(exc)
                self.syncing = False
                self._stop.wait(60)                 # don't hammer an impostor
                continue
            except self.R.RemoteError as exc:
                self.reachable = False
                self.syncing = False
                self.error = ("this viewer's key was revoked on the logger — re-pair it"
                              if exc.status == 401 else exc.msg)
            except Exception as exc:
                self.reachable = False
                self.syncing = False
                self.error = f"unreachable ({exc.__class__.__name__})"
            self._wake.wait(2 if self.reachable else 10)
            self._wake.clear()

    def _poll_status(self):
        t0 = time.time()
        st = self.client.json("GET", "/api/status")
        t1 = time.time()
        st["_recv"] = (t0 + t1) / 2
        try:
            server_local = datetime.fromisoformat(st["server_local"])
            viewer_local = datetime.fromtimestamp(st["_recv"])
            off = round((server_local - viewer_local).total_seconds())
            if not self._offset_known or abs(off - self.offset.total_seconds()) > 2:
                self.offset = timedelta(seconds=off)
                self._offset_known = True
        except (KeyError, ValueError):
            pass
        self._server_today = st.get("today")
        self.status = st
        self._save_cached_meta()

    def _poll_config(self):
        cfg = self.client.json("GET", "/api/config")
        if cfg != self.config:
            self.config = cfg
            self._config_ver += 1
            self._save_cached_meta()

    def _download(self, name, dest: Path):
        status, _h, data = self.client.request("GET", f"/api/file/{name}")
        if status != 200:
            raise self.R.RemoteError(status, f"download of {name} failed")
        tmp = dest.with_name(dest.name + ".dl")
        tmp.write_bytes(data)
        os.replace(tmp, dest)

    def _append(self, name, dest: Path, server_size=None):
        """Fetch only the bytes after what we already have (today's growing file)."""
        have = dest.stat().st_size if dest.exists() else 0
        if server_size is not None and server_size == have:
            return
        if server_size is not None and server_size < have:
            return self._download(name, dest)       # rewritten on the logger: start over
        status, h, data = self.client.request("GET", f"/api/file/{name}",
                                              headers={"Range": f"bytes={have}-"})
        if status == 206:
            with open(dest, "ab") as fh:
                fh.write(data)
        elif status == 200:                          # server ignored the range
            dest.write_bytes(data)
        elif status == 416:
            total = (h.get("Content-Range") or "").rpartition("/")[2]
            if total.isdigit() and int(total) < have:
                self._download(name, dest)
        else:
            raise self.R.RemoteError(status, f"fetch of {name} failed")

    def _sync_days(self):
        listing = self.client.json("GET", "/api/days")
        self._server_today = listing.get("today", self._server_today)
        remote = {f["name"]: f for f in listing.get("files", [])}
        before = {p.name: p.stat().st_size for p in self.mirror.iterdir()
                  if p.name.startswith("latency_")}
        today_name = f"latency_{self._server_today}.csv"
        # newest first, so recent history shows up quickly
        for name in sorted(remote, reverse=True):
            f = remote[name]
            dest = self.mirror / name
            if name.endswith(".gz"):
                if not dest.exists() or dest.stat().st_size != f["size"]:
                    self._download(name, dest)
                plain = self.mirror / name[:-3]
                if plain.exists() and name[:-3] not in remote:
                    plain.unlink()                    # the logger compressed that day
            else:
                self._append(name, dest, f["size"])
            if self._stop.is_set():
                return
        for p in self.mirror.iterdir():               # drop what the logger no longer has
            if p.name.startswith("latency_") and p.name not in remote and \
                    not p.name.endswith((".dl", ".tmp")):
                try:
                    p.unlink()
                except OSError:
                    pass
        after = {p.name: p.stat().st_size for p in self.mirror.iterdir()
                 if p.name.startswith("latency_")}
        before.pop(today_name, None)
        after.pop(today_name, None)
        if before != after:
            self.data_version += 1

    def _tail_today(self):
        today = self._server_today or self.today().isoformat()
        name = f"latency_{today}.csv"
        self._append(name, self.mirror / name)

    def forget_cache(self):
        shutil.rmtree(self.cache, ignore_errors=True)
        self.mirror.mkdir(parents=True, exist_ok=True)


def make_sources(prefs: Prefs):
    out = {"local": LocalSource()}
    for e in prefs.sources:
        try:
            out[e["id"]] = RemoteSource(e)
        except Exception:
            pass
    return out


# --------------------------------------------------------------------------- #
# Per-location data held by the viewer
# --------------------------------------------------------------------------- #
class SourceData:
    def __init__(self, source):
        self.source = source
        self.logger = CsvLogger(Path(source.log_dir))
        self.history = HistoryStore(self.logger)
        self.tail = LogTail(self.logger, now_fn=source.now)
        self.data = {}                       # key -> deque[(datetime, latency|None)]
        self.gw_events = deque(maxlen=5000)  # [(ts, new_gateway_ip)]
        self.gw_last_host = None
        self.pub_last = None
        self.last_status = {}
        self.loaded = False
        self._seen_version = getattr(source, "data_version", 0)

    def now(self):
        return self.source.now()

    def today(self):
        return self.source.today()

    def reset(self):
        """Log folder changed (local) or cache refreshed (remote)."""
        self.__init__(self.source)

    def check_updates(self) -> bool:
        """A remote sync brought new/changed past days → drop cached history."""
        v = getattr(self.source, "data_version", 0)
        if v != self._seen_version:
            self._seen_version = v
            self.history.clear()
            return True
        return False

    def add_point(self, ts, key, latency):
        dq = self.data.get(key)
        if dq is None:
            dq = self.data[key] = deque(maxlen=MAX_POINTS_PER_TARGET)
        dq.append((ts, latency))

    def load_recent(self):
        """Memory ← the last 24 h (covers all of the logger's today) from the logs."""
        n = 0
        last_gw = None
        for path_day in (self.today() - timedelta(days=1), self.today()):
            for p in self.logger.day_files(path_day):
                for ts, key, host, lat, status, pub in core.iter_log_rows(p):
                    if ts < self.now() - timedelta(days=1):
                        continue
                    self.add_point(ts, key, lat)
                    self.last_status[key] = status
                    if key == GATEWAY_KEY:
                        if last_gw is not None and host != last_gw:
                            self.gw_events.append((ts, host))
                        last_gw = host
                    if pub:
                        self.pub_last = pub
                    n += 1
        self.gw_last_host = last_gw
        self.tail.skip_to_end()
        self.loaded = True
        return n

    def poll(self, keys):
        """New rows since last call. Returns (got_data, events[(kind, old, new)])."""
        got, events = False, []
        for ts, key, host, latency, status, pub in self.tail.read_new():
            if key == GATEWAY_KEY and host != self.gw_last_host:
                if self.gw_last_host is not None:
                    self.gw_events.append((ts, host))
                    events.append(("gw", self.gw_last_host, host))
                self.gw_last_host = host
            if pub and pub != self.pub_last:
                if self.pub_last:
                    events.append(("pub", self.pub_last, pub))
                self.pub_last = pub
            if key in keys or key == GATEWAY_KEY:
                self.add_point(ts, key, latency)
                self.last_status[key] = status
                got = True
        return got, events

    @staticmethod
    def _days(start, end):
        d = start.date()
        while d <= end.date():
            yield d
            d += timedelta(days=1)

    def raw_series(self, key, start, end):
        today = self.today()
        pts = []
        for d in self._days(start, end):
            src = self.data.get(key, ()) if d == today else self.history.raw(d).get(key, ())
            pts.extend(p for p in src if start <= p[0] <= end and p[0].date() == d)
        return pts

    def agg_series(self, key, start, end, bucket):
        today = self.today()
        out = {}
        for d in self._days(start, end):
            if d == today:
                for ts, lat in self.data.get(key, ()):
                    if start <= ts <= end and ts.date() == d:
                        b = floor_ts(ts, bucket)
                        acc = out.get(b)
                        if acc is None:
                            acc = out[b] = new_acc()
                        acc_add(acc, lat)
            else:
                for m, macc in self.history.minutes(d).get(key, {}).items():
                    if start <= m <= end:
                        b = floor_ts(m, bucket)
                        acc = out.get(b)
                        if acc is None:
                            acc = out[b] = new_acc()
                        acc_merge(acc, macc)
        return sorted(out.items())

    def first_data_ts(self, keys, start, end):
        mem = [self.data[k][0][0] for k in keys if self.data.get(k)]
        earliest = min(mem) if mem else None
        if earliest is not None and earliest <= start:
            return None
        stop = earliest.date() if earliest else end.date() + timedelta(days=1)
        for d in self._days(start, end):
            if d >= stop or d == self.today():
                break
            mins = self.history.minutes(d)
            firsts = [min(mins[k]) for k in keys if mins.get(k)]
            if firsts:
                return max(start, min(firsts))
        return earliest

    def gateway_changes(self, start, end):
        today = self.today()
        ev = []
        for d in self._days(start, end):
            src = self.gw_events if d == today else self.history.gw_events(d)
            ev.extend(e for e in src if start <= e[0] <= end and e[0].date() == d)
        return ev

    def uncached_days(self, start, end):
        return any(d != self.today() and d not in self.history._minutes
                   for d in self._days(start, end))
