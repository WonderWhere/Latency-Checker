#!/usr/bin/env python3
"""
latency_remote — secure logger ⇄ viewer communication for Latency Checker.

Standard library only (certificate creation uses `openssl` or, if installed, the
`cryptography` package).

Security model
--------------
* TLS 1.2+ for every request. The logger has its own self-signed certificate; the
  viewer *pins* its SHA-256 fingerprint on first contact (like SSH), so no CA or
  domain name is needed and an impostor logger is rejected.
* Each viewer gets its own random 256-bit access key through a one-time pairing
  code shown on the logger. The logger stores only a hash of each key; keys can be
  revoked individually. Roles: "admin" (may change targets/settings) or "read".
* Remote access is off until enabled; it binds to one address; failed logins and
  pairing attempts are rate-limited per client IP; pairings, revocations, config
  changes and auth failures are written to the logger's log.
"""

import base64
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import threading
import time
from collections import defaultdict, deque
from datetime import date, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import latency_core as core

DEFAULT_PORT = 8765
PAIR_TTL = 600                  # pairing codes are valid for 10 minutes
MAX_BODY = 256 * 1024
FAIL_LIMIT, FAIL_WINDOW = 10, 300   # 10 failures per 5 min per IP → blocked for 5 min
LOG_FILE_RE = re.compile(r"^latency_\d{4}-\d{2}-\d{2}\.csv(\.gz)?$")
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-:_%]{0,252}$")
EDITABLE_KEYS = ("targets", "interval_sec", "timeout_ms", "auto_gateway", "public_ip",
                 "compress_logs", "compress_after_days", "names", "location_name")


def remote_dir() -> Path:
    return core.APP_DIR / "remote"


def _secure_write(path: Path, text: str):
    """Atomic write, readable by the owner only (on macOS/Linux)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        try:
            os.chmod(path.parent, 0o700)
        except OSError:
            pass
    tmp = path.with_name(path.name + f".{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, path)


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# Certificate + fingerprint
# --------------------------------------------------------------------------- #
def fingerprint_der(der: bytes) -> str:
    """SHA-256 of the certificate, shown as 16 groups of 4 hex digits."""
    h = hashlib.sha256(der).hexdigest().upper()
    return " ".join(h[i:i + 4] for i in range(0, 64, 4))


def fingerprint_pem(cert_path: Path) -> str:
    return fingerprint_der(ssl.PEM_cert_to_DER_cert(Path(cert_path).read_text()))


def _make_cert_cryptography(cert: Path, key: Path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    import datetime as dt
    k = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Latency Checker logger")])
    now = dt.datetime.now(dt.timezone.utc)
    c = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
         .public_key(k.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - dt.timedelta(days=1))
         .not_valid_after(now + dt.timedelta(days=3650))
         .sign(k, hashes.SHA256()))
    _secure_write(key, k.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()).decode())
    _secure_write(cert, c.public_bytes(serialization.Encoding.PEM).decode())


def _make_cert_openssl(cert: Path, key: Path):
    exe = shutil.which("openssl")
    if not exe:
        raise FileNotFoundError("openssl")
    r = subprocess.run([exe, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
                        "-days", "3650", "-subj", "/CN=Latency Checker logger",
                        "-keyout", str(key), "-out", str(cert)],
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0 or not cert.exists():
        raise RuntimeError("openssl failed: " + r.stderr.strip())
    if os.name != "nt":
        os.chmod(key, 0o600)


def ensure_certificate():
    """Create the logger's TLS certificate once. Returns (cert_path, key_path)."""
    d = remote_dir()
    cert, key = d / "cert.pem", d / "key.pem"
    if cert.exists() and key.exists():
        return cert, key
    d.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        os.chmod(d, 0o700)
    errors = []
    for maker in (_make_cert_cryptography, _make_cert_openssl):
        try:
            maker(cert, key)
            return cert, key
        except Exception as exc:
            errors.append(f"{maker.__name__}: {exc}")
    raise RuntimeError("Could not create a TLS certificate. Install the 'cryptography' "
                       "package (pip install cryptography) or OpenSSL.\n" + "\n".join(errors))


# --------------------------------------------------------------------------- #
# Access keys (per viewer) and one-time pairing codes
# --------------------------------------------------------------------------- #
class ClientStore:
    """remote/clients.json — one entry per paired viewer; only key hashes are stored."""

    def __init__(self):
        self.path = remote_dir() / "clients.json"
        self._mtime = None
        self._data = {"clients": {}}
        self._lock = threading.Lock()
        self._last_touch = {}

    def _load(self):
        try:
            m = self.path.stat().st_mtime
        except OSError:
            self._data, self._mtime = {"clients": {}}, None
            return
        if m != self._mtime:
            try:
                self._data = json.loads(self.path.read_text(encoding="utf-8"))
                self._data.setdefault("clients", {})
            except Exception:
                self._data = {"clients": {}}
            self._mtime = m

    def _save(self):
        _secure_write(self.path, json.dumps(self._data, indent=1))
        self._mtime = self.path.stat().st_mtime

    def add(self, name: str, role: str) -> tuple:
        with self._lock:
            self._load()
            cid = secrets.token_hex(4)
            token = "lc1_" + secrets.token_urlsafe(32)
            self._data["clients"][cid] = {
                "name": (name or "viewer")[:80], "role": "read" if role == "read" else "admin",
                "hash": _sha(token), "created": datetime.now().isoformat(timespec="seconds"),
                "last_seen": None,
            }
            self._save()
            return cid, token

    def verify(self, token: str):
        """(client_id, entry) for a valid key, else None. Constant-time comparison."""
        if not token or not token.startswith("lc1_"):
            return None
        h = _sha(token)
        with self._lock:
            self._load()
            found = None
            for cid, c in self._data["clients"].items():
                if hmac.compare_digest(c.get("hash", ""), h):
                    found = (cid, dict(c))
            if found and time.time() - self._last_touch.get(found[0], 0) > 60:
                self._last_touch[found[0]] = time.time()
                self._data["clients"][found[0]]["last_seen"] = datetime.now().isoformat(
                    timespec="seconds")
                try:
                    self._save()
                except OSError:
                    pass
            return found

    def list(self):
        with self._lock:
            self._load()
            return dict(self._data["clients"])

    def revoke(self, ident: str):
        with self._lock:
            self._load()
            gone = [cid for cid, c in self._data["clients"].items()
                    if cid == ident or c.get("name") == ident]
            for cid in gone:
                del self._data["clients"][cid]
            if gone:
                self._save()
            return gone


_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"     # no 0/O, 1/I


def create_pairing_code(role="admin", ttl=PAIR_TTL) -> str:
    code = "".join(secrets.choice(_CODE_ALPHABET) for _ in range(8))
    code = f"{code[:4]}-{code[4:]}"
    path = remote_dir() / "pairing.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        data = {"codes": []}
    now = time.time()
    data["codes"] = [c for c in data.get("codes", []) if c.get("expires", 0) > now]
    data["codes"].append({"hash": _sha(code), "expires": now + ttl,
                          "role": "read" if role == "read" else "admin"})
    _secure_write(path, json.dumps(data))
    return code


_pair_lock = threading.Lock()


def redeem_pairing_code(code: str):
    """The role for a valid, unexpired code (which is then used up), else None."""
    code = (code or "").strip().upper().replace(" ", "")
    if len(code) == 8:
        code = f"{code[:4]}-{code[4:]}"
    path = remote_dir() / "pairing.json"
    with _pair_lock:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return None
        now, h, role = time.time(), _sha(code), None
        keep = []
        for c in data.get("codes", []):
            if c.get("expires", 0) <= now:
                continue
            if role is None and hmac.compare_digest(c.get("hash", ""), h):
                role = c.get("role", "admin")
                continue                           # single use
            keep.append(c)
        data["codes"] = keep
        _secure_write(path, json.dumps(data))
        return role


class RateLimiter:
    def __init__(self, limit=FAIL_LIMIT, window=FAIL_WINDOW):
        self.limit, self.window = limit, window
        self.fails = defaultdict(deque)
        self.lock = threading.Lock()

    def blocked(self, ip) -> bool:
        with self.lock:
            q = self.fails[ip]
            while q and q[0] < time.time() - self.window:
                q.popleft()
            return len(q) >= self.limit

    def fail(self, ip):
        with self.lock:
            self.fails[ip].append(time.time())


# --------------------------------------------------------------------------- #
# Config validation (for changes coming from a remote viewer)
# --------------------------------------------------------------------------- #
def valid_host(h) -> bool:
    return isinstance(h, str) and bool(HOST_RE.match(h)) and not h.startswith("-")


def sanitize_config_update(upd: dict) -> dict:
    """Keep only editable keys with sane values; raise ValueError on bad input."""
    out = {}
    if not isinstance(upd, dict):
        raise ValueError("expected a JSON object")
    for k, v in upd.items():
        if k not in EDITABLE_KEYS:
            continue
        if k == "targets":
            if not isinstance(v, list) or len(v) > 100:
                raise ValueError("targets must be a list (max 100)")
            ts = []
            for t in v:
                if not isinstance(t, dict) or not valid_host(t.get("host")):
                    raise ValueError(f"invalid target: {t!r}")
                ts.append({"host": t["host"], "label": str(t.get("label") or t["host"])[:80]})
            out[k] = ts
        elif k == "interval_sec":
            out[k] = min(3600.0, max(1.0, float(v)))
        elif k == "timeout_ms":
            out[k] = int(min(10000, max(100, int(v))))
        elif k == "compress_after_days":
            out[k] = int(min(365, max(1, int(v))))
        elif k in ("auto_gateway", "public_ip", "compress_logs"):
            out[k] = bool(v)
        elif k == "names":
            if not isinstance(v, dict) or len(v) > 1000:
                raise ValueError("names must be an object")
            names = {}
            for ip, name in v.items():
                ipaddress.ip_address(ip)           # raises ValueError
                if name:
                    names[ip] = str(name)[:80]
            out[k] = names
        elif k == "location_name":
            out[k] = str(v)[:80]
    return out


def location_name(cfg=None) -> str:
    cfg = cfg or core.load_config()
    return cfg.get("location_name") or socket.gethostname().split(".")[0]


# --------------------------------------------------------------------------- #
# Server (runs inside the logger)
# --------------------------------------------------------------------------- #
class _Handler(BaseHTTPRequestHandler):
    server_version = "LatencyLogger"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = 20                                   # slow / idle clients are dropped

    # --- plumbing ---
    def handle(self):
        # TLS handshake here, in the per-connection thread (with the socket timeout set).
        try:
            self.request.do_handshake()
        except (ssl.SSLError, OSError):
            return
        super().handle()

    def log_message(self, fmt, *args):             # keep the default access log quiet
        pass

    @property
    def ctx(self):
        return self.server.ctx

    def _send(self, code, body=b"", ctype="application/json", extra=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _err(self, code, msg):
        self._send(code, {"error": msg})

    def _read_body(self):
        """Always consume the request body first, so a refused request can't leave
        bytes behind that would corrupt the next request on a kept-alive connection."""
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = -1
        if n < 0 or n > MAX_BODY:
            self.close_connection = True
            self._err(413, "request too large")
            return None
        self._raw = self.rfile.read(n) if n else b""
        return self._raw

    def _body_json(self):
        return json.loads(getattr(self, "_raw", b"") or b"{}")

    def _ip(self):
        return self.client_address[0]

    def _auth(self):
        ip = self._ip()
        if self.ctx.limiter.blocked(ip):
            self._err(429, "too many failed attempts — try again later")
            return None
        hdr = self.headers.get("Authorization", "")
        tok = hdr[7:].strip() if hdr.startswith("Bearer ") else ""
        found = self.ctx.clients.verify(tok)
        if not found:
            self.ctx.limiter.fail(ip)
            self.ctx.audit("rejected request from %s (bad or revoked key)", ip, throttle=ip)
            self._err(401, "unauthorized")
            return None
        return found

    # --- routes ---
    def do_GET(self):
        try:
            path = self.path.split("?", 1)[0]
            if path == "/hello":
                return self._send(200, {"app": "latency-checker-logger", "version": core.VERSION})
            who = self._auth()
            if not who:
                return
            if path == "/api/status":
                st = core.read_status() or {}
                for private in ("log_dir", "pid"):      # nothing about local paths/processes
                    st.pop(private, None)
                st["server_time"] = time.time()
                st["server_local"] = datetime.now().isoformat()   # → time-zone offset
                st["location"] = location_name()
                st["today"] = date.today().isoformat()
                return self._send(200, st)
            if path == "/api/config":
                cfg = core.load_config()
                out = {k: cfg.get(k) for k in EDITABLE_KEYS}
                out["location_name"] = location_name(cfg)
                out["_mtime"] = core.config_mtime()
                out["_role"] = who[1].get("role")
                return self._send(200, out)
            if path == "/api/days":
                log_dir = self.ctx.log_dir()
                files = []
                try:
                    for p in sorted(log_dir.iterdir()):
                        if LOG_FILE_RE.match(p.name):
                            st = p.stat()
                            files.append({"name": p.name, "size": st.st_size, "mtime": st.st_mtime})
                except OSError:
                    pass
                return self._send(200, {"today": date.today().isoformat(), "files": files})
            if path.startswith("/api/file/"):
                return self._file(path[len("/api/file/"):])
            self._err(404, "not found")
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass
        except Exception as exc:                   # pragma: no cover
            self.ctx.audit("request error: %s", exc)
            try:
                self._err(500, "internal error")
            except Exception:
                pass

    def _file(self, name):
        if not LOG_FILE_RE.match(name):
            return self._err(404, "not found")
        p = self.ctx.log_dir() / name
        try:
            size = p.stat().st_size
        except OSError:
            return self._err(404, "not found")
        start = 0
        rng = self.headers.get("Range", "")
        m = re.match(r"^bytes=(\d+)-$", rng)
        if m:
            start = int(m.group(1))
            if start >= size:
                return self._send(416, b"", "application/octet-stream",
                                  {"Content-Range": f"bytes */{size}"})
        length = size - start
        self.send_response(206 if m else 200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        if m:
            self.send_header("Content-Range", f"bytes {start}-{size - 1}/{size}")
        self.end_headers()
        with open(p, "rb") as fh:
            fh.seek(start)
            left = length
            while left > 0:
                chunk = fh.read(min(65536, left))
                if not chunk:
                    break
                self.wfile.write(chunk)
                left -= len(chunk)

    def do_POST(self):
        try:
            path = self.path.split("?", 1)[0]
            if self._read_body() is None:
                return
            if path != "/pair":
                return self._err(404, "not found")
            ip = self._ip()
            if self.ctx.limiter.blocked(ip):
                return self._err(429, "too many failed attempts — try again later")
            try:
                body = self._body_json()
            except Exception:
                return self._err(400, "bad request")
            role = redeem_pairing_code(str(body.get("code", "")))
            if not role:
                self.ctx.limiter.fail(ip)
                self.ctx.audit("pairing attempt with an invalid/expired code from %s", ip)
                return self._err(403, "invalid or expired pairing code")
            name = str(body.get("name") or f"viewer@{ip}")[:80]
            cid, token = self.ctx.clients.add(name, role)
            self.ctx.audit("paired new viewer '%s' (%s, id %s) from %s", name, role, cid, ip)
            self._send(200, {"token": token, "client_id": cid, "role": role,
                             "location": location_name()})
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass

    def do_PUT(self):
        try:
            if self._read_body() is None:
                return
            if self.path.split("?", 1)[0] != "/api/config":
                return self._err(404, "not found")
            who = self._auth()
            if not who:
                return
            if who[1].get("role") != "admin":
                return self._err(403, "this viewer is read-only")
            try:
                upd = sanitize_config_update(self._body_json())
            except (ValueError, TypeError) as exc:
                return self._err(400, str(exc))
            cfg = core.load_config()
            cfg.update(upd)
            core.save_config(cfg)
            self.ctx.audit("config changed by viewer '%s': %s", who[1].get("name"),
                           ", ".join(sorted(upd)) or "nothing")
            out = {k: cfg.get(k) for k in EDITABLE_KEYS}
            out["location_name"] = location_name(cfg)
            out["_mtime"] = core.config_mtime()
            out["_role"] = who[1].get("role")
            self._send(200, out)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass


class _Ctx:
    def __init__(self, log_dir_fn, log):
        self.log_dir = log_dir_fn
        self.log = log
        self.clients = ClientStore()
        self.limiter = RateLimiter()
        self._throttle = {}

    def audit(self, msg, *args, throttle=None):
        if throttle is not None:
            if time.time() - self._throttle.get(throttle, 0) < 60:
                return
            self._throttle[throttle] = time.time()
        if self.log:
            self.log.warning(msg, *args) if "rejected" in msg or "invalid" in msg \
                else self.log.info(msg, *args)


class RemoteServer:
    """HTTPS API for remote viewers. start()/stop() may be called repeatedly."""

    def __init__(self, log_dir_fn, log=None):
        self.ctx = _Ctx(log_dir_fn, log)
        self.log = log
        self.httpd = None
        self.thread = None
        self.addr = None

    def start(self, bind="0.0.0.0", port=DEFAULT_PORT):
        self.stop()
        cert, key = ensure_certificate()
        sslctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sslctx.minimum_version = ssl.TLSVersion.TLSv1_2
        sslctx.load_cert_chain(str(cert), str(key))
        family = socket.AF_INET6 if ":" in bind else socket.AF_INET

        class Server(ThreadingHTTPServer):
            address_family = family
            daemon_threads = True
            allow_reuse_address = True

        httpd = Server((bind, int(port)), _Handler)
        # Handshake happens in each request thread (a slow client can't stall the server).
        httpd.socket = sslctx.wrap_socket(httpd.socket, server_side=True,
                                          do_handshake_on_connect=False)
        httpd.ctx = self.ctx
        self.httpd = httpd
        self.addr = (bind, int(port))
        self.thread = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.5},
                                       daemon=True, name="remote-api")
        self.thread.start()
        if self.log:
            self.log.info("remote access ON: https://%s:%d  (certificate %s)", bind, int(port),
                          fingerprint_pem(cert))

    def stop(self):
        if self.httpd:
            try:
                self.httpd.shutdown()
                self.httpd.server_close()
            except Exception:
                pass
            if self.log:
                self.log.info("remote access OFF")
        self.httpd = None
        self.addr = None


# --------------------------------------------------------------------------- #
# Client (used by the viewer)
# --------------------------------------------------------------------------- #
class FingerprintMismatch(Exception):
    pass


class RemoteError(Exception):
    def __init__(self, status, msg):
        super().__init__(f"{status}: {msg}")
        self.status = status
        self.msg = msg


def _client_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False          # identity is checked by fingerprint pinning below
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def probe(host, port=DEFAULT_PORT, timeout=8):
    """First contact: (fingerprint, hello-json). Used before pairing, to show the fingerprint."""
    conn = http.client.HTTPSConnection(host, int(port), context=_client_ctx(), timeout=timeout)
    try:
        conn.connect()
        fp = fingerprint_der(conn.sock.getpeercert(binary_form=True))
        conn.request("GET", "/hello")
        r = conn.getresponse()
        hello = json.loads(r.read() or b"{}")
        if hello.get("app") != "latency-checker-logger":
            raise RemoteError(r.status, "that address is not a Latency Checker logger")
        return fp, hello
    finally:
        conn.close()


class RemoteClient:
    """Pinned-certificate HTTPS client with a reusable connection."""

    def __init__(self, host, port, fingerprint, token=None, timeout=10):
        self.host, self.port = host, int(port)
        self.fingerprint = fingerprint
        self.token = token
        self.timeout = timeout
        self.conn = None
        self.lock = threading.Lock()

    def _connect(self):
        conn = http.client.HTTPSConnection(self.host, self.port, context=_client_ctx(),
                                           timeout=self.timeout)
        conn.connect()
        fp = fingerprint_der(conn.sock.getpeercert(binary_form=True))
        if not hmac.compare_digest(fp, self.fingerprint):
            conn.close()
            raise FingerprintMismatch(
                f"The logger at {self.host}:{self.port} presented a different certificate "
                f"({fp[:19]}…) than the one you paired with ({self.fingerprint[:19]}…). "
                "Refusing to connect.")
        self.conn = conn

    def close(self):
        with self.lock:
            if self.conn:
                self.conn.close()
            self.conn = None

    def request(self, method, path, body=None, headers=None):
        hdrs = {"User-Agent": "LatencyViewer/" + core.VERSION}
        if self.token:
            hdrs["Authorization"] = "Bearer " + self.token
        if body is not None:
            body = json.dumps(body).encode()
            hdrs["Content-Type"] = "application/json"
        hdrs.update(headers or {})
        with self.lock:
            for attempt in (1, 2):
                try:
                    if self.conn is None:
                        self._connect()
                    self.conn.request(method, path, body=body, headers=hdrs)
                    r = self.conn.getresponse()
                    data = r.read()
                    return r.status, dict(r.getheaders()), data
                except FingerprintMismatch:
                    raise
                except (http.client.HTTPException, OSError):
                    if self.conn:
                        self.conn.close()
                    self.conn = None
                    if attempt == 2:
                        raise

    def json(self, method, path, body=None):
        status, _h, data = self.request(method, path, body)
        try:
            obj = json.loads(data or b"{}")
        except ValueError:
            obj = {}
        if status >= 400:
            raise RemoteError(status, obj.get("error") or f"HTTP {status}")
        return obj

    def pair(self, code, name):
        return self.json("POST", "/pair", {"code": code, "name": name})


def local_addresses():
    """Best-effort list of this machine's IPv4 addresses (for 'connect to …' hints)."""
    ips = set()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.0.2.1", 9))                 # no packet is sent
        ips.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(info[4][0])
    except OSError:
        pass
    return sorted(ip for ip in ips if not ip.startswith("127."))


def b64id(s: str) -> str:
    """Filesystem-safe short id (for cache folders)."""
    return base64.urlsafe_b64encode(hashlib.sha256(s.encode()).digest()[:9]).decode().rstrip("=")
