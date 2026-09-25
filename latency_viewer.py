#!/usr/bin/env python3
"""
Latency Checker — viewer
------------------------
Desktop window that shows what the logger records: live and historical latency
graphs, per-target stats, current gateway and public IP. It does not ping
anything itself; it reads the CSV logs (following today's file live) and the
logger's status file. Targets and settings edited here are written to
config.json, and the running logger picks them up within one round.

Needs Python 3.9+ with Tkinter and matplotlib (+ optional sv-ttk, darkdetect).
"""

import os
import re
import subprocess
import sys
import time
from collections import OrderedDict, deque
from datetime import date, datetime, timedelta
from pathlib import Path

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import matplotlib

matplotlib.use("TkAgg")
import matplotlib.dates as mdates  # noqa: E402
import matplotlib.ticker as mticker  # noqa: E402
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg  # noqa: E402
from matplotlib.figure import Figure  # noqa: E402

HERE = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
sys.path.insert(0, str(HERE))
import latency_core as core  # noqa: E402
from latency_core import (  # noqa: E402
    AGG_LOSS_MARK, APP_NAME, COLORS, GATEWAY_KEY, GATEWAY_LABEL, MAX_POINTS_PER_TARGET,
    SYSTEM, CsvLogger, HistoryStore, LogTail, acc_add, acc_merge, bucket_size_for,
    floor_ts, fmt_bucket, new_acc,
)

# Settings this window owns in config.json (everything else is left untouched).
VIEWER_KEYS = ("targets", "interval_sec", "timeout_ms", "log_dir", "auto_gateway",
               "public_ip", "span_sec", "theme", "log_scale")

# --------------------------------------------------------------------------- #
# GUI
# --------------------------------------------------------------------------- #
try:  # modern Windows-11 style theme (light + dark); optional
    import sv_ttk
except Exception:  # pragma: no cover
    sv_ttk = None
try:  # follow the OS light/dark setting; optional
    import darkdetect
except Exception:  # pragma: no cover
    darkdetect = None

import tkinter.font as tkfont  # noqa: E402

SPAN_PRESETS = OrderedDict([
    ("15m", 900), ("1h", 3600), ("6h", 6 * 3600), ("12h", 12 * 3600),
    ("24h", 86400), ("7d", 7 * 86400), ("30d", 30 * 86400),
])
MIN_SPAN, MAX_SPAN = 60, 400 * 86400

PLOT_THEME = {
    "dark": {"bg": "#1c1c1c", "fg": "#e6e6e6", "muted": "#9a9a9a", "grid": "#303030",
             "gateway": "#f2f2f2", "select": "#57c8ff", "ok": "#4ade80", "bad": "#f87171"},
    "light": {"bg": "#fafafa", "fg": "#1f2328", "muted": "#6b6f76", "grid": "#e6e6e6",
              "gateway": "#111827", "select": "#005fb8", "ok": "#16a34a", "bad": "#dc2626"},
}


def span_label(secs: float) -> str:
    for k, v in SPAN_PRESETS.items():
        if abs(v - secs) < 1:
            return k
    if secs < 3600:
        return f"{secs / 60:.0f} min"
    if secs < 2 * 86400:
        return f"{secs / 3600:.1f} h".replace(".0 h", " h")
    return f"{secs / 86400:.1f} days".replace(".0 days", " days")


def parse_when(txt: str) -> datetime:
    txt = txt.strip()
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(txt, fmt)
        except ValueError:
            pass
    raise ValueError(txt)


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.cfg = core.load_config()
        self.apply_cfg(self.cfg)
        self.gateway = {"ip": None, "iface": None}
        self.public_ip = None
        self.logger = CsvLogger(Path(self.cfg["log_dir"]))
        self.history = HistoryStore(self.logger)
        self.tail = LogTail(self.logger)
        self.data = {}              # key -> deque[(datetime, latency|None)]  (recent, in memory)
        self.gw_events = deque(maxlen=5000)   # [(ts, new_gateway_ip)]
        self._gw_last_host = None   # last gateway IP seen in the log (change markers)
        self._pub_last = None       # last public IP seen in the log
        self.last_status = {}       # key -> status str
        self.status = None          # logger heartbeat (status.json)
        self.logger_ok = False
        self._cfg_mtime = core.config_mtime()
        self._spawned = None
        self.span_sec = float(self.cfg["span_sec"])
        self.log_scale = bool(self.cfg.get("log_scale", False))
        self.view_end = None        # None = live (window ends "now"); else a datetime
        self.dirty = True
        self._last_draw = 0.0
        self._drag = None           # (x0, patch) while drag-selecting on the graph
        self._dots = {}
        self._tick = 0

        root.title(APP_NAME)
        root.geometry("1320x800")
        root.minsize(1040, 600)
        self.theme = self.resolve_theme()
        self.setup_style()
        self.build_ui()
        self.load_recent()
        self.tail.skip_to_end()
        self.refresh_logger_status()
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(300, self.poll)

    # ---- config ---------------------------------------------------------- #
    def apply_cfg(self, cfg):
        self.targets = [t for t in cfg["targets"] if t.get("host")]
        self.interval_sec = float(cfg["interval_sec"])
        self.timeout_ms = int(cfg["timeout_ms"])
        self.gateway_enabled = bool(cfg.get("auto_gateway", True))
        self.public_ip_enabled = bool(cfg.get("public_ip", True))

    def save_config(self):
        """Merge this window's settings into config.json (the logger reads it)."""
        mine = {
            "targets": self.targets,
            "interval_sec": self.interval_sec,
            "timeout_ms": self.timeout_ms,
            "log_dir": str(self.logger.log_dir),
            "span_sec": self.span_sec,
            "auto_gateway": self.gateway_enabled,
            "public_ip": self.public_ip_enabled,
            "theme": self.cfg.get("theme", "system"),
            "log_scale": self.log_scale,
        }
        try:
            cfg = core.load_config()            # keep anything else in the file as-is
            cfg.update(mine)
            core.save_config(cfg)
            self.cfg = cfg
            self._cfg_mtime = core.config_mtime()
        except Exception as exc:
            self.set_status(f"Could not save config: {exc}")

    def check_config_changed(self):
        """Someone else (another viewer, a text editor) changed config.json."""
        m = core.config_mtime()
        if m == self._cfg_mtime:
            return
        self._cfg_mtime = m
        cfg = core.load_config()
        self.cfg = cfg
        self.apply_cfg(cfg)
        self.interval_var.set(f"{self.interval_sec:g}")
        self.timeout_var.set(str(self.timeout_ms))
        self.gw_var.set(self.gateway_enabled)
        self.pub_var.set(self.public_ip_enabled)
        self.log_scale = bool(cfg.get("log_scale", self.log_scale))
        self.log_var.set(self.log_scale)
        if Path(cfg["log_dir"]) != self.logger.log_dir:
            self.logger.log_dir = Path(cfg["log_dir"])
            self.history.clear()
            self.tail = LogTail(self.logger)
            self.tail.skip_to_end()
        self.dirty = True

    # ---- theme ----------------------------------------------------------- #
    def resolve_theme(self):
        pref = self.cfg.get("theme", "system")
        if pref in ("dark", "light"):
            return pref
        try:
            return "dark" if darkdetect and darkdetect.isDark() else "light"
        except Exception:
            return "light"

    def setup_style(self):
        self.style = ttk.Style(self.root)
        if sv_ttk:
            sv_ttk.set_theme(self.theme, self.root)
            self.S = {"accent": "Accent.TButton", "toggle": "Toggle.TButton",
                      "switch": "Switch.TCheckbutton", "card": "Card.TFrame"}
            self._fix_fonts()
        else:
            self.style.theme_use("clam")
            self.S = {"accent": "TButton", "toggle": "Toolbutton",
                      "switch": "TCheckbutton", "card": "TFrame"}
        f = tkfont.nametofont("TkDefaultFont")
        fam = f.actual("family")
        self.f_title = tkfont.Font(family=fam, size=18, weight="bold")
        self.f_sub = tkfont.Font(family=fam, size=11)
        self.f_section = tkfont.Font(family=fam, size=12, weight="bold")
        self.f_small = tkfont.Font(family=fam, size=10)
        self.custom_styles()

    def custom_styles(self):
        """ttk styles are per-theme, so this runs again after every light/dark switch."""
        self.style.configure("Treeview", rowheight=30, indent=0)
        # Rows never have children: drop the expand/collapse arrow from the item layout.
        def strip(layout):
            out = []
            for name, opts in layout:
                if "indicator" in name.lower():
                    continue
                opts = dict(opts)
                if "children" in opts:
                    opts["children"] = strip(opts["children"])
                out.append((name, opts))
            return out
        try:
            self.style.layout("Treeview.Item", strip(self.style.layout("Treeview.Item")))
        except tk.TclError:
            pass
        self.style.configure("Title.TLabel", font=self.f_title)
        self.style.configure("Section.TLabel", font=self.f_section)
        self.style.configure("Muted.TLabel", font=self.f_small, foreground=self.pt["muted"])
        self.style.configure("Sub.TLabel", font=self.f_sub, foreground=self.pt["muted"])
        self.style.configure("Dot.TLabel", font=self.f_sub)

    def _fix_fonts(self):
        """Sun Valley asks for Segoe UI Variable; use the native UI font where it's missing."""
        families = set(tkfont.families(self.root))
        if "Segoe UI Variable Text" in families or "Segoe UI Variable Static Text" in families:
            return
        native = "Segoe UI" if SYSTEM == "Windows" else tkfont.nametofont("TkDefaultFont").actual("family")
        for name in ("SunValleyCaptionFont", "SunValleyBodyFont", "SunValleyBodyStrongFont",
                     "SunValleyBodyLargeFont", "SunValleySubtitleFont", "SunValleyTitleFont",
                     "SunValleyTitleLargeFont", "SunValleyDisplayFont"):
            try:
                tkfont.nametofont(name).configure(family=native)
            except tk.TclError:
                pass

    @property
    def pt(self):
        return PLOT_THEME[self.theme]

    def toggle_theme(self):
        self.theme = "light" if self.theme == "dark" else "dark"
        self.cfg["theme"] = self.theme
        self.apply_theme()
        self.save_config()

    def apply_theme(self):
        if sv_ttk:
            sv_ttk.set_theme(self.theme, self.root)
        self.custom_styles()
        self.theme_btn.config(text="☀" if self.theme == "dark" else "☾")
        self.canvas.get_tk_widget().config(bg=self.pt["bg"])
        self._dots.clear()
        self.update_status_pill()
        self.dirty = True

    def dot(self, color):
        """Small round colour swatch for the table."""
        if color not in self._dots:
            img = tk.PhotoImage(master=self.root, width=12, height=12)
            for y in range(12):
                for x in range(12):
                    if (x - 5.5) ** 2 + (y - 5.5) ** 2 <= 20:
                        img.put(color, to=(x, y))
            self._dots[color] = img
        return self._dots[color]

    # ---- UI -------------------------------------------------------------- #
    def build_ui(self):
        outer = ttk.Frame(self.root, padding=(18, 14, 18, 10))
        outer.pack(fill="both", expand=True)

        # Header ------------------------------------------------------------
        head = ttk.Frame(outer)
        head.pack(fill="x")
        titles = ttk.Frame(head)
        titles.pack(side="left")
        ttk.Label(titles, text=APP_NAME, style="Title.TLabel").pack(anchor="w")
        pill = ttk.Frame(titles)
        pill.pack(anchor="w", pady=(2, 0))
        self.pill_dot = ttk.Label(pill, text="●", style="Dot.TLabel")
        self.pill_dot.pack(side="left")
        self.pill_text = ttk.Label(pill, text="", style="Sub.TLabel")
        self.pill_text.pack(side="left", padx=(4, 0))

        self.theme_btn = ttk.Button(head, text="☀" if self.theme == "dark" else "☾", width=3,
                                    command=self.toggle_theme)
        self.theme_btn.pack(side="right")
        self.start_btn = ttk.Button(head, text="Start logger", width=12, style=self.S["accent"],
                                    command=self.start_logger)
        self.start_btn.pack(side="right", padx=(0, 8))

        # Time-range toolbar -------------------------------------------------
        bar = ttk.Frame(outer)
        bar.pack(fill="x", pady=(14, 10))
        seg = ttk.Frame(bar)
        seg.pack(side="left")
        self.span_var = tk.StringVar(value=span_label(self.span_sec))
        for label, secs in SPAN_PRESETS.items():
            ttk.Radiobutton(seg, text=label, value=label, variable=self.span_var,
                            style=self.S["toggle"], width=4,
                            command=lambda s=secs: self.set_span(s)).pack(side="left", padx=1)
        ttk.Button(bar, text="Custom…", command=self.custom_range).pack(side="left", padx=(10, 0))

        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=12)
        ttk.Button(bar, text="‹", width=3, command=lambda: self.shift(-1)).pack(side="left")
        ttk.Button(bar, text="›", width=3, command=lambda: self.shift(1)).pack(side="left", padx=4)
        self.live_btn = ttk.Button(bar, text="Live", command=self.go_live)
        self.live_btn.pack(side="left")
        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=12)
        self.log_var = tk.BooleanVar(value=self.log_scale)
        ttk.Checkbutton(bar, text="Log scale", variable=self.log_var, style=self.S["toggle"],
                        command=self.on_log_toggle).pack(side="left")

        self.range_var = tk.StringVar()
        ttk.Label(bar, textvariable=self.range_var, style="Sub.TLabel").pack(side="right")

        # Body -------------------------------------------------------------
        body = ttk.PanedWindow(outer, orient="horizontal")
        body.pack(fill="both", expand=True)

        side = ttk.Frame(body, padding=(0, 0, 12, 0))
        body.add(side, weight=0)
        graph_card = ttk.Frame(body, style=self.S["card"], padding=10)
        body.add(graph_card, weight=1)

        # Targets
        ttk.Label(side, text="Targets", style="Section.TLabel").pack(anchor="w", pady=(0, 6))
        card = ttk.Frame(side, style=self.S["card"], padding=6)
        card.pack(fill="both", expand=True)
        cols = ("host", "last", "avg", "min", "max", "loss")
        heads = ("Host / IP", "Last", "Avg", "Min", "Max", "Loss")
        widths = (150, 48, 48, 48, 48, 52)
        self.tree = ttk.Treeview(card, columns=cols, show="tree headings", height=4,
                                 selectmode="extended")
        self.tree.heading("#0", text="Name", anchor="w")
        self.tree.column("#0", width=140, minwidth=110, anchor="w")
        for c, h, w in zip(cols, heads, widths):
            self.tree.heading(c, text=h, anchor="w" if c == "host" else "e")
            self.tree.column(c, width=w, minwidth=40, anchor="w" if c == "host" else "e")
        self.tree.pack(fill="both", expand=True)
        ttk.Label(side, text="Latency in ms · stats cover the range on the graph",
                  style="Muted.TLabel").pack(anchor="w", pady=(4, 10))

        add = ttk.Frame(side)
        add.pack(fill="x")
        add.columnconfigure(0, weight=3)
        add.columnconfigure(1, weight=2)
        ttk.Label(add, text="Host or IP", style="Muted.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(add, text="Name", style="Muted.TLabel").grid(row=0, column=1, sticky="w", padx=(6, 0))
        self.host_entry = ttk.Entry(add)
        self.host_entry.grid(row=1, column=0, sticky="ew")
        self.label_entry = ttk.Entry(add)
        self.label_entry.grid(row=1, column=1, sticky="ew", padx=(6, 0))
        ttk.Button(add, text="Add", style=self.S["accent"], command=self.add_target).grid(
            row=1, column=2, padx=(6, 0))
        ttk.Button(add, text="Remove", command=self.remove_target).grid(row=1, column=3, padx=(6, 0))
        self.host_entry.bind("<Return>", lambda e: self.add_target())
        self.label_entry.bind("<Return>", lambda e: self.add_target())

        # Settings
        ttk.Label(side, text="Settings", style="Section.TLabel").pack(anchor="w", pady=(18, 6))
        st = ttk.Frame(side, style=self.S["card"], padding=12)
        st.pack(fill="x")
        st.columnconfigure(1, weight=1)
        self.gw_var = tk.BooleanVar(value=self.gateway_enabled)
        ttk.Checkbutton(st, text="Auto-detect local gateway", variable=self.gw_var,
                        style=self.S["switch"], command=self.on_gateway_toggle).grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(0, 4))
        self.pub_var = tk.BooleanVar(value=self.public_ip_enabled)
        ttk.Checkbutton(st, text="Record public IP", variable=self.pub_var,
                        style=self.S["switch"], command=self.on_public_ip_toggle).grid(
            row=1, column=0, columnspan=3, sticky="w", pady=(0, 8))

        ttk.Label(st, text="Ping every").grid(row=2, column=0, sticky="w")
        self.interval_var = tk.StringVar(value=f"{self.interval_sec:g}")
        sp = ttk.Spinbox(st, from_=1, to=3600, increment=1, width=6,
                         textvariable=self.interval_var, command=self.apply_settings)
        sp.grid(row=2, column=1, sticky="e", pady=3)
        ttk.Label(st, text="s", style="Muted.TLabel").grid(row=2, column=2, sticky="w", padx=(6, 0))

        ttk.Label(st, text="Timeout").grid(row=3, column=0, sticky="w")
        self.timeout_var = tk.StringVar(value=str(self.timeout_ms))
        sp2 = ttk.Spinbox(st, from_=100, to=10000, increment=100, width=6,
                          textvariable=self.timeout_var, command=self.apply_settings)
        sp2.grid(row=3, column=1, sticky="e", pady=3)
        ttk.Label(st, text="ms", style="Muted.TLabel").grid(row=3, column=2, sticky="w", padx=(6, 0))
        for w in (sp, sp2):
            w.bind("<Return>", lambda e: self.apply_settings())
            w.bind("<FocusOut>", lambda e: self.apply_settings())

        logs = ttk.Frame(st)
        logs.grid(row=4, column=0, columnspan=3, sticky="ew", pady=(10, 0))
        ttk.Button(logs, text="Open log folder", command=self.open_logs).pack(side="left")
        ttk.Button(logs, text="Change…", command=self.change_log_dir).pack(side="left", padx=6)
        self.archive_btn = ttk.Button(logs, text="Compress old logs", command=self.archive_now)
        self.archive_btn.pack(side="left")

        # Graph
        # "constrained" layout recalculates margins on every draw (incl. window resizes),
        # so the plot always fills the card.
        self.fig = Figure(figsize=(8, 5), dpi=100, layout="constrained")
        self.fig.get_layout_engine().set(w_pad=6 / 72, h_pad=6 / 72, wspace=0, hspace=0)
        self.ax = self.fig.add_subplot(111)
        self.canvas = FigureCanvasTkAgg(self.fig, master=graph_card)
        cw = self.canvas.get_tk_widget()
        cw.config(highlightthickness=0, bg=self.pt["bg"])
        cw.pack(fill="both", expand=True)
        # add="+": keep matplotlib's own <Configure> handler (it resizes the figure);
        # without it the plot stays at its first size when the window grows.
        cw.bind("<Configure>", lambda e: setattr(self, "dirty", True), add="+")
        self.canvas.mpl_connect("button_press_event", self.on_press)
        self.canvas.mpl_connect("motion_notify_event", self.on_motion)
        self.canvas.mpl_connect("button_release_event", self.on_release)
        self.hint_var = tk.StringVar()
        ttk.Label(graph_card, textvariable=self.hint_var, style="Muted.TLabel").pack(
            anchor="e", pady=(4, 0))

        # Status line
        self.status_var = tk.StringVar()
        ttk.Label(outer, textvariable=self.status_var, style="Muted.TLabel").pack(
            fill="x", pady=(8, 0))
        self.update_status_pill()

    def set_status(self, msg):
        self.status_var.set(msg)

    def update_status_pill(self):
        ok = self.logger_ok
        self.pill_dot.config(foreground=self.pt["ok"] if ok else self.pt["bad"])
        st = self.status or {}
        if ok:
            txt = (f"Logger running{' as a service' if st.get('mode') == 'service' else ''}"
                   f" · every {float(st.get('interval_sec', self.interval_sec)):g} s")
            if self.gateway_enabled and self.gateway["ip"]:
                txt += f"  ·  gateway {self.gateway['ip']}"
            if self.public_ip_enabled:
                txt += f"  ·  public IP {self.public_ip or 'checking…'}"
        elif st:
            age = time.time() - float(st.get("heartbeat", 0))
            txt = f"Logger not running (last seen {self._ago(age)} ago) — showing saved logs"
        else:
            txt = "Logger not running — press Start logger, or install it as a service"
        self.pill_text.config(text=txt)
        try:
            if ok:
                self.start_btn.config(text="Logger running")
                self.start_btn.state(["disabled"])
            else:
                self.start_btn.config(text="Start logger")
                self.start_btn.state(["!disabled"])
        except Exception:
            pass

    @staticmethod
    def _ago(secs):
        if secs < 90:
            return f"{secs:.0f} s"
        if secs < 5400:
            return f"{secs / 60:.0f} min"
        if secs < 172800:
            return f"{secs / 3600:.0f} h"
        return f"{secs / 86400:.0f} days"

    def refresh_logger_status(self):
        self.status = core.read_status()
        was = self.logger_ok
        self.logger_ok = core.logger_alive(self.status)
        if self.status and self.logger_ok:
            gw = self.status.get("gateway") or {}
            self.gateway = {"ip": gw.get("ip"), "iface": gw.get("iface")}
            self.public_ip = self.status.get("public_ip")
        if was != self.logger_ok:
            self.dirty = True
        self.update_status_pill()

    def start_logger(self):
        """Run the logger in the background (for when it isn't installed as a service)."""
        if self.logger_ok:
            return
        if getattr(sys, "frozen", False):
            name = "LatencyLogger.exe" if SYSTEM == "Windows" else "LatencyLogger"
            cands = [Path(sys.executable).with_name(name),
                     Path(sys.executable).parents[3] / name if SYSTEM == "Darwin" else None]
            exe = next((c for c in cands if c and c.exists()), None)
            if exe is None:
                messagebox.showerror(APP_NAME, f"Couldn't find {name} next to the viewer.")
                return
            cmd = [str(exe), "run", "--quiet"]
        else:
            py = sys.executable
            if SYSTEM == "Windows" and py.lower().endswith("python.exe"):
                w = py[:-10] + "pythonw.exe"
                py = w if os.path.exists(w) else py
            cmd = [py, str(HERE / "latency_logger.py"), "run", "--quiet"]
        kwargs = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL,
                  "stderr": subprocess.DEVNULL, "cwd": str(HERE)}
        if SYSTEM == "Windows":
            kwargs["creationflags"] = 0x00000008 | 0x00000200 | 0x08000000  # detached, no window
        else:
            kwargs["start_new_session"] = True     # keeps running after the viewer closes
        try:
            self._spawned = subprocess.Popen(cmd, **kwargs)
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"Couldn't start the logger:\n{exc}")
            return
        self.set_status("Logger started in the background. It keeps running after you close "
                        "this window (until you log out). Install it as a service to have it "
                        "start at boot.")
        self.start_btn.config(text="Starting…")
        self.start_btn.state(["disabled"])

    # ---- rows (gateway + user targets) ----------------------------------- #
    def rows(self):
        """[(key, label, host_display, color)] in display order."""
        out = []
        if self.gateway_enabled:
            ip, iface = self.gateway["ip"], self.gateway["iface"]
            if not ip:                                   # logger stopped: last one in the log
                ip, iface = self._gw_last_host or None, None
            shown = f"{ip} ({iface})" if ip and iface else (ip or "–")
            out.append((GATEWAY_KEY, GATEWAY_LABEL, shown, self.pt["gateway"]))
        for i, t in enumerate(self.targets):
            out.append((t["host"], t.get("label") or t["host"], t["host"],
                        COLORS[i % len(COLORS)]))
        return out

    def keys(self):
        return [r[0] for r in self.rows()]

    # ---- targets --------------------------------------------------------- #
    def add_target(self):
        host = self.host_entry.get().strip()
        label = self.label_entry.get().strip()
        if not host:
            return
        if not re.fullmatch(r"[A-Za-z0-9.\-:_%]+", host):
            messagebox.showerror(APP_NAME, f"'{host}' is not a valid host name or IP.")
            return
        if any(t["host"] == host for t in self.targets):
            messagebox.showinfo(APP_NAME, f"{host} is already in the list.")
            return
        self.targets = self.targets + [{"host": host, "label": label or host}]
        self.host_entry.delete(0, "end")
        self.label_entry.delete(0, "end")
        self.save_config()
        self.dirty = True

    def remove_target(self):
        sel = set(self.tree.selection())
        if not sel:
            return
        if GATEWAY_KEY in sel:
            self.gw_var.set(False)
            self.on_gateway_toggle()
        self.targets = [t for t in self.targets if t["host"] not in sel]
        for k in sel:
            self.data.pop(k, None)
            self.last_status.pop(k, None)
        self.save_config()
        self.dirty = True

    def on_public_ip_toggle(self):
        self.public_ip_enabled = bool(self.pub_var.get())
        if not self.public_ip_enabled:
            self.public_ip = None
        self.save_config()
        self.update_status_pill()

    def on_gateway_toggle(self):
        self.gateway_enabled = bool(self.gw_var.get())
        self.save_config()
        self.update_status_pill()
        self.dirty = True

    # ---- settings -------------------------------------------------------- #
    def apply_settings(self):
        try:
            self.interval_sec = max(1.0, float(self.interval_var.get()))
        except ValueError:
            self.interval_var.set(f"{self.interval_sec:g}")
        try:
            self.timeout_ms = max(100, int(float(self.timeout_var.get())))
        except ValueError:
            self.timeout_var.set(str(self.timeout_ms))
        self.save_config()
        self.update_status_pill()

    def change_log_dir(self):
        d = filedialog.askdirectory(initialdir=str(self.logger.log_dir),
                                    title="Choose log folder")
        if d:
            self.logger.log_dir = Path(d)
            self.history.clear()
            self.tail = LogTail(self.logger)
            self.tail.skip_to_end()
            self.save_config()
            self.dirty = True
            self.set_status(f"The logger will write to {d} from its next round.")

    def archive_now(self):
        """gzip finished daily logs now (the logger also does this daily by itself)."""
        import threading
        self.archive_btn.state(["disabled"])
        self.set_status("Compressing old daily logs…")
        keep = max(1, int(self.cfg.get("compress_after_days", 1)))

        def work():
            try:
                res = core.archive_old_logs(self.logger.log_dir, keep)
            except Exception as exc:        # pragma: no cover
                res = exc
            self.root.after(0, lambda: self._archive_done(res))
        threading.Thread(target=work, daemon=True).start()

    def _archive_done(self, res):
        self.archive_btn.state(["!disabled"])
        if isinstance(res, Exception):
            self.set_status(f"Compressing failed: {res}")
            return
        n, before, after = res
        if n:
            self.history.clear()                 # re-read the archives (same data)
            self.set_status(f"Compressed {n} daily log{'s' if n != 1 else ''}: "
                            f"{core.fmt_bytes(before)} → {core.fmt_bytes(after)}")
        else:
            self.set_status("Nothing to compress — finished days are already archived.")

    def open_logs(self):
        path = self.logger.log_dir
        path.mkdir(parents=True, exist_ok=True)
        try:
            if SYSTEM == "Windows":
                os.startfile(str(path))  # type: ignore[attr-defined]
            elif SYSTEM == "Darwin":
                subprocess.Popen(["open", str(path)])
            else:
                subprocess.Popen(["xdg-open", str(path)])
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"Could not open folder:\n{exc}")

    # ---- time span / navigation ------------------------------------------ #
    def span(self):
        return self.span_sec

    def view_range(self):
        end = self.view_end or datetime.now()
        return end - timedelta(seconds=self.span_sec), end

    def set_view(self, start: datetime, end: datetime):
        """Show an arbitrary span [start, end]. Ending at/after now → live."""
        secs = (end - start).total_seconds()
        self.span_sec = float(round(min(MAX_SPAN, max(MIN_SPAN, secs))))
        now = datetime.now()
        self.view_end = None if end >= now - timedelta(seconds=2) else end
        self.span_var.set(span_label(self.span_sec))
        self.save_config()
        self.dirty = True

    def set_span(self, secs):
        """Preset button: keep the current end (live stays live)."""
        if self.view_end is not None:
            self.set_view(self.view_end - timedelta(seconds=secs), self.view_end)
            return
        self.span_sec = float(secs)
        self.span_var.set(span_label(self.span_sec))
        self.save_config()
        self.dirty = True

    def shift(self, direction):
        start, end = self.view_range()
        d = timedelta(seconds=direction * self.span_sec)
        self.set_view(start + d, end + d)

    def on_log_toggle(self):
        self.log_scale = bool(self.log_var.get())
        self.save_config()
        self.dirty = True

    def go_live(self):
        self.view_end = None
        self.dirty = True

    def custom_range(self):
        start, end = self.view_range()
        dlg = tk.Toplevel(self.root)
        dlg.title("Custom time range")
        dlg.transient(self.root)
        dlg.resizable(False, False)
        frm = ttk.Frame(dlg, padding=18)
        frm.pack(fill="both", expand=True)
        ttk.Label(frm, text="Show a custom time range", style="Section.TLabel").grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 10))
        ttk.Label(frm, text="From").grid(row=1, column=0, sticky="w", pady=4)
        ttk.Label(frm, text="To").grid(row=2, column=0, sticky="w", pady=4)
        e_from = ttk.Entry(frm, width=20)
        e_to = ttk.Entry(frm, width=20)
        e_from.insert(0, f"{start:%Y-%m-%d %H:%M}")
        e_to.insert(0, f"{end:%Y-%m-%d %H:%M}")
        e_from.grid(row=1, column=1, padx=(10, 0))
        e_to.grid(row=2, column=1, padx=(10, 0))
        ttk.Label(frm, text="Format: YYYY-MM-DD HH:MM (time optional)", style="Muted.TLabel").grid(
            row=3, column=0, columnspan=2, sticky="w", pady=(6, 12))

        quick = ttk.Frame(frm)
        quick.grid(row=4, column=0, columnspan=2, sticky="w", pady=(0, 12))

        def set_fields(a, b):
            e_from.delete(0, "end"); e_from.insert(0, f"{a:%Y-%m-%d %H:%M}")  # noqa: E702
            e_to.delete(0, "end"); e_to.insert(0, f"{b:%Y-%m-%d %H:%M}")      # noqa: E702

        today0 = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        ttk.Button(quick, text="Today", command=lambda: set_fields(today0, datetime.now())).pack(side="left")
        ttk.Button(quick, text="Yesterday", command=lambda: set_fields(
            today0 - timedelta(days=1), today0)).pack(side="left", padx=4)
        ttk.Button(quick, text="This week", command=lambda: set_fields(
            today0 - timedelta(days=today0.weekday()), datetime.now())).pack(side="left")
        ttk.Button(quick, text="This month", command=lambda: set_fields(
            today0.replace(day=1), datetime.now())).pack(side="left", padx=4)

        def apply():
            try:
                a = parse_when(e_from.get())
                b_txt = e_to.get().strip()
                b = parse_when(b_txt)
                if len(b_txt) == 10:          # a bare date means "until the end of that day"
                    b += timedelta(days=1)
            except ValueError:
                messagebox.showerror(APP_NAME, "Use the format YYYY-MM-DD HH:MM.", parent=dlg)
                return
            if b <= a:
                messagebox.showerror(APP_NAME, "'To' must be after 'From'.", parent=dlg)
                return
            self.set_view(a, b)
            dlg.destroy()

        btns = ttk.Frame(frm)
        btns.grid(row=5, column=0, columnspan=2, sticky="e")
        ttk.Button(btns, text="Cancel", command=dlg.destroy).pack(side="right")
        ttk.Button(btns, text="Show", style=self.S["accent"], command=apply).pack(side="right", padx=6)
        dlg.bind("<Return>", lambda e: apply())
        dlg.bind("<Escape>", lambda e: dlg.destroy())
        dlg.update_idletasks()
        x = self.root.winfo_rootx() + (self.root.winfo_width() - dlg.winfo_width()) // 2
        y = self.root.winfo_rooty() + 120
        dlg.geometry(f"+{x}+{y}")
        try:
            dlg.wait_visibility()
            dlg.grab_set()
        except tk.TclError:
            pass
        e_from.focus_set()

    # ---- drag-to-zoom on the graph --------------------------------------- #
    @staticmethod
    def _xdt(x):
        return mdates.num2date(x).replace(tzinfo=None)

    DRAG_MIN_PX = 12   # a real drag, not the tiny wobble of a normal click

    def on_press(self, ev):
        if ev.inaxes is not self.ax or ev.xdata is None or ev.button != 1:
            return
        if ev.dblclick:                                   # zoom out ×3 around centre
            self._cancel_drag()
            start, end = self.view_range()
            mid = start + (end - start) / 2
            half = timedelta(seconds=self.span_sec * 1.5)
            self.set_view(mid - half, min(mid + half, datetime.now()) if self.view_end is None
                          else mid + half)
            return
        # Remember where the press happened; the selection only appears once the
        # mouse has actually moved a few pixels.
        self._drag = {"x0": ev.xdata, "px0": ev.x, "patch": None}

    def _cancel_drag(self):
        if self._drag and self._drag["patch"] is not None:
            try:
                self._drag["patch"].remove()
            except Exception:
                pass
            self.canvas.draw_idle()
        self._drag = None

    def on_motion(self, ev):
        if not self._drag or ev.xdata is None:
            return
        d = self._drag
        if d["patch"] is None and abs(ev.x - d["px0"]) < self.DRAG_MIN_PX:
            return
        if d["patch"] is not None:
            d["patch"].remove()
        d["patch"] = self.ax.axvspan(min(d["x0"], ev.xdata), max(d["x0"], ev.xdata),
                                     color=self.pt["select"], alpha=0.18, lw=0)
        self.canvas.draw_idle()

    def on_release(self, ev):
        if not self._drag:
            return
        d = self._drag
        moved = ev.x is not None and abs(ev.x - d["px0"]) >= self.DRAG_MIN_PX
        self._cancel_drag()
        if not moved:                      # plain click → nothing changes
            return
        x1 = ev.xdata if ev.xdata is not None else d["x0"]
        a, b = sorted((self._xdt(d["x0"]), self._xdt(x1)))
        if (b - a).total_seconds() < MIN_SPAN:
            return
        self.set_view(a, b)

    # ---- data ------------------------------------------------------------ #
    def add_point(self, ts, key, latency):
        dq = self.data.get(key)
        if dq is None:
            dq = self.data[key] = deque(maxlen=MAX_POINTS_PER_TARGET)
        dq.append((ts, latency))

    def load_recent(self):
        """Fill memory with the last 24 h (covers all of today) from the logs."""
        keys = set(self.keys()) | {GATEWAY_KEY}
        last_gw, n = None, 0
        for ts, key, host, lat in self.logger.read_since(datetime.now() - timedelta(days=1), keys):
            self.add_point(ts, key, lat)
            if key == GATEWAY_KEY:
                if last_gw is not None and host != last_gw:
                    self.gw_events.append((ts, host))
                last_gw = host
            n += 1
        self._gw_last_host = last_gw
        if n:
            self.set_status(f"Loaded {n:,} earlier results from the logs.")

    @staticmethod
    def _days(start, end):
        d = start.date()
        while d <= end.date():
            yield d
            d += timedelta(days=1)

    def raw_series(self, key, start, end):
        today = date.today()
        pts = []
        for d in self._days(start, end):
            src = self.data.get(key, ()) if d == today else self.history.raw(d).get(key, ())
            pts.extend(p for p in src if start <= p[0] <= end and p[0].date() == d)
        return pts

    def agg_series(self, key, start, end, bucket):
        """Averaged buckets: [(bucket_start, acc)] sorted by time."""
        today = date.today()
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

    def first_data_ts(self, start, end):
        """Earliest sample in [start, end] for the current rows, or None."""
        keys = self.keys()
        mem = [self.data[k][0][0] for k in keys if self.data.get(k)]
        earliest = min(mem) if mem else None
        if earliest is not None and earliest <= start:
            return None
        # Anything in older log files inside the range? Then there's nothing to trim.
        stop = earliest.date() if earliest else end.date() + timedelta(days=1)
        for d in self._days(start, end):
            if d >= stop or d == date.today():
                break
            mins = self.history.minutes(d)
            firsts = [min(mins[k]) for k in keys if mins.get(k)]
            if firsts:
                return max(start, min(firsts))
        return earliest

    def gateway_changes(self, start, end):
        today = date.today()
        ev = []
        for d in self._days(start, end):
            src = self.gw_events if d == today else self.history.gw_events(d)
            ev.extend(e for e in src if start <= e[0] <= end and e[0].date() == d)
        return ev

    # ---- main loop ------------------------------------------------------- #
    def poll(self):
        got = False
        keys = set(self.keys())
        for ts, key, host, latency, status, pub in self.tail.read_new():
            if key == GATEWAY_KEY:
                if host != self._gw_last_host:
                    if self._gw_last_host is not None:
                        self.gw_events.append((ts, host))      # a real network switch
                        self.set_status(f"Network change — local gateway is now {host}"
                                        if host else "No local gateway — offline?")
                    self._gw_last_host = host
            if pub and pub != self._pub_last:
                if self._pub_last:
                    self.set_status(f"Public IP changed: {self._pub_last} → {pub}")
                self._pub_last = pub
            if key in keys or key == GATEWAY_KEY:
                self.add_point(ts, key, latency)
                self.last_status[key] = status
                got = True

        self._tick += 1
        if self._tick % 4 == 0:                      # every 2 s
            self.refresh_logger_status()
            self.check_config_changed()
        if self._tick % 20 == 0 and self.cfg.get("theme") == "system":   # follow OS dark mode
            t = self.resolve_theme()
            if t != self.theme:
                self.theme = t
                self.apply_theme()

        live = self.view_end is None
        bucket = bucket_size_for(self.span_sec)
        min_gap = 0 if bucket is None else 10   # averaged live views: redraw ≤ every 10 s
        if not self._drag and (self.dirty or (live and got and
                                              time.monotonic() - self._last_draw >= min_gap)):
            self.render()
        self.root.after(500, self.poll)

    # ---- rendering ------------------------------------------------------- #
    def render(self):
        self.dirty = False
        self._last_draw = time.monotonic()
        start, end = self.view_range()
        today = date.today()
        # Live view with less history than the chosen span: start the graph where the
        # data starts, so the left side isn't empty and averaging matches what's shown.
        self._fitted_from = None
        if self.view_end is None:
            first = self.first_data_ts(start, end)
            if first is not None and first > start + (end - start) * 0.03:
                self._fitted_from = first
                start = max(start, first - (end - first) * 0.02)
        bucket = bucket_size_for((end - start).total_seconds())
        prev_status = None
        if any(d != today and d not in self.history._minutes for d in self._days(start, end)):
            prev_status = self.status_var.get()
            self.set_status("Reading history from log files…")
            try:
                self.root.update_idletasks()
            except Exception:
                pass
        series = {}
        for key, label, shown, color in self.rows():
            if bucket is None:
                series[key] = ("raw", self.raw_series(key, start, end))
            else:
                series[key] = ("agg", self.agg_series(key, start, end, bucket))
        self.refresh_table(series)
        self.redraw(series, start, end, bucket)

        fmt = "%a %d %b %H:%M" if self.span_sec >= 3600 else "%a %d %b %H:%M:%S"
        mode = "● Live" if self.view_end is None else "History"
        res = "every sample" if bucket is None else f"avg per {fmt_bucket(bucket)}"
        self.range_var.set(f"{mode}   {start:{fmt}}  →  {end:{fmt}}   ·   "
                           f"{span_label(self.span_sec)}, {res}")
        try:
            self.live_btn.state(["disabled"] if self.view_end is None else ["!disabled"])
        except Exception:
            pass
        hint = ("| = timeout" if bucket is None else
                f"line = average · band = min–max · | = ≥{AGG_LOSS_MARK:.0%} loss")
        hint += ("  ·  log scale" if self.log_scale else "  ·  ▲ = above scale")
        hint += "  ·  drag to zoom, double-click to zoom out"
        if getattr(self, "_fitted_from", None):
            hint = f"showing data since {self._fitted_from:%d %b %H:%M}  ·  " + hint
        try:
            self.hint_var.set(hint)
        except AttributeError:
            pass
        if prev_status is not None:
            self.set_status(prev_status)

    def refresh_table(self, series):
        rows = self.rows()
        existing = set(self.tree.get_children())
        wanted = [r[0] for r in rows]
        for iid in existing - set(wanted):
            self.tree.delete(iid)
        fmt = lambda v: "–" if v is None else f"{v:.1f}"  # noqa: E731
        live = self.view_end is None
        for i, (key, label, shown, color) in enumerate(rows):
            kind, pts = series.get(key, ("raw", []))
            total = new_acc()
            last = None
            if kind == "raw":
                for _, v in pts:
                    acc_add(total, v)
                last = pts[-1][1] if pts else None
            else:
                for _, acc in pts:
                    acc_merge(total, acc)
                if pts and pts[-1][1][1]:
                    last = pts[-1][1][0] / pts[-1][1][1]
            s, ok, lost, mn, mx = total
            n = ok + lost
            last_txt = fmt(last)
            if live and last is None and key in self.last_status:
                last_txt = self.last_status[key]          # e.g. "timeout", "no network"
            values = (shown, last_txt, fmt(s / ok if ok else None),
                      fmt(mn if ok else None), fmt(mx if ok else None),
                      f"{100 * lost / n:.1f}%" if n else "–")
            if key in existing:
                self.tree.item(key, text=f"  {label}", image=self.dot(color), values=values)
            else:
                self.tree.insert("", "end", iid=key, text=f"  {label}", image=self.dot(color),
                                 values=values)
            self.tree.move(key, "", i)

    @staticmethod
    def y_top(vals):
        """Upper y-limit that uses the full height; a few extreme spikes don't flatten the rest."""
        if not vals:
            return 1.0
        vs = sorted(vals)
        hi = vs[-1]
        p = vs[min(len(vs) - 1, int(len(vs) * 0.995))]      # 99.5th percentile
        robust = p * 1.3
        top = hi * 1.08 if hi <= robust else robust
        return max(top, 1.0)

    def redraw(self, series, start, end, bucket):
        pt = self.pt
        fig, ax = self.fig, self.ax
        ax.clear()
        for old in list(fig.legends):
            old.remove()
        # Reserve ~26 px at the top for the legend (as a fraction of the current height).
        h_px = max(200.0, fig.get_size_inches()[1] * fig.dpi)
        fig.get_layout_engine().set(rect=(0, 0, 1, 1 - 26 / h_px))
        fig.set_facecolor(pt["bg"])
        ax.set_facecolor(pt["bg"])
        log = self.log_scale
        if log:
            ax.set_yscale("log")
        any_data = False
        line_vals, spikes = [], []          # plotted values → y-axis scaling
        for key, label, shown, color in self.rows():
            kind, pts = series.get(key, ("raw", []))
            if not pts:
                continue
            any_data = True
            lw = 2.0 if key == GATEWAY_KEY else 1.6
            name = label
            if kind == "raw":
                xs = [p[0] for p in pts]
                ys = [p[1] if p[1] is not None else float("nan") for p in pts]
                ax.plot(xs, ys, "-", color=color, linewidth=lw, label=name,
                        marker="o" if len(pts) < 120 else None, markersize=2.5,
                        solid_joinstyle="round", solid_capstyle="round")
                lost = [p[0] for p in pts if p[1] is None]
                pv = [(x, y) for x, y in zip(xs, ys) if y == y]
            else:
                half = timedelta(seconds=bucket / 2)
                xs = [b + half for b, _ in pts]
                avg = [a[0] / a[1] if a[1] else float("nan") for _, a in pts]
                lo = [a[3] if a[1] and (a[3] > 0 or not log) else float("nan") for _, a in pts]
                hi = [a[4] if a[1] else float("nan") for _, a in pts]
                ax.fill_between(xs, lo, hi, color=color, alpha=0.10, linewidth=0)
                ax.plot(xs, avg, "-", color=color, linewidth=lw, label=name,
                        solid_joinstyle="round", solid_capstyle="round")
                lost = [b + half for b, a in pts
                        if a[2] and a[2] / (a[1] + a[2]) >= AGG_LOSS_MARK]
                pv = [(x, y) for x, y in zip(xs, avg) if y == y]
            line_vals.extend(y for _, y in pv)
            spikes.append((color, pv))
            if lost:
                # bottom edge of the plot (axes coords) → works for linear and log scale
                ax.plot(lost, [0] * len(lost), linestyle="none", marker="|", color=color,
                        markersize=10, markeredgewidth=2, clip_on=False,
                        transform=ax.get_xaxis_transform())

        if self.gateway_enabled:
            changes = self.gateway_changes(start, end)
            for ts, ip in changes:
                ax.axvline(ts, color=pt["muted"], linestyle=(0, (4, 3)), linewidth=1, alpha=0.8)
                if len(changes) <= 15:
                    ax.text(ts, 0.98, f" {ip or 'offline'}", transform=ax.get_xaxis_transform(),
                            rotation=90, va="top", ha="left", fontsize=8, color=pt["muted"])

        # Minimal, modern axes styling
        for side in ("top", "right", "left"):
            ax.spines[side].set_visible(False)
        ax.spines["bottom"].set_color(pt["grid"])
        ax.tick_params(colors=pt["muted"], labelsize=9, length=0, pad=6)
        ax.yaxis.grid(True, color=pt["grid"], linewidth=0.8)
        ax.xaxis.grid(False)
        ax.set_axisbelow(True)
        ax.set_ylabel("ms", color=pt["muted"], fontsize=9, rotation=0, labelpad=14, va="center")
        if log:
            # Log scale shows small and huge values together, so nothing is clipped.
            pos = [v for v in line_vals if v > 0]
            lo_v, hi_v = (min(pos), max(pos)) if pos else (1.0, 10.0)
            ax.set_ylim(max(0.05, lo_v / 1.6), max(hi_v * 1.6, lo_v * 4))
            ax.yaxis.set_major_locator(mticker.LogLocator(base=10, subs=(1.0, 2.0, 5.0)))
            ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda v, _: f"{v:g}"))
            ax.yaxis.set_minor_locator(mticker.NullLocator())
            top = float("inf")
        else:
            top = self.y_top(line_vals)
            ax.set_ylim(0, top)
        for color, pv in spikes:              # values above the scale → ▲ on the top edge
            over = [x for x, y in pv if y > top]
            if over:
                ax.plot(over, [top] * len(over), linestyle="none", marker="^", color=color,
                        markersize=6, clip_on=False)
        ax.set_xlim(start, end)
        ax.margins(x=0)
        locator = mdates.AutoDateLocator(minticks=4, maxticks=9)
        formatter = mdates.ConciseDateFormatter(locator)
        ax.xaxis.set_major_locator(locator)
        ax.xaxis.set_major_formatter(formatter)
        ax.xaxis.get_offset_text().set_color(pt["muted"])
        if any_data:
            # Legend lives in a fixed strip above the plot and is kept OUT of the layout
            # solver: a legend wider than the plot used to make the solver shrink the
            # plot again and again until it collapsed into a thin strip.
            handles, labels = ax.get_legend_handles_labels()
            leg = fig.legend(handles, labels, loc="upper left", bbox_to_anchor=(0.01, 1.0),
                             ncol=max(1, len(labels)), frameon=False, fontsize=9,
                             handlelength=1.4, columnspacing=1.4, borderaxespad=0.3)
            leg.set_in_layout(False)
            for txt in leg.get_texts():
                txt.set_color(pt["fg"])
        else:
            ax.text(0.5, 0.5, "No data in this time range", transform=ax.transAxes,
                    ha="center", va="center", color=pt["muted"], fontsize=11)
        self.canvas.draw_idle()

    def on_close(self):
        self.apply_settings()
        self.root.destroy()


def main():
    if SYSTEM == "Windows":
        try:  # crisp text on high-DPI displays (must happen before Tk starts)
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    sys.exit(main())
