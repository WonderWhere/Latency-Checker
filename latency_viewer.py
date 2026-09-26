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
from collections import OrderedDict
from datetime import datetime, timedelta
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
import latency_sources as sources  # noqa: E402
from latency_core import (  # noqa: E402
    AGG_LOSS_MARK, APP_NAME, COLORS, GATEWAY_KEY, GATEWAY_LABEL,
    SYSTEM, acc_add, acc_merge, bucket_size_for, fmt_bucket, ip_label, is_private_ip, new_acc,
)

# Settings this window owns in config.json (everything else is left untouched).
VIEWER_KEYS = ("targets", "interval_sec", "timeout_ms", "log_dir", "auto_gateway",
               "public_ip", "span_sec", "theme", "log_scale", "names")

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


def json_equal(a, b) -> bool:
    import json
    return json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


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
        self.prefs = sources.Prefs()
        self.sources = sources.make_sources(self.prefs)     # id -> Local/RemoteSource
        self.sd = {}                                         # id -> SourceData (loaded lazily)
        sel = self.prefs.get("selected", "local")
        self.cur = self.sdata(sel if sel in self.sources else "local")
        self.compare = False
        self.compare_key = None
        self.cfg = self.source.get_config()
        self.apply_cfg(self.cfg)
        self._cfg_ver = self.source.config_version()
        self.gateway = {"ip": None, "iface": None}
        self.public_ip = None
        self.status = None          # logger heartbeat of the selected location
        self.logger_ok = False
        self._spawned = None
        self.span_sec = float(self.prefs.get("span_sec", 3600))
        self.log_scale = bool(self.prefs.get("log_scale", False))
        self.view_end = None        # None = live (window ends "now"); else a datetime
        self.dirty = True
        self._last_draw = 0.0
        self._drag = None           # drag-selection on the graph
        self._dots = {}
        self._tick = 0

        root.title(APP_NAME)
        root.geometry("1320x800")
        root.minsize(1040, 600)
        self.theme = self.resolve_theme()
        self.setup_style()
        self.build_ui()
        for src in self.sources.values():
            src.start()                                      # remote locations sync in background
        n = self.cur.load_recent()
        if n:
            self.set_status(f"Loaded {n:,} earlier results from the logs.")
        self.refresh_logger_status()
        self.update_location_ui()
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(300, self.poll)

    # ---- locations ------------------------------------------------------- #
    @property
    def source(self):
        return self.cur.source

    def sdata(self, sid):
        d = self.sd.get(sid)
        if d is None:
            d = self.sd[sid] = sources.SourceData(self.sources[sid])
        return d

    # Existing code talks about "the" logger/history/data: that's the selected location.
    logger = property(lambda self: self.cur.logger)
    history = property(lambda self: self.cur.history)
    data = property(lambda self: self.cur.data)
    gw_events = property(lambda self: self.cur.gw_events)
    last_status = property(lambda self: self.cur.last_status)
    _gw_last_host = property(lambda self: self.cur.gw_last_host)

    def now(self):
        """The time axis: the selected location's clock (viewer clock when comparing)."""
        return datetime.now() if self.compare else self.cur.now()

    def today(self):
        return self.now().date()

    @property
    def is_local(self):
        return self.source.kind == "local"

    @property
    def can_edit(self):
        return not self.compare and self.source.role != "read"

    # ---- config ---------------------------------------------------------- #
    def apply_cfg(self, cfg):
        self.targets = [t for t in cfg["targets"] if t.get("host")]
        self.interval_sec = float(cfg["interval_sec"])
        self.timeout_ms = int(cfg["timeout_ms"])
        self.gateway_enabled = bool(cfg.get("auto_gateway", True))
        self.public_ip_enabled = bool(cfg.get("public_ip", True))
        self.names = dict(cfg.get("names") or {})     # ip -> your name for that network

    LOGGER_KEYS = ("targets", "interval_sec", "timeout_ms", "auto_gateway", "public_ip", "names")

    def save_config(self):
        """Viewer settings → viewer.json; logger settings → the selected location's logger."""
        self.prefs.set(span_sec=self.span_sec, log_scale=self.log_scale,
                       theme=self.prefs.get("theme", "system"))
        mine = {k: getattr(self, {"auto_gateway": "gateway_enabled",
                                  "public_ip": "public_ip_enabled"}.get(k, k))
                for k in self.LOGGER_KEYS}
        if self.is_local:
            mine["log_dir"] = str(self.logger.log_dir)
        if json_equal(mine, {k: self.cfg.get(k) for k in mine}):
            return
        if not self.is_local and self.source.role == "read":
            self.set_status(f"{self.source.name} is paired read-only — changes aren't sent.")
            return

        def done(err):
            self.root.after(0, lambda: self.set_status(
                f"Couldn't save to {self.source.name}: {err}" if err else
                ("" if self.is_local else f"Saved to {self.source.name}'s logger.")))
        try:
            self.cfg.update(mine)
            self.source.save_config(mine, on_done=done)
            self._cfg_ver = self.source.config_version()
        except Exception as exc:
            self.set_status(f"Could not save config: {exc}")

    def check_config_changed(self):
        """The selected location's config changed elsewhere (logger, another viewer, editor)."""
        v = self.source.config_version()
        if v == self._cfg_ver:
            return
        self._cfg_ver = v
        cfg = self.source.get_config()
        old_dir = self.logger.log_dir
        self.cfg = cfg
        self.apply_cfg(cfg)
        self.sync_setting_widgets()
        if self.is_local and Path(cfg["log_dir"]) != old_dir:
            self.cur.reset()
            self.cur.load_recent()
        self.dirty = True

    def sync_setting_widgets(self):
        self.interval_var.set(f"{self.interval_sec:g}")
        self.timeout_var.set(str(self.timeout_ms))
        self.gw_var.set(self.gateway_enabled)
        self.pub_var.set(self.public_ip_enabled)

    # ---- theme ----------------------------------------------------------- #
    def resolve_theme(self):
        pref = self.prefs.get("theme", "system")
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
        self.prefs.set(theme=self.theme)
        self.apply_theme()

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
        self.loc_var = tk.StringVar()
        self.loc_sel = tk.StringVar(value=self.cur.source.id)
        self.compare_var = tk.BooleanVar(value=False)
        self.loc_menu = tk.Menu(self.root, tearoff=False, postcommand=self.build_location_menu)
        self.loc_btn = ttk.Menubutton(head, textvariable=self.loc_var, menu=self.loc_menu,
                                      width=26)
        self.loc_btn.pack(side="right", padx=(0, 10))
        ttk.Label(head, text="Location", style="Sub.TLabel").pack(side="right", padx=(0, 6))

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

        self.cmp_frame = ttk.Frame(bar)
        ttk.Separator(self.cmp_frame, orient="vertical").pack(side="left", fill="y", padx=12)
        ttk.Label(self.cmp_frame, text="Compare").pack(side="left", padx=(0, 6))
        self.cmp_var = tk.StringVar()
        self.cmp_box = ttk.Combobox(self.cmp_frame, textvariable=self.cmp_var, state="readonly",
                                    width=30)
        self.cmp_box.pack(side="left")
        self.cmp_box.bind("<<ComboboxSelected>>", lambda e: self.on_compare_target())
        self._cmp_map = {}
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
        self.tree.bind("<Double-1>", lambda e: self.networks_dialog()
                       if self.tree.identify_row(e.y) == GATEWAY_KEY else None)
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
        add_b = ttk.Button(add, text="Add", style=self.S["accent"], command=self.add_target)
        add_b.grid(row=1, column=2, padx=(6, 0))
        rem_b = ttk.Button(add, text="Remove", command=self.remove_target)
        rem_b.grid(row=1, column=3, padx=(6, 0))
        self.host_entry.bind("<Return>", lambda e: self.add_target())
        self.label_entry.bind("<Return>", lambda e: self.add_target())

        # Settings
        ttk.Label(side, text="Settings", style="Section.TLabel").pack(anchor="w", pady=(18, 6))
        st = ttk.Frame(side, style=self.S["card"], padding=12)
        st.pack(fill="x")
        st.columnconfigure(1, weight=1)
        self.gw_var = tk.BooleanVar(value=self.gateway_enabled)
        gw_c = ttk.Checkbutton(st, text="Auto-detect local gateway", variable=self.gw_var,
                               style=self.S["switch"], command=self.on_gateway_toggle)
        gw_c.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 4))
        self.pub_var = tk.BooleanVar(value=self.public_ip_enabled)
        pub_c = ttk.Checkbutton(st, text="Record public IP", variable=self.pub_var,
                                style=self.S["switch"], command=self.on_public_ip_toggle)
        pub_c.grid(row=1, column=0, columnspan=3, sticky="w", pady=(0, 8))

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
        self.open_btn = ttk.Button(logs, text="Open log folder", command=self.open_logs)
        self.open_btn.pack(side="left")
        self.change_btn = ttk.Button(logs, text="Change…", command=self.change_log_dir)
        self.change_btn.pack(side="left", padx=6)
        self.archive_btn = ttk.Button(logs, text="Compress old logs", command=self.archive_now)
        self.archive_btn.pack(side="left")
        net_b = ttk.Button(st, text="Networks…  (name your public IPs and gateways)",
                           command=self.networks_dialog)
        net_b.grid(row=5, column=0, columnspan=3, sticky="w", pady=(8, 0))
        # disabled in compare mode and for read-only remote locations
        self._edit_widgets = (add_b, rem_b, gw_c, pub_c, sp, sp2, net_b,
                              self.host_entry, self.label_entry)

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
        st = self.status or {}
        src = self.source
        where = "" if self.is_local else f"{src.name}: "
        if self.compare:
            n_ok = sum(1 for sid in self.compare_ids() if self.source_alive(sid))
            n = len(self.compare_ids())
            self.pill_dot.config(foreground=self.pt["ok"] if n_ok == n else self.pt["bad"])
            self.pill_text.config(text=f"Comparing {n} locations — {n_ok} logger"
                                       f"{'s' if n_ok != 1 else ''} live · times on this "
                                       "computer's clock")
            self._set_start_btn(None)
            return
        self.pill_dot.config(foreground=self.pt["ok"] if ok else self.pt["bad"])
        if ok:
            mode = ("remote" if not self.is_local else
                    "as a service" if st.get("mode") == "service" else "")
            txt = (f"{where}Logger running{(' ' + mode) if mode else ''}"
                   f" · every {float(st.get('interval_sec', self.interval_sec)):g} s")
            if self.gateway_enabled and self.gateway["ip"]:
                txt += f"  ·  gateway {ip_label(self.gateway['ip'], self.names)}"
            if self.public_ip_enabled:
                txt += f"  ·  public IP {ip_label(self.public_ip, self.names, 'checking…')}"
            if not self.is_local and src.role == "read":
                txt += "  ·  read-only"
        elif not self.is_local and not src.reachable and not src.error and not src.last_ok:
            txt = f"{where}connecting…"
        elif not self.is_local and not src.reachable:
            seen = (f"last contact {self._ago(time.time() - src.last_ok)} ago"
                    if src.last_ok else "not reached yet")
            txt = f"{where}{src.error or 'unreachable'} — {seen}; showing cached data"
        elif st:
            age = time.time() - float(st.get("heartbeat", 0))
            txt = f"{where}Logger not running (last seen {self._ago(age)} ago) — showing saved logs"
        else:
            txt = "Logger not running — press Start logger, or install it as a service"
        if not self.is_local and src.syncing:
            txt += "  ·  syncing history…"
        self.pill_text.config(text=txt)
        self._set_start_btn(ok)

    def _set_start_btn(self, ok):
        try:
            if self.compare or not self.is_local:
                self.start_btn.config(text="Remote" if not self.compare else "Comparing")
                self.start_btn.state(["disabled"])
            elif ok:
                self.start_btn.config(text="Logger running")
                self.start_btn.state(["disabled"])
            else:
                self.start_btn.config(text="Start logger")
                self.start_btn.state(["!disabled"])
        except Exception:
            pass

    def source_alive(self, sid):
        src = self.sources[sid]
        return (src.reachable or src.kind == "local") and core.logger_alive(src.read_status())

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
        self.status = self.source.read_status()
        was = self.logger_ok
        self.logger_ok = self.source_alive(self.source.id)
        if self.status and self.logger_ok:
            gw = self.status.get("gateway") or {}
            self.gateway = {"ip": gw.get("ip"), "iface": gw.get("iface")}
            self.public_ip = self.status.get("public_ip")
        if was != self.logger_ok:
            self.dirty = True
        self.update_status_pill()

    def start_logger(self):
        """Run the logger in the background (for when it isn't installed as a service)."""
        if self.logger_ok or not self.is_local or self.compare:
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
        if self.compare:
            return self.compare_rows()
        out = []
        if self.gateway_enabled:
            ip, iface = self.gateway["ip"], self.gateway["iface"]
            if not ip:                                   # logger stopped: last one in the log
                ip, iface = self._gw_last_host or None, None
            shown = f"{ip} ({iface})" if ip and iface else (ip or "–")
            name = self.names.get(ip) if ip else None
            label = f"{GATEWAY_LABEL} · {name}" if name else GATEWAY_LABEL
            out.append((GATEWAY_KEY, label, shown, self.pt["gateway"]))
        for i, t in enumerate(self.targets):
            out.append((t["host"], t.get("label") or t["host"], t["host"],
                        COLORS[i % len(COLORS)]))
        return out

    def keys(self):
        if self.compare:
            return [self.compare_key]
        return [r[0] for r in self.rows()]

    # ---- compare mode ---------------------------------------------------- #
    def compare_ids(self):
        return list(self.sources)

    def compare_rows(self):
        out = []
        for i, sid in enumerate(self.compare_ids()):
            src = self.sources[sid]
            cfg = src.get_config()
            key = self.compare_key
            if key == GATEWAY_KEY:
                if not cfg.get("auto_gateway", True):
                    continue
                sd = self.sdata(sid)
                st = src.read_status() or {}
                ip = ((st.get("gateway") or {}).get("ip")) or sd.gw_last_host or "–"
                shown = ip_label(ip, cfg.get("names") or {})
            else:
                if not any(t.get("host") == key for t in cfg.get("targets", [])):
                    continue
                shown = key
            out.append((sid, src.name, shown, COLORS[i % len(COLORS)]))
        return out

    def compare_choices(self):
        """[(display, key)] – the local gateway plus every target any location pings."""
        seen, out = set(), [("Local gateway (each location's own)", GATEWAY_KEY)]
        for sid in self.compare_ids():
            for t in self.sources[sid].get_config().get("targets", []):
                h = t.get("host")
                if h and h not in seen:
                    seen.add(h)
                    lab = t.get("label") or h
                    out.append((f"{lab} ({h})" if lab != h else h, h))
        return out

    def set_compare(self, on):
        if on and len(self.sources) < 2:
            messagebox.showinfo(APP_NAME, "Add another location first (Location › Add location…).")
            self.compare_var.set(False)
            return
        self.compare = bool(on)
        self.compare_var.set(self.compare)
        if self.compare:
            for sid in self.compare_ids():
                d = self.sdata(sid)
                if not d.loaded:
                    d.load_recent()
            choices = self.compare_choices()
            self._cmp_map = {lab: key for lab, key in choices}
            self.cmp_box.config(values=[lab for lab, _ in choices])
            keep = next((lab for lab, key in choices if key == self.compare_key), None)
            if keep is None:                     # default: first internet target
                keep = choices[1][0] if len(choices) > 1 else choices[0][0]
            self.cmp_var.set(keep)
            self.compare_key = self._cmp_map[keep]
            self.cmp_frame.pack(side="left")
        else:
            self.cmp_frame.pack_forget()
        self.view_end = None
        self.tree.delete(*self.tree.get_children())
        self.update_location_ui()
        self.refresh_logger_status()
        self.dirty = True

    def on_compare_target(self):
        self.compare_key = self._cmp_map.get(self.cmp_var.get(), self.compare_key)
        self.tree.delete(*self.tree.get_children())
        self.dirty = True

    # ---- location picker ------------------------------------------------- #
    def location_label(self, sid):
        src = self.sources[sid]
        if src.kind == "local":
            state = "this computer"
        elif src.reachable:
            state = "online" if core.logger_alive(src.read_status()) else "logger stopped"
        else:
            state = "offline"
        return f"{src.name}  —  {state}"

    def build_location_menu(self):
        m = self.loc_menu
        m.delete(0, "end")
        for sid in self.sources:
            m.add_radiobutton(label=self.location_label(sid), variable=self.loc_sel, value=sid,
                              command=lambda s=sid: self.select_source(s))
        m.add_separator()
        m.add_checkbutton(label="Compare locations", variable=self.compare_var,
                          command=lambda: self.set_compare(self.compare_var.get()))
        m.add_separator()
        m.add_command(label="Add location…", command=self.add_location_dialog)
        m.add_command(label="Manage locations…", command=self.manage_locations_dialog)

    def update_location_ui(self):
        self.loc_var.set("All locations (compare)" if self.compare else self.source.name)
        self.loc_sel.set(self.source.id)
        local_only = self.is_local and not self.compare
        for b in (self.open_btn, self.change_btn, self.archive_btn):
            try:
                b.state(["!disabled"] if local_only else ["disabled"])
            except Exception:
                pass
        for w in getattr(self, "_edit_widgets", ()):
            try:
                w.state(["!disabled"] if self.can_edit else ["disabled"])
            except Exception:
                pass

    def select_source(self, sid):
        if sid not in self.sources:
            return
        if self.compare:
            self.set_compare(False)
        self.cur = self.sdata(sid)
        if not self.cur.loaded:
            self.cur.load_recent()
        self.prefs.set(selected=sid)
        self.cfg = self.source.get_config()
        self.apply_cfg(self.cfg)
        self._cfg_ver = self.source.config_version()
        self.sync_setting_widgets()
        self.gateway, self.public_ip = {"ip": None, "iface": None}, None
        self.view_end = None
        self.tree.delete(*self.tree.get_children())
        self.refresh_logger_status()
        self.update_location_ui()
        self.set_status(f"Showing {self.source.name}" + (
            "" if self.is_local else
            f" (times in that location's clock{self._offset_note(self.source)})"))
        self.dirty = True

    @staticmethod
    def _offset_note(src):
        off = src.offset.total_seconds()
        if abs(off) < 90:
            return ""
        h, m = divmod(int(abs(off)) // 60, 60)
        return f", {'+' if off > 0 else '−'}{h}:{m:02d} from here"

    # ---- add / manage locations ------------------------------------------ #
    def _dialog(self, title, size="560x420"):
        dlg = tk.Toplevel(self.root)
        dlg.title(title)
        dlg.transient(self.root)
        dlg.geometry(size)
        frm = ttk.Frame(dlg, padding=18)
        frm.pack(fill="both", expand=True)
        return dlg, frm

    def add_location_dialog(self, prefill=None):
        import threading
        import latency_remote as R
        dlg, frm = self._dialog("Add location", "600x470")
        ttk.Label(frm, text="Add a remote location", style="Section.TLabel").pack(anchor="w")
        ttk.Label(frm, style="Muted.TLabel", wraplength=560, justify="left",
                  text="On the other machine run   latency_logger.py remote enable   once, then "
                       "latency_logger.py pair   — it prints the address, a one-time code and the "
                       "certificate fingerprint.").pack(anchor="w", pady=(2, 12))
        grid = ttk.Frame(frm)
        grid.pack(fill="x")
        grid.columnconfigure(1, weight=1)
        fields = {}
        for r, (key, label, default) in enumerate([
                ("host", "Address (host or IP)", (prefill or {}).get("host", "")),
                ("port", "Port", str((prefill or {}).get("port", R.DEFAULT_PORT))),
                ("code", "Pairing code", ""),
                ("name", "Name (optional)", (prefill or {}).get("name", ""))]):
            ttk.Label(grid, text=label).grid(row=r, column=0, sticky="w", pady=4)
            e = ttk.Entry(grid, width=34)
            e.insert(0, default)
            e.grid(row=r, column=1, sticky="ew", padx=(10, 0), pady=4)
            fields[key] = e
        fp_var = tk.StringVar()
        msg_var = tk.StringVar()
        ttk.Label(frm, textvariable=fp_var, wraplength=560, justify="left",
                  font=("Courier", 11)).pack(anchor="w", pady=(12, 0))
        ttk.Label(frm, textvariable=msg_var, style="Muted.TLabel", wraplength=560,
                  justify="left").pack(anchor="w", pady=(6, 0))
        btns = ttk.Frame(frm)
        btns.pack(side="bottom", fill="x", pady=(12, 0))
        ttk.Button(btns, text="Cancel", command=dlg.destroy).pack(side="right")
        pair_b = ttk.Button(btns, text="Fingerprint matches — Pair", style=self.S["accent"])
        pair_b.pack(side="right", padx=6)
        pair_b.state(["disabled"])
        conn_b = ttk.Button(btns, text="Connect", style=self.S["accent"])
        conn_b.pack(side="left")
        state = {}

        def ui(fn):
            self.root.after(0, lambda: dlg.winfo_exists() and fn())

        def connect():
            host = fields["host"].get().strip()
            try:
                port = int(fields["port"].get().strip() or R.DEFAULT_PORT)
            except ValueError:
                msg_var.set("The port must be a number.")
                return
            if not host:
                msg_var.set("Enter the logger machine's address.")
                return
            conn_b.state(["disabled"])
            msg_var.set(f"Connecting to {host}:{port}…")

            def work():
                try:
                    fp, hello = R.probe(host, port)
                except Exception as exc:
                    err = str(exc)

                    def fail():
                        conn_b.state(["!disabled"])
                        msg_var.set(f"Couldn't reach a logger there: {err}")
                    return ui(fail)

                def ok():
                    state.update(host=host, port=port, fp=fp)
                    fp_var.set("Certificate fingerprint:\n" + fp)
                    msg_var.set(f"Connected (logger {hello.get('version')}). Compare the "
                                "fingerprint with the one printed by  latency_logger.py pair  on "
                                "that machine. Only pair if they are identical.")
                    conn_b.state(["!disabled"])
                    pair_b.state(["!disabled"])
                ui(ok)
            threading.Thread(target=work, daemon=True).start()

        def pair():
            code = fields["code"].get().strip()
            if not code:
                msg_var.set("Enter the pairing code shown by  latency_logger.py pair.")
                return
            pair_b.state(["disabled"])
            msg_var.set("Pairing…")
            host, port, fp = state["host"], state["port"], state["fp"]
            viewer_name = f"viewer on {os.uname().nodename if hasattr(os, 'uname') else 'Windows'}"

            def work():
                try:
                    res = R.RemoteClient(host, port, fp).pair(code, viewer_name)
                except Exception as exc:
                    err = getattr(exc, "msg", None) or str(exc)

                    def fail():
                        pair_b.state(["!disabled"])
                        msg_var.set(f"Pairing failed: {err}")
                    return ui(fail)

                def ok():
                    entry = {"id": R.b64id(f"{host}:{port}:{fp}:{time.time()}"),
                             "name": fields["name"].get().strip() or res.get("location") or host,
                             "host": host, "port": port, "fingerprint": fp,
                             "token": res["token"], "role": res.get("role", "admin"),
                             "client_id": res.get("client_id")}
                    self.prefs.sources.append(entry)
                    self.prefs.save()
                    src = sources.RemoteSource(entry)
                    self.sources[entry["id"]] = src
                    src.start()
                    dlg.destroy()
                    self.select_source(entry["id"])
                    self.set_status(f"Paired with {entry['name']} "
                                    f"({'read-only' if entry['role'] == 'read' else 'full access'})."
                                    " Its history is being copied in the background.")
                ui(ok)
            threading.Thread(target=work, daemon=True).start()

        conn_b.config(command=connect)
        pair_b.config(command=pair)
        fields["host"].focus_set()

    def manage_locations_dialog(self):
        dlg, frm = self._dialog("Locations", "720x380")
        ttk.Label(frm, text="Locations", style="Section.TLabel").pack(anchor="w", pady=(0, 8))
        box = ttk.Frame(frm, style=self.S["card"], padding=6)
        box.pack(fill="both", expand=True)
        cols = ("name", "addr", "access", "state")
        tree = ttk.Treeview(box, columns=cols, show="headings", selectmode="browse", height=6)
        for c, h, w in zip(cols, ("Name", "Address", "Access", "Status"), (190, 200, 100, 180)):
            tree.heading(c, text=h, anchor="w")
            tree.column(c, width=w, anchor="w")
        tree.pack(fill="both", expand=True)

        def fill():
            tree.delete(*tree.get_children())
            for sid, src in self.sources.items():
                if src.kind == "local":
                    tree.insert("", "end", iid=sid, values=(src.name, "this computer", "full", "local"))
                else:
                    e = src.entry
                    tree.insert("", "end", iid=sid, values=(
                        src.name, f"{e['host']}:{e.get('port')}",
                        "read-only" if src.role == "read" else "full",
                        self.location_label(sid).split("—")[-1].strip()))
        fill()
        row = ttk.Frame(frm)
        row.pack(fill="x", pady=(10, 0))
        ttk.Label(row, text="Name").pack(side="left")
        name_e = ttk.Entry(row, width=28)
        name_e.pack(side="left", padx=8)

        def sel():
            s = tree.selection()
            return s[0] if s else None

        def on_sel(_e=None):
            sid = sel()
            name_e.delete(0, "end")
            if sid:
                name_e.insert(0, self.sources[sid].name)

        def rename():
            sid = sel()
            new = name_e.get().strip()
            if not sid or not new:
                return
            if sid == "local":
                cfg = core.load_config()
                cfg["location_name"] = new[:80]
                core.save_config(cfg)
            else:
                self.sources[sid].entry["name"] = new[:80]
                self.prefs.save()
            fill()
            self.update_location_ui()

        def remove():
            sid = sel()
            if not sid or sid == "local":
                return
            src = self.sources[sid]
            if not messagebox.askyesno(APP_NAME, f"Remove {src.name} from this viewer?\n\n"
                                       "Its cached history on this computer is deleted. To also "
                                       "cut off this viewer's key on the logger, run there:\n"
                                       "  latency_logger.py remote revoke <id>", parent=dlg):
                return
            if self.source.id == sid or self.compare:
                self.select_source("local")
            src.stop()
            src.forget_cache()
            try:
                import shutil
                shutil.rmtree(src.cache, ignore_errors=True)
            except Exception:
                pass
            self.prefs.data["sources"] = [e for e in self.prefs.sources if e["id"] != sid]
            self.prefs.save()
            del self.sources[sid]
            self.sd.pop(sid, None)
            fill()

        def repair():
            sid = sel()
            if not sid or sid == "local":
                return
            e = dict(self.sources[sid].entry)
            dlg.destroy()
            messagebox.showinfo(APP_NAME, "Pair again with a new code; then remove the old "
                                "entry here.")
            self.add_location_dialog(prefill=e)

        tree.bind("<<TreeviewSelect>>", on_sel)
        ttk.Button(row, text="Rename", command=rename).pack(side="left")
        ttk.Button(row, text="Re-pair…", command=repair).pack(side="left", padx=6)
        ttk.Button(row, text="Remove", command=remove).pack(side="left")
        ttk.Button(row, text="Close", command=dlg.destroy).pack(side="right")

    # ---- targets --------------------------------------------------------- #
    def add_target(self):
        if not self.can_edit:
            self.set_status("Targets can't be changed here (compare mode or read-only location).")
            return
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
        if not self.can_edit:
            self.set_status("Targets can't be changed here (compare mode or read-only location).")
            return
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
        if not self.is_local or self.compare:
            return
        d = filedialog.askdirectory(initialdir=str(self.logger.log_dir),
                                    title="Choose log folder")
        if d:
            self.cfg["log_dir"] = d
            self.source.save_config({"log_dir": d})
            self._cfg_ver = self.source.config_version()
            self.cur.reset()
            self.cur.load_recent()
            self.dirty = True
            self.set_status(f"The logger will write to {d} from its next round.")

    # ---- networks: name public IPs and local gateways ---------------------- #
    def networks_dialog(self):
        import threading
        if getattr(self, "_net_dlg", None) and self._net_dlg.winfo_exists():
            self._net_dlg.lift()
            return
        dlg = self._net_dlg = tk.Toplevel(self.root)
        dlg.title("Networks")
        dlg.transient(self.root)
        dlg.geometry("820x480")
        dlg.minsize(640, 360)
        frm = ttk.Frame(dlg, padding=16)
        frm.pack(fill="both", expand=True)
        ttk.Label(frm, text="Networks you've been on", style="Section.TLabel").pack(anchor="w")
        ttk.Label(frm, style="Muted.TLabel", wraplength=780, justify="left",
                  text="Every public IP and local gateway found in your logs. Give them names "
                       "(e.g. \"Lisbon home – fibre\", \"Office\", \"Phone hotspot\"); names "
                       "show up in the header, the table, the graph and status messages, "
                       "for past data too.").pack(anchor="w", pady=(2, 10))

        box = ttk.Frame(frm, style=self.S["card"], padding=6)
        box.pack(fill="both", expand=True)
        cols = ("kind", "ip", "name", "first", "last")
        tree = ttk.Treeview(box, columns=cols, show="headings", selectmode="browse")
        for c, h, w, st in zip(cols, ("Type", "IP address", "Name", "First seen", "Last seen"),
                               (105, 135, 250, 130, 130), (0, 0, 1, 0, 0)):
            tree.heading(c, text=h, anchor="w")
            tree.column(c, width=w, anchor="w", stretch=bool(st))
        sb = ttk.Scrollbar(box, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        edit = ttk.Frame(frm)
        edit.pack(fill="x", pady=(10, 0))
        ttk.Label(edit, text="Name").pack(side="left")
        name_e = ttk.Entry(edit, width=36)
        name_e.pack(side="left", padx=8)
        save_b = ttk.Button(edit, text="Save name", style=self.S["accent"])
        save_b.pack(side="left")
        look_b = ttk.Button(edit, text="Look up ISP")
        look_b.pack(side="left", padx=6)
        ttk.Button(edit, text="Close", command=dlg.destroy).pack(side="right")
        msg = tk.StringVar(value="Scanning logs…")
        ttk.Label(frm, textvariable=msg, style="Muted.TLabel", wraplength=780,
                  justify="left").pack(anchor="w", pady=(8, 0))

        def fmt(iso):
            try:
                return datetime.fromisoformat(iso).strftime("%d %b %Y %H:%M")
            except Exception:
                return iso or ""

        def current():
            sel = tree.selection()
            return sel[0].split("|", 1) if sel else (None, None)

        def fill(nets):
            if not dlg.winfo_exists():
                return
            # include what the logger sees right now, even if not in the logs yet
            now = datetime.now().isoformat(timespec="seconds")
            for kind, ip in (("pub", self.public_ip), ("gw", self.gateway.get("ip"))):
                if ip and ip not in nets[kind]:
                    nets[kind][ip] = [now, now, 0]
            items = [(kind, ip, e) for kind in ("pub", "gw") for ip, e in nets[kind].items()]
            items.sort(key=lambda x: x[2][1], reverse=True)          # most recent first
            tree.delete(*tree.get_children())
            for kind, ip, (first, last, n) in items:
                tree.insert("", "end", iid=f"{kind}|{ip}",
                            values=("Public IP" if kind == "pub" else "Local gateway", ip,
                                    self.names.get(ip, ""), fmt(first), fmt(last)))
            npub, ngw = len(nets["pub"]), len(nets["gw"])
            msg.set(f"{npub} public IP{'s' if npub != 1 else ''} and {ngw} local gateway"
                    f"{'s' if ngw != 1 else ''} found. Select one, type a name, press Save "
                    "(or Enter). Tip: local gateway addresses like 192.168.1.1 are used by "
                    "many routers, so public IPs identify a network better.")
            if items and not tree.selection():
                tree.selection_set(tree.get_children()[0])

        def on_select(_e=None):
            kind, ip = current()
            name_e.delete(0, "end")
            if ip:
                name_e.insert(0, self.names.get(ip, ""))
                look_b.state(["!disabled"] if kind == "pub" and not is_private_ip(ip)
                             else ["disabled"])

        def save(_e=None):
            kind, ip = current()
            if not ip:
                return
            name = name_e.get().strip()
            if name:
                self.names[ip] = name
            else:
                self.names.pop(ip, None)
            self.save_config()
            tree.set(f"{kind}|{ip}", "name", name)
            msg.set(f"Saved: {ip} → {name}" if name else f"Name removed for {ip}")
            self.update_status_pill()
            self.dirty = True

        def lookup():
            kind, ip = current()
            if not ip:
                return
            look_b.state(["disabled"])
            msg.set(f"Asking ipinfo.io who {ip} belongs to…")

            def work():
                res = core.lookup_ip_owner(ip)

                def done():
                    if not dlg.winfo_exists():
                        return
                    look_b.state(["!disabled"])
                    if res:
                        name_e.delete(0, "end")
                        name_e.insert(0, res)
                        msg.set("Suggestion from ipinfo.io — edit it if you like, then Save.")
                    else:
                        msg.set("No answer from ipinfo.io (offline, or rate-limited).")
                self.root.after(0, done)
            threading.Thread(target=work, daemon=True).start()

        tree.bind("<<TreeviewSelect>>", on_select)
        name_e.bind("<Return>", save)
        save_b.config(command=save)
        look_b.config(command=lookup)

        def scan():
            try:
                nets = core.scan_networks(self.logger)
            except Exception as exc:          # pragma: no cover
                err = str(exc)
                self.root.after(0, lambda: msg.set(f"Couldn't read the logs: {err}"))
                return
            self.root.after(0, lambda: fill(nets))
        threading.Thread(target=scan, daemon=True).start()

    def archive_now(self):
        """gzip finished daily logs now (the logger also does this daily by itself)."""
        import threading
        if not self.is_local or self.compare:
            return
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
        end = self.view_end or self.now()
        return end - timedelta(seconds=self.span_sec), end

    def set_view(self, start: datetime, end: datetime):
        """Show an arbitrary span [start, end]. Ending at/after now → live."""
        secs = (end - start).total_seconds()
        self.span_sec = float(round(min(MAX_SPAN, max(MIN_SPAN, secs))))
        now = self.now()
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

        today0 = self.now().replace(hour=0, minute=0, second=0, microsecond=0)
        ttk.Button(quick, text="Today", command=lambda: set_fields(today0, self.now())).pack(side="left")
        ttk.Button(quick, text="Yesterday", command=lambda: set_fields(
            today0 - timedelta(days=1), today0)).pack(side="left", padx=4)
        ttk.Button(quick, text="This week", command=lambda: set_fields(
            today0 - timedelta(days=today0.weekday()), self.now())).pack(side="left")
        ttk.Button(quick, text="This month", command=lambda: set_fields(
            today0.replace(day=1), self.now())).pack(side="left", padx=4)

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
            self.set_view(mid - half, min(mid + half, self.now()) if self.view_end is None
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
    def load_recent(self):
        return self.cur.load_recent()

    def _days(self, start, end):
        return sources.SourceData._days(start, end)

    def raw_series(self, key, start, end):
        return self.cur.raw_series(key, start, end)

    def agg_series(self, key, start, end, bucket):
        return self.cur.agg_series(key, start, end, bucket)

    def first_data_ts(self, start, end):
        if self.compare:
            return None
        return self.cur.first_data_ts(self.keys(), start, end)

    def gateway_changes(self, start, end):
        return [] if self.compare else self.cur.gateway_changes(start, end)

    def row_series(self, rowkey, start, end, bucket):
        """Series for one table row: a target (normal) or a location (compare mode)."""
        if not self.compare:
            if bucket is None:
                return "raw", self.cur.raw_series(rowkey, start, end)
            return "agg", self.cur.agg_series(rowkey, start, end, bucket)
        sd = self.sdata(rowkey)
        off = sd.source.offset                       # that location's clock vs ours
        key = self.compare_key
        if bucket is None:
            pts = sd.raw_series(key, start + off, end + off)
            return "raw", [(ts - off, v) for ts, v in pts]
        pts = sd.agg_series(key, start + off, end + off, bucket)
        return "agg", [(b - off, acc) for b, acc in pts]

    def row_last_status(self, rowkey):
        if self.compare:
            return self.sdata(rowkey).last_status.get(self.compare_key)
        return self.cur.last_status.get(rowkey)

    # ---- main loop ------------------------------------------------------- #
    def poll(self):
        got = False
        active = [self.sdata(sid) for sid in self.compare_ids()] if self.compare else [self.cur]
        for d in active:
            if d.check_updates():                    # remote sync brought new history
                self.dirty = True
            keys = {self.compare_key} if self.compare else set(self.keys())
            g, events = d.poll(keys)
            got = got or g
            if d is not self.cur or self.compare:
                continue
            for kind, old, new in events:
                if kind == "gw":
                    self.set_status(f"Network change — local gateway is now "
                                    f"{ip_label(new, self.names)}" if new else
                                    "No local gateway — offline?")
                else:
                    msg = (f"Public IP changed: {ip_label(old, self.names)} → "
                           f"{ip_label(new, self.names)}")
                    if new not in self.names:
                        msg += "  —  new network? Name it under Settings › Networks…"
                    self.set_status(msg)

        self._tick += 1
        if self._tick % 4 == 0:                      # every 2 s
            self.refresh_logger_status()
            if not self.compare:
                self.check_config_changed()
        if self._tick % 20 == 0 and self.prefs.get("theme") == "system":   # follow OS dark mode
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
        busy = ([self.sdata(sid) for sid in self.compare_ids()] if self.compare else [self.cur])
        if any(d.uncached_days(start, end) for d in busy):
            prev_status = self.status_var.get()
            self.set_status("Reading history from log files…")
            try:
                self.root.update_idletasks()
            except Exception:
                pass
        series = {}
        for key, label, shown, color in self.rows():
            series[key] = self.row_series(key, start, end, bucket)
        self.refresh_table(series)
        self.redraw(series, start, end, bucket)

        fmt = "%a %d %b %H:%M" if self.span_sec >= 3600 else "%a %d %b %H:%M:%S"
        mode = "● Live" if self.view_end is None else "History"
        res = "every sample" if bucket is None else f"avg per {fmt_bucket(bucket)}"
        clock = "" if self.compare or self.is_local or abs(
            self.source.offset.total_seconds()) < 90 else f"  ·  {self.source.name} time"
        self.range_var.set(f"{mode}   {start:{fmt}}  →  {end:{fmt}}   ·   "
                           f"{span_label(self.span_sec)}, {res}{clock}")
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
            st_txt = self.row_last_status(key)
            if live and last is None and st_txt:
                last_txt = st_txt                          # e.g. "timeout", "no network"
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
                    ax.text(ts, 0.98, f" {self.names.get(ip) or ip or 'offline'}",
                            transform=ax.get_xaxis_transform(),
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
        for src in self.sources.values():
            src.stop()
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
