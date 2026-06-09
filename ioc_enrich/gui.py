"""CustomTkinter desktop front-end for the IOC enrichment engine.

A thin UI over :mod:`ioc_enrich.engine`: it gathers files via native pickers,
runs the analysis on a background thread (so the window never freezes during
API calls), renders results in a table, and shows the equivalent PowerShell
command with a copy button.
"""

from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import filedialog, ttk

import customtkinter as ctk
from dotenv import load_dotenv

from . import __version__
from .engine import analyse, collect_files
from .enrichment import fetch_quotas
from .logparse import parse_files
from .report import export_csv, export_json

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

_VERDICT_COLORS = {
    "malicious": "#ff5c5c",
    "suspicious": "#ffcf5c",
    "clean": "#5cd65c",
    "unknown": "#9aa0a6",
    "skipped": "#9aa0a6",
}


def _quote(path: str) -> str:
    return f'"{path}"' if " " in path else path


class IOCApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"IOC Enrichment Tool  v{__version__}")
        self.geometry("1200x760")
        self.minsize(900, 620)

        load_dotenv()
        self.vt_key = os.getenv("VIRUSTOTAL_API_KEY") or None
        self.abuse_key = os.getenv("ABUSEIPDB_API_KEY") or None

        # Paths for the built-in log export (native Windows logs and Sysmon).
        pkg_dir = os.path.dirname(os.path.abspath(__file__))
        self.project_root = os.path.dirname(pkg_dir)
        self.export_script = os.path.join(self.project_root, "scripts", "Export-WindowsLogs.ps1")
        self.win_logs_dir = os.path.join(self.project_root, "eventlogs")
        self.sysmon_logs_dir = os.path.join(self.project_root, "sysmonlogs")
        self.hours_map = {"Last 24 hours": 24, "Last 72 hours": 72, "Last 7 days": 168}

        self.selected_files: list[str] = []
        self.selected_label = "no files selected"
        self.last_rows: list[dict] = []
        self._events: queue.Queue = queue.Queue()
        self._running = False

        self._build_layout()
        self._refresh_powershell()
        self._update_quota({})  # set initial bar states (no key / awaiting scan)
        self.after(100, self._drain_events)
        if self.vt_key or self.abuse_key:
            self.after(300, self._refresh_quota)  # show usage right away

    # -- layout ---------------------------------------------------------------

    def _build_layout(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)  # results table expands

        # Header / scan controls
        top = ctk.CTkFrame(self)
        top.grid(row=0, column=0, sticky="ew", padx=16, pady=(16, 8))
        top.grid_columnconfigure(6, weight=1)

        ctk.CTkLabel(top, text="Scan:", font=ctk.CTkFont(size=14, weight="bold")).grid(
            row=0, column=0, padx=(12, 8), pady=12
        )
        ctk.CTkButton(top, text="Pick Files", width=110, command=self._pick_files).grid(
            row=0, column=1, padx=4, pady=12
        )
        ctk.CTkButton(top, text="Pick Folder", width=110, command=self._pick_folder).grid(
            row=0, column=2, padx=4, pady=12
        )
        ctk.CTkButton(
            top, text="Folder + Subfolders", width=150,
            command=lambda: self._pick_folder(recursive=True),
        ).grid(row=0, column=3, padx=4, pady=12)

        self.selection_lbl = ctk.CTkLabel(top, text=self.selected_label, text_color="#9aa0a6")
        self.selection_lbl.grid(row=0, column=6, sticky="e", padx=12)

        # Second row: pull this PC's Windows Event Logs directly.
        ctk.CTkLabel(top, text="Or pull from this PC:", text_color="#9aa0a6").grid(
            row=1, column=0, columnspan=2, padx=(12, 8), pady=(0, 12), sticky="w"
        )
        self.hours_var = ctk.StringVar(value="Last 72 hours")
        self.hours_menu = ctk.CTkOptionMenu(
            top, values=list(self.hours_map.keys()), variable=self.hours_var, width=140
        )
        self.hours_menu.grid(row=1, column=2, padx=4, pady=(0, 12), sticky="w")
        self.pull_btn = ctk.CTkButton(
            top, text="Pull Windows Logs", width=160, command=self._pull_logs
        )
        self.pull_btn.grid(row=1, column=3, padx=4, pady=(0, 12), sticky="w")
        if sys.platform != "win32":
            self.pull_btn.configure(state="disabled")

        self.parse_btn = ctk.CTkButton(
            top, text="View Parsed Logs", width=150,
            fg_color="#3a3a3a", hover_color="#4a4a4a", command=self._open_parsed,
        )
        self.parse_btn.grid(row=1, column=4, padx=(24, 4), pady=(0, 12), sticky="w")

        # Options + run
        opts = ctk.CTkFrame(self)
        opts.grid(row=1, column=0, sticky="ew", padx=16, pady=8)
        opts.grid_columnconfigure(7, weight=1)

        self.enrich_var = ctk.BooleanVar(value=bool(self.vt_key or self.abuse_key))
        self.enrich_chk = ctk.CTkCheckBox(
            opts, text="Enrich (VirusTotal + AbuseIPDB)",
            variable=self.enrich_var, command=self._refresh_powershell,
        )
        self.enrich_chk.grid(row=0, column=0, padx=(12, 16), pady=12)

        ctk.CTkLabel(opts, text="Pause (s):").grid(row=0, column=1, padx=(0, 4))
        self.pause_var = ctk.StringVar(value="15" if (self.vt_key or self.abuse_key) else "0")
        self.pause_entry = ctk.CTkEntry(opts, width=56, textvariable=self.pause_var)
        self.pause_entry.grid(row=0, column=2, padx=(0, 16))
        self.pause_var.trace_add("write", lambda *_: self._refresh_powershell())

        self.private_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            opts, text="Include private IPs",
            variable=self.private_var, command=self._refresh_powershell,
        ).grid(row=0, column=3, padx=(0, 16))

        # Log source for the "Pull" button: native Windows logs vs Sysmon.
        ctk.CTkLabel(opts, text="Source:").grid(row=0, column=4, padx=(0, 4))
        self.source_var = ctk.StringVar(value="Windows Logs")
        self.source_seg = ctk.CTkSegmentedButton(
            opts, values=["Windows Logs", "Sysmon"],
            variable=self.source_var, command=self._on_source_change,
        )
        self.source_seg.grid(row=0, column=5, padx=(0, 16))

        if not (self.vt_key or self.abuse_key):
            ctk.CTkLabel(
                opts, text="no API keys in .env — extract-only",
                text_color="#ffcf5c",
            ).grid(row=0, column=6, padx=8)

        self.run_btn = ctk.CTkButton(
            opts, text="RUN SCAN", width=140,
            font=ctk.CTkFont(size=14, weight="bold"), command=self._run,
        )
        self.run_btn.grid(row=0, column=7, sticky="e", padx=12, pady=12)

        # API usage bars
        self._build_quota_panel()

        # Results table (ttk.Treeview, themed dark)
        table_frame = ctk.CTkFrame(self)
        table_frame.grid(row=3, column=0, sticky="nsew", padx=16, pady=8)
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)

        self._style_treeview()
        cols = ("verdict", "type", "ioc", "hits", "action", "why", "intel", "files")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", style="IOC.Treeview")
        headings = {
            "verdict": ("Verdict", 90), "type": ("Type", 60), "ioc": ("IOC", 220),
            "hits": ("Hits", 45), "action": ("Action", 120),
            "why": ("Why this verdict?", 340),
            "intel": ("Intel", 180), "files": ("Files", 120),
        }
        for col, (label, width) in headings.items():
            self.tree.heading(col, text=label)
            anchor = "center" if col in ("hits", "type", "verdict") else "w"
            self.tree.column(col, width=width, anchor=anchor)
        for verdict, color in _VERDICT_COLORS.items():
            self.tree.tag_configure(verdict, foreground=color)
        self.tree.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        scroll.grid(row=0, column=1, sticky="ns")
        hscroll = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(xscrollcommand=hscroll.set)
        hscroll.grid(row=1, column=0, sticky="ew")

        # Status + export
        status = ctk.CTkFrame(self)
        status.grid(row=4, column=0, sticky="ew", padx=16, pady=4)
        status.grid_columnconfigure(0, weight=1)
        self.status_lbl = ctk.CTkLabel(status, text="Ready.", anchor="w")
        self.status_lbl.grid(row=0, column=0, sticky="ew", padx=12, pady=8)
        self.progress = ctk.CTkProgressBar(status, width=200)
        self.progress.set(0)
        self.progress.grid(row=0, column=1, padx=8)
        self.export_json_btn = ctk.CTkButton(
            status, text="Export JSON", width=110, state="disabled",
            command=lambda: self._export("json"),
        )
        self.export_json_btn.grid(row=0, column=2, padx=4)
        self.export_csv_btn = ctk.CTkButton(
            status, text="Export CSV", width=110, state="disabled",
            command=lambda: self._export("csv"),
        )
        self.export_csv_btn.grid(row=0, column=3, padx=(4, 12))

        # PowerShell template
        ps = ctk.CTkFrame(self)
        ps.grid(row=5, column=0, sticky="ew", padx=16, pady=(8, 16))
        ps.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            ps, text="PowerShell equivalent", font=ctk.CTkFont(size=12, weight="bold"),
        ).grid(row=0, column=0, sticky="w", padx=12, pady=(8, 0))
        self.ps_box = ctk.CTkTextbox(ps, height=56, wrap="word", font=ctk.CTkFont(family="Consolas", size=12))
        self.ps_box.grid(row=1, column=0, sticky="ew", padx=12, pady=(2, 10))
        ctk.CTkButton(ps, text="Copy", width=80, command=self._copy_powershell).grid(
            row=1, column=1, padx=(0, 12)
        )

    def _build_quota_panel(self) -> None:
        q = ctk.CTkFrame(self)
        q.grid(row=2, column=0, sticky="ew", padx=16, pady=8)
        q.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            q, text="API usage (today)", font=ctk.CTkFont(size=12, weight="bold")
        ).grid(row=0, column=0, columnspan=3, sticky="w", padx=12, pady=(8, 0))

        self.quota_bars: dict[str, ctk.CTkProgressBar] = {}
        self.quota_vals: dict[str, ctk.CTkLabel] = {}
        for i, provider in enumerate(("VirusTotal", "AbuseIPDB"), start=1):
            ctk.CTkLabel(q, text=provider, width=90, anchor="w").grid(
                row=i, column=0, padx=(12, 6), pady=4, sticky="w"
            )
            bar = ctk.CTkProgressBar(q)
            bar.set(0)
            bar.grid(row=i, column=1, sticky="ew", padx=6, pady=4)
            val = ctk.CTkLabel(q, text="—", width=170, anchor="e", text_color="#9aa0a6")
            val.grid(row=i, column=2, padx=(6, 8), pady=4, sticky="e")
            self.quota_bars[provider] = bar
            self.quota_vals[provider] = val

        self.refresh_btn = ctk.CTkButton(
            q, text="Refresh", width=80, command=self._refresh_quota
        )
        self.refresh_btn.grid(row=1, column=3, rowspan=2, padx=(0, 12), pady=4)

    def _update_quota(self, usage: dict) -> None:
        for provider in ("VirusTotal", "AbuseIPDB"):
            bar = self.quota_bars[provider]
            val = self.quota_vals[provider]
            has_key = bool(self.vt_key if provider == "VirusTotal" else self.abuse_key)
            info = usage.get(provider)
            if not has_key:
                bar.set(0)
                bar.configure(progress_color="#3a3a3a")
                val.configure(text="no API key", text_color="#9aa0a6")
                continue
            if not info or not info.get("limit"):
                val.configure(text="run a scan to update", text_color="#9aa0a6")
                continue
            used, limit, remaining = info["used"], info["limit"], info["remaining"]
            frac = min(1.0, used / limit) if limit else 0.0
            color = "#5cd65c" if frac < 0.75 else "#ffcf5c" if frac < 0.9 else "#ff5c5c"
            bar.set(frac)
            bar.configure(progress_color=color)
            val.configure(
                text=f"{used} / {limit}  ({remaining} left)", text_color="#e0e0e0"
            )

    def _refresh_quota(self) -> None:
        if not (self.vt_key or self.abuse_key):
            self._set_status("No API keys in .env to check usage.", error=True)
            return
        self.refresh_btn.configure(state="disabled", text="...")
        self._set_status("Checking API usage ...")

        def work() -> None:
            usage = fetch_quotas(self.vt_key, self.abuse_key, probe_abuse=True)
            self._events.put(("quota", usage))
            self._events.put(("quota_done", None))

        threading.Thread(target=work, daemon=True).start()

    def _style_treeview(self) -> None:
        style = ttk.Style()
        style.theme_use("default")
        style.configure(
            "IOC.Treeview", background="#1f1f1f", fieldbackground="#1f1f1f",
            foreground="#e0e0e0", rowheight=26, borderwidth=0,
        )
        style.configure(
            "IOC.Treeview.Heading", background="#2b2b2b",
            foreground="#cfd2d6", relief="flat",
        )
        style.map("IOC.Treeview", background=[("selected", "#2f5d8a")])

    # -- selection ------------------------------------------------------------

    def _pick_files(self) -> None:
        paths = filedialog.askopenfilenames(title="Select log files")
        if paths:
            self.selected_files = list(paths)
            self.selection_mode = ("files", None, False)
            self._set_selection(f"{len(paths)} file(s) selected")

    def _pick_folder(self, recursive: bool = False) -> None:
        folder = filedialog.askdirectory(title="Select a log folder")
        if folder:
            try:
                files = collect_files(folder=folder, recursive=recursive)
            except NotADirectoryError:
                self._set_status("Not a folder.", error=True)
                return
            self.selected_files = files
            self.selection_mode = ("folder", folder, recursive)
            suffix = " + subfolders" if recursive else ""
            self._set_selection(f"{len(files)} file(s) from {os.path.basename(folder)}{suffix}")

    def _set_selection(self, text: str) -> None:
        self.selected_label = text
        self.selection_lbl.configure(text=text)
        self._refresh_powershell()

    # -- pull logs (native Windows logs or Sysmon) ---------------------------

    def _current_source(self) -> str:
        return "Sysmon" if self.source_var.get() == "Sysmon" else "Windows"

    def _on_source_change(self, _value: str | None = None) -> None:
        source = self._current_source()
        self.pull_btn.configure(
            text="Pull Sysmon Logs" if source == "Sysmon" else "Pull Windows Logs"
        )

    def _pull_logs(self) -> None:
        if sys.platform != "win32":
            self._set_status("Pulling logs only works on Windows.", error=True)
            return
        if self._running:
            return
        if not os.path.isfile(self.export_script):
            self._set_status("Export script not found.", error=True)
            return
        source = self._current_source()
        outdir = self.sysmon_logs_dir if source == "Sysmon" else self.win_logs_dir
        hours = self.hours_map.get(self.hours_var.get(), 72)
        self.pull_btn.configure(state="disabled", text="Pulling...")
        if source == "Sysmon":
            self._set_status(
                f"Exporting Sysmon logs (last {hours}h) - approve the admin (UAC) prompt ..."
            )
        else:
            self._set_status(f"Exporting Windows Event Logs (last {hours}h) - one moment ...")
        threading.Thread(
            target=self._export_worker, args=(hours, source, outdir), daemon=True
        ).start()

    def _export_worker(self, hours: int, source: str, outdir: str) -> None:
        try:
            no_window = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            subprocess.run(
                [
                    "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                    "-File", self.export_script,
                    "-Hours", str(hours), "-OutDir", outdir, "-Source", source,
                ],
                capture_output=True, text=True, timeout=300, creationflags=no_window,
            )
            self._events.put(("export_done", (source, outdir)))
        except Exception as exc:
            self._events.put(("export_error", str(exc)))

    def _on_export_done(self, payload) -> None:
        source, outdir = payload
        self._on_source_change()  # restore button label
        self.pull_btn.configure(state="normal")
        try:
            files = collect_files(folder=outdir, recursive=False)
        except (NotADirectoryError, FileNotFoundError):
            files = []
        if not files:
            if source == "Sysmon":
                msg = ("No Sysmon logs produced - is Sysmon installed, and did you "
                       "approve the admin prompt?")
            else:
                msg = ("Export ran but produced no logs "
                       "(run as Administrator to include the Security log).")
            self._set_status(msg, error=True)
            return
        self.selected_files = files
        self.selection_mode = ("folder", outdir, False)
        label = "Sysmon" if source == "Sysmon" else "Windows"
        self._set_selection(f"{len(files)} {label} log(s) pulled - ready to RUN SCAN")
        self._set_status(f"Pulled {len(files)} {label} log file(s). Click RUN SCAN.")

    # -- parsed log viewer ----------------------------------------------------

    def _open_parsed(self) -> None:
        if not self.selected_files:
            self._set_status("Pick files or pull logs first, then view parsed logs.", error=True)
            return
        try:
            parsed = parse_files(self.selected_files)
        except Exception as exc:
            self._set_status(f"Parse failed: {exc}", error=True)
            return
        if not parsed:
            self._set_status("No readable log lines found to parse.", error=True)
            return
        self._show_parsed_window(parsed)

    def _show_parsed_window(self, parsed: list) -> None:
        win = ctk.CTkToplevel(self)
        win.title(f"Parsed Logs - {len(parsed)} lines")
        win.geometry("1280x680")
        win.grid_columnconfigure(0, weight=1)
        win.grid_rowconfigure(1, weight=1)

        bar = ctk.CTkFrame(win)
        bar.grid(row=0, column=0, sticky="ew", padx=12, pady=8)
        bar.grid_columnconfigure(2, weight=1)
        only_var = ctk.BooleanVar(value=False)
        count_lbl = ctk.CTkLabel(bar, text="", anchor="w")
        count_lbl.grid(row=0, column=0, padx=12, pady=6, sticky="w")

        frame = ctk.CTkFrame(win)
        frame.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 12))
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        cols = ("line", "ts", "source", "level", "src_ip", "dst_ip", "user", "iocs", "message")
        tree = ttk.Treeview(frame, columns=cols, show="headings", style="IOC.Treeview")
        heads = {
            "line": ("#", 50), "ts": ("Time", 150), "source": ("Source", 90),
            "level": ("Level / Action", 110), "src_ip": ("Src IP", 120),
            "dst_ip": ("Dst IP", 130), "user": ("User", 90),
            "iocs": ("IOCs", 200), "message": ("Message", 380),
        }
        for col, (label, width) in heads.items():
            tree.heading(col, text=label)
            tree.column(col, width=width, anchor="center" if col == "line" else "w")
        tree.tag_configure("hasioc", foreground="#ffd479")
        tree.grid(row=0, column=0, sticky="nsew")
        vs = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        hs = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        vs.grid(row=0, column=1, sticky="ns")
        hs.grid(row=1, column=0, sticky="ew")

        def populate() -> None:
            tree.delete(*tree.get_children())
            shown = 0
            for p in parsed:
                if only_var.get() and not p.iocs:
                    continue
                tree.insert(
                    "", "end",
                    values=(
                        p.lineno, p.ts or "-", p.source or "-", p.level or "-",
                        p.fields.get("src_ip", "-"), p.fields.get("dst_ip", "-"),
                        p.fields.get("user", "-"), ", ".join(p.iocs) or "-",
                        p.message,
                    ),
                    tags=("hasioc",) if p.iocs else (),
                )
                shown += 1
            with_iocs = sum(1 for p in parsed if p.iocs)
            count_lbl.configure(
                text=f"{len(parsed)} lines parsed  |  {with_iocs} contain IOCs  |  showing {shown}"
            )

        ctk.CTkCheckBox(
            bar, text="Only lines containing IOCs", variable=only_var, command=populate
        ).grid(row=0, column=1, padx=12, pady=6)
        populate()
        win.after(50, win.lift)

    # -- run (threaded) -------------------------------------------------------

    def _run(self) -> None:
        if self._running:
            return
        if not self.selected_files:
            self._set_status("Pick files or a folder first.", error=True)
            return
        try:
            pause = float(self.pause_var.get() or 0)
        except ValueError:
            self._set_status("Pause must be a number.", error=True)
            return

        self._running = True
        self.run_btn.configure(state="disabled", text="Running...")
        self.export_json_btn.configure(state="disabled")
        self.export_csv_btn.configure(state="disabled")
        self.tree.delete(*self.tree.get_children())
        self.progress.set(0)

        args = dict(
            files=list(self.selected_files),
            enrich=self.enrich_var.get(),
            vt_key=self.vt_key,
            abuse_key=self.abuse_key,
            pause=pause,
            include_private_ips=self.private_var.get(),
        )
        threading.Thread(target=self._worker, kwargs=args, daemon=True).start()

    def _worker(self, **kwargs) -> None:
        def progress(done: int, total: int, msg: str) -> None:
            self._events.put(("progress", (done, total, msg)))

        try:
            usage: dict = {}
            rows = analyse(progress=progress, usage_out=usage, **kwargs)
            if usage:
                self._events.put(("quota", usage))
            self._events.put(("done", rows))
        except Exception as exc:  # surface any failure in the UI, don't crash
            self._events.put(("error", str(exc)))

    def _drain_events(self) -> None:
        try:
            while True:
                kind, payload = self._events.get_nowait()
                if kind == "progress":
                    done, total, msg = payload
                    self.progress.set(done / total if total else 1.0)
                    self._set_status(msg)
                elif kind == "export_done":
                    self._on_export_done(payload)
                elif kind == "export_error":
                    self.pull_btn.configure(state="normal", text="Pull Windows Logs")
                    self._set_status(f"Export failed: {payload}", error=True)
                elif kind == "quota":
                    self._update_quota(payload)
                elif kind == "quota_done":
                    self.refresh_btn.configure(state="normal", text="Refresh")
                    self._set_status("API usage updated.")
                elif kind == "done":
                    self._finish(payload)
                elif kind == "error":
                    self._running = False
                    self.run_btn.configure(state="normal", text="RUN SCAN")
                    self._set_status(f"Error: {payload}", error=True)
        except queue.Empty:
            pass
        self.after(100, self._drain_events)

    def _finish(self, rows: list[dict]) -> None:
        self._running = False
        self.last_rows = rows
        self.run_btn.configure(state="normal", text="RUN SCAN")
        self.progress.set(1.0)
        self._populate_table(rows)
        counts: dict[str, int] = {}
        for r in rows:
            counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
        summary = "  ".join(f"{k}={v}" for k, v in sorted(counts.items()))
        self._set_status(f"{len(rows)} IOCs  |  {summary}" if rows else "No IOCs found.")
        if rows:
            self.export_json_btn.configure(state="normal")
            self.export_csv_btn.configure(state="normal")

    def _populate_table(self, rows: list[dict]) -> None:
        self.tree.delete(*self.tree.get_children())
        for r in rows:
            self.tree.insert(
                "", "end",
                values=(
                    r["verdict"], r["type"], r["value"], r["count"],
                    r.get("action", "-"), r.get("why", "") or "-",
                    r["providers"] or "-", ", ".join(r.get("sources", [])) or "-",
                ),
                tags=(r["verdict"],),
            )

    # -- export ---------------------------------------------------------------

    def _export(self, fmt: str) -> None:
        if not self.last_rows:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=f".{fmt}",
            filetypes=[(fmt.upper(), f"*.{fmt}")],
            title=f"Export {fmt.upper()}",
        )
        if not path:
            return
        (export_json if fmt == "json" else export_csv)(self.last_rows, path)
        self._set_status(f"Wrote {path}")

    # -- powershell template --------------------------------------------------

    def _powershell_command(self) -> str:
        parts = ["python -m ioc_enrich.cli"]
        mode = getattr(self, "selection_mode", None)
        if mode and mode[0] == "folder":
            parts.append(f"--dir {_quote(mode[1])}")
            if mode[2]:
                parts.append("--recursive")
        elif self.selected_files:
            parts.extend(_quote(f) for f in self.selected_files)
        else:
            parts.append("<files or --dir FOLDER>")
        if not self.enrich_var.get():
            parts.append("--no-enrich")
        elif self.pause_var.get() not in ("", "0"):
            parts.append(f"--pause {self.pause_var.get()}")
        if self.private_var.get():
            parts.append("--include-private-ips")
        return " ".join(parts)

    def _refresh_powershell(self) -> None:
        self.ps_box.delete("1.0", "end")
        self.ps_box.insert("1.0", self._powershell_command())

    def _copy_powershell(self) -> None:
        self.clipboard_clear()
        self.clipboard_append(self._powershell_command())
        self._set_status("PowerShell command copied to clipboard.")

    # -- status ---------------------------------------------------------------

    def _set_status(self, text: str, error: bool = False) -> None:
        self.status_lbl.configure(text=text, text_color="#ff5c5c" if error else "#e0e0e0")


def main() -> None:
    app = IOCApp()
    app.mainloop()


if __name__ == "__main__":
    main()
