"""Evidence-first local desktop interface using the FUSE CLI."""

from __future__ import annotations

import json
import queue
import tempfile
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Any, Callable

from .backend import (
    CommandResult,
    Runner,
    ScanOptions,
    export_reports,
    filter_findings,
    load_report,
    paginate_findings,
    prepare_export_metadata,
)

BG = "#171719"
PANEL = "#131217"
RAISED = "#252527"
TEXT = "#f1f1f2"
MUTED = "#b4b4ba"
ACCENT = "#71a8d9"
PAGE_SIZE = 250


class FuseApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        root.title("FUSE | Security workstation")
        root.geometry("1280x800")
        root.minsize(820, 600)
        root.configure(bg=BG)
        self.temp = tempfile.TemporaryDirectory(prefix="fuse-desktop-")
        self.workdir = Path(self.temp.name)
        self.runner = Runner(self.workdir)
        self.events: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.busy = False
        self.report: dict[str, Any] | None = None
        self.report_dir: Path | None = None
        self.findings: list[dict[str, Any]] = []
        self.changes: dict[str, str] = {}
        self.context_inspected_id: str | None = None
        self.page = 0
        self.plan_key: tuple[Any, ...] | None = None
        self.path = tk.StringVar()
        self.profile = tk.StringVar(value="generic")
        self.online = tk.BooleanVar(value=False)
        self.dependencies = tk.BooleanVar(value=False)
        self.search = tk.StringVar()
        self.filter_field = tk.StringVar(value="severity")
        self.filter_value = tk.StringVar(value="all")
        self.status = tk.StringVar(value="Choose a project to begin.")
        self.count = tk.StringVar(value="No scan loaded")
        self._style()
        self._build()
        root.protocol("WM_DELETE_WINDOW", self.close)
        root.after(100, self._poll)

    def _style(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure(
            ".",
            background=BG,
            foreground=TEXT,
            fieldbackground=RAISED,
            font=("Segoe UI", 10),
            bordercolor=RAISED,
        )
        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=PANEL)
        style.configure("TLabel", background=BG, foreground=TEXT)
        style.configure("Muted.TLabel", foreground=MUTED)
        style.configure("Title.TLabel", font=("Segoe UI", 19, "bold"))
        style.configure("TButton", padding=(12, 7), background=RAISED, foreground=TEXT)
        style.map(
            "TButton",
            background=[("active", "#3a3a3e"), ("disabled", BG)],
            foreground=[("disabled", "#77777a")],
        )
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", padding=(16, 9), background=BG, foreground=MUTED)
        style.map(
            "TNotebook.Tab", foreground=[("selected", TEXT)], background=[("selected", PANEL)]
        )
        style.configure(
            "Treeview",
            background=PANEL,
            fieldbackground=PANEL,
            foreground=TEXT,
            rowheight=27,
            borderwidth=0,
        )
        style.configure("Treeview.Heading", background=RAISED, foreground=TEXT, relief="flat")
        style.map("Treeview", background=[("selected", "#344650")])
        style.configure("TCheckbutton", background=BG, foreground=TEXT)

    def _text(self, parent: tk.Misc) -> scrolledtext.ScrolledText:
        return scrolledtext.ScrolledText(
            parent,
            wrap="word",
            bg=PANEL,
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            padx=14,
            pady=12,
            font=("Consolas", 10),
        )

    def _build(self) -> None:
        outer = ttk.Frame(self.root, padding=18)
        outer.pack(fill="both", expand=True)
        top = ttk.Frame(outer)
        top.pack(fill="x")
        ttk.Label(top, text="FUSE", style="Title.TLabel").pack(side="left")
        ttk.Label(top, text="  Security workstation", style="Muted.TLabel").pack(
            side="left", pady=(8, 0)
        )
        ttk.Button(top, text="Doctor", command=self.doctor).pack(side="right")
        ttk.Label(outer, text="Project directory", style="Muted.TLabel").pack(
            anchor="w", pady=(15, 4)
        )
        project = ttk.Frame(outer)
        project.pack(fill="x")
        ttk.Entry(project, textvariable=self.path).pack(side="left", fill="x", expand=True)
        ttk.Button(project, text="Browse", command=self.select_project).pack(
            side="left", padx=(8, 0)
        )
        controls = ttk.Frame(outer)
        controls.pack(fill="x", pady=(12, 4))
        ttk.Label(controls, text="Profile").pack(side="left")
        ttk.Combobox(
            controls,
            textvariable=self.profile,
            state="readonly",
            width=16,
            values=("generic", "esp-idf", "zephyr", "embedded-linux", "rtl"),
        ).pack(side="left", padx=8)
        ttk.Checkbutton(controls, text="Dependency analysis", variable=self.dependencies).pack(
            side="left", padx=8
        )
        ttk.Checkbutton(controls, text="Allow advisory network", variable=self.online).pack(
            side="left", padx=8
        )
        self.plan_button = ttk.Button(controls, text="Preview plan", command=self.plan)
        self.plan_button.pack(side="right", padx=(8, 0))
        self.scan_button = ttk.Button(controls, text="Run scan", command=self.scan)
        self.scan_button.pack(side="right")
        self.cancel_button = ttk.Button(
            controls, text="Cancel", command=self.cancel, state="disabled"
        )
        self.cancel_button.pack(side="right", padx=8)
        ttk.Label(outer, textvariable=self.status, style="Muted.TLabel").pack(
            anchor="w", pady=(4, 10)
        )
        self.tabs = ttk.Notebook(outer)
        self.tabs.pack(fill="both", expand=True)
        self.plan_tab = ttk.Frame(self.tabs, padding=8)
        self.finding_tab = ttk.Frame(self.tabs, padding=8)
        self.coverage_tab = ttk.Frame(self.tabs, padding=8)
        self.report_tab = ttk.Frame(self.tabs, padding=8)
        self.ai_tab = ttk.Frame(self.tabs, padding=8)
        for tab, title in (
            (self.plan_tab, "Plan"),
            (self.finding_tab, "Findings"),
            (self.coverage_tab, "Coverage"),
            (self.report_tab, "Reports & baseline"),
            (self.ai_tab, "Local explanation"),
        ):
            self.tabs.add(tab, text=title)
        self.plan_text = self._text(self.plan_tab)
        self.plan_text.pack(fill="both", expand=True)
        self._set_text(
            self.plan_text,
            "Choose a project, then preview the FUSE scan plan.\n\nThe plan describes selected inputs, limitations, network and resource bounds. No scan has run.",
        )
        toolbar = ttk.Frame(self.finding_tab)
        toolbar.pack(fill="x", pady=(0, 8))
        ttk.Label(toolbar, text="Search").pack(side="left")
        search = ttk.Entry(toolbar, textvariable=self.search, width=25)
        search.pack(side="left", padx=8)
        search.bind("<KeyRelease>", lambda _event: self.render_findings(reset=True))
        fields = (
            "severity",
            "confidence",
            "applicability",
            "validation_status",
            "category",
            "analyzer",
            "change",
        )
        field = ttk.Combobox(
            toolbar, textvariable=self.filter_field, state="readonly", values=fields, width=17
        )
        field.pack(side="left", padx=4)
        field.bind("<<ComboboxSelected>>", lambda _event: self.update_filter_values())
        self.filter_combo = ttk.Combobox(
            toolbar, textvariable=self.filter_value, state="readonly", width=18
        )
        self.filter_combo.pack(side="left", padx=4)
        self.filter_combo.bind(
            "<<ComboboxSelected>>", lambda _event: self.render_findings(reset=True)
        )
        ttk.Label(toolbar, textvariable=self.count, style="Muted.TLabel").pack(side="right")
        pane = ttk.Panedwindow(self.finding_tab, orient="vertical")
        pane.pack(fill="both", expand=True)
        table_frame = ttk.Frame(pane)
        columns = ("severity", "confidence", "applicability", "rule", "title", "file")
        self.table = ttk.Treeview(
            table_frame, columns=columns, show="headings", selectmode="browse"
        )
        for col, width in (
            ("severity", 75),
            ("confidence", 90),
            ("applicability", 100),
            ("rule", 110),
            ("title", 330),
            ("file", 260),
        ):
            self.table.heading(col, text=col.title())
            self.table.column(col, width=width, minwidth=60, stretch=col in {"title", "file"})
        scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=scroll.set)
        self.table.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.table.bind("<<TreeviewSelect>>", self.show_finding)
        pane.add(table_frame, weight=3)
        self.detail = self._text(pane)
        pane.add(self.detail, weight=2)
        pages = ttk.Frame(self.finding_tab)
        pages.pack(fill="x", pady=(8, 0))
        ttk.Button(pages, text="Previous", command=lambda: self.turn_page(-1)).pack(side="left")
        ttk.Button(pages, text="Next", command=lambda: self.turn_page(1)).pack(side="left", padx=8)
        ttk.Button(pages, text="Inspect local model context", command=self.reasoning_context).pack(
            side="right"
        )
        self.coverage = self._text(self.coverage_tab)
        self.coverage.pack(fill="both", expand=True)
        self._set_text(
            self.coverage,
            "No coverage report yet. Skipped or unavailable stages will be shown here.",
        )
        report_controls = ttk.Frame(self.report_tab)
        report_controls.pack(fill="x", pady=(0, 8))
        ttk.Button(report_controls, text="Export reports", command=self.export).pack(side="left")
        ttk.Button(report_controls, text="Compare previous report", command=self.compare).pack(
            side="left", padx=8
        )
        self.report_text = self._text(self.report_tab)
        self.report_text.pack(fill="both", expand=True)
        self._set_text(
            self.report_text,
            "Reports and baseline comparisons will appear here. Files are kept outside the project until you export them.",
        )
        ttk.Button(
            self.ai_tab, text="Explain selected finding with local model", command=self.reason
        ).pack(anchor="w", pady=(0, 8))
        self.ai_text = self._text(self.ai_tab)
        self.ai_text.pack(fill="both", expand=True)
        self._set_text(
            self.ai_text,
            "Local model explanations are optional and separate from FUSE findings. Inspect the context before requesting an explanation.",
        )
        self.update_filter_values()

    @staticmethod
    def _set_text(widget: scrolledtext.ScrolledText, value: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", value)
        widget.configure(state="disabled")

    def _select_tab(self, tab: ttk.Frame) -> None:
        self.tabs.tk.call(str(self.tabs), "select", str(tab))

    def select_project(self) -> None:
        selected = filedialog.askdirectory(parent=self.root, title="Select a FUSE project")
        if selected:
            self.path.set(selected)
            self.plan_key = None
            self.status.set("Project selected. Preview the scan plan.")
            self._select_tab(self.plan_tab)

    def options(self) -> ScanOptions:
        if not self.path.get().strip():
            raise ValueError("Select a project directory first")
        options = ScanOptions(
            Path(self.path.get()), self.profile.get(), self.online.get(), self.dependencies.get()
        )
        options.arguments()
        return options

    def _launch(
        self, label: str, operation: Callable[[], Any], callback: Callable[[Any], None]
    ) -> None:
        if self.busy:
            return
        self.busy = True
        self.runner.prepare()
        self.status.set(f"{label} running. FUSE does not provide per-stage progress here.")
        self.plan_button.configure(state="disabled")
        self.scan_button.configure(state="disabled")
        self.cancel_button.configure(state="normal")

        def worker() -> None:
            try:
                self.events.put(("done", (callback, operation())))
            except Exception as error:
                self.events.put(("error", str(error)))

        threading.Thread(target=worker, daemon=True).start()

    def _poll(self) -> None:
        try:
            while True:
                kind, payload = self.events.get_nowait()
                self.busy = False
                self.plan_button.configure(state="normal")
                self.scan_button.configure(state="normal")
                self.cancel_button.configure(state="disabled")
                if kind == "error":
                    self.status.set("Operation failed. See details.")
                    messagebox.showerror("FUSE", payload, parent=self.root)
                else:
                    callback, result = payload
                    callback(result)
        except queue.Empty:
            pass
        self.root.after(100, self._poll)

    def _command(
        self, args: list[str], title: str, widget: scrolledtext.ScrolledText, tab: ttk.Frame
    ) -> None:
        def done(result: CommandResult) -> None:
            self._set_text(widget, (result.stdout + "\n" + result.stderr).strip() or "No output.")
            self._select_tab(tab)
            self.status.set(
                "Cancelled." if result.cancelled else f"{title}: exit {result.returncode}"
            )

        self._launch(title, lambda: self.runner.run(args), done)

    def doctor(self) -> None:
        self._command(["doctor"], "Doctor", self.plan_text, self.plan_tab)

    def plan(self) -> None:
        try:
            options = self.options()
            args = options.arguments()
        except (ValueError, OSError) as error:
            messagebox.showerror("Invalid project", str(error), parent=self.root)
            return

        def done(result: CommandResult) -> None:
            self._set_text(self.plan_text, (result.stdout + "\n" + result.stderr).strip())
            self._select_tab(self.plan_tab)
            self.plan_key = (
                (options.target.resolve(), options.profile, options.network, options.dependencies)
                if result.returncode == 0 and not result.cancelled
                else None
            )
            self.status.set(
                "Plan ready. Review it before scanning."
                if self.plan_key
                else "Plan failed or cancelled."
            )

        self._launch("Plan", lambda: self.runner.run(["scan", *args, "--plan"]), done)

    def scan(self) -> None:
        try:
            options = self.options()
            key = (options.target.resolve(), options.profile, options.network, options.dependencies)
            if key != self.plan_key:
                raise ValueError("Preview a plan for the current project and options first.")
            args = options.arguments()
        except (ValueError, OSError) as error:
            messagebox.showerror("Cannot scan", str(error), parent=self.root)
            return
        output = Path(tempfile.mkdtemp(prefix="scan-", dir=self.workdir))

        def done(result: CommandResult) -> None:
            if result.cancelled:
                self.status.set("Scan cancelled; no result was loaded.")
                return
            try:
                report = load_report(output / "findings.json")
            except (OSError, ValueError, json.JSONDecodeError) as error:
                self.status.set("Scan failed; no report was loaded.")
                messagebox.showerror("Scan failed", f"{result.stderr}\n{error}", parent=self.root)
                return
            self.report, self.report_dir = report, output
            self.changes = {}
            self.context_inspected_id = None
            prepare_export_metadata(output, report)
            self.update_filter_values()
            self.render_findings(reset=True)
            self.render_coverage()
            self._set_text(
                self.report_text,
                f"Reports: {output}\n\nCLI exit: {result.returncode}\n\n{result.stdout}\n{result.stderr}\n\nSelect Export reports to copy the canonical files elsewhere.",
            )
            self.status.set(
                "Scan complete."
                if result.returncode == 0
                else f"Scan incomplete or failed (exit {result.returncode}); review coverage."
            )
            self._select_tab(self.finding_tab)

        self._launch(
            "Scan", lambda: self.runner.run(["scan", *args, "--output-dir", str(output)]), done
        )

    def cancel(self) -> None:
        if self.runner.cancel():
            self.status.set("Cancellation requested.")

    def update_filter_values(self) -> None:
        field = self.filter_field.get()
        if field == "change":
            values = sorted(set(self.changes.values()))
        else:
            values = sorted(
                {
                    str(item.get(field, "unknown"))
                    for item in (self.report or {}).get("findings", [])
                }
            )
        self.filter_combo.configure(values=["all", *values])
        self.filter_value.set("all")
        self.render_findings(reset=True)

    def render_findings(self, reset: bool = False) -> None:
        if not hasattr(self, "table"):
            return
        if reset:
            self.page = 0
            self.context_inspected_id = None
        all_findings = (self.report or {}).get("findings", [])
        field, value = self.filter_field.get(), self.filter_value.get()
        if field == "change":
            filtered = filter_findings(all_findings, self.search.get(), "severity", "all")
            if value != "all":
                filtered = [
                    item
                    for item in filtered
                    if self.changes.get(item.get("fingerprint", ""), "unknown") == value
                ]
        else:
            filtered = filter_findings(all_findings, self.search.get(), field, value)
        self.findings, self.page, max_page = paginate_findings(filtered, self.page, PAGE_SIZE)
        self.table.delete(*self.table.get_children())
        for index, item in enumerate(self.findings):
            location = item.get("location") or {}
            where = f"{location.get('file', 'unknown')}:{location.get('start_line') or '?'}"
            self.table.insert(
                "",
                "end",
                iid=str(index),
                values=(
                    item.get("severity", "unknown"),
                    item.get("confidence", "unknown"),
                    item.get("applicability", "unknown"),
                    item.get("rule_id", "unknown"),
                    item.get("title", ""),
                    where,
                ),
            )
        self.count.set(f"{len(filtered)} findings · page {self.page + 1} / {max_page + 1}")
        self._set_text(self.detail, "Select a finding to inspect its evidence and limitations.")

    def turn_page(self, delta: int) -> None:
        self.page += delta
        self.render_findings()

    def selected(self) -> dict[str, Any] | None:
        selected = self.table.selection()
        return self.findings[int(selected[0])] if selected else None

    def show_finding(self, _event: Any = None) -> None:
        item = self.selected()
        if not item:
            return
        if self.context_inspected_id != str(item["id"]):
            self.context_inspected_id = None
        fields = (
            "id",
            "fingerprint",
            "title",
            "severity",
            "severity_basis",
            "confidence",
            "applicability",
            "validation_method",
            "validation_status",
            "category",
            "analyzer",
            "location",
            "evidence",
            "explanation",
            "potential_impact",
            "remediation",
            "references",
            "vex_review",
        )
        self._set_text(
            self.detail,
            "\n\n".join(
                f"{key.replace('_', ' ').title()}\n{json.dumps(item.get(key), ensure_ascii=False, indent=2) if isinstance(item.get(key), (dict, list)) else item.get(key) or 'unknown'}"
                for key in fields
            ),
        )

    def render_coverage(self) -> None:
        if not self.report:
            return
        coverage = self.report.get("coverage", {})
        context = self.report.get("project_context", {})
        identity = {
            "target": self.report.get("target"),
            "scan": self.report.get("scan"),
            "project_context": context,
            "finding_summary": self.report.get("summary"),
        }
        lines = [
            "Project identity and scan",
            json.dumps(identity, ensure_ascii=False, indent=2),
            "",
            "Analyzer coverage",
        ]
        for item in coverage.get("analyzers", []):
            lines.append(
                f"{item.get('name', 'unknown')}: {item.get('status', 'unknown')}\n  {item.get('detail', '')}"
            )
        lines += [
            "",
            "Discovery and limits",
            json.dumps(
                {key: value for key, value in coverage.items() if key != "analyzers"},
                ensure_ascii=False,
                indent=2,
            ),
            "",
            "A clean list with partial or unavailable coverage is not a complete assessment.",
        ]
        self._set_text(self.coverage, "\n".join(lines))

    def export(self) -> None:
        if not self.report_dir:
            messagebox.showinfo("Export", "Run a scan first.", parent=self.root)
            return
        selected = filedialog.askdirectory(
            parent=self.root, title="Choose an empty export directory"
        )
        if not selected:
            return
        try:
            files = export_reports(self.report_dir, Path(selected))
            self.status.set(f"Exported {len(files)} reports to {selected}")
        except (OSError, ValueError) as error:
            messagebox.showerror("Export failed", str(error), parent=self.root)

    def compare(self) -> None:
        if not self.report_dir:
            messagebox.showinfo("Baseline", "Run a current scan first.", parent=self.root)
            return
        previous = filedialog.askopenfilename(
            parent=self.root, title="Select previous findings.json", filetypes=[("JSON", "*.json")]
        )
        if not previous:
            return
        current = self.report_dir / "findings.json"
        baseline = self.workdir / "baseline.json"

        def operation() -> tuple[CommandResult, CommandResult | None]:
            first = self.runner.run(["baseline", "create", previous, "--output", str(baseline)])
            if first.returncode != 0 or first.cancelled:
                return first, None
            return first, self.runner.run(
                ["baseline", "diff", str(current), "--baseline", str(baseline), "--format", "json"]
            )

        def done(results: tuple[CommandResult, CommandResult | None]) -> None:
            first, second = results
            if second is None:
                self._set_text(
                    self.report_text, f"Baseline unavailable:\n{first.stderr}\n{first.stdout}"
                )
                self.status.set("Baseline could not be created.")
                return
            try:
                diff = json.loads(second.stdout)
                self.changes = {
                    item["fingerprint"]: item["change"] for item in diff.get("findings", [])
                }
                self.update_filter_values()
                self._set_text(self.report_text, json.dumps(diff, indent=2, ensure_ascii=False))
                self.status.set(
                    "Comparison complete."
                    if second.returncode == 0
                    else "Comparison incomplete; inspect the reasons."
                )
            except (ValueError, KeyError, TypeError):
                self._set_text(
                    self.report_text, f"Comparison failed:\n{second.stderr}\n{second.stdout}"
                )
                self.status.set("Comparison failed.")
            self._select_tab(self.report_tab)

        self._launch("Baseline comparison", operation, done)

    def reasoning_context(self) -> None:
        item = self.selected()
        if not item or not self.report_dir:
            messagebox.showinfo("Local reasoning", "Select a finding first.", parent=self.root)
            return
        finding_id = str(item["id"])
        args = [
            "reasoning-context",
            str(self.report_dir / "findings.json"),
            "--finding",
            finding_id,
        ]

        def done(result: CommandResult) -> None:
            self._set_text(self.ai_text, (result.stdout + "\n" + result.stderr).strip())
            self._select_tab(self.ai_tab)
            self.context_inspected_id = (
                finding_id if result.returncode == 0 and not result.cancelled else None
            )
            self.status.set(
                "Context inspected. Review it before requesting an explanation."
                if self.context_inspected_id
                else "Context inspection failed or was cancelled."
            )

        self._launch("Reasoning context", lambda: self.runner.run(args), done)

    def reason(self) -> None:
        item = self.selected()
        if not item or not self.report_dir:
            messagebox.showinfo("Local reasoning", "Select a finding first.", parent=self.root)
            return
        if self.context_inspected_id != str(item["id"]):
            messagebox.showinfo(
                "Local reasoning",
                "Inspect the selected finding's bounded context first.",
                parent=self.root,
            )
            return
        if not messagebox.askyesno(
            "Local model",
            "This sends FUSE's bounded evidence context to the configured local model. Inspect the context first and proceed only if it is appropriate to share.",
            parent=self.root,
        ):
            return
        self._command(
            ["reason", str(self.report_dir / "findings.json"), "--finding", str(item["id"])],
            "Local explanation",
            self.ai_text,
            self.ai_tab,
        )

    def close(self) -> None:
        if self.busy:
            self.runner.cancel()
        self.root.destroy()


def main() -> None:
    root = tk.Tk()
    FuseApp(root)
    root.mainloop()
