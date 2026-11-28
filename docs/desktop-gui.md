## Desktop GUI

Install the repository or package in the Python environment you want FUSE to use, then launch:

```sh
python -m pip install -e .
vigil-fuse-gui
# equivalent:
python -m vigil_fuse.gui
```

The GUI requires Python's Tk interface. The full Windows Python installer includes Tcl/Tk. On Debian and Ubuntu install the matching `python3-tk` package. On macOS use a Python distribution built with Tk, such as python.org's installer. The Python wheel adds no GUI framework dependency. In packaged or managed environments, launch the GUI with the same Python environment where FUSE is installed.

The app flow is project selection, FUSE doctor or scan plan, scan, findings and evidence, coverage, baseline comparison, and report export. The plan must match the selected path, profile and options before the Run button will proceed. The report keeps FUSE's severity, confidence, applicability, validation, rule IDs, fingerprints, project context, coverage, and provenance. Findings can be searched and filtered by severity, confidence, applicability, validation, category, analyzer, or baseline change, then paged in groups of 250. Selecting one shows its evidence and remediation fields. The app does not calculate a combined risk score.

FUSE runs in a separate local Python process. Output is created in a temporary directory outside the selected project, and the app does not execute project build scripts. Dependency analysis and advisory network access are opt-in. By default the scan disables network access, firmware analysis, Ghidra, Git history, and optional dependency tools. FUSE's plan and coverage report show selected, skipped, partial, failed, and unavailable stages and limits. During a scan the interface reports only that the process is running because the CLI does not provide reliable stage progress or an ETA. Cancel terminates the scan process tree.

Baseline comparison uses FUSE's `baseline create` and `baseline diff` commands and their fingerprints. It requires a compatible prior FUSE report and sufficient coverage. If the comparison is incomplete, the report says so; it does not call the scan clean. Report export copies the canonical JSON, text and SARIF files, a provenance sidecar from the JSON report, and a FUSE citation note. If a PDF already exists in the report directory it can be copied too. The desktop scan path does not generate PDFs; FUSE's current PDF generation is available through its interactive terminal when `pdflatex` is installed.

Local model explanations are optional and are displayed separately from FUSE findings. First inspect the bounded context for the selected finding. Then confirm before asking FUSE to send that context to the configured local model. A model explanation never becomes a finding.

### Desktop technology choice

| Option | Python integration and boundary | Packaging and upkeep | Offline and performance |
| --- | --- | --- | --- |
| Tkinter with a FUSE subprocess | Uses the Python standard library and invokes the same local CLI used by terminal users. The UI does not implement analysis. | Small app code and no GUI package dependency. Tk availability follows the Python distribution, so Linux and some macOS installs need a Tk-enabled runtime. No standalone binary is produced. | Fully local. A native table is sufficient for FUSE reports and does not require a bundled browser engine. |
| Qt for Python | Strong native widget set, but adds a Python GUI runtime beside FUSE. | Larger dependency and platform packaging effort. | Works offline; its richer features are unnecessary for the current scan and evidence flow. |
| Electron or a webview shell | Browser UI needs a bridge to the local scanner process and additional validation at that boundary. | Adds a web runtime or native shell and a second UI stack to maintain. | Can work offline, with more packaging and process-boundary parts than this GUI needs. |

Tkinter is the smallest cross-platform choice for a local wrapper around the existing Python CLI. It keeps analysis in FUSE and avoids a server, cloud login, telemetry, or an additional GUI dependency. The app is intended for local engineering work, not headless servers.

Known limitations: the scan process reports overall state only, not reliable per-analyzer live progress; the app does not generate a PDF; analyzer availability depends on installed tools; and the scan's platform-specific results depend on the host Python and operating system. See [FUSE limits](limitations.md) and [CLI usage](usage.md).
