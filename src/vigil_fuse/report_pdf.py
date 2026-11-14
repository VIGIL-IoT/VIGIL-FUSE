from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from .model import ScanResult
from .text_safety import safe_report_text


_LATEX_ESCAPES = str.maketrans(
    {
        "\\": r"\textbackslash{}",
        "&": r"\&",
        "%": r"\%",
        "$": r"\$",
        "#": r"\#",
        "_": r"\_",
        "{": r"\{",
        "}": r"\}",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
    }
)


def _latex_text(value: object, *, limit: int = 1600) -> str:
    text = safe_report_text(value, limit=limit) or "Not provided"
    rendered: list[str] = []
    for character in text:
        if ord(character) > 127:
            rendered.append(r"\texttt{U+" + f"{ord(character):04X}" + "}")
        else:
            rendered.append(character.translate(_LATEX_ESCAPES))
    return "".join(rendered).replace("/", r"/\allowbreak{}")


def _render_report(result: ScanResult) -> str:
    counts = {name: 0 for name in ("critical", "high", "medium", "low", "info", "unknown")}
    for finding in result.findings:
        counts[finding.severity] += 1

    findings = []
    for finding in result.findings:
        location = _latex_text(finding.file)
        if finding.start_line is not None:
            location += f" : {finding.start_line}"
        findings.append(
            "\\subsection*{\\textcolor{signal}{"
            + _latex_text(finding.severity.upper())
            + "} \\textbar{} "
            + _latex_text(finding.title)
            + "}\n"
            + "\\textbf{Rule:} \\texttt{"
            + _latex_text(finding.rule_id)
            + "} \\quad \\textbf{Severity:} "
            + _latex_text(finding.severity)
            + " \\quad \\textbf{Confidence:} "
            + _latex_text(finding.confidence)
            + " \\quad \\textbf{Category:} "
            + _latex_text(finding.category)
            + "\\\\[3pt]\n\\textbf{Location:} "
            + location
            + "\\\\[3pt]\n\\textbf{Evidence:} \\begin{quote}\\small "
            + _latex_text(finding.evidence)
            + "\\end{quote}\n\\textbf{Explanation:} "
            + _latex_text(finding.explanation)
            + "\\\\[3pt]\n\\textbf{Potential impact:} "
            + _latex_text(finding.potential_impact)
            + "\\\\[3pt]\n\\textbf{Remediation:} "
            + _latex_text(finding.remediation)
        )

    finding_section = (
        "\n\\section*{Findings}\n" + "\n\\medskip\n".join(findings)
        if findings
        else "\n\\section*{Findings}\nNo findings were emitted for this scan."
    )
    coverage_lines = [
        f"Selected files: {result.files_selected}",
        f"Scanned files: {result.files_scanned}",
        f"Skipped files: {result.files_skipped}",
        "Discovery complete: " + ("yes" if result.discovery_complete else "no"),
    ]
    if result.limits_reached:
        coverage_lines.append("Limits reached: " + ", ".join(result.limits_reached))
    coverage = "\\\\\n".join(_latex_text(line) for line in coverage_lines)
    analyzers = [f"{item.name}: {item.status}" for item in result.analyzers]
    analyzer_section = (
        "\\section*{Analysis stages}\n" + "\\\\\n".join(_latex_text(item) for item in analyzers)
        if analyzers
        else ""
    )
    severity_counts = " \\quad ".join(
        f"\\textbf{{{_latex_text(name.title())}}} {count}"
        for name, count in counts.items()
        if count
    ) or "No findings"

    return rf"""\documentclass[10pt,a4paper]{{article}}
\usepackage[margin=20mm]{{geometry}}
\usepackage[T1]{{fontenc}}
\usepackage[utf8]{{inputenc}}
\usepackage{{lmodern,tabularx,array,xcolor,hyperref}}
\definecolor{{signal}}{{HTML}}{{D92B21}}
\hypersetup{{colorlinks=true,urlcolor=signal,linkcolor=signal,pdftitle={{FUSE scan report}}}}
\setlength{{\parindent}}{{0pt}}
\setlength{{\parskip}}{{5pt}}
\begin{{document}}
\begin{{center}}
{{\sffamily\bfseries\color{{signal}}\fontsize{{34}}{{38}}\selectfont FUSE\par}}
{{\sffamily\large Firmware \& Unified Security Engine\par}}
{{\small A VIGIL Project\par}}
\vspace{{5pt}}\color{{signal}}\rule{{\linewidth}}{{1.2pt}}
{{\Large\sffamily\bfseries Scan report\par}}
\end{{center}}

\textbf{{Target:}} {_latex_text(result.target)}\\
\textbf{{Profile:}} {_latex_text(result.profile)} \quad
\textbf{{Input:}} {_latex_text(result.target_kind)}\\
\textbf{{Started:}} {_latex_text(result.started_at)} \quad
\textbf{{Completed:}} {_latex_text(result.completed_at)}

\section*{{Scan summary}}
\begin{{tabularx}}{{\linewidth}}{{>{{\centering\arraybackslash}}X >{{\centering\arraybackslash}}X >{{\centering\arraybackslash}}X}}
{{\Large\color{{signal}}{result.files_scanned}}} & {{\Large\color{{signal}}{len(result.findings)}}} & {{\Large\color{{signal}}{result.files_skipped}}}\\
Files scanned & Finding candidates & Files skipped
\end{{tabularx}}

\textbf{{Severity:}} {severity_counts}

\textbf{{Coverage}}\\
{coverage}

{analyzer_section}
{finding_section}

\vfill
{{\footnotesize FUSE reports static review leads and analysis coverage. A finding is not a confirmed vulnerability. Severity describes potential impact; confidence describes evidence strength. Review the evidence and limits before making deployment decisions.\par}}
\end{{document}}
"""


def write_pdf_report(result: ScanResult, output_dir: Path) -> tuple[Path | None, str | None]:
    """Save a LaTeX report and compile it when pdflatex is available."""
    output_dir.mkdir(parents=True, exist_ok=True)
    tex_path = output_dir / "fuse-report.tex"
    pdf_path = output_dir / "fuse-report.pdf"
    for path in (tex_path, pdf_path):
        if path.is_symlink():
            raise OSError(f"Refusing to write report through symbolic link: {path.name}")
        if path.exists() and not path.is_file():
            raise OSError(f"Report output path is not a regular file: {path.name}")

    source = _render_report(result)
    tex_path.write_text(source, encoding="utf-8")
    pdflatex = shutil.which("pdflatex")
    if pdflatex is None:
        return None, "pdflatex was not found; the LaTeX source was saved."

    try:
        with tempfile.TemporaryDirectory(prefix="vigil-fuse-report-") as temporary:
            build_dir = Path(temporary)
            (build_dir / tex_path.name).write_text(source, encoding="utf-8")
            completed = subprocess.run(
                [
                    pdflatex,
                    "-no-shell-escape",
                    "-interaction=nonstopmode",
                    "-halt-on-error",
                    tex_path.name,
                ],
                cwd=build_dir,
                capture_output=True,
                text=True,
                timeout=90,
                check=False,
            )
            compiled_pdf = build_dir / "fuse-report.pdf"
            if completed.returncode != 0 or not compiled_pdf.is_file():
                return None, "pdflatex could not build the PDF; the LaTeX source was saved."
            pdf_path.write_bytes(compiled_pdf.read_bytes())
    except (OSError, subprocess.TimeoutExpired):
        return None, "PDF compilation failed; the LaTeX source was saved."
    return pdf_path, None
