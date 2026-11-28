from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from . import __version__
from .model import ScanResult
from .terminal import _ASCII_MARK
from .text_safety import safe_report_text
from .path_safety import (
    assert_no_path_aliases,
    ensure_safe_directory,
    safe_write_bytes,
    safe_write_text,
)


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


def _render_report(result: ScanResult, *, xelatex: bool = True) -> str:
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
            + "\\textbf{Finding ID:} \\texttt{"
            + _latex_text(finding.id)
            + "} \\quad \\textbf{Rule:} \\texttt{"
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
            + "\\\\[3pt]\n\\textbf{References:} "
            + _latex_text("; ".join(finding.references) if finding.references else "None listed")
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
    severity_counts = (
        " \\quad ".join(
            f"\\textbf{{{_latex_text(name.title())}}} {count}"
            for name, count in counts.items()
            if count
        )
        or "No findings"
    )
    cli_logo = r"\par ".join(
        r"\makebox[\linewidth][c]{\ttfamily " + line.replace(" ", r"\ ") + "}"
        for line in _ASCII_MARK
    )
    font_setup = (
        r"\usepackage{fontspec}"
        "\n"
        r"\setmainfont{Times New Roman}"
        "\n"
        r"\setsansfont{Times New Roman}"
        if xelatex
        else r"\usepackage[T1]{fontenc}"
        "\n"
        r"\usepackage[utf8]{inputenc}"
        "\n"
        r"\usepackage{mathptmx}"
    )

    return rf"""\documentclass[10pt,a4paper]{{article}}
{font_setup}
\usepackage{{color}}
\definecolor{{signal}}{{rgb}}{{0.851,0.169,0.129}}
\definecolor{{frame}}{{rgb}}{{0.376,0.396,0.851}}
\setlength{{\oddsidemargin}}{{-15.6pt}}
\setlength{{\textwidth}}{{481pt}}
\setlength{{\topmargin}}{{-15.6pt}}
\setlength{{\headheight}}{{0pt}}
\setlength{{\headsep}}{{0pt}}
\setlength{{\textheight}}{{720pt}}
\setlength{{\parindent}}{{0pt}}
\setlength{{\parskip}}{{5pt}}
\begin{{document}}
\begin{{center}}
{{\setlength{{\fboxsep}}{{8pt}}\setlength{{\fboxrule}}{{0.8pt}}\color{{frame}}
\fbox{{\begin{{minipage}}{{0.86\linewidth}}
\color{{black}}\centering
{{\small\color{{signal}}
{cli_logo}
\par}}
{{\large Firmware \& Unified Security Engine\par}}
{{\small by VIGIL \textbullet{{}} v{_latex_text(__version__)}\par}}
{{\small Static evidence. Explicit coverage.\par}}
{{\small\texttt{{LOCAL ANALYSIS / Type /help to begin}}\par}}
\end{{minipage}}}}}}
\par
\vspace{{7pt}}
{{\Large\bfseries Scan report\par}}
\end{{center}}

\textbf{{Target:}} {_latex_text(result.target)}\\
\textbf{{Profile:}} {_latex_text(result.profile)} \quad
\textbf{{Input:}} {_latex_text(result.target_kind)}\\
\textbf{{Started:}} {_latex_text(result.started_at)} \quad
\textbf{{Completed:}} {_latex_text(result.completed_at)}

\section*{{Scan summary}}
\begin{{tabular}}{{ccc}}
{{\Large\color{{signal}}{result.files_scanned}}} & {{\Large\color{{signal}}{len(result.findings)}}} & {{\Large\color{{signal}}{result.files_skipped}}}\\
Files scanned & Finding candidates & Files skipped
\end{{tabular}}

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
    """Save a LaTeX report and compile it when a supported engine is available."""
    output_dir = ensure_safe_directory(output_dir)
    tex_path = output_dir / "fuse-report.tex"
    pdf_path = output_dir / "fuse-report.pdf"
    xelatex = shutil.which("xelatex")
    pdflatex = shutil.which("pdflatex")
    engine = xelatex or pdflatex
    source = _render_report(result, xelatex=xelatex is not None)
    safe_write_text(tex_path, source)
    if engine is None:
        return None, "xelatex and pdflatex were not found; the LaTeX source was saved."

    try:
        with tempfile.TemporaryDirectory(prefix="vigil-fuse-report-") as temporary:
            build_dir = Path(temporary)
            assert_no_path_aliases(build_dir)
            safe_write_text(build_dir / tex_path.name, source)
            arguments = [engine]
            if "miktex" in engine.casefold():
                arguments.append("-disable-installer")
            arguments.extend(
                [
                    "-no-shell-escape",
                    "-interaction=nonstopmode",
                    "-halt-on-error",
                    tex_path.name,
                ]
            )
            completed = subprocess.run(
                arguments,
                cwd=build_dir,
                capture_output=True,
                text=True,
                timeout=90,
                check=False,
            )
            compiled_pdf = build_dir / "fuse-report.pdf"
            if completed.returncode != 0 or not compiled_pdf.is_file():
                return (
                    None,
                    f"{Path(engine).name} could not build the PDF; the LaTeX source was saved.",
                )
            safe_write_bytes(pdf_path, compiled_pdf.read_bytes())
    except (OSError, subprocess.TimeoutExpired):
        return None, "PDF compilation failed; the LaTeX source was saved."
    note = (
        "XeLaTeX was unavailable; the report uses a Times-compatible font."
        if xelatex is None
        else None
    )
    return pdf_path, note
