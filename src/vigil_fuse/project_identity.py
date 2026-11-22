"""Bounded, deterministic project identity signals for scan context."""

from __future__ import annotations

import json
import os
import stat
import time
import tomllib
from collections import Counter
from dataclasses import dataclass, field
from math import exp, isfinite
from pathlib import Path
from typing import Literal

ProjectType = Literal["software", "firmware", "embedded", "hardware", "rtl", "hybrid", "unknown"]
ProjectConfidence = Literal["high", "medium", "low", "unknown"]
PROJECT_DOMAINS = ("software", "firmware", "embedded", "hardware", "rtl")

MAX_IDENTITY_PATHS = 20_000
MAX_IDENTITY_DIRECTORIES = 4_000
MAX_IDENTITY_DEPTH = 12
MAX_IDENTITY_SECONDS = 2.0
MAX_MANIFEST_FILES = 16
MAX_MANIFEST_BYTES = 256 * 1024
MAX_TOTAL_MANIFEST_BYTES = 1024 * 1024

_SKIPPED_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "build",
    "dist",
    "__pycache__",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".fuse-results",
    "fuse-results",
}
_SOURCE_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".cs",
    ".go",
    ".h",
    ".hpp",
    ".java",
    ".js",
    ".jsx",
    ".kt",
    ".m",
    ".mm",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".swift",
    ".ts",
    ".tsx",
}
_MANIFEST_NAMES = {"package.json", "pyproject.toml"}
_ROOT_SOFTWARE_MANIFESTS = {
    "cargo.toml",
    "composer.json",
    "go.mod",
    "gemfile",
    "package.json",
    "pom.xml",
    "pyproject.toml",
    "requirements.txt",
}
_FIRMWARE_SUFFIXES = {".bin", ".efi", ".elf", ".fw", ".hex", ".img", ".rom"}
_RTL_SUFFIXES = {".v", ".vh", ".sv", ".svh"}


@dataclass(frozen=True)
class ProjectIdentity:
    """Explainable project classification; evidence scores are not probabilities."""

    primary_type: ProjectType = "unknown"
    subtype: str | None = None
    confidence: ProjectConfidence = "unknown"
    evidence_score: float = 0.0
    domains: dict[str, float] = field(
        default_factory=lambda: {domain: 0.0 for domain in PROJECT_DOMAINS}
    )
    supporting_signals: tuple[str, ...] = ()
    complete: bool = True
    limitations: tuple[str, ...] = ()
    recommended_stages: tuple[str, ...] = ()
    optional_stages: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "1.0",
            "primary_type": self.primary_type,
            "subtype": self.subtype,
            "confidence": self.confidence,
            "evidence_score": round(self.evidence_score, 3),
            "domains": {key: round(value, 3) for key, value in self.domains.items()},
            "supporting_signals": list(self.supporting_signals),
            "complete": self.complete,
            "limitations": list(self.limitations),
            "analysis_recommendations": {
                "recommended": list(self.recommended_stages),
                "optional": list(self.optional_stages),
                "advisory_only": True,
            },
        }


def _unknown(
    *,
    complete: bool,
    limitations: list[str],
    signals: tuple[str, ...] = (),
    domains: dict[str, float] | None = None,
    evidence_score: float = 0.0,
) -> ProjectIdentity:
    if not limitations and complete:
        limitations = ["No sufficiently independent project markers were observed."]
    return ProjectIdentity(
        domains=domains or {domain: 0.0 for domain in PROJECT_DOMAINS},
        evidence_score=evidence_score,
        supporting_signals=signals,
        complete=complete,
        limitations=tuple(sorted(set(limitations))),
    )


def _read_manifest(path: Path) -> bytes:
    if path.is_symlink():
        raise ValueError("symbolic-link manifest was not read")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("manifest is not a regular file")
        if info.st_size > MAX_MANIFEST_BYTES:
            raise ValueError("manifest exceeds the identity inspection limit")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            data = stream.read(MAX_MANIFEST_BYTES + 1)
        if len(data) > MAX_MANIFEST_BYTES:
            raise ValueError("manifest exceeds the identity inspection limit")
        return data
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _manifest_frameworks(root: Path, paths: list[str]) -> tuple[set[str], list[str]]:
    frameworks: set[str] = set()
    limitations: list[str] = []
    candidates = [
        relative for relative in paths if Path(relative).name.casefold() in _MANIFEST_NAMES
    ]
    if len(candidates) > MAX_MANIFEST_FILES:
        limitations.append("Project manifest count limit reached.")
        candidates = candidates[:MAX_MANIFEST_FILES]
    total_bytes = 0
    for relative in candidates:
        try:
            raw = _read_manifest(root / Path(relative))
            total_bytes += len(raw)
            if total_bytes > MAX_TOTAL_MANIFEST_BYTES:
                limitations.append("Total project manifest byte limit reached.")
                break
            text = raw.decode("utf-8")
            if Path(relative).name.casefold() == "package.json":
                document = json.loads(text)
                if not isinstance(document, dict):
                    raise ValueError("package manifest must be an object")
                dependencies: set[str] = set()
                for key in ("dependencies", "devDependencies", "peerDependencies"):
                    value = document.get(key)
                    if value is not None and not isinstance(value, dict):
                        raise ValueError("package dependency section must be an object")
                    if isinstance(value, dict):
                        dependencies.update(str(item).casefold() for item in value)
            else:
                document = tomllib.loads(text)
                if not isinstance(document, dict):
                    raise ValueError("Python project manifest must be a table")
                project = document.get("project", {})
                if not isinstance(project, dict):
                    raise ValueError("Python project section must be a table")
                raw_dependencies = project.get("dependencies", [])
                if not isinstance(raw_dependencies, list):
                    raise ValueError("Python dependencies must be an array")
                dependencies = {
                    str(item).split("[", 1)[0].split(">", 1)[0].casefold()
                    for item in raw_dependencies
                }
            for package, label in (
                ("next", "web-frontend"),
                ("react", "web-frontend"),
                ("vue", "web-frontend"),
                ("svelte", "web-frontend"),
                ("express", "web-backend"),
                ("fastapi", "web-backend"),
                ("django", "web-backend"),
                ("flask", "web-backend"),
            ):
                if package in dependencies:
                    frameworks.add(label)
        except (
            OSError,
            UnicodeError,
            ValueError,
            json.JSONDecodeError,
            RecursionError,
            tomllib.TOMLDecodeError,
        ):
            limitations.append("A selected project manifest could not be fully inspected.")
    return frameworks, limitations


def inspect_project_identity(
    target: str | Path,
    *,
    max_paths: int = MAX_IDENTITY_PATHS,
    max_directories: int = MAX_IDENTITY_DIRECTORIES,
    max_depth: int = MAX_IDENTITY_DEPTH,
    budget_seconds: float = MAX_IDENTITY_SECONDS,
) -> ProjectIdentity:
    """Classify from bounded names, directory structure, and small root manifests.

    It never runs project code, build tools, package managers, or network requests.
    Symbolic links are excluded and make the result incomplete.
    """
    if not isinstance(max_paths, int) or isinstance(max_paths, bool) or max_paths < 1:
        raise ValueError("max_paths must be a positive integer")
    if (
        not isinstance(max_directories, int)
        or isinstance(max_directories, bool)
        or max_directories < 1
    ):
        raise ValueError("max_directories must be a positive integer")
    if not isinstance(max_depth, int) or isinstance(max_depth, bool) or max_depth < 0:
        raise ValueError("max_depth must be a non-negative integer")
    if (
        isinstance(budget_seconds, bool)
        or not isinstance(budget_seconds, (int, float))
        or not isfinite(budget_seconds)
        or budget_seconds <= 0
    ):
        raise ValueError("budget_seconds must be a finite positive number")

    root = Path(target).expanduser()
    if root.is_symlink():
        raise ValueError("Symbolic-link targets are not followed")
    if not root.exists() or (not root.is_dir() and not root.is_file()):
        raise ValueError("target must be an existing regular file or directory")
    root = root.resolve(strict=True)

    limitations: list[str] = []
    paths: list[str] = []
    directories: set[str] = set()
    complete = True
    single_file_target = root.is_file()
    if single_file_target:
        paths = [root.name]
    else:
        deadline = time.monotonic() + min(budget_seconds, MAX_IDENTITY_SECONDS)
        paths_seen = 0
        directories_seen = 0

        def onerror(_error: OSError) -> None:
            limitations.append("A directory could not be inspected.")

        for directory, names, filenames in os.walk(
            root, topdown=True, followlinks=False, onerror=onerror
        ):
            if time.monotonic() >= deadline:
                limitations.append("Project identity time limit reached.")
                complete = False
                break
            current = Path(directory)
            directories_seen += 1
            if directories_seen > min(max_directories, MAX_IDENTITY_DIRECTORIES):
                limitations.append("Project identity directory limit reached.")
                complete = False
                break
            relative_dir = current.relative_to(root).as_posix()
            depth = 0 if relative_dir == "." else len(Path(relative_dir).parts)
            if relative_dir != ".":
                directories.add(relative_dir.casefold())
            if depth >= min(max_depth, MAX_IDENTITY_DEPTH) and names:
                limitations.append("Project identity depth limit reached.")
                complete = False
                names[:] = []
            kept_names: list[str] = []
            for name in names:
                candidate = current / name
                if name.casefold() in _SKIPPED_DIRECTORIES:
                    continue
                if candidate.is_symlink():
                    limitations.append("Symbolic links were excluded from project identity.")
                    complete = False
                    continue
                kept_names.append(name)
            names[:] = sorted(kept_names, key=str.casefold)
            for filename in sorted(filenames, key=str.casefold):
                if paths_seen >= min(max_paths, MAX_IDENTITY_PATHS):
                    limitations.append("Project identity path limit reached.")
                    complete = False
                    break
                if time.monotonic() >= deadline:
                    limitations.append("Project identity time limit reached.")
                    complete = False
                    break
                paths_seen += 1
                path = current / filename
                try:
                    if path.is_symlink() or not path.is_file():
                        if path.is_symlink():
                            limitations.append(
                                "Symbolic links were excluded from project identity."
                            )
                            complete = False
                        continue
                except OSError:
                    limitations.append("A file entry could not be inspected.")
                    complete = False
                    continue
                paths.append(path.relative_to(root).as_posix())
            if not complete:
                break

    manifest_frameworks, manifest_limitations = (
        (set(), []) if single_file_target else _manifest_frameworks(root, paths)
    )
    if manifest_limitations:
        limitations.extend(manifest_limitations)
        complete = False
    if limitations:
        complete = False

    files = [path.casefold() for path in paths]
    names = [Path(path).name.casefold() for path in files]
    name_set = set(names)
    directory_names = {Path(path).name.casefold() for path in directories}
    extensions = Counter(Path(path).suffix.casefold() for path in files)
    root_names = {Path(path).name.casefold() for path in paths if "/" not in path}
    weights: dict[str, dict[str, float]] = {domain: {} for domain in PROJECT_DOMAINS}
    messages: dict[str, set[str]] = {domain: set() for domain in PROJECT_DOMAINS}

    def add(domain: str, group: str, weight: float, message: str) -> None:
        weights[domain][group] = max(weights[domain].get(group, 0.0), weight)
        messages[domain].add(message)

    software_manifests = sorted(root_names & _ROOT_SOFTWARE_MANIFESTS)
    if software_manifests:
        add(
            "software",
            "root-manifest",
            0.7,
            "Root software manifest: " + ", ".join(software_manifests[:4]),
        )
    source_count = sum(extensions[suffix] for suffix in _SOURCE_SUFFIXES)
    if source_count:
        weight = 0.55 if source_count >= 10 else 0.4 if source_count >= 3 else 0.22
        add("software", "source-code", weight, f"Source files: {source_count}")
    if "cmakelists.txt" in name_set or "makefile" in name_set:
        add("software", "build-manifest", 0.22, "Native build manifest present")

    idf_markers = name_set & {"sdkconfig", "sdkconfig.defaults", "idf_component.yml"}
    for marker in sorted(idf_markers):
        add("embedded", "esp-idf-" + marker, 0.48, "ESP-IDF marker: " + marker)
        add("firmware", "esp-idf", 0.55, "ESP-IDF firmware configuration present")
    if idf_markers and ("cmakelists.txt" in name_set or directory_names & {"main", "components"}):
        add("embedded", "esp-idf-layout", 0.38, "ESP-IDF component build structure present")
    if "platformio.ini" in name_set:
        add("embedded", "platformio", 0.58, "PlatformIO configuration present")
        add("firmware", "platformio", 0.35, "PlatformIO embedded project marker present")
        add("software", "platformio", 0.2, "PlatformIO project manifest present")
        if source_count or directory_names & {"src", "lib"}:
            add("embedded", "platformio-code", 0.42, "PlatformIO source structure present")
    zephyr_markers = name_set & {"prj.conf", "west.yml", "module.yml"}
    for marker in sorted(zephyr_markers):
        add("embedded", "zephyr-" + marker, 0.45, "Zephyr marker: " + marker)
        add("firmware", "zephyr", 0.55, "Zephyr firmware configuration present")
    if zephyr_markers and ("boards" in directory_names or source_count):
        add("embedded", "zephyr-source-layout", 0.32, "Zephyr board or source structure present")
    if "boards" in directory_names and source_count:
        add("embedded", "board-layout", 0.32, "Board source directory and code present")

    inf_count = extensions[".inf"]
    if inf_count:
        add(
            "firmware",
            "edk2-inf",
            0.65 if inf_count >= 2 else 0.28,
            f"EDK2 INF descriptors: {inf_count}",
        )
    if extensions[".dsc"]:
        add("firmware", "edk2-dsc", 0.62, f"EDK2 DSC descriptors: {extensions['.dsc']}")
    if extensions[".fdf"]:
        add("firmware", "edk2-fdf", 0.55, f"EDK2 FDF descriptors: {extensions['.fdf']}")
    edk2_dirs = directory_names & {"silicon", "platform", "mdepkg", "edk2"}
    if edk2_dirs or "edksetup.bat" in name_set:
        markers = sorted(edk2_dirs | ({"edksetup.bat"} if "edksetup.bat" in name_set else set()))
        add("firmware", "edk2-structure", 0.48, "EDK2 structure: " + ", ".join(markers))
    if "linker.ld" in name_set or any(path.endswith(".ld") for path in files):
        if source_count:
            add("firmware", "linker-script", 0.42, "Linker script and source files present")
    firmware_count = sum(extensions[suffix] for suffix in _FIRMWARE_SUFFIXES)
    if firmware_count:
        add(
            "firmware",
            "firmware-artifact",
            0.32 if firmware_count >= 2 else 0.16,
            f"Firmware image candidates: {firmware_count}",
        )
    if directory_names & {"bootloader", "u-boot", "uboot"}:
        add("firmware", "bootloader-layout", 0.52, "Bootloader directory structure present")

    kicad_pcb = extensions[".kicad_pcb"]
    kicad_sch = extensions[".kicad_sch"]
    if kicad_pcb:
        add("hardware", "kicad-pcb", 0.78, f"KiCad PCB layouts: {kicad_pcb}")
    if kicad_sch:
        add("hardware", "kicad-schematic", 0.78, f"KiCad schematics: {kicad_sch}")
    if extensions[".kicad_pro"]:
        add("hardware", "kicad-project", 0.3, "KiCad project file present")
    legacy_cad = extensions[".brd"] + extensions[".sch"]
    if legacy_cad >= 2:
        add("hardware", "legacy-cad", 0.52, f"Legacy board and schematic files: {legacy_cad}")
    if extensions[".step"] + extensions[".stp"] + extensions[".gbr"] >= 2:
        add("hardware", "manufacturing-files", 0.38, "Multiple CAD or manufacturing files present")

    rtl_count = sum(extensions[suffix] for suffix in _RTL_SUFFIXES)
    rtl_types = sum(1 for suffix in _RTL_SUFFIXES if extensions[suffix])
    if rtl_count:
        add("rtl", "hdl-files", 0.7 if rtl_count >= 2 else 0.24, f"RTL source files: {rtl_count}")
    if rtl_types >= 2:
        add("rtl", "hdl-families", 0.38, f"RTL file types: {rtl_types}")
    constraints = sum(extensions[suffix] for suffix in (".xdc", ".sdc", ".qsf", ".xpr"))
    if constraints:
        add("rtl", "fpga-constraints", 0.58, f"FPGA constraint or project files: {constraints}")
    if directory_names & {"rtl", "hdl", "fpga"}:
        add("rtl", "rtl-directory", 0.3, "RTL or FPGA source directory present")

    frontend_markers = {
        name
        for name in name_set
        if name.startswith(("next.config.", "vite.config.", "nuxt.config."))
        or name in {"angular.json", "vue.config.js", "index.html"}
    }
    if "web-frontend" in manifest_frameworks or frontend_markers:
        add(
            "software",
            "web-frontend",
            0.65,
            "Web frontend markers: "
            + ", ".join(
                sorted(frontend_markers)[:4] or sorted(manifest_frameworks & {"web-frontend"})
            ),
        )
    backend_markers = name_set & {"manage.py", "wsgi.py", "asgi.py", "server.js"}
    if "web-backend" in manifest_frameworks or backend_markers:
        add(
            "software",
            "web-backend",
            0.65,
            "Web backend markers: "
            + ", ".join(
                sorted(backend_markers)[:4] or sorted(manifest_frameworks & {"web-backend"})
            ),
        )
    if backend_markers or "web-backend" in manifest_frameworks:
        subtype = "web-backend"
    elif frontend_markers or "web-frontend" in manifest_frameworks:
        subtype = "web-frontend"
    else:
        subtype = None

    has_kubernetes = bool(name_set & {"chart.yaml", "kustomization.yaml"}) or (
        bool(directory_names & {"k8s", "kubernetes", "charts"})
        and bool(name_set & {"deployment.yaml", "service.yaml", "statefulset.yaml"})
    )
    if has_kubernetes:
        add("software", "kubernetes", 0.58, "Kubernetes manifest structure present")
    tf_count = extensions[".tf"]
    if tf_count >= 2 or "terragrunt.hcl" in name_set or "pulumi.yaml" in name_set:
        add("software", "iac", 0.58, f"Infrastructure-as-code files: {max(tf_count, 1)}")
    notebook_count = extensions[".ipynb"]
    if notebook_count and ("notebooks" in directory_names or "environment.yml" in name_set):
        add(
            "software", "data-science", 0.58, f"Notebook and data-science markers: {notebook_count}"
        )
    if "paper.tex" in name_set and ("references.bib" in name_set or "citation.cff" in name_set):
        add("software", "research", 0.58, "Research paper and citation metadata present")
    kernel_markers = name_set & {"kconfig", "kbuild"}
    if kernel_markers and ("drivers" in directory_names or source_count):
        add("software", "kernel-driver", 0.58, "Kernel or driver build markers present")

    raw_scores = {domain: sum(weights[domain].values()) for domain in PROJECT_DOMAINS}
    scores = {domain: 1.0 - exp(-value) for domain, value in raw_scores.items()}
    ordered_core = sorted(
        ((domain, scores[domain]) for domain in ("software", "firmware", "hardware", "rtl")),
        key=lambda item: item[1],
        reverse=True,
    )
    strong = [domain for domain, score in ordered_core if score >= 0.57]
    supporting = tuple(sorted({message for values in messages.values() for message in values})[:32])
    if not complete:
        return _unknown(
            complete=False,
            limitations=limitations,
            signals=supporting,
            domains=scores,
            evidence_score=max(scores.values()),
        )

    primary: ProjectType = "unknown"
    chosen_subtype: str | None = None
    if len(strong) >= 2:
        primary = "hybrid"
        chosen_subtype = "-".join(strong[:3])
        evidence_score = min(scores[strong[0]], scores[strong[1]])
    elif extensions[".dsc"] and extensions[".inf"] and extensions[".fdf"]:
        primary = "firmware"
        chosen_subtype = "uefi-platform-firmware"
        evidence_score = scores["firmware"]
    elif any(group.startswith("esp-idf-") for group in weights["embedded"]):
        if len(weights["embedded"]) < 2:
            return _unknown(complete=True, limitations=[], signals=supporting, domains=scores)
        primary = "embedded"
        chosen_subtype = "esp-idf"
        evidence_score = scores["embedded"]
    elif any(group.startswith("zephyr-") for group in weights["embedded"]):
        if len(weights["embedded"]) < 2:
            return _unknown(complete=True, limitations=[], signals=supporting, domains=scores)
        primary = "embedded"
        chosen_subtype = "zephyr"
        evidence_score = scores["embedded"]
    elif "platformio" in weights["embedded"]:
        if len(weights["embedded"]) < 2:
            return _unknown(complete=True, limitations=[], signals=supporting, domains=scores)
        primary = "embedded"
        chosen_subtype = "platformio"
        evidence_score = scores["embedded"]
    elif scores["hardware"] >= 0.57:
        primary = "hardware"
        chosen_subtype = (
            "kicad-hardware" if kicad_pcb or kicad_sch or extensions[".kicad_pro"] else None
        )
        evidence_score = scores["hardware"]
    elif scores["rtl"] >= 0.57:
        primary = "rtl"
        chosen_subtype = "fpga" if constraints or "fpga" in directory_names else "rtl-design"
        evidence_score = scores["rtl"]
    elif scores["software"] >= 0.52 and len(weights["software"]) >= 2:
        primary = "software"
        chosen_subtype = (
            "kubernetes"
            if has_kubernetes
            else "iac"
            if tf_count >= 2 or "terragrunt.hcl" in name_set or "pulumi.yaml" in name_set
            else "data-science"
            if notebook_count
            else "research"
            if "paper.tex" in name_set
            else "kernel-driver"
            if kernel_markers
            else subtype
        )
        evidence_score = scores["software"]
    elif scores["firmware"] >= 0.52 and len(weights["firmware"]) >= 2:
        primary = "firmware"
        chosen_subtype = (
            "bootloader" if directory_names & {"bootloader", "u-boot", "uboot"} else None
        )
        evidence_score = scores["firmware"]
    else:
        return _unknown(
            complete=True,
            limitations=[],
            signals=supporting,
            domains=scores,
            evidence_score=max(scores.values()),
        )

    confidence: ProjectConfidence = (
        "high"
        if evidence_score >= 0.78 and len(strong or weights[primary]) >= 3
        else "medium"
        if evidence_score >= 0.63 and len(weights.get(primary, {})) >= 2
        else "low"
        if evidence_score >= 0.52
        else "unknown"
    )
    if primary == "hybrid":
        confidence = (
            "high" if evidence_score >= 0.78 else "medium" if evidence_score >= 0.63 else "low"
        )

    recommended: set[str] = set()
    optional: set[str] = set()
    recommended.add("native source checks")
    if scores["embedded"] >= 0.57:
        recommended.add("embedded build-context inspection")
    if scores["hardware"] >= 0.57:
        recommended.add("hardware artifact inventory")
        optional.update({"KiCad netlist analysis", "hardware BOM import"})
    if scores["rtl"] >= 0.57:
        recommended.add("bounded RTL structure analysis")
    if scores["firmware"] >= 0.57:
        recommended.add("firmware candidate inventory")
        optional.update({"Binwalk signature identification", "Ghidra metadata analysis"})

    return ProjectIdentity(
        primary_type=primary,
        subtype=chosen_subtype,
        confidence=confidence,
        evidence_score=evidence_score,
        domains=scores,
        supporting_signals=supporting,
        complete=True,
        limitations=(),
        recommended_stages=tuple(sorted(recommended)),
        optional_stages=tuple(sorted(optional)),
    )
