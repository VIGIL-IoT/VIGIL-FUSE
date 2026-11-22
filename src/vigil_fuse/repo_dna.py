"""Bounded, passive repository classification based on observable file names."""

from __future__ import annotations

import os
import json
from pathlib import Path
from typing import TypedDict

from .scanner import SKIPPED_DIRECTORIES
from .platform_context import detect_project_frameworks

MAX_PATHS = 10_000
MAX_DIRECTORIES = 2_000
MAX_DEPTH = 5
MAX_COMPONENTS = 100
MARKERS: dict[str, tuple[str, ...]] = {
    "container": ("dockerfile", "compose.yaml", "docker-compose.yml"),
    "terraform/iac": ("main.tf", "terraform.tf"),
    "embedded": ("sdkconfig", "idf_component.yml", "prj.conf", "platformio.ini"),
    "ci/cd": (".github/workflows",),
    "notebooks/research": (".ipynb",),
    "web-frontend": ("next.config.js", "next.config.mjs", "next.config.ts"),
    "kubernetes": ("kustomization.yaml", "chart.yaml"),
    "data-science": ("environment.yml",),
    "data-pipeline": ("airflow.cfg", "dags.yaml"),
    "kernel/driver": ("kconfig", "kbuild"),
    "toolchain": ("toolchain.cmake",),
    "detection-rules": ("sigma.yml",),
}
ROOT_MARKERS = frozenset(
    {
        "pyproject.toml",
        "package.json",
        "cargo.toml",
        "platformio.ini",
        "go.mod",
        "kustomization.yaml",
    }
)
LANGUAGES = {
    ".py": "Python",
    ".c": "C",
    ".cpp": "C++",
    ".go": "Go",
    ".rs": "Rust",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".java": "Java",
}


class Classification(TypedDict):
    type: str
    confidence: None
    supporting_signals: list[str]


class RepoDNA(TypedDict):
    schema_version: str
    classifications: list[Classification]
    languages: list[str]
    frameworks: list[str]
    components: list[str]
    complete: bool
    limitations: list[str]


def inspect_repository(target: str | Path) -> RepoDNA:
    """Classify a directory without reading or executing its contents."""
    root = Path(target).expanduser()
    if root.is_symlink() or not root.is_dir():
        raise ValueError("target must be a non-symlink directory")
    root = root.resolve(strict=True)
    signals: dict[str, set[str]] = {}
    languages: set[str] = set()
    components: set[str] = set()
    limitations: list[str] = []
    frameworks: set[str] = set()
    count = 0
    directories = 0

    def onerror(_error: OSError) -> None:
        if "unreadable directory" not in limitations:
            limitations.append("unreadable directory")

    for directory, names, files in os.walk(root, topdown=True, followlinks=False, onerror=onerror):
        directories += 1
        if directories > MAX_DIRECTORIES:
            limitations.append("directory limit reached")
            break
        current = Path(directory)
        depth = len(current.relative_to(root).parts)
        children = sorted(
            n for n in names if n not in SKIPPED_DIRECTORIES and not (current / n).is_symlink()
        )
        if depth >= MAX_DEPTH and children:
            limitations.append("directory depth limit reached")
            children = []
        names[:] = children
        for filename in sorted(files):
            if count >= MAX_PATHS:
                limitations.append("path limit reached")
                break
            count += 1
            path = current / filename
            if path.is_symlink() or not path.is_file():
                continue
            relative = path.relative_to(root).as_posix()
            lower = filename.casefold()
            if path.suffix.casefold() in LANGUAGES:
                languages.add(LANGUAGES[path.suffix.casefold()])
            if lower in ROOT_MARKERS:
                components.add(current.relative_to(root).as_posix())
            if lower == "package.json":
                try:
                    if path.stat().st_size <= 262_144:
                        with path.open("rb") as stream:
                            raw = stream.read(262_145)
                        if len(raw) > 262_144:
                            limitations.append("package manifest exceeds size limit")
                            continue
                        manifest = json.loads(raw.decode("utf-8"))
                        if isinstance(manifest, dict):
                            deps: set[str] = set()
                            for key in ("dependencies", "devDependencies"):
                                value = manifest.get(key)
                                if isinstance(value, dict):
                                    deps.update(value)
                            for package, label in (
                                ("next", "Next.js"),
                                ("react", "React"),
                                ("express", "Express"),
                            ):
                                if package in deps:
                                    frameworks.add(label)
                                    category = (
                                        "web-backend" if package == "express" else "web-frontend"
                                    )
                                    signals.setdefault(category, set()).add(
                                        relative + ": " + package
                                    )
                    else:
                        limitations.append("package manifest exceeds size limit")
                except (OSError, UnicodeError, ValueError, RecursionError):
                    limitations.append("package manifest could not be parsed")
            for label, markers in MARKERS.items():
                if (
                    lower in markers
                    or path.suffix.casefold() in markers
                    or relative.casefold().startswith(".github/workflows/")
                    and label == "ci/cd"
                ):
                    signals.setdefault(label, set()).add(relative)
        if count >= MAX_PATHS:
            break
    if len(components) > MAX_COMPONENTS:
        limitations.append("component limit reached")
    for component in sorted(components | {"."})[:MAX_COMPONENTS]:
        try:
            for framework, evidence in detect_project_frameworks(root / component):
                frameworks.add(framework)
                signals.setdefault("embedded", set()).update(
                    f"{component}: {item}" for item in evidence
                )
        except OSError:
            limitations.append("framework context could not be inspected")
    classifications: list[Classification] = [
        {
            "type": label,
            "confidence": None,
            "supporting_signals": sorted(paths)[:10],
        }
        for label, paths in sorted(signals.items())
    ]
    return {
        "schema_version": "0.1",
        "classifications": classifications,
        "languages": sorted(languages),
        "frameworks": sorted(frameworks),
        "components": sorted(components)[:MAX_COMPONENTS],
        "complete": not limitations,
        "limitations": sorted(set([*limitations, "confidence is not calibrated"])),
    }
