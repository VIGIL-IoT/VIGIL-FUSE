"""Generate a byte-weighted language inventory for a Git commit."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import xml.sax.saxutils
from collections import defaultdict
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
from typing import Any

LINGUIST_IMAGE = (
    "ghcr.io/github-linguist/linguist@"
    "sha256:cfe77ac6fe1d7d46c2e705922f53ddb8260f2bbe37ccceb8d9ef13ddce151fb6"
)
FORBIDDEN_BUCKETS = {"other", "misc", "miscellaneous", "remaining", "everything else"}
LANGUAGE_ALIASES = {"Open Policy Agent": "Rego"}
HDL_LANGUAGES = {"Verilog", "SystemVerilog"}
SCHEMA_VERSION = "1.0"


def _docker_path(path: Path) -> str:
    return path.resolve().as_posix()


def read_linguist_inventory(repo: Path, ref: str, image: str) -> dict[str, Any]:
    if not re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", image):
        raise ValueError("Linguist image must be pinned by sha256 digest")
    helper = Path(__file__).with_name("language_composition_linguist.rb").resolve()
    docker_user = []
    if hasattr(os, "getuid") and hasattr(os, "getgid"):
        docker_user = [
            "--user",
            f"{getattr(os, 'getuid')()}:{getattr(os, 'getgid')()}",
        ]
    command = [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        *docker_user,
        "--volume",
        f"{_docker_path(repo)}:/repo:ro",
        "--volume",
        f"{_docker_path(helper)}:/language_composition_linguist.rb:ro",
        "--workdir",
        "/repo",
        "--entrypoint",
        "ruby",
        image,
        "/language_composition_linguist.rb",
        "--repo",
        "/repo",
        "--ref",
        ref,
    ]
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    inventory = json.loads(result.stdout)
    if not isinstance(inventory, dict) or not isinstance(inventory.get("files"), list):
        raise ValueError("Linguist returned an invalid file inventory")
    return inventory


def _percentage(byte_count: int, total_bytes: int) -> Decimal:
    return Decimal(byte_count) * Decimal(100) / Decimal(total_bytes)


def format_percentage(byte_count: int, total_bytes: int) -> str:
    if byte_count == 0 or total_bytes == 0:
        return "0.00%"
    percentage = _percentage(byte_count, total_bytes)
    places = 2 if percentage >= 1 else 3
    quantum = Decimal(1).scaleb(-places)
    while percentage.quantize(quantum, rounding=ROUND_HALF_UP) == 0:
        places += 1
        quantum = Decimal(1).scaleb(-places)
    return f"{percentage.quantize(quantum, rounding=ROUND_HALF_UP):.{places}f}%"


def aggregate_inventory(raw: dict[str, Any]) -> dict[str, Any]:
    language_totals: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"bytes": 0, "files": 0, "color": None}
    )
    unclassified: list[dict[str, Any]] = []
    assets: list[dict[str, Any]] = []
    file_inventory: list[dict[str, Any]] = []

    for item in raw["files"]:
        path = item["path"]
        byte_count = item["bytes"]
        language = item.get("language")
        is_text = item.get("text") is True
        if not isinstance(path, str) or not isinstance(byte_count, int) or byte_count < 0:
            raise ValueError("Linguist returned an invalid path or byte count")

        category = (
            "language"
            if is_text and isinstance(language, str)
            else ("unclassified" if is_text else "non_language_asset")
        )
        if category == "language":
            language = LANGUAGE_ALIASES.get(language, language)
            suffix = Path(path).suffix.casefold()
            if language in HDL_LANGUAGES and suffix in {".v", ".vh"}:
                language = "Verilog"
            elif language in HDL_LANGUAGES and suffix in {".sv", ".svh"}:
                language = "SystemVerilog"
            if language.strip().casefold() in FORBIDDEN_BUCKETS:
                raise ValueError(f"Linguist returned a forbidden bucket name: {language}")
            total = language_totals[language]
            total["bytes"] += byte_count
            total["files"] += 1
            total["color"] = total["color"] or item.get("color")
        elif category == "unclassified":
            unclassified.append({"path": path, "bytes": byte_count})
        else:
            assets.append(
                {
                    "path": path,
                    "bytes": byte_count,
                    "mime_type": item.get("mime_type"),
                }
            )

        file_inventory.append(
            {
                "path": path,
                "bytes": byte_count,
                "language": language if category == "language" else None,
                "classification": category,
                "generated": item.get("generated", False),
                "vendored": item.get("vendored", False),
                "mime_type": item.get("mime_type"),
            }
        )

    total_bytes = sum(language["bytes"] for language in language_totals.values())
    languages = [
        {
            "name": name,
            "bytes": info["bytes"],
            "files": info["files"],
            "percentage": float(_percentage(info["bytes"], total_bytes)) if total_bytes else 0.0,
            "color": info["color"] or fallback_color(name),
        }
        for name, info in language_totals.items()
    ]
    languages.sort(key=lambda language: (-language["bytes"], language["name"].casefold()))

    return {
        "schema_version": SCHEMA_VERSION,
        "commit": raw["commit"],
        "generated_at": raw["generated_at"],
        "total_classified_bytes": total_bytes,
        "total_classified_files": sum(language["files"] for language in languages),
        "language_count": len(languages),
        "languages": [
            {key: language[key] for key in ("name", "bytes", "files", "percentage")}
            | {"color": language["color"]}
            for language in languages
        ],
        "unclassified_files": sorted(unclassified, key=lambda file: file["path"]),
        "non_language_assets": sorted(assets, key=lambda file: file["path"]),
        "file_inventory": sorted(file_inventory, key=lambda file: file["path"]),
    }


def fallback_color(language: str) -> str:
    hue = int(hashlib.sha256(language.encode("utf-8")).hexdigest()[:6], 16) % 360
    return f"hsl({hue}, 72%, 64%)"


def render_svg(data: dict[str, Any]) -> str:
    languages = data["languages"]
    width = max(560, 120 + len(languages) * 15)
    padding = 20
    plot_left = 44
    plot_right = width - 18
    plot_top = 104
    plot_bottom = 224
    plot_height = plot_bottom - plot_top
    total_bytes = data["total_classified_bytes"]
    labels = [
        (language, format_percentage(language["bytes"], total_bytes)) for language in languages
    ]
    label_y = plot_bottom + 10
    longest_label = max((len(f"{item['name']} · {percent}") for item, percent in labels), default=0)
    footer_y = label_y + longest_label * 7 + 14
    height = footer_y + 42
    x_step = (plot_right - plot_left) / max(1, len(languages) - 1)
    points = []
    for index, language in enumerate(languages):
        x = (plot_left + index * x_step) if len(languages) > 1 else (plot_left + plot_right) / 2
        share = (
            Decimal(language["bytes"]) * Decimal(100) / Decimal(total_bytes)
            if total_bytes
            else Decimal(0)
        )
        y = plot_bottom - float(share) * plot_height / 100
        points.append((x, y))
    polyline_points = " ".join(f"{x:.3f},{y:.3f}" for x, y in points)
    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" role="img" '
        f'aria-labelledby="title description" viewBox="0 0 {width} {height}" '
        f'width="{width}" height="{height}">',
        '<title id="title">FUSE language composition</title>',
        '<desc id="description">A compact line graph of every detected textual language, sorted by byte share. Rotated point labels show each language name and exact percentage.</desc>',
        '<rect width="100%" height="100%" rx="16" fill="#0d1421"/>',
        f'<text x="{padding}" y="34" fill="#f4f7fb" font-size="20" '
        'font-weight="700" font-family="Segoe UI, Arial, sans-serif">FUSE · Language Composition</text>',
        f'<text x="{padding}" y="55" fill="#9aabc0" font-size="12" '
        'font-family="Segoe UI, Arial, sans-serif">Sorted by byte share · each point label gives its exact percentage</text>',
    ]
    summary = (
        f"{data['language_count']} languages  ·  {data['total_classified_files']:,} files  ·  "
        f"{data['total_classified_bytes']:,} bytes"
    )
    lines.append(
        f'<text x="{padding}" y="78" fill="#cbd5e1" font-size="12" '
        f'font-family="Segoe UI, Arial, sans-serif">{xml.sax.saxutils.escape(summary)}</text>'
    )
    for tick in range(0, 101, 25):
        y = plot_bottom - tick * plot_height / 100
        lines.extend(
            [
                f'<line x1="{plot_left}" y1="{y:.3f}" x2="{plot_right}" y2="{y:.3f}" '
                'stroke="#26364a" stroke-width="1"/>',
                f'<text x="{plot_left - 8}" y="{y + 3:.3f}" text-anchor="end" '
                'fill="#91a2b7" font-size="10" font-family="Segoe UI, Arial, sans-serif">'
                f"{tick}%</text>",
            ]
        )
    if points:
        lines.append(
            f'<polyline points="{polyline_points}" fill="none" stroke="#7aa2d6" '
            'stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>'
        )
    for (language, percent), (x, y) in zip(labels, points, strict=True):
        color = xml.sax.saxutils.escape(language["color"])
        label = xml.sax.saxutils.escape(f"{language['name']} · {percent}")
        lines.extend(
            [
                f'<circle cx="{x:.3f}" cy="{y:.3f}" r="3.5" fill="{color}" '
                'stroke="#0d1421" stroke-width="1.2"/>',
                f'<text x="{x:.3f}" y="{label_y}" transform="rotate(90 {x:.3f} {label_y})" '
                'text-anchor="start" fill="#d5dfeb" font-size="11" '
                f'font-family="Segoe UI, Arial, sans-serif">{label}</text>',
            ]
        )
    source = f"main @ {data['commit'][:7]}  ·  generated {data['generated_at']}"
    footer = (
        f"Unclassified text: {len(data['unclassified_files'])}  ·  "
        f"Non-language assets: {len(data['non_language_assets'])}"
    )
    lines.extend(
        [
            f'<text x="{padding}" y="{footer_y}" fill="#9aabc0" font-size="11" '
            f'font-family="Segoe UI, Arial, sans-serif">{xml.sax.saxutils.escape(footer)}</text>',
            f'<text x="{padding}" y="{footer_y + 18}" fill="#718198" font-size="10" '
            f'font-family="Segoe UI, Arial, sans-serif">{xml.sax.saxutils.escape(source)}</text>',
            "</svg>",
        ]
    )
    return "\n".join(lines) + "\n"


def write_outputs(data: dict[str, Any], output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "language-composition.json"
    svg_path = output_dir / "language-composition.svg"
    json_path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    svg_path.write_text(render_svg(data), encoding="utf-8")
    return svg_path, json_path


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=root, help="Git repository to inspect")
    parser.add_argument("--ref", default="HEAD", help="Git commit or ref to inspect")
    parser.add_argument("--output-dir", type=Path, default=root / "assets" / "generated")
    parser.add_argument(
        "--image",
        default=os.environ.get("FUSE_LINGUIST_IMAGE", LINGUIST_IMAGE),
        help=argparse.SUPPRESS,
    )
    args = parser.parse_args()
    try:
        raw = read_linguist_inventory(args.repo.resolve(), args.ref, args.image)
        data = aggregate_inventory(raw)
        svg_path, json_path = write_outputs(data, args.output_dir)
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or "").strip()
        print(
            f"language composition generation failed: {detail or error}",
            file=sys.stderr,
        )
        return 1
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"language composition generation failed: {error}", file=sys.stderr)
        return 1
    print(f"Generated {svg_path} and {json_path} from {data['commit']}")
    print(f"Languages: {', '.join(language['name'] for language in data['languages'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
