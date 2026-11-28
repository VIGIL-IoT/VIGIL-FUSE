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
    command = [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
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
    width = 520
    padding = 20
    row_height = 34
    header_height = 108
    footer_height = 58
    height = header_height + len(data["languages"]) * row_height + footer_height
    track_width = width - (padding * 2)
    total_bytes = data["total_classified_bytes"]
    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" role="img" '
        f'aria-labelledby="title description" viewBox="0 0 {width} {height}" '
        f'width="{width}" height="{height}">',
        '<title id="title">FUSE language composition</title>',
        '<desc id="description">Every Linguist-detected textual language in the tracked source commit, weighted by bytes.</desc>',
        '<rect width="100%" height="100%" rx="16" fill="#0d1421"/>',
        f'<text x="{padding}" y="34" fill="#f4f7fb" font-size="20" '
        'font-weight="700" font-family="Segoe UI, Arial, sans-serif">FUSE · Language Composition</text>',
        f'<text x="{padding}" y="56" fill="#9aabc0" font-size="12" '
        'font-family="Segoe UI, Arial, sans-serif">Tracked textual files · byte-weighted · all detected languages</text>',
    ]
    summary = (
        f"{data['language_count']} languages  ·  {data['total_classified_files']:,} files  ·  "
        f"{data['total_classified_bytes']:,} bytes"
    )
    lines.append(
        f'<text x="{padding}" y="82" fill="#cbd5e1" font-size="12" '
        f'font-family="Segoe UI, Arial, sans-serif">{xml.sax.saxutils.escape(summary)}</text>'
    )
    for index, language in enumerate(data["languages"]):
        y = header_height + index * row_height
        name = xml.sax.saxutils.escape(language["name"])
        percent = format_percentage(language["bytes"], total_bytes)
        details = f"{percent}  ·  {language['files']} files"
        color = language["color"]
        bar_width = (
            Decimal(track_width) * Decimal(language["bytes"]) / Decimal(total_bytes)
            if total_bytes
            else Decimal(0)
        )
        lines.extend(
            [
                f'<text x="{padding}" y="{y + 14}" fill="#e6edf5" font-size="15" '
                f'font-weight="600" font-family="Segoe UI, Arial, sans-serif">{name}</text>',
                f'<text x="{width - padding}" y="{y + 14}" text-anchor="end" '
                'fill="#b6c3d4" font-size="13" font-family="Segoe UI, Arial, sans-serif">'
                f"{details}</text>",
                f'<rect x="{padding}" y="{y + 20}" width="{track_width}" height="7" '
                'rx="3" fill="#1d2a3b"/>',
                f'<rect x="{padding}" y="{y + 20}" width="{format(bar_width, "f")}" height="7" '
                f'rx="3" fill="{xml.sax.saxutils.escape(color).replace(chr(34), "&quot;")}"/>',
            ]
        )
    footer_y = header_height + len(data["languages"]) * row_height + 20
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
