"""Render bounded Ghidra controls with endpoints after ordinary strings."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

ORDINARY_STRING_COUNT = 1600
LIMIT_REFERENCE_COUNT = 2050
KINDS = ("positive", "secure", "unreferenced", "limited")
ENDPOINTS = {
    "positive": (
        "http://fixture-user:sentinel-password@device.example/update?token=sentinel-query-value",
        "mqtt://fixture-user:sentinel-password@broker.example:1883/topic",
    ),
    "secure": ("https://device.example/update", "mqtts://broker.example:8883"),
    "unreferenced": (
        "http://unused.example/update",
        "mqtt://unused.example:1883/topic",
    ),
    "limited": (
        "http://fixture-user:sentinel-password@device.example/update?token=sentinel-query-value",
        "mqtt://fixture-user:sentinel-password@broker.example:1883/topic",
    ),
}


def render_source(kind: str) -> str:
    if kind not in KINDS:
        raise ValueError(f"Unsupported Ghidra fixture kind: {kind}")
    lines = ["static const char * volatile fuse_sink;"]
    lines.extend(
        f'__attribute__((used, section(".fuse_ordinary"))) '
        f'static const char ordinary_{index:04d}[] = "ordinary-{index:04d}-fixture";'
        for index in range(ORDINARY_STRING_COUNT)
    )
    http, mqtt = ENDPOINTS[kind]
    lines.extend(
        [
            f'__attribute__((used, section(".fuse_candidates"))) '
            f'static const char endpoint_http[] = "{http}";',
            f'__attribute__((used, section(".fuse_candidates"))) '
            f'static const char endpoint_mqtt[] = "{mqtt}";',
        ]
    )
    if kind != "unreferenced":
        lines.append("__attribute__((noinline)) void use_endpoints(void) {")
        if kind == "limited":
            lines.extend("    fuse_sink = endpoint_http;" for _ in range(LIMIT_REFERENCE_COUNT))
            lines.append("    fuse_sink = endpoint_mqtt;")
        else:
            lines.extend(["    fuse_sink = endpoint_http;", "    fuse_sink = endpoint_mqtt;"])
        lines.append("}")
    lines.extend(
        [
            "void _start(void) {",
            "    fuse_sink = ordinary_1599;",
            *(["    use_endpoints();"] if kind != "unreferenced" else []),
            "    for (;;) {}",
            "}",
        ]
    )
    return "\n".join(lines) + "\n"


def build(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    linker_script = """ENTRY(_start)
SECTIONS {
  . = 0x400000;
  .text : { *(.text*) }
  .rodata : { *(.fuse_ordinary) *(.fuse_candidates) *(.rodata*) }
  .data : { *(.data*) }
  .bss : { *(.bss*) *(COMMON) }
}
"""
    (output_dir / "layout.ld").write_text(linker_script, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--kind", choices=KINDS)
    args = parser.parse_args()
    build(args.output_dir)
    if args.kind:
        sys.stdout.write(render_source(args.kind))


if __name__ == "__main__":
    main()
