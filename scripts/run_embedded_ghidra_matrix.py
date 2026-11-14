"""Build controlled binaries and record real Ghidra results without changing detectors."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import sys
import time

import psutil
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.benchmark_process import sample_process_tree_rss  # noqa: E402
from scripts.evaluate_detection_accuracy import write_results  # noqa: E402
from scripts.freeze_evaluation import verify  # noqa: E402

IDF_IMAGE = "espressif/idf@sha256:bf72fe7a15c22849a9a94147301165a545fb8905d97c176cf748e3e4614cac84"
IDF_COMMIT = "880a203ae603d08a94d06aa01e0d6761958e5e9e"
RULES = ["FUSE-BIN-001", "FUSE-BIN-002"]
TARGETS = {
    "x86_64": {
        "architecture": "x86-64",
        "compiler": "gcc",
        "flags": ["-fno-pie", "-no-pie"],
        "base": "0x400000",
    },
    "cortex_m4": {
        "architecture": "ARM Cortex-M4",
        "compiler": "clang",
        "flags": ["--target=arm-none-eabi", "-mcpu=cortex-m4", "-mthumb", "-fuse-ld=lld"],
        "base": "0x08000000",
    },
    "esp32": {
        "architecture": "Xtensa",
        "compiler": "xtensa-esp-elf-gcc",
        "flags": ["-mcpu=esp32", "-mtext-section-literals"],
        "base": "0x40080000",
    },
    "esp32s3": {
        "architecture": "Xtensa",
        "compiler": "xtensa-esp-elf-gcc",
        "flags": ["-mcpu=esp32s3", "-mtext-section-literals"],
        "base": "0x40370000",
    },
    "esp32c6": {
        "architecture": "RISC-V RV32",
        "compiler": "riscv32-esp-elf-gcc",
        "flags": ["-march=rv32imac_zicsr_zifencei", "-mabi=ilp32", "-mno-relax"],
        "base": "0x42000000",
    },
}


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_controlled(target: str, work: Path) -> tuple[list[dict], dict]:
    spec = TARGETS[target]
    source = ROOT / "tests/fixtures/embedded_binary/endpoints.c"
    shutil.copyfile(source, work / "endpoints.c")
    (work / "layout.ld").write_text(
        f"ENTRY(_start)\nSECTIONS {{ . = {spec['base']}; .text : {{ *(.literal*) *(.text*) }} "
        ".rodata : { *(.rodata*) } .data : { *(.data*) } .bss : { *(.bss*) *(COMMON) } }\n"
    )
    compiler = str(spec["compiler"])
    prefix = compiler.removesuffix("gcc") if compiler.endswith("gcc") else "llvm-"
    if target == "x86_64":
        prefix = ""
    container = target.startswith("esp")
    commands = []
    cases = []
    for optimization in ("O0", "O1", "O2", "Os"):
        for kind in ("positive", "secure"):
            cases.append(
                {
                    "id": f"{target}-{optimization}-{kind}",
                    "optimization": optimization,
                    "kind": kind,
                    "stripped": False,
                    "format": "ELF",
                    "experimental": False,
                }
            )
    cases.append(
        {
            "id": f"{target}-O2-unreferenced",
            "optimization": "O2",
            "kind": "unreferenced",
            "stripped": False,
            "format": "ELF",
            "experimental": False,
        }
    )
    for case in cases:
        commands.append(
            [
                compiler,
                *spec["flags"],
                "-" + case["optimization"],
                "-nostdlib",
                "-fno-stack-protector",
                "-fno-unwind-tables",
                "-fno-asynchronous-unwind-tables",
                "-Wl,--build-id=none",
                "-Wl,-T,layout.ld",
                f"-DSECURE={int(case['kind'] == 'secure')}",
                f"-DUNREFERENCED={int(case['kind'] == 'unreferenced')}",
                "endpoints.c",
                "-o",
                case["id"] + ".elf",
            ]
        )
    for kind in ("positive", "secure"):
        name = f"{target}-O2-{kind}-stripped"
        commands.append(
            [prefix + "strip", "--strip-all", f"{target}-O2-{kind}.elf", "-o", name + ".elf"]
        )
        cases.append(
            {
                "id": name,
                "optimization": "O2",
                "kind": kind,
                "stripped": True,
                "format": "ELF",
                "experimental": False,
            }
        )
    if target == "cortex_m4":
        for kind in ("positive", "secure"):
            name = f"{target}-O2-{kind}-raw"
            commands.append(
                [prefix + "objcopy", "-O", "binary", f"{target}-O2-{kind}.elf", name + ".bin"]
            )
            cases.append(
                {
                    "id": name,
                    "optimization": "O2",
                    "kind": kind,
                    "stripped": True,
                    "format": "raw",
                    "experimental": True,
                    "language": "ARM:LE:32:Cortex",
                    "base_address": spec["base"],
                    "memory_assumption": "single flat region at linker origin; Thumb Cortex-M language; no vector table",
                }
            )
    if container:
        # Only fixed, repository-owned compiler arguments enter this shell script.
        import shlex

        script = 'set -eu\ntest "$(git -C "$IDF_PATH" rev-parse HEAD)" = ' + IDF_COMMIT + "\n"
        script += f"{compiler} --version > compiler-version.txt\n"
        script += "\n".join(shlex.join(command) for command in commands)
        (work / "build.sh").write_text(script + "\n")
        subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--network=none",
                "--volume",
                f"{work}:/work",
                "--workdir",
                "/work",
                IDF_IMAGE,
                "bash",
                "build.sh",
            ],
            check=True,
        )
        compiler_version = (work / "compiler-version.txt").read_text().strip()
    else:
        compiler_version = subprocess.check_output([compiler, "--version"], text=True).strip()
        for command in commands:
            subprocess.run(command, cwd=work, check=True, capture_output=True)
    return cases, {
        "compiler": compiler,
        "compiler_version": compiler_version,
        "commands": commands,
        "image": IDF_IMAGE if container else None,
        "idf_commit": IDF_COMMIT if container else None,
        "fixture_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
    }


def analyze(case: dict, binary: Path, work: Path, ghidra: Path, timeout: int) -> dict:
    output = work / "outputs" / case["id"]
    temporary = work / "temporary" / case["id"]
    temporary.mkdir(parents=True)
    environment = {
        **os.environ,
        "TMPDIR": str(temporary),
        "TEMP": str(temporary),
        "TMP": str(temporary),
    }
    command = [
        sys.executable,
        "-m",
        "vigil_fuse",
        "scan",
        str(binary),
        "--ghidra",
        "--ghidra-install-dir",
        str(ghidra),
        "--ghidra-timeout-seconds",
        str(timeout),
        "--output-dir",
        str(output),
        "--format",
        "json",
        "--no-network",
    ]
    if case["format"] == "raw":
        command.extend(
            ["--ghidra-language", case["language"], "--ghidra-base-address", case["base_address"]]
        )
    started = time.perf_counter()
    peak, inaccessible = 0, 0
    with (work / "cli-errors.log").open("w") as errors:
        process = subprocess.Popen(
            command, stdout=subprocess.DEVNULL, stderr=errors, env=environment
        )
        while process.poll() is None:
            rss, denied = sample_process_tree_rss(process.pid, psutil)
            peak = max(peak, rss)
            inaccessible += denied
            # The adapter enforces its own bounded timeout and kills its process tree.
            time.sleep(0.05)
    elapsed = time.perf_counter() - started
    report_path, artifact_path = output / "findings.json", output / "ghidra-analysis.json"
    report = json.loads(report_path.read_text()) if report_path.exists() else None
    artifact = json.loads(artifact_path.read_text()) if artifact_path.exists() else None
    schemas_valid = True
    for document, name in ((report, "fuse-report-1.11"), (artifact, "ghidra-analysis")):
        if document is not None:
            schema = json.loads((ROOT / f"src/vigil_fuse/schemas/{name}.schema.json").read_text())
            Draft202012Validator(schema).validate(document)
        else:
            schemas_valid = False
    status = (
        next((a for a in report["coverage"]["analyzers"] if a["name"] == "ghidra"), {})
        if report
        else {}
    )
    found = sorted({f["rule_id"] for f in report["findings"]}) if report else []
    serialized = "\n".join(path.read_text() for path in output.glob("*.*") if path.is_file())
    redaction = not any(
        secret in serialized
        for secret in ("sentinel-query-value", "sentinel-password", "fixture-user")
    )
    cleanup = not any(temporary.iterdir())
    expected = set(RULES) if case["kind"] == "positive" else set()
    matched = (expected <= set(found)) if expected else not (set(RULES) & set(found))
    raw_status = status.get("status", "failed")
    normalized = (
        raw_status
        if raw_status in {"completed", "partial", "unsupported", "failed", "timeout"}
        else "failed"
    )
    return {
        **case,
        "input_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "input_bytes": binary.stat().st_size,
        "status": normalized,
        "detail": status.get("detail"),
        "exit_code": process.returncode,
        "analysis": artifact["analysis"] if artifact else None,
        "counts": {
            name: artifact[name]["reported"]
            for name in ("functions", "strings", "cross_references")
        }
        if artifact
        else {},
        "truncation": artifact["truncation"] if artifact else None,
        "tool": artifact["tool"] if artifact else None,
        "rule_ids": found,
        "schemas_valid": schemas_valid,
        "temporary_cleanup": cleanup,
        "redaction_passed": redaction,
        "expected_rules_match": matched,
        "elapsed_seconds": elapsed,
        "peak_process_tree_rss_bytes": peak,
        "rss_inaccessible_observations": inaccessible,
        "artifact_bytes": artifact_path.stat().st_size if artifact_path.exists() else 0,
        "report_sha256": hashlib.sha256(report_path.read_bytes()).hexdigest() if report else None,
        "artifact_sha256": hashlib.sha256(artifact_path.read_bytes()).hexdigest()
        if artifact
        else None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=TARGETS, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--ghidra-install-dir", type=Path, required=True)
    parser.add_argument(
        "--manifest", type=Path, default=ROOT / "reports/evaluation/2026-11-14/manifest.json"
    )
    parser.add_argument("--timeout-seconds", type=int, default=300)
    parser.add_argument("--real-binary", type=Path)
    args = parser.parse_args()
    frozen = json.loads(args.manifest.read_text())
    verify(frozen)
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=False)
    cases, build = build_controlled(args.target, work)
    records = []
    for case in cases:
        binary = work / (case["id"] + (".bin" if case["format"] == "raw" else ".elf"))
        record = analyze(case, binary, work, args.ghidra_install_dir, args.timeout_seconds)
        records.append(record)
        write_json(
            work / "compatibility.json", {"target": args.target, "build": build, "records": records}
        )
        print(
            case["id"],
            record["status"],
            record["rule_ids"],
            "expected:",
            record["expected_rules_match"],
            flush=True,
        )
    if args.real_binary:
        record = analyze(
            {
                "id": args.target + "-idf-hello-world",
                "kind": "unknown",
                "format": "ELF",
                "experimental": True,
                "provenance": {
                    "project": "ESP-IDF hello_world",
                    "repository": "https://github.com/espressif/esp-idf",
                    "commit": IDF_COMMIT,
                    "license": "Apache-2.0; example public domain (see source header)",
                    "source_available": True,
                    "redistribution": "binary not committed; build from pinned official image",
                    "image": IDF_IMAGE,
                    "command": "idf.py set-target TARGET && idf.py build",
                },
            },
            args.real_binary,
            work,
            args.ghidra_install_dir,
            args.timeout_seconds,
        )
        records.append(record)
    dataset = {
        "schema_version": "1.0",
        "dataset_id": "embedded-controls-" + args.target,
        "split": "controlled-binary",
        "scope": "Ghidra code-referenced plaintext HTTP/MQTT endpoints, ELF only",
        "ground_truth": "controlled source construction; no target execution, network call, or vulnerability claim",
        "fuse_commit": frozen["fuse_commit"],
        "rules": RULES,
        "cases": [],
    }
    seen = set()
    for record in records:
        if record["experimental"]:
            continue
        if record["input_sha256"] in seen:
            continue
        seen.add(record["input_sha256"])
        for rule in RULES:
            dataset["cases"].append(
                {
                    "id": record["id"] + "-" + rule,
                    "rule_id": rule,
                    "input_sha256": record["input_sha256"],
                    "expected": "positive" if record["kind"] == "positive" else "negative",
                    "observed": rule in record["rule_ids"] if record["schemas_valid"] else None,
                    "status": record["status"],
                    "coverage": {
                        "complete": record["status"] == "completed" and record["schemas_valid"],
                        "files_discovered": 1,
                        "files_scanned": int(record["schemas_valid"]),
                        "files_skipped": int(not record["schemas_valid"]),
                        "bytes_scanned": record["input_bytes"] if record["schemas_valid"] else 0,
                    },
                }
            )
    write_json(work / "dataset.json", dataset)
    write_results(dataset, work / "metrics")
    summary = {
        "schema_version": "1.0",
        "target": args.target,
        "architecture": TARGETS[args.target]["architecture"],
        "fuse_commit": frozen["fuse_commit"],
        "harness_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "environment": {
            "os": platform.platform(),
            "python": platform.python_version(),
            "java": subprocess.run(
                ["java", "-version"], capture_output=True, text=True
            ).stderr.strip(),
        },
        "build": build,
        "records": records,
        "status_counts": dict(Counter(r["status"] for r in records)),
        "median_elapsed_seconds": statistics.median(r["elapsed_seconds"] for r in records),
    }
    write_json(work / "compatibility.json", summary)
    return int(
        any(
            not (
                r["expected_rules_match"]
                and r["status"] == "completed"
                and r["schemas_valid"]
                and r["temporary_cleanup"]
                and r["redaction_passed"]
            )
            for r in records
            if not r["experimental"]
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
