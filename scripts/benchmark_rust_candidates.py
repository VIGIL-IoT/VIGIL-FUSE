"""Measure bounded FUSE primitives on deterministic synthetic inputs."""

from __future__ import annotations
import argparse
import cProfile
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import pstats
import tempfile
import time
import tracemalloc
import psutil

from vigil_fuse.device_tree import parse_device_tree
from vigil_fuse.hardware_netlist import read_netlist_topology
from vigil_fuse.scanner import preview_discovery
from vigil_fuse.svd import parse_svd
from vigil_fuse.model import SourceFile
from vigil_fuse.rules.registry import RULES


def measure(name, size, data, operation):
    runs = []
    digest = None
    for _ in range(3):
        start, cpu = time.perf_counter(), time.process_time()
        result = operation()
        elapsed, cpu = time.perf_counter() - start, time.process_time() - cpu
        tracemalloc.start()
        checked = operation()
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        if checked != result:
            raise RuntimeError("output changed under tracing")
        encoded = json.dumps(result, sort_keys=True, default=str).encode()
        current = hashlib.sha256(encoded).hexdigest()
        if digest is not None and digest != current:
            raise RuntimeError("nondeterministic output")
        digest = current
        if isinstance(result, dict) and result.get("status") not in (
            None,
            "parsed",
            "partial",
            "completed",
        ):
            raise RuntimeError(f"unexpected status: {result.get('status')}")
        runs.append(
            {
                "wall_seconds": elapsed,
                "cpu_seconds": cpu,
                "peak_traced_bytes": peak,
                "process_peak_working_set_bytes": getattr(
                    psutil.Process().memory_info(), "peak_wset", None
                ),
            }
        )
    return {
        "operation": name,
        "size": size,
        "input_bytes": len(data),
        "input_sha256": hashlib.sha256(data).hexdigest(),
        "output_sha256": digest,
        "status": result.get("status") if isinstance(result, dict) else "completed",
        "output_count": (
            len(result["device"]["peripherals"][0]["registers"])
            if name == "svd"
            else len(result["nodes"])
            if name == "device_tree"
            else len(result["nets"])
            if name == "netlist_topology"
            else result["files_selected"]
            if name == "discovery"
            else len(result)
            if isinstance(result, list)
            else 1
        ),
        "runs": runs,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    args = parser.parse_args()
    reports = []
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        for count in (100, 1000, 4000):
            svd = (
                "<device><name>CHIP</name><peripherals><peripheral><name>UART</name><baseAddress>0x40000000</baseAddress><registers>"
                + "".join(
                    f"<register><name>R{i}</name><addressOffset>{i * 4}</addressOffset></register>"
                    for i in range(count)
                )
                + "</registers></peripheral></peripherals></device>"
            ).encode()
            dts = (
                "/dts-v1/;\n/ {\n"
                + "".join(
                    f'node{i}: device@{i:x} {{ compatible = "test,device"; reg = <{i}>; }};\n'
                    for i in range(count)
                )
                + "};\n"
            ).encode()
            net = (
                '<export><components><comp ref="U1"><value>MCU</value></comp></components><nets>'
                + "".join(
                    f'<net code="{i}" name="NET{i}"><node ref="U1" pin="{i}"/></net>'
                    for i in range(count)
                )
                + "</nets></export>"
            ).encode()
            path = root / "test.net"
            path.write_bytes(net)
            reports.append(measure("svd", count, svd, lambda: asdict(parse_svd(svd, "test.svd"))))
            reports.append(
                measure("device_tree", count, dts, lambda: asdict(parse_device_tree(dts)))
            )
            reports.append(
                measure(
                    "netlist_topology",
                    count,
                    net,
                    lambda: asdict(read_netlist_topology(root, path.name)),
                )
            )
            reports.append(measure("sha256", count, svd, lambda: hashlib.sha256(svd).hexdigest()))
            text = ("void example(void) { int value = 1; }\n" * count).encode()
            source = SourceFile("example.c", text.decode())
            reports.append(
                measure(
                    "text_rules",
                    count,
                    text,
                    lambda: [asdict(finding) for rule in RULES for finding in rule.scan(source)],
                )
            )
            tree = asdict(parse_device_tree(dts))
            reports.append(
                measure("serialize_evidence", count, dts, lambda: json.dumps(tree, sort_keys=True))
            )
        d = root / "project"
        d.mkdir()
        for i in range(2000):
            (d / f"f{i:04}.c").write_text("void example(void) {}\n")
        reports.append(
            measure(
                "discovery",
                2000,
                b"2000 files of 22 bytes",
                lambda: preview_discovery(d, "generic", budget_seconds=120),
            )
        )
        profile = cProfile.Profile()
        profile.enable()
        parse_device_tree(dts)
        profile.disable()
        with args.profile.open("w") as stream:
            pstats.Stats(profile, stream=stream).strip_dirs().sort_stats("cumulative").print_stats(
                20
            )
    args.output.write_text(json.dumps(reports, indent=2) + "\n")


if __name__ == "__main__":
    main()
