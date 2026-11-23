"""Run only inside an explicitly selected analyzer image containing LIEF."""

import hashlib
import importlib
import json
from pathlib import Path
import re
from typing import Any


def state(value: bool | None) -> str:
    return "unknown" if value is None else "present" if value else "absent"


def metadata(binary: Any, format_name: str, digest: str, lief: Any) -> dict[str, Any]:
    hardening: dict[str, str] = {}
    if format_name == "ELF":
        segments = list(binary.segments)
        stack = next((s for s in segments if s.type == lief.ELF.Segment.TYPE.GNU_STACK), None)
        hardening["NX"] = state(not stack.has(lief.ELF.Segment.FLAGS.X) if stack else None)
        hardening["PIE"] = state(binary.is_pie if binary.has_interpreter else None)
        hardening["RELRO"] = state(any(s.type == lief.ELF.Segment.TYPE.GNU_RELRO for s in segments))
        names = {s.name for s in binary.imported_symbols}
        hardening["stack canary"] = "present" if "__stack_chk_fail" in names else "unknown"
        hardening["FORTIFY"] = "present" if any(n.endswith("_chk") for n in names) else "unknown"
        architecture = str(binary.header.machine_type)
    elif format_name == "PE":
        flags = binary.optional_header.dll_characteristics
        hardening["ASLR"] = state(bool(flags & 0x40))
        hardening["DEP"] = state(bool(flags & 0x100))
        hardening["CFG"] = state(bool(flags & 0x4000) and binary.load_configuration is not None)
        hardening["signing"] = state(binary.has_signatures)
        architecture = str(binary.header.machine)
    else:
        hardening["PIE"] = state(bool(int(binary.header.flags) & 0x200000))
        hardening["code signing"] = state(binary.has_code_signature)
        hardening["hardened runtime"] = "unknown"
        architecture = str(binary.header.cpu_type)
    symbols: list[dict[str, str]] = []
    truncated = False
    for index, symbol in enumerate(binary.symbols):
        if index >= 4096:
            truncated = True
            break
        name = symbol.name
        if not name or len(name) > 128 or not re.fullmatch(r"[A-Za-z0-9_.$@?<>:~+\-/]+", name):
            continue
        symbols.append({"name": name, "address": str(symbol.value)})
    return {
        "schema_version": "1.0",
        "producer": {"name": "LIEF", "version": lief.__version__},
        "sha256": digest,
        "format": format_name,
        "architecture": architecture,
        "hardening": hardening,
        "symbols": symbols,
        "truncated": truncated,
        "limitations": [
            "Hardening metadata is not a vulnerability verdict.",
            "Canary/FORTIFY symbol presence does not prove protection of every function.",
            "Signing presence does not verify trust or authenticity.",
            "Absent symbols in stripped/static binaries do not prove absent controls.",
        ],
    }


def main() -> None:
    lief = importlib.import_module("lief")
    path = Path("/input0")
    if not path.is_file() or path.stat().st_size > 128 * 1024 * 1024:
        raise ValueError("binary input limit")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    binary = lief.parse(path)
    if isinstance(binary, lief.ELF.Binary):
        format_name = "ELF"
    elif isinstance(binary, lief.PE.Binary):
        format_name = "PE"
    elif isinstance(binary, lief.MachO.Binary):
        format_name = "Mach-O"
    else:
        raise ValueError("unsupported binary format")
    payload = json.dumps(metadata(binary, format_name, digest, lief), allow_nan=False)
    if len(payload.encode()) > 8 * 1024 * 1024:
        raise ValueError("binary artifact limit")
    print(payload)


if __name__ == "__main__":
    main()
