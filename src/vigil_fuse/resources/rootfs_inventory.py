"""Bounded metadata inventory of extractor output, never an archive extractor."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any
from urllib.parse import quote

MAX_ENTRIES = 4000
MAX_FILE = 16 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
MAX_DEPTH = 32


def inventory(root: Path, firmware_sha256: str, producer: str = "Binwalk") -> dict[str, Any]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Invalid extraction root")
    root = root.resolve()
    result: dict[str, Any] = {
        "schema_version": "1.0",
        "producer": producer,
        "firmware_sha256": firmware_sha256,
        "entries": [],
        "services": [],
        "accounts": [],
        "packages": [],
        "certificates": [],
        "keys": [],
        "web_interfaces": [],
        "kernel_config": [],
        "binaries": [],
        "architecture": "unknown",
        "limitations": [
            "Filesystem presence does not establish service execution, network exposure or accessibility.",
            "Secret contents and password hashes are omitted.",
            "Architecture and extraction completeness may remain unknown.",
        ],
    }
    stack = [root]
    total = 0
    while stack:
        directory = stack.pop()
        with os.scandir(directory) as iterator:
            children = []
            for entry in iterator:
                children.append(Path(entry.path))
                if len(result["entries"]) + len(children) > MAX_ENTRIES:
                    raise ValueError("Filesystem entry limit")
        for path in sorted(children):
            relative = path.relative_to(root).as_posix()
            if (
                len(path.relative_to(root).parts) > MAX_DEPTH
                or len(relative) > 4096
                or any(ord(c) < 32 for c in relative)
            ):
                raise ValueError("Filesystem depth/path limit")
            info = path.lstat()
            if path.is_symlink():
                try:
                    path.resolve().relative_to(root)
                except (ValueError, RuntimeError, OSError) as exc:
                    raise ValueError("Symlink escape or cycle") from exc
                result["entries"].append(
                    {"path": relative, "kind": "symlink", "sha256": None, "byte_size": 0}
                )
                continue
            if stat.S_ISDIR(info.st_mode):
                stack.append(path)
                result["entries"].append(
                    {"path": relative, "kind": "directory", "sha256": None, "byte_size": 0}
                )
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink > 1:
                raise ValueError("Special file or hardlink rejected")
            if info.st_size > MAX_FILE or total + info.st_size > MAX_TOTAL:
                raise ValueError("Filesystem size limit")
            total += info.st_size
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
            descriptor = os.open(path, flags)
            with os.fdopen(descriptor, "rb") as stream:
                actual = os.fstat(stream.fileno())
                if (
                    not stat.S_ISREG(actual.st_mode)
                    or actual.st_ino != info.st_ino
                    or actual.st_size != info.st_size
                ):
                    raise ValueError("Filesystem changed during inventory")
                data = stream.read(MAX_FILE + 1)
            if len(data) != info.st_size:
                raise ValueError("Filesystem changed or exceeded limits")
            digest = hashlib.sha256(data).hexdigest()
            record = {"path": relative, "kind": "file", "sha256": digest, "byte_size": len(data)}
            result["entries"].append(record)
            metadata = {"path": relative, "sha256": digest}
            if "-----BEGIN" in data[:64].decode("ascii", errors="ignore"):
                if b"PRIVATE KEY-----" in data[:256]:
                    result["keys"].append({**metadata, "kind": "private-key"})
                elif b"CERTIFICATE-----" in data[:256]:
                    result["certificates"].append({**metadata, "kind": "certificate"})
            parts = path.relative_to(root).parts
            if "init.d" in parts or relative.endswith(".service"):
                result["services"].append({**metadata, "name": path.name})
            if data.startswith((b"\x7fELF", b"MZ", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")):
                result["binaries"].append(
                    {
                        **metadata,
                        "kind": "library"
                        if ".so" in path.name or path.suffix == ".dll"
                        else "binary",
                    }
                )
            decoded = data.decode("utf-8", errors="replace") if len(data) < 2 * 1024 * 1024 else ""
            if relative.endswith("etc/passwd"):
                for line in decoded.splitlines():
                    account_fields = line.split(":")
                    if len(account_fields) == 7 and account_fields[2].isdigit():
                        result["accounts"].append(
                            {
                                "name_sha256": hashlib.sha256(
                                    account_fields[0].encode()
                                ).hexdigest(),
                                "uid": int(account_fields[2]),
                                "password_state": "not-imported",
                            }
                        )
            if relative.endswith(
                ("var/lib/dpkg/status", "usr/lib/opkg/status", "var/lib/opkg/status")
            ):
                for paragraph in decoded.split("\n\n"):
                    fields = dict(
                        line.split(": ", 1)
                        for line in paragraph.splitlines()
                        if ": " in line and not line.startswith(" ")
                    )
                    if fields.get("Package") and fields.get("Version"):
                        name, version = fields["Package"], fields["Version"]
                        package_type = (
                            "deb" if relative.endswith("var/lib/dpkg/status") else "generic"
                        )
                        result["packages"].append(
                            {
                                "purl": "pkg:"
                                + package_type
                                + "/"
                                + quote(name, safe="")
                                + "@"
                                + quote(version, safe=""),
                                "version": version,
                            }
                        )
                        if name in {"nginx", "lighttpd", "apache2", "uhttpd"}:
                            result["web_interfaces"].append(
                                {"path": relative, "package": name, "exposure": "unknown"}
                            )
            if ("kernel" in relative or "boot" in parts) and (
                path.name in {"config", ".config"} or path.name.startswith("config-")
            ):
                for line in decoded.splitlines():
                    if line.startswith(
                        (
                            "CONFIG_MODULE_SIG=",
                            "CONFIG_DEBUG_KERNEL=",
                            "CONFIG_STRICT_KERNEL_RWX=",
                            "CONFIG_SECURITY=",
                        )
                    ):
                        name, value = line.split("=", 1)
                        if value in {"y", "n", "m"}:
                            result["kernel_config"].append(
                                {"name": name, "value": value, "path": relative}
                            )
            if len(result["accounts"]) + len(result["packages"]) > 2000:
                raise ValueError("Filesystem metadata limit")
    return result


def main() -> None:
    import subprocess
    import sys

    image = Path("/input0")
    if not image.is_file() or image.stat().st_size > 128 * 1024 * 1024:
        raise ValueError("Firmware size limit")
    with image.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    root = Path("/work/extracted")
    root.mkdir()
    command = ["binwalk", "--extract", "--directory", str(root)]
    if "--recursive" in sys.argv:
        command.append("--matryoshka")
    subprocess.run(
        [*command, "/input0"],
        cwd=root,
        stdout=sys.stderr,
        stderr=sys.stderr,
        timeout=250,
        check=True,
        env={**os.environ, "BINWALK_RM_EXTRACTION_SYMLINK": "1"},
    )
    payload = json.dumps(inventory(root, digest), allow_nan=False)
    if len(payload.encode()) > 8 * 1024 * 1024:
        raise ValueError("Inventory artifact limit")
    print(payload)


if __name__ == "__main__":
    main()
