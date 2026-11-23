from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import runpy

import pytest

from vigil_fuse.evidence_graph import EvidenceGraph
from vigil_fuse.firmware_rootfs import add_rootfs, validate_rootfs


def resource() -> dict:
    return runpy.run_path(
        str(Path(__file__).parents[1] / "src/vigil_fuse/resources/rootfs_inventory.py")
    )


def safe_root(root: Path) -> dict:
    files = {
        "nested/root/etc/passwd": "root:x:0:0:root:/root:/bin/sh\n",
        "nested/root/etc/init.d/http": "service configuration\n",
        "nested/root/var/lib/dpkg/status": "Package: nginx\nVersion: 1.0\nStatus: install ok installed\n",
        "nested/root/etc/device.key": "-----BEGIN PRIVATE KEY-----\nSENSITIVE_MATERIAL\n",
        "nested/root/etc/device.crt": "-----BEGIN CERTIFICATE-----\nCERTIFICATE_CONTENT\n",
        "nested/root/boot/config-1": "CONFIG_DEBUG_KERNEL=y\n",
        "nested/root/bin/server": "\x7fELFfixture",
    }
    for name, value in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)
    return resource()["inventory"](root, "a" * 64)


def test_safe_nested_inventory_services_packages_and_secret_metadata(tmp_path: Path) -> None:
    doc = safe_root(tmp_path)
    validate_rootfs(doc)
    assert len(doc["services"]) == 1 and len(doc["packages"]) == 1
    assert len(doc["keys"]) == 1 and len(doc["certificates"]) == 1
    assert doc["kernel_config"][0]["value"] == "y"
    assert doc["web_interfaces"][0]["exposure"] == "unknown"
    serialized = json.dumps(doc)
    assert "SENSITIVE_MATERIAL" not in serialized and "CERTIFICATE_CONTENT" not in serialized
    assert "root:x:" not in serialized
    g = EvidenceGraph("firmware")
    add_rootfs(g, doc)
    assert {"FirmwareImage", "Filesystem", "Binary", "Service", "Package"} <= {
        n["type"] for n in g.nodes.values()
    }
    assert EvidenceGraph.from_dict(g.to_dict()).to_dict() == g.to_dict()


@pytest.mark.parametrize(
    "mode", ["traversal", "extra-secret-field", "oversized", "dangling", "exposure"]
)
def test_malformed_and_overclaiming_manifests_rejected(tmp_path: Path, mode: str) -> None:
    doc = copy.deepcopy(safe_root(tmp_path))
    if mode == "traversal":
        doc["entries"][0]["path"] = "../escape"
    if mode == "extra-secret-field":
        doc["keys"][0]["contents"] = "secret"
    if mode == "oversized":
        doc["entries"][0]["byte_size"] = 20 * 1024 * 1024
    if mode == "dangling":
        doc["services"][0]["path"] = "missing"
    if mode == "exposure":
        doc["web_interfaces"][0]["exposure"] = "public"
    with pytest.raises(ValueError):
        validate_rootfs(doc)


def test_symlink_escape_and_hardlink_rejected(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("outside")
    try:
        (root / "escape").symlink_to(outside)
    except OSError:
        pytest.skip("Creating symlinks requires unavailable Windows privilege")
    with pytest.raises(ValueError):
        resource()["inventory"](root, "a" * 64)
    (root / "escape").unlink()
    os.link(outside, root / "hardlink")
    with pytest.raises(ValueError):
        resource()["inventory"](root, "a" * 64)


def test_sparse_oversized_and_deep_filesystems_rejected(tmp_path: Path) -> None:
    huge = tmp_path / "huge"
    with huge.open("wb") as stream:
        stream.truncate(17 * 1024 * 1024)
    with pytest.raises(ValueError):
        resource()["inventory"](tmp_path, "a" * 64)
    huge.unlink()
    deep = tmp_path
    for _ in range(34):
        deep = deep / "nested"
    deep.mkdir(parents=True)
    with pytest.raises(ValueError):
        resource()["inventory"](tmp_path, "a" * 64)
