from __future__ import annotations

import re
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "binwalk-adapter.yml"
BINWALK_SOURCE_COMMIT = "4fdab3d464d97b68e0af9088df3f9e2e1545b21c"
TASMOTA_FIRMWARE_SHA256 = "15a8e568af5096c9f43efd636da534214f2d170faf6551b4a9e9b6182117766c"
OPENWRT_SQUASHFS_SHA256 = "b285ce3b64377db55507ccce276881252e125039794f953d0f4d0f054775aafa"


def test_binwalk_workflow_is_manual_and_uses_windows_and_ubuntu() -> None:
    workflow = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)

    assert workflow["on"] == {"workflow_dispatch": ""}
    assert workflow["permissions"] == {}
    assert workflow["jobs"]["adapter-smoke"]["strategy"]["matrix"]["os"] == [
        "ubuntu-latest",
        "windows-latest",
    ]


def test_binwalk_workflow_pins_upstream_source_and_actions() -> None:
    workflow = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    job = workflow["jobs"]["adapter-smoke"]
    steps = job["steps"]

    assert workflow["env"]["BINWALK_SOURCE_COMMIT"] == BINWALK_SOURCE_COMMIT
    assert workflow["env"]["TASMOTA_FIRMWARE_URL"].endswith("/v16.0.0/tasmota-4M.bin.gz")
    assert workflow["env"]["TASMOTA_FIRMWARE_SHA256"] == TASMOTA_FIRMWARE_SHA256
    assert workflow["env"]["OPENWRT_SQUASHFS_URL"].endswith(
        "/openwrt-25.12.6-malta-be-rootfs-squashfs.img.gz"
    )
    assert workflow["env"]["OPENWRT_SQUASHFS_SHA256"] == OPENWRT_SQUASHFS_SHA256
    action_uses = [step["uses"] for step in steps if "uses" in step]
    assert len(action_uses) == 3
    for use in action_uses:
        assert re.fullmatch(r".+@[0-9a-f]{40}(?:\s+#\s+v\S+)?", use)

    rust_step = next(step for step in steps if "setup-rust-toolchain" in step.get("uses", ""))
    assert rust_step["with"]["rustflags"] == ""


def test_binwalk_workflow_builds_locked_source_and_scans_pinned_real_firmware() -> None:
    workflow = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    steps = workflow["jobs"]["adapter-smoke"]["steps"]
    build_steps = [
        step for step in steps if "cargo build --release --locked" in step.get("run", "")
    ]

    assert len(build_steps) == 2
    assert "--expected-version 3.1.0" in build_steps[0]["run"]
    assert "--expected-version 3.1.0" in build_steps[1]["run"]
    assert all("--binwalk-executable" in step["run"] for step in build_steps)
    assert all("--real-firmware" in step["run"] for step in build_steps)
    assert all("--real-firmware-sha256" in step["run"] for step in build_steps)
    assert all("--real-firmware-marker gzip" in step["run"] for step in build_steps)
    assert all("--real-filesystem-archive" in step["run"] for step in build_steps)
    assert all("--real-filesystem-sha256" in step["run"] for step in build_steps)
    assert all(
        "--real-filesystem-marker" in step["run"] and "SquashFS file system" in step["run"]
        for step in build_steps
    )
    assert build_steps[0]["run"].count("curl --fail --location") == 2
    assert build_steps[1]["run"].count("Invoke-WebRequest") == 2
