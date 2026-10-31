from __future__ import annotations

import re
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "binwalk-adapter.yml"
BINWALK_SOURCE_COMMIT = "4fdab3d464d97b68e0af9088df3f9e2e1545b21c"
TASMOTA_FIRMWARE_SHA256 = "15a8e568af5096c9f43efd636da534214f2d170faf6551b4a9e9b6182117766c"
OPENWRT_UIMAGE_SHA256 = "561db5bcecc5ff73d7fb2c18fe1b1d95708ea813ccdb3559db7634133bc9d1cf"
OPENWRT_SQUASHFS_SHA256 = "b285ce3b64377db55507ccce276881252e125039794f953d0f4d0f054775aafa"
OPENWRT_EXT4_SHA256 = "8e6979b0024018e31fe5a8fe71be2a253c2cc2b6ae9991071e6fadcabfd91044"
OPENWRT_MT7621_INITRAMFS_SHA256 = "503bf12e6b8dce51102ada7219ba38f85cfe75dcc6b50610a4b434b412eae3ee"
OPENWRT_MT7621_SYSUPGRADE_SHA256 = "20cbe57eb177b1eda050e470fe4bc0fc2ee744f523b99f09fbe34dd7bd42ba1d"


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
    assert workflow["env"]["OPENWRT_UIMAGE_URL"].endswith("/openwrt-25.12.6-malta-be-uImage-gzip")
    assert workflow["env"]["OPENWRT_UIMAGE_SHA256"] == OPENWRT_UIMAGE_SHA256
    assert workflow["env"]["OPENWRT_SQUASHFS_URL"].endswith(
        "/openwrt-25.12.6-malta-be-rootfs-squashfs.img.gz"
    )
    assert workflow["env"]["OPENWRT_SQUASHFS_SHA256"] == OPENWRT_SQUASHFS_SHA256
    assert workflow["env"]["OPENWRT_EXT4_URL"].endswith(
        "/openwrt-25.12.6-malta-be-rootfs-ext4.img.gz"
    )
    assert workflow["env"]["OPENWRT_EXT4_SHA256"] == OPENWRT_EXT4_SHA256
    assert workflow["env"]["OPENWRT_MT7621_INITRAMFS_URL"].endswith(
        "/openwrt-25.12.6-ramips-mt7621-mediatek_mt7621-eval-board-initramfs-kernel.bin"
    )
    assert workflow["env"]["OPENWRT_MT7621_INITRAMFS_SHA256"] == OPENWRT_MT7621_INITRAMFS_SHA256
    assert workflow["env"]["OPENWRT_MT7621_SYSUPGRADE_URL"].endswith(
        "/openwrt-25.12.6-ramips-mt7621-mediatek_mt7621-eval-board-squashfs-sysupgrade.bin"
    )
    assert workflow["env"]["OPENWRT_MT7621_SYSUPGRADE_SHA256"] == OPENWRT_MT7621_SYSUPGRADE_SHA256
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
    assert all(step["run"].count("--real-firmware ") == 4 for step in build_steps)
    assert all("TASMOTA_FIRMWARE_SHA256" in step["run"] for step in build_steps)
    assert all("OPENWRT_UIMAGE_SHA256" in step["run"] for step in build_steps)
    assert all(
        '"uImage firmware image"' in step["run"] or "'uImage firmware image'" in step["run"]
        for step in build_steps
    )
    assert all(step["run"].count("--real-filesystem ") == 2 for step in build_steps)
    assert all("OPENWRT_SQUASHFS_SHA256" in step["run"] for step in build_steps)
    assert all("OPENWRT_EXT4_SHA256" in step["run"] for step in build_steps)
    assert all("OPENWRT_MT7621_INITRAMFS_SHA256" in step["run"] for step in build_steps)
    assert all("OPENWRT_MT7621_SYSUPGRADE_SHA256" in step["run"] for step in build_steps)
    assert all("SquashFS file system" in step["run"] for step in build_steps)
    assert all("EXT filesystem" in step["run"] for step in build_steps)
    assert build_steps[0]["run"].count("curl --fail --location") == 6
    assert build_steps[1]["run"].count("Invoke-WebRequest") == 6
