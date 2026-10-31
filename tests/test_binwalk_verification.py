from __future__ import annotations

import gzip
import hashlib
import lzma
import os
import struct
import zlib
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.verify_binwalk_adapter import (
    FIRMWARE_PREFIX,
    PAYLOAD,
    configure_binwalk_environment,
    real_firmware_case,
    real_filesystem_cases,
    signature_marker_found,
    signature_cases,
)


def test_signature_cases_are_deterministic_and_cover_firmware_formats() -> None:
    cases = signature_cases()

    assert cases == signature_cases()
    assert [case.label for case in cases] == [
        "gzip-positive",
        "xz-positive",
        "uimage-positive",
        "clean",
        "invalid-uimage-control",
    ]
    assert [case.marker for case in cases[:3]] == [
        "gzip",
        "xz compressed data",
        "uimage firmware image",
    ]
    assert all(case.detected for case in cases[:3])
    assert not any(case.detected for case in cases[3:])


def test_signature_fixture_payloads_and_uimage_crc_are_valid() -> None:
    cases = {case.label: case for case in signature_cases()}
    assert gzip.decompress(cases["gzip-positive"].data[len(FIRMWARE_PREFIX) :]) == PAYLOAD
    assert lzma.decompress(cases["xz-positive"].data[len(FIRMWARE_PREFIX) :]) == PAYLOAD

    image = cases["uimage-positive"].data[len(FIRMWARE_PREFIX) :]
    header = bytearray(image[:64])
    fields = struct.unpack(">7I4B32s", header)
    assert len(header) == 64
    assert fields[0] == 0x27051956
    assert fields[3] == len(PAYLOAD)
    assert fields[6] == zlib.crc32(PAYLOAD)
    struct.pack_into(">I", header, 4, 0)
    assert fields[1] == zlib.crc32(header)
    assert image[64:] == PAYLOAD

    malformed = cases["invalid-uimage-control"].data[len(FIRMWARE_PREFIX) :]
    assert malformed.startswith(struct.pack(">I", 0x27051956))
    assert malformed[4:64] == bytes(60)


def test_configure_binwalk_environment_adds_explicit_executable_directory(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "binwalk.exe"
    executable.write_bytes(b"synthetic executable path placeholder")
    env = {"PATH": "existing-path"}

    resolved = configure_binwalk_environment(executable, env)

    assert resolved == executable.resolve()
    assert env["PATH"].split(os.pathsep) == [str(tmp_path.resolve()), "existing-path"]


def test_configure_binwalk_environment_rejects_missing_explicit_executable(
    tmp_path: Path,
) -> None:
    env = {"PATH": "existing-path"}

    with pytest.raises(FileNotFoundError, match="does not exist"):
        configure_binwalk_environment(tmp_path / "missing-binwalk", env)

    assert env["PATH"] == "existing-path"


def test_configure_binwalk_environment_uses_path_when_no_override_is_given() -> None:
    with patch("scripts.verify_binwalk_adapter.shutil.which", return_value="/tools/binwalk"):
        resolved = configure_binwalk_environment(None, {"PATH": "/tools"})

    assert resolved == Path("/tools/binwalk")


def test_real_firmware_case_requires_and_preserves_the_pinned_sample(
    tmp_path: Path,
) -> None:
    sample = tmp_path / "upstream-firmware.bin.gz"
    data = b"\x1f\x8b externally sourced firmware sample"
    sample.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()

    case = real_firmware_case(sample, digest, "gzip")

    assert case.label == "upstream-real-firmware"
    assert case.data == data
    assert case.marker == "gzip"
    assert case.detected


def test_real_firmware_case_rejects_a_changed_sample(tmp_path: Path) -> None:
    sample = tmp_path / "upstream-firmware.bin.gz"
    sample.write_bytes(b"changed firmware sample")

    with pytest.raises(ValueError, match="SHA-256 did not match"):
        real_firmware_case(sample, "0" * 64, "gzip")


def test_real_firmware_case_decompresses_hash_pinned_filesystem_sample(
    tmp_path: Path,
) -> None:
    sample = tmp_path / "openwrt-rootfs.img.gz"
    rootfs = b"hash-pinned SquashFS test payload"
    compressed = gzip.compress(rootfs, mtime=0)
    sample.write_bytes(compressed)
    digest = hashlib.sha256(compressed).hexdigest()

    case = real_firmware_case(
        sample,
        digest,
        "SquashFS file system",
        label="upstream-real-filesystem",
        decompress_gzip_payload=True,
    )

    assert case.label == "upstream-real-filesystem"
    assert case.data == rootfs
    assert case.source_name == sample.name
    assert case.source_sha256 == digest


def test_real_filesystem_cases_load_multiple_pinned_samples(tmp_path: Path) -> None:
    expected_payloads = (
        ("openwrt-squashfs.img.gz", b"OpenWrt SquashFS image", "SquashFS file system"),
        ("openwrt-ext4.img.gz", b"OpenWrt ext4 image", "EXT filesystem"),
    )
    samples = []
    for name, payload, marker in expected_payloads:
        archive = tmp_path / name
        compressed = gzip.compress(payload, mtime=0)
        archive.write_bytes(compressed)
        samples.append((archive, hashlib.sha256(compressed).hexdigest(), marker))

    cases = real_filesystem_cases(samples)

    assert [case.label for case in cases] == [
        "upstream-real-filesystem-1",
        "upstream-real-filesystem-2",
    ]
    assert [case.data for case in cases] == [payload for _, payload, _ in expected_payloads]
    assert [case.marker for case in cases] == [marker for _, _, marker in expected_payloads]


def test_real_firmware_case_enforces_decompressed_filesystem_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sample = tmp_path / "oversized-rootfs.img.gz"
    compressed = gzip.compress(b"more than the configured cap", mtime=0)
    sample.write_bytes(compressed)
    digest = hashlib.sha256(compressed).hexdigest()
    monkeypatch.setattr(
        "scripts.verify_binwalk_adapter.MAX_DECOMPRESSED_FILESYSTEM_BYTES",
        8,
    )

    with pytest.raises(ValueError, match="configured size limit"):
        real_firmware_case(
            sample,
            digest,
            "SquashFS file system",
            label="upstream-real-filesystem",
            decompress_gzip_payload=True,
        )


def test_signature_marker_matching_ignores_capitalization() -> None:
    assert signature_marker_found("SquashFS file system", "squashfs file system")
    assert not signature_marker_found("SquashFS file system", "ext4 filesystem")
