from __future__ import annotations

import gzip
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
