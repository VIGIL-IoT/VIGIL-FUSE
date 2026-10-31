"""Run a pinned, non-redistributed NIST SARD regression cohort for FUSE001."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import stat
import subprocess
import sys
import tempfile
from typing import IO
from urllib.request import Request, urlopen
from zipfile import BadZipFile, ZipFile

ROOT = Path(__file__).resolve().parents[1]
MAX_ARCHIVE_BYTES = 1_000_000
MAX_EXTRACTED_BYTES = 2_000_000
MAX_ARCHIVE_ENTRIES = 64
DOWNLOAD_TIMEOUT_SECONDS = 30
SCAN_TIMEOUT_SECONDS = 120
READ_CHUNK_BYTES = 64 * 1024


@dataclass(frozen=True)
class SardCase:
    case_id: str
    flow_variant: str
    archive_sha256: str
    target_filename: str
    expected_fuse_files: tuple[str, ...]

    @property
    def download_url(self) -> str:
        return f"https://samate.nist.gov/SARD/downloads/versions/{self.case_id}-v1.0.0.zip"


@dataclass(frozen=True)
class CohortResult:
    case_id: str
    flow_variant: str
    files_scanned: int
    finding_count: int
    rule_version: str
    target_detected: bool


CASES = (
    SardCase(
        "93498",
        "01",
        "eb565270918c60192bb7c5a69e91381e0af1792edb2b41927167b1a520bd17b1",
        "CWE259_Hard_Coded_Password__w32_char_01.c",
        ("CWE259_Hard_Coded_Password__w32_char_01.c",),
    ),
    SardCase(
        "93521",
        "34",
        "40a76a13594f377c3e806137b6b56900d061eeaf8fb50d66bc3c99e313fc4b7d",
        "CWE259_Hard_Coded_Password__w32_char_34.c",
        ("CWE259_Hard_Coded_Password__w32_char_34.c",),
    ),
    SardCase(
        "93547",
        "02",
        "b8c1c3bd2971ec90a4b25bf78edf6c1ccc1211e51772c29390b6eb86a5dd7350",
        "CWE259_Hard_Coded_Password__w32_wchar_t_02.c",
        ("CWE259_Hard_Coded_Password__w32_wchar_t_02.c",),
    ),
    SardCase(
        "93553",
        "08",
        "e8fe04d77361ccf4e23a414cb369cf09260d6a0d2f73ec8e1342c9b9eb10f866",
        "CWE259_Hard_Coded_Password__w32_wchar_t_08.c",
        ("CWE259_Hard_Coded_Password__w32_wchar_t_08.c",),
    ),
    SardCase(
        "93562",
        "17",
        "3e7d55811890d27a2604eeb679c7f59c9dd1e510c57d723c8df1a1c7f4104156",
        "CWE259_Hard_Coded_Password__w32_wchar_t_17.c",
        ("CWE259_Hard_Coded_Password__w32_wchar_t_17.c",),
    ),
    SardCase(
        "93566",
        "31",
        "30aea80c628716fa710391f19eb6693a24ed6cfaddb7c8c15639359c74a4893e",
        "CWE259_Hard_Coded_Password__w32_wchar_t_31.c",
        ("CWE259_Hard_Coded_Password__w32_wchar_t_31.c",),
    ),
    SardCase(
        "93570",
        "41",
        "9532273951c12201553b61e26caa4ab7333abb8dc6f894fd4f86c53257fb062e",
        "CWE259_Hard_Coded_Password__w32_wchar_t_41.c",
        ("CWE259_Hard_Coded_Password__w32_wchar_t_41.c",),
    ),
    SardCase(
        "93573",
        "44",
        "cefcbd1f522886a751c321d99c223af1f9b983ad88ba1c1f5f71cb35bb251ffe",
        "CWE259_Hard_Coded_Password__w32_wchar_t_44.c",
        ("CWE259_Hard_Coded_Password__w32_wchar_t_44.c",),
    ),
    SardCase(
        "93579",
        "61",
        "629a3fef228a2e4b96b7b33ab5a9efd7cfd0f385d02da4236b6177c0123cc1ac",
        "CWE259_Hard_Coded_Password__w32_wchar_t_61b.c",
        (
            "CWE259_Hard_Coded_Password__w32_wchar_t_61a.c",
            "CWE259_Hard_Coded_Password__w32_wchar_t_61b.c",
        ),
    ),
    SardCase(
        "93585",
        "67",
        "16b4a66f253919052578fb134038519ed5f5a73cf87290047af143e69354e408",
        "CWE259_Hard_Coded_Password__w32_wchar_t_67a.c",
        (
            "CWE259_Hard_Coded_Password__w32_wchar_t_67a.c",
            "CWE259_Hard_Coded_Password__w32_wchar_t_67b.c",
        ),
    ),
)


def _write_limited(source: IO[bytes], destination: Path, byte_limit: int) -> int:
    written = 0
    with destination.open("xb") as output:
        while chunk := source.read(READ_CHUNK_BYTES):
            written += len(chunk)
            if written > byte_limit:
                raise ValueError("input exceeds the configured byte limit")
            output.write(chunk)
    return written


def download_case(case: SardCase, destination: Path) -> None:
    request = Request(
        case.download_url,
        headers={"User-Agent": "VIGIL-FUSE-SARD-validation/1.0"},
    )
    try:
        with urlopen(request, timeout=DOWNLOAD_TIMEOUT_SECONDS) as response:
            content_length = response.headers.get("Content-Length")
            if content_length is not None and int(content_length) > MAX_ARCHIVE_BYTES:
                raise ValueError("NIST archive exceeds the configured download limit")
            _write_limited(response, destination, MAX_ARCHIVE_BYTES)
    except (OSError, ValueError) as error:
        destination.unlink(missing_ok=True)
        raise RuntimeError(f"could not download SARD case {case.case_id}") from error

    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    if digest != case.archive_sha256:
        destination.unlink(missing_ok=True)
        raise RuntimeError(f"SHA-256 mismatch for SARD case {case.case_id}")


def _safe_extract_zip(
    archive_path: Path,
    destination: Path,
    *,
    max_entries: int = MAX_ARCHIVE_ENTRIES,
    max_uncompressed_bytes: int = MAX_EXTRACTED_BYTES,
) -> int:
    destination.mkdir(parents=True, exist_ok=True)
    resolved_root = destination.resolve()
    total_bytes = 0
    seen_paths: set[str] = set()

    try:
        with ZipFile(archive_path) as archive:
            entries = archive.infolist()
            if len(entries) > max_entries:
                raise ValueError("archive exceeds the configured entry limit")

            for info in entries:
                name = info.filename
                relative = PurePosixPath(name)
                windows_path = PureWindowsPath(name)
                if (
                    not name
                    or not relative.parts
                    or "\x00" in name
                    or "\\" in name
                    or relative.is_absolute()
                    or windows_path.drive
                    or ".." in relative.parts
                ):
                    raise ValueError("archive contains an unsafe path")

                normalized = relative.as_posix().casefold()
                if normalized in seen_paths:
                    raise ValueError("archive contains a duplicate path")
                seen_paths.add(normalized)

                mode = info.external_attr >> 16
                file_type = stat.S_IFMT(mode)
                if file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise ValueError("archive contains a link or special file")

                target = destination.joinpath(*relative.parts)
                if not target.resolve(strict=False).is_relative_to(resolved_root):
                    raise ValueError("archive path escapes the extraction directory")

                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue

                total_bytes += info.file_size
                if total_bytes > max_uncompressed_bytes:
                    raise ValueError("archive exceeds the configured expanded-size limit")

                target.parent.mkdir(parents=True, exist_ok=True)
                if not target.resolve(strict=False).is_relative_to(resolved_root):
                    raise ValueError("archive parent escapes the extraction directory")
                with archive.open(info) as source:
                    extracted = _write_limited(
                        source,
                        target,
                        max_uncompressed_bytes - (total_bytes - info.file_size),
                    )
                if extracted != info.file_size:
                    raise ValueError("archive entry size does not match its metadata")
    except BadZipFile as error:
        raise ValueError("download is not a valid ZIP archive") from error

    return total_bytes


def _scan_case(case: SardCase, target: Path, report_path: Path) -> CohortResult:
    environment = os.environ.copy()
    source_path = str(ROOT / "src")
    existing_pythonpath = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        source_path
        if not existing_pythonpath
        else os.pathsep.join((source_path, existing_pythonpath))
    )
    command = [
        sys.executable,
        "-m",
        "vigil_fuse",
        "scan",
        str(target),
        "--profile",
        "generic",
        "--target-label",
        f"NIST SARD case {case.case_id}",
        "--no-sbom",
        "--no-vulnerabilities",
        "--no-firmware",
        "--no-git-history",
        "--no-network",
        "--format",
        "json",
        "--output",
        str(report_path),
    ]
    try:
        subprocess.run(
            command,
            check=True,
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=SCAN_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise RuntimeError(f"FUSE scan failed for SARD case {case.case_id}") from error

    report = json.loads(report_path.read_text(encoding="utf-8"))
    findings = report.get("findings")
    if not isinstance(findings, list):
        raise ValueError(f"FUSE report for SARD case {case.case_id} is malformed")
    fuse_findings = [
        finding
        for finding in findings
        if isinstance(finding, dict) and finding.get("rule_id") == "FUSE001"
    ]
    matched_files = {
        str(finding.get("location", {}).get("file", "")).replace("\\", "/").rsplit("/", 1)[-1]
        for finding in fuse_findings
    }
    expected = set(case.expected_fuse_files)
    if matched_files != expected:
        raise RuntimeError(
            f"FUSE001 file set changed for SARD case {case.case_id}: "
            f"expected {len(expected)} file(s), observed {len(matched_files)}"
        )
    if case.target_filename not in matched_files:
        raise RuntimeError(f"NIST target file was not detected for case {case.case_id}")

    versions = {finding.get("rule_version") for finding in fuse_findings}
    rule_version = next(iter(versions)) if len(versions) == 1 else None
    if not isinstance(rule_version, str):
        raise ValueError(f"FUSE001 version is missing or inconsistent for {case.case_id}")
    summary = report.get("summary")
    scanned_files = summary.get("files_scanned") if isinstance(summary, dict) else None
    if not isinstance(scanned_files, int):
        raise ValueError(f"FUSE file count is missing for SARD case {case.case_id}")
    return CohortResult(
        case_id=case.case_id,
        flow_variant=case.flow_variant,
        files_scanned=scanned_files,
        finding_count=len(fuse_findings),
        rule_version=rule_version,
        target_detected=True,
    )


def run_cohort() -> list[CohortResult]:
    results: list[CohortResult] = []
    with tempfile.TemporaryDirectory(prefix="fuse-sard-validation-") as temporary:
        temporary_root = Path(temporary)
        for case in CASES:
            case_root = temporary_root / case.case_id
            case_root.mkdir()
            archive_path = case_root / "case.zip"
            extracted_root = case_root / "source"
            report_path = case_root / "findings.json"

            download_case(case, archive_path)
            _safe_extract_zip(archive_path, extracted_root)
            results.append(_scan_case(case, extracted_root, report_path))

    return results


def main() -> int:
    results = run_cohort()
    total_findings = sum(result.finding_count for result in results)
    target_hits = sum(result.target_detected for result in results)
    versions = {result.rule_version for result in results}

    print("case  flow  files  FUSE001  target")
    for result in results:
        print(
            f"{result.case_id}  {result.flow_variant}  "
            f"{result.files_scanned}  {result.finding_count}  PASS"
        )
    print(
        f"Result: {target_hits}/{len(CASES)} NIST target files detected; "
        f"{total_findings} FUSE001 findings; rule version {', '.join(sorted(versions))}."
    )
    print("This selected known-case regression is not a field-accuracy estimate.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
