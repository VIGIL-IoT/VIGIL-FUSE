# Binwalk adapter end-to-end check

**Date:** 2026-10-31 | **FUSE source:** local worktree based on `a4e4b90`, including the version fallback described here

**Purpose:** Exercise FUSE's optional firmware signature adapter using a real Binwalk executable with a positive signature and a clean control. Verify that the adapter records the executable version and does not enable extraction.

## Environment and tool provenance

- Windows 11 build `10.0.26300` with WSL2
- Ubuntu `24.04.3 LTS`
- Python `3.12.3`
- Ubuntu Noble archive packages extracted to a temporary directory, not installed system-wide:
  - `binwalk` package `2.3.4+dfsg1-5`, SHA-256 `8d700a7eb3d0d07e8644d0acab641331b19f3e3c89bcc51abd07a83dcfac80e0`
  - `python3-binwalk` package `2.3.4+dfsg1-5`, SHA-256 `88248deaba2ddbc9fef84e5adbd86bd87d109116d7f286f1ea7c0e946fe0b82b`
  - `python3-zombie-imp` package `0.0.2-2`, SHA-256 `7cd53dc0b7ca71670a409c946c8421e5f81918edca76b64ef1e570051ba0c4a9`
- The executable help banner reported `Binwalk v2.3.3`.
- [ReFirmLabs Binwalk source](https://github.com/ReFirmLabs/binwalk)

## Method

The [repeatable harness](../../scripts/verify_binwalk_adapter.py) creates two temporary firmware files. The positive input is a gzip-compressed synthetic string. The clean control is plain synthetic text. FUSE runs each with `--firmware`, `--no-sbom`, and `--no-vulnerabilities`.

Run the harness from the FUSE repository root when Binwalk is on `PATH`:

```powershell
python scripts/verify_binwalk_adapter.py --expected-version "Binwalk v2.3.3"
```

The harness checks the JSON analyzer status, reported version, firmware identification sidecar, positive and clean signature behavior, and absence of extraction output. It does not contact a network or install the fixture contents.

## Results

| Case | Binwalk status | Reported version | Gzip signature | Extraction output |
| --- | --- | --- | --- | --- |
| Synthetic gzip image | completed | `Binwalk v2.3.3` | Present | None |
| Clean byte-string control | completed | `Binwalk v2.3.3` | Absent | None |

The check exposed a version-reporting gap. This Binwalk executable rejected `--version`, while its `--help` banner included the version. FUSE now falls back to parsing a bounded `Binwalk v...` banner from `--help` when `--version` is unsupported. A unit regression test covers this fallback.

## Interpretation and limits

This is a signature-identification integration smoke check for one Linux package version and one gzip signature. It does not test Binwalk v3.1.0, Windows-native execution, broad signature coverage, real firmware, extraction, detector accuracy, exploitability, or device applicability. The adapter remains identification-only and the external process is not sandboxed.
