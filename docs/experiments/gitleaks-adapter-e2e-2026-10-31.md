# Gitleaks adapter end-to-end check

**Date:** 2026-10-31 | **FUSE source:** `2c5afa8`

**Purpose:** Verify FUSE's optional Git-history adapter with the real Gitleaks executable, including a positive signal, a clean control, completed coverage status, and report redaction.

## Environment and tool provenance

- Windows 11 build `10.0.26300`
- Python `3.14.7`
- Git `2.51.2.windows.1`
- [Gitleaks `v8.30.0`](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.0), Windows x64 release asset
- Release asset SHA-256: `54fe94f644b832dd08e8c3a5915efb3bfa862386d59fb27ca0792cb687a83573`

The Gitleaks release asset hash was checked before execution. Both repositories and all reports were created in a temporary directory and removed after the run. No remote repository or credential service was contacted.

## Method

The positive case committed a randomly generated, never-issued string with a GitHub-token-shaped prefix to a one-commit local repository. The negative control committed only `FIRMWARE_MODE=production`. FUSE scanned each repository with `--git-history`; SBOM, vulnerability, and firmware stages were disabled. The report JSON, Gitleaks sidecar, and captured output were checked for the generated value.

Run the [repeatable check script](../../scripts/verify_gitleaks_adapter.py) from the FUSE repository root after installing Git and Gitleaks on `PATH`:

```powershell
gitleaks version
python scripts/verify_gitleaks_adapter.py --expected-version 8.30.0
```

The script makes its own temporary repositories, validates positive and negative results, checks the analyzer status and tool version, and fails if the generated test value appears in output or any report artifact. It does not print that value.

## Results

| Case | Gitleaks status | Gitleaks findings | Output value retained |
| --- | --- | ---: | --- |
| Positive synthetic history | completed | 2: `generic-api-key` and `github-pat` at the same file and line | No |
| Clean control history | completed | 0 | No |

FUSE reported Gitleaks `8.30.0` for both scans. Its history sidecar declared `secrets_redacted: true`. A byte search across all generated reports and captured process output found no copy of the generated test value.

## Interpretation and limits

This check verifies that the adapter can invoke Gitleaks, parse its JSON output, normalize positive matches, report a clean scan as completed, and avoid persisting the matched value. It is an integration smoke check with one synthetic pattern and a one-commit history. It does not validate real credential validity, broad detector precision or recall, long-history behavior, other operating systems, or the Syft, OSV-Scanner, and Binwalk adapters.
