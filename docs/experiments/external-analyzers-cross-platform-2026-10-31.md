# External analyzer cross-platform smoke check

**Date:** 2026-10-31 | **FUSE source:** `d2c58f3`

**Purpose:** Verify that FUSE can install and invoke SHA-256-pinned Syft, OSV-Scanner, and Gitleaks releases on the supported hosted runner targets. The check covers positive inputs, clean controls, a no-package-source case, adapter status, and secret redaction.

## Environment and tool provenance

The [workflow](../../.github/workflows/external-analyzer-matrix.yml) installs release assets through the bounded [installer](../../scripts/install_ci_analyzers.py). It verifies each complete release archive or binary against a pinned SHA-256 digest before extraction or execution. The source file contains the digest for each supported tool and platform.

| Runner | Detected target | Syft | OSV-Scanner | Gitleaks |
| --- | --- | --- | --- | --- |
| `ubuntu-latest` | Linux x86_64 | 1.55.0 | 2.7.0 | 8.30.0 |
| `macos-latest` | Darwin arm64 | 1.55.0 | 2.7.0 | 8.30.0 |
| `windows-latest` | Windows AMD64 | 1.55.0 | 2.7.0 | 8.30.0 |

The [GitHub Actions run](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41164846477) passed all three matrix jobs. The [FUSE CI run](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41164846373), [CodeQL run](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41164846453), and [dependency audit](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41164846371) also passed for the same commit.

## Method

The dependency harness runs FUSE with `--sbom --vulnerabilities` against three temporary projects:

1. Positive dependency: `urllib3==1.25.2`.
2. Clean control: `idna==3.15`.
3. No-source control: a README-only project without a package manifest.

It validates generated CycloneDX and OSV JSON, analyzer versions and status, and expected positive, clean, and partial behavior. The two dependency cases use OSV-Scanner's online advisory lookup.

The Gitleaks harness creates two temporary local Git repositories. One contains a randomly generated, never-issued GitHub-token-shaped string. The clean control contains only `FIRMWARE_MODE=production`. It checks findings, completed coverage, and all generated report artifacts and captured output for the generated string.

Reproduce both checks from the repository root after running the installer and adding its output directory to `PATH`:

```powershell
python scripts/verify_dependency_adapters.py --expected-syft-version 1.55.0 --expected-osv-version 2.7.0
python scripts/verify_gitleaks_adapter.py --expected-version 8.30.0
```

The FUSE CI run also passed the full Python test matrix on Python 3.11 through 3.14, package build and install, strict type checks, documentation checks, self-scan, and coverage gate.

## Results

| Runner | Dependency positive | Dependency clean | No package sources | Gitleaks positive | Gitleaks clean | Secret retained in output |
| --- | ---: | ---: | --- | ---: | ---: | --- |
| Ubuntu | 11 | 0 | exit 2; OSV partial; no fabricated result artifact | 2 | 0 | No |
| macOS | 11 | 0 | exit 2; OSV partial; no fabricated result artifact | 2 | 0 | No |
| Windows | 11 | 0 | exit 2; OSV partial; no fabricated result artifact | 2 | 0 | No |

All three jobs reported the expected tool versions and successful Syft, OSV-Scanner, and Gitleaks adapter coverage for the cases that had analyzable input. The Gitleaks sidecar declared `secrets_redacted: true`. A local Windows run of the same harnesses also passed.

## Interpretation and limits

This is cross-platform integration evidence for these specific binaries and fixtures. It is not a detector accuracy study and says nothing about vulnerability prevalence in public repositories, real credential validity, project build behavior, or device behavior. The OSV advisory database can change, so dependency finding counts may change on rerun. Runner coverage here is Linux x86_64, macOS arm64, and Windows x86_64; it does not cover Linux arm64 or macOS x86_64. The external tools are invoked on hosted runners without a FUSE-managed OS sandbox. This check does not close the analyzer-isolation or independent field-evaluation gaps.
