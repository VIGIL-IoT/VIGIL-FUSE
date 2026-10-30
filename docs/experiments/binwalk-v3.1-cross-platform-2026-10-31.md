# Binwalk v3.1.0 cross-platform adapter smoke check

| Field | Value |
| --- | --- |
| Date | 2026-10-31 |
| FUSE revision | `d873da619e08a4ab5a71ac7802cb55656608b442` |
| Binwalk source revision | `4fdab3d464d97b68e0af9088df3f9e2e1545b21c` |
| Workflow run | [41134907521](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41134907521) |

## Purpose

Verify that FUSE can invoke a source-built Binwalk v3.1.0 on GitHub-hosted Ubuntu and native Windows runners, report the tool version, identify one known signature, keep a clean control clear, and avoid extraction.

## Environment and provenance

| Runner | Operating system label | Rust | Python | Binwalk source |
| --- | --- | --- | --- | --- |
| Ubuntu | `ubuntu-latest` | 1.89.0 | 3.12 | `4fdab3d464d97b68e0af9088df3f9e2e1545b21c` |
| Windows | `windows-latest` | 1.89.0 | 3.12 | `4fdab3d464d97b68e0af9088df3f9e2e1545b21c` |

The workflow checks out the exact Binwalk source revision and builds it with `cargo build --release --locked`. The harness uses the resulting executable directly. Binwalk is an optional external executable and is not added as a FUSE runtime dependency.

## Method

The [repeatable harness](../../scripts/verify_binwalk_adapter.py) writes two temporary inputs. The positive control contains a deterministic gzip-compressed byte string. The clean control contains plain synthetic text. FUSE scans each with firmware identification enabled and SBOM and vulnerability analysis disabled.

For each case, the harness checks that the JSON report and firmware-identification sidecar exist, Binwalk status is `completed`, the reported version contains `3.1.0`, the gzip marker appears only for the positive control, and no extraction directory was created.

## Results

| Runner | Binwalk version | Gzip positive | Clean control | Extraction output | Result |
| --- | --- | --- | --- | --- | --- |
| Ubuntu | `binwalk 3.1.0` | Detected | Clear | None | Passed |
| Native Windows | `binwalk 3.1.0` | Detected | Clear | None | Passed |

Both job logs report: `Binwalk adapter smoke check passed: binwalk 3.1.0; gzip positive detected, clean control clear, no extraction.`

The first workflow attempt, [run 41134622611](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41134622611), failed because the pinned Rust setup action supplied `RUSTFLAGS=-D warnings`, promoting existing upstream compiler warnings to errors. The workflow now sets the action's `rustflags` input to an empty string. The successful rerun still reports upstream compiler warnings as warnings; FUSE does not modify Binwalk source.

## Interpretation and limits

This demonstrates build and adapter integration for one pinned Binwalk release, one gzip signature, and two hosted operating systems. It is not an accuracy, precision, recall, or firmware-compatibility study. It does not test real firmware, malformed images, other signatures or Binwalk versions, extraction, exploitability, device applicability, or hostile-input isolation. The external executable is not sandboxed by FUSE.
