# Binwalk v3.1.0 signature matrix

| Field | Value |
| --- | --- |
| Date | 2026-10-31 |
| FUSE revision | `1a5db88c32d888d980e6f3373c94cd9027c2cb29` |
| Binwalk source revision | `4fdab3d464d97b68e0af9088df3f9e2e1545b21c` |
| Workflow run | [41146514105](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41146514105) |
| FUSE CI run | [41146503462](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41146503462) |

## Purpose

Extend the previous single-gzip adapter smoke check to several signature types while retaining clean and malformed controls. Confirm that the CLI reports the pinned analyzer version and does not create extraction output.

## Method

The repeatable [harness](../../scripts/verify_binwalk_adapter.py) creates all inputs in a temporary directory. Positive files contain a non-signature prefix followed by deterministic synthetic content generated with Python's standard library. The U-Boot legacy image has a 64-byte header with valid header and payload CRCs. The negative U-Boot control keeps the magic bytes but has an invalid header checksum. A plain text file is the clean control.

Each file is scanned through FUSE with firmware identification enabled and SBOM and vulnerability analysis disabled. The harness requires completed Binwalk status, the expected version and signature description, the expected clear result for negative controls, and absence of a `.extracted` output directory.

## Results

| Input | Expected result | Ubuntu | Native Windows |
| --- | --- | --- | --- |
| Synthetic gzip stream | `gzip` signature present | Detected | Detected |
| Synthetic XZ stream | `XZ compressed data` present | Detected | Detected |
| CRC-valid U-Boot legacy image | `uImage firmware image` present | Detected | Detected |
| Plain synthetic text | No known signature | Clear | Clear |
| uImage magic with invalid header CRC | No accepted uImage result | Clear | Clear |

Both jobs reported Binwalk `3.1.0`, completed all five FUSE scans, and produced no extraction directory. The workflow run passed on Ubuntu and native Windows.

## Interpretation and limits

This verifies the adapter contract for three synthetic formats on one pinned Binwalk release and two operating systems. It does not measure signature accuracy on real firmware, cover filesystem images such as SquashFS, exercise the v2.3 adapter with this matrix, or test extraction, exploitability, device applicability, or hostile-input isolation. The optional executable remains unsandboxed by FUSE. The result does not change the 91/100 maturity score because independent accuracy evidence and sandboxing remain open.

The fixture formats are grounded in the pinned upstream definitions for [gzip](https://github.com/ReFirmLabs/binwalk/blob/4fdab3d464d97b68e0af9088df3f9e2e1545b21c/src/signatures/gzip.rs), [XZ](https://github.com/ReFirmLabs/binwalk/blob/4fdab3d464d97b68e0af9088df3f9e2e1545b21c/src/signatures/xz.rs), and [uImage](https://github.com/ReFirmLabs/binwalk/blob/4fdab3d464d97b68e0af9088df3f9e2e1545b21c/src/signatures/uimage.rs). The U-Boot header and checksum requirements are implemented in the pinned [uImage parser](https://github.com/ReFirmLabs/binwalk/blob/4fdab3d464d97b68e0af9088df3f9e2e1545b21c/src/structures/uimage.rs) and [dry-run validator](https://github.com/ReFirmLabs/binwalk/blob/4fdab3d464d97b68e0af9088df3f9e2e1545b21c/src/extractors/uimage.rs).
