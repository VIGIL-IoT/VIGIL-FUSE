# Binwalk pinned real firmware smoke check

| Field | Value |
| --- | --- |
| Date | 2026-10-31 |
| FUSE revision | `d69922eb7b6f6274f847820d0097aa5a2f58b81c` |
| Binwalk source revision | `4fdab3d464d97b68e0af9088df3f9e2e1545b21c` |
| Firmware release | [Tasmota v16.0.0](https://github.com/arendst/Tasmota/releases/tag/v16.0.0) |
| Firmware artifact | `tasmota-4M.bin.gz`, 521,817 bytes |
| Expected SHA-256 | `15a8e568af5096c9f43efd636da534214f2d170faf6551b4a9e9b6182117766c` |
| Workflow run | [41147524184](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41147524184) |

## Purpose

Add one upstream firmware release artifact to the Binwalk adapter smoke checks. The workflow downloads the pinned file to the hosted runner's temporary directory, verifies its SHA-256, scans it through FUSE, and checks the expected signature text. The binary is not added to the FUSE repository or uploaded as a workflow artifact.

## Provenance and method

The artifact is the official compressed Tasmota v16.0.0 `tasmota-4M.bin.gz` release file. The upstream release page lists the file and matching SHA-256. The [Tasmota source repository](https://github.com/arendst/Tasmota/blob/v16.0.0/LICENSE.txt) identifies its license. The FUSE workflow retrieves the exact release URL and the verification harness rejects a changed digest or a sample larger than 16 MiB.

The pinned Binwalk v3.1.0 adapter workflow scans the artifact in explicit firmware mode on Ubuntu and native Windows. The harness expects the gzip signature and checks that FUSE reports completed Binwalk coverage. It also runs the synthetic gzip, XZ, and CRC-valid U-Boot uImage positives, the clean text control, and the invalid-uImage control. No extraction is requested or created.

## Results

| Platform | Sample hash | Expected gzip marker | Result | Extraction output |
| --- | --- | --- | --- | --- |
| Ubuntu hosted runner | Matches pinned SHA-256 | Detected | Passed | None |
| Native Windows runner | Matches pinned SHA-256 | Detected | Passed | None |

Both jobs reported Binwalk `3.1.0` and completed the synthetic controls and the real release-artifact scan. The workflow run passed on both platforms.

## Interpretation and limits

This is evidence that FUSE can pass one real, compressed firmware release artifact to the selected Binwalk version and record its gzip signature on two operating systems. It does not verify the inner ESP firmware structure, discover a filesystem, inventory components, find vulnerabilities, assess device applicability, or measure signature accuracy. The scan is identification-only and does not extract the gzip stream.

The test downloads the upstream artifact at workflow time and does not redistribute it from FUSE. This experiment is not a legal review of the firmware license or FUSE's custom license. The example adds one real artifact to the three synthetic signature cases, but it does not close the need for broader real firmware and filesystem-image validation. It does not change the 91/100 repository maturity assessment.
