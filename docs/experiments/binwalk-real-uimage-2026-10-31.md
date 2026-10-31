# Binwalk pinned real OpenWrt uImage signature check

| Field | Value |
| --- | --- |
| Date | 2026-10-31 |
| FUSE revision | `a2ec0b7` |
| Binwalk source revision | `4fdab3d464d97b68e0af9088df3f9e2e1545b21c` |
| Upstream image | OpenWrt 25.12.6 Malta BE `uImage-gzip` |
| Artifact | `openwrt-25.12.6-malta-be-uImage-gzip` |
| Image size | 4,786,528 bytes |
| SHA-256 | `561db5bcecc5ff73d7fb2c18fe1b1d95708ea813ccdb3559db7634133bc9d1cf` |
| Workflow run | [41151936784](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41151936784) |

## Purpose

Check whether FUSE's pinned Binwalk v3.1.0 adapter identifies a real OpenWrt uImage firmware artifact on hosted Ubuntu and native Windows, while retaining synthetic positive and negative controls and leaving extraction disabled.

## Provenance and method

The image comes from the official [OpenWrt 25.12.6 Malta BE download index](https://downloads.openwrt.org/releases/25.12.6/targets/malta/be/), which publishes the filename and matching SHA-256. The integration workflow downloads the image to runner temporary storage and the harness verifies the digest before scanning. FUSE does not store or redistribute the binary.

The sample is 4,786,528 bytes, within the harness's 16 MiB firmware-sample cap. A local preflight verified the U-Boot legacy image magic, header CRC, and payload CRC. The workflow then scans it through FUSE in explicit firmware mode with pinned Binwalk v3.1.0 and expects the `uImage firmware image` marker. The same jobs repeat the Tasmota gzip sample, OpenWrt SquashFS and ext4 samples, synthetic gzip, XZ, and uImage controls, clean text and invalid-uImage controls. Binwalk extraction is disabled.

The expected description is grounded in the pinned [Binwalk uImage signature definition](https://github.com/ReFirmLabs/binwalk/blob/4fdab3d464d97b68e0af9088df3f9e2e1545b21c/src/signatures/uimage.rs), which validates the legacy image structure and uses `uImage firmware image` as its base description.

## Results

| Platform | Pinned digest | uImage marker | Synthetic and other real controls | Extraction output | Result |
| --- | --- | --- | --- | --- | --- |
| Ubuntu hosted runner | Matched | Detected | Passed | None | Passed |
| Native Windows runner | Matched | Detected | Passed | None | Passed |

Both jobs reported Binwalk 3.1.0 and logged the expected filename, digest, and uImage marker. No extraction directory was produced.

## Interpretation and limits

This verifies one SHA-256-pinned OpenWrt Malta BE uImage artifact on two operating systems, alongside synthetic controls. CRC-valid header and payload checks do not establish that the image boots, matches a physical device, is secure, or is free of vulnerabilities. The result does not test extraction, emulation, device behavior, arbitrary firmware, field accuracy, or hostile-input isolation. The external Binwalk process remains unsandboxed.

This adds a real uImage firmware case to the integration matrix. It does not change the repository maturity score of 91/100 because independent detector accuracy and analyzer isolation remain open.
