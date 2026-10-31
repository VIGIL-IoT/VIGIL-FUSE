# Binwalk pinned real SquashFS rootfs smoke check

| Field | Value |
| --- | --- |
| Date | 2026-10-31 |
| FUSE revision | `892e6fdcf3c64ee41f358bc62be0886659e9b6a2` |
| Binwalk source revision | `4fdab3d464d97b68e0af9088df3f9e2e1545b21c` |
| Upstream image | OpenWrt 25.12.6 Malta BE root filesystem |
| Artifact | `openwrt-25.12.6-malta-be-rootfs-squashfs.img.gz` |
| Compressed size in upstream index | 4,459.7 KB |
| Decompressed image size | 109,051,904 bytes (104 MiB) |
| SHA-256 of compressed artifact | `b285ce3b64377db55507ccce276881252e125039794f953d0f4d0f054775aafa` |
| Workflow run | [41149656874](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41149656874) |

## Purpose

Check whether FUSE's Binwalk v3.1.0 adapter recognizes a real SquashFS root filesystem image on hosted Ubuntu and native Windows. The workflow downloads the pinned compressed image to runner temporary storage, checks its digest, expands the gzip stream within a 128 MiB output limit, then scans the raw filesystem image in explicit firmware mode. The binary is not stored in or uploaded from the FUSE repository.

## Provenance and method

The artifact comes from the official [OpenWrt 25.12.6 Malta BE download index](https://downloads.openwrt.org/releases/25.12.6/targets/malta/be/). The index publishes the matching filename, SHA-256, and compressed size. The harness verifies that digest before decompression and rejects compressed samples above 16 MiB or decompressed filesystem images above 128 MiB.

FUSE passes the resulting raw image to pinned Binwalk v3.1.0 through explicit firmware mode and expects the `SquashFS file system` marker in the identification report. This decompresses only the outer gzip stream. Binwalk extraction is not requested, and FUSE does not enumerate or read files inside the filesystem. The run also repeats the existing synthetic gzip, XZ, and CRC-valid U-Boot uImage positives, clean text control, invalid-uImage control, and pinned Tasmota gzip-signature check.

## Results

| Platform | Pinned source digest | SquashFS marker | Synthetic controls | Binwalk extraction output | Result |
| --- | --- | --- | --- | --- | --- |
| Ubuntu hosted runner | Matched | Detected | Passed | None | Passed |
| Native Windows runner | Matched | Detected | Passed | None | Passed |

Both jobs reported Binwalk 3.1.0 and completed the filesystem image scan. The workflow log records the expected OpenWrt SHA-256 and signature marker on both systems.

## Failed input attempt

The first run, [41149029928](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41149029928), used an x86/64 rootfs image with a 64 MiB decompression limit. The image exceeded that limit and the harness stopped before invoking Binwalk on the sample. This was a rejected input-size case, not a signature-detection result. The workflow then switched to the smaller Malta BE image and retained a bounded 128 MiB decompression ceiling.

## Interpretation and limits

This is evidence that the pinned adapter detected a filesystem signature in one SHA-256-pinned upstream rootfs image on two hosted operating systems. It does not establish compatibility with other SquashFS variants, other filesystems, arbitrary firmware, device applicability, file-level security findings, exploitability, or field accuracy. It does not test filesystem extraction, emulation, or hardware behavior. The 128 MiB limit bounds this workflow input but does not sandbox the external Binwalk process.

The image is fetched at workflow time and is not redistributed by FUSE. The experiment does not provide legal review of either project's licensing terms. The result adds one real filesystem-signature integration case and does not change the repository maturity score of 91/100.
