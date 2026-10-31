# Binwalk pinned real EXT filesystem signature check

| Field | Value |
| --- | --- |
| Date | 2026-10-31 |
| FUSE revision | `3392b75543b9d6eff8ae0179385c1be7426b7091` |
| Binwalk source revision | `4fdab3d464d97b68e0af9088df3f9e2e1545b21c` |
| Upstream image | OpenWrt 25.12.6 Malta BE ext4 root filesystem |
| Artifact | `openwrt-25.12.6-malta-be-rootfs-ext4.img.gz` |
| Compressed size | 5,646,416 bytes |
| Decompressed image size | 109,051,904 bytes (104 MiB) |
| SHA-256 of compressed artifact | `8e6979b0024018e31fe5a8fe71be2a253c2cc2b6ae9991071e6fadcabfd91044` |
| Workflow run | [41151119131](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41151119131) |

## Purpose

Check whether the FUSE Binwalk v3.1.0 adapter recognizes the generic EXT filesystem signature in a real, hash-pinned OpenWrt ext4 root filesystem image on hosted Ubuntu and native Windows. The workflow downloads the compressed artifact to runner temporary storage, verifies its digest, expands the gzip stream within a 128 MiB limit, and scans the raw image in explicit firmware mode.

## Provenance and method

The image comes from the official [OpenWrt 25.12.6 Malta BE download index](https://downloads.openwrt.org/releases/25.12.6/targets/malta/be/). The index publishes the `rootfs-ext4.img.gz` artifact and matching SHA-256. FUSE does not store or redistribute the image.

The harness limits compressed samples to 16 MiB and decompressed filesystem images to 128 MiB. It verifies the digest before decompression, then passes the raw image to pinned Binwalk v3.1.0 with extraction disabled. The expected report marker is `EXT filesystem`. Binwalk's pinned signature definition names the signature family generically as EXT, so this check confirms that marker in an artifact identified by OpenWrt as ext4. It does not claim that Binwalk independently distinguishes ext4 from other EXT-family formats.

The same Ubuntu and Windows jobs also repeat the synthetic gzip, XZ, and CRC-valid U-Boot uImage positives, clean text and invalid-uImage controls, the pinned Tasmota gzip-signature check, and the OpenWrt SquashFS check.

## Results

| Platform | Archive digest | Generic EXT marker | Other controls | Binwalk extraction output | Result |
| --- | --- | --- | --- | --- | --- |
| Ubuntu hosted runner | Matched | Detected | Passed | None | Passed |
| Native Windows runner | Matched | Detected | Passed | None | Passed |

Both jobs reported Binwalk 3.1.0, completed the bounded filesystem image scan, and produced no extraction directory. The run logs record the expected SHA-256 and `EXT filesystem` marker on both platforms.

## Interpretation and limits

This is one real OpenWrt ext4 image with a generic EXT-family signature detected on two operating systems. It does not test filesystem extraction, file-level FUSE findings, compatibility with other EXT variants, arbitrary firmware, device applicability, exploitability, field accuracy, or hostile-input isolation. The 128 MiB decompression bound is not an OS sandbox for Binwalk.

The adapter evidence now includes one OpenWrt SquashFS image and one OpenWrt ext4 image, while FUSE still performs signature identification only. This adds format-coverage evidence but does not change the repository maturity score of 91/100.
