# Binwalk pinned OpenWrt MT7621 firmware checks

| Field | Value |
| --- | --- |
| Date | 2026-10-31 |
| FUSE revision | `40d8f79` |
| Binwalk source revision | `4fdab3d464d97b68e0af9088df3f9e2e1545b21c` |
| Upstream release | OpenWrt 25.12.6, ramips/mt7621 |
| Workflow run | [41180343853](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41180343853) |

## Purpose

Check whether the pinned Binwalk v3.1.0 adapter identifies expected signatures in two official OpenWrt MT7621 images on hosted Ubuntu and native Windows. The workflow also runs its existing synthetic and upstream firmware controls. Extraction remains disabled.

## Provenance and method

Both samples are listed in the official [OpenWrt 25.12.6 MT7621 download index](https://downloads.openwrt.org/releases/25.12.6/targets/ramips/mt7621/), which publishes their SHA-256 digests. The workflow downloads each artifact to runner temporary storage. The FUSE harness verifies the expected digest before invoking Binwalk. Neither image is stored in this repository.

| Artifact | Upstream file | Size | SHA-256 | Expected Binwalk marker |
| --- | --- | ---: | --- | --- |
| Initramfs kernel | [`mediatek_mt7621-eval-board-initramfs-kernel.bin`](https://downloads.openwrt.org/releases/25.12.6/targets/ramips/mt7621/openwrt-25.12.6-ramips-mt7621-mediatek_mt7621-eval-board-initramfs-kernel.bin) | 6,287,712 bytes | `503bf12e6b8dce51102ada7219ba38f85cfe75dcc6b50610a4b434b412eae3ee` | `uImage firmware image` |
| Sysupgrade image | [`mediatek_mt7621-eval-board-squashfs-sysupgrade.bin`](https://downloads.openwrt.org/releases/25.12.6/targets/ramips/mt7621/openwrt-25.12.6-ramips-mt7621-mediatek_mt7621-eval-board-squashfs-sysupgrade.bin) | 6,423,131 bytes | `20cbe57eb177b1eda050e470fe4bc0fc2ee744f523b99f09fbe34dd7bd42ba1d` | `SquashFS file system` |

The harness uses explicit firmware mode and checks signatures only. It does not extract the image or inspect files inside it.

## Results

| Platform | Initramfs digest and marker | Sysupgrade digest and marker | Other controls | Result |
| --- | --- | --- | --- | --- |
| Hosted Ubuntu | Matched, detected | Matched, detected | Passed | Passed |
| Native Windows | Matched, detected | Matched, detected | Passed | Passed |

Workflow [41180343853](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41180343853) passed both platform jobs. The job logs record both expected markers and confirm that no extraction output was created.

## Interpretation and limits

This is evidence for two hash-pinned artifacts from one OpenWrt target and release, using one pinned Binwalk version on two operating systems. The expected signatures do not establish device compatibility, successful boot or upgrade, firmware security, vulnerability-detection accuracy, or behavior on other firmware. The workflow does not inspect extracted filesystem contents, emulate a device, or test hardware. The Binwalk process remains unsandboxed by the operating system.

The result broadens real-image signature integration coverage. It does not change the repository's 91/100 maturity assessment because detector accuracy, broader firmware coverage, and analyzer isolation remain open.
