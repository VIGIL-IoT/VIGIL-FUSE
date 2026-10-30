# Cross-platform pinned repository scan performance

- Date: 2026-10-31
- Workflow run: [41130740188](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41130740188)
- FUSE version: 0.2.0
- FUSE revision: `fa600e01578db3555b9822085fb393d70f63bcf2`
- Manifest SHA-256: `cb75e3de0a9e5d7b3e97a3bd844dd9b5857f868e0cae4f4adff6a6732a30cfd1`

## Question

Can the same FUSE revision scan the same four pinned embedded and IoT repository scopes on GitHub-hosted Linux, Windows, and macOS runners while reporting consistent input and coverage metadata?

This is a reproducibility check. Its runner timings are descriptive samples, not a controlled ranking of operating systems or hardware.

## Inputs and method

The workflow used the four repositories and selected include patterns in [`fresh-validation-next/manifest.json`](../../reports/repository-scans/fresh-validation-next/manifest.json). Each target was sparsely checked out at its recorded commit. The preparer sets `core.autocrlf=false` and `core.eol=lf` before checkout, so text files use LF on every host. The manifest digest normalizes line endings, so equivalent manifest content has the same fingerprint across hosts.

Each scope received one warm-up and three measured scans. Process-tree RSS was sampled every 20 ms during each run using psutil. Network, SBOM generation, vulnerability database queries, firmware analysis, and Git history analysis were disabled. Native rules and static inventory checks were enabled. Every report passed the checked-in JSON Schema and was reviewed for source revision, manifest digest, repository commits, selected file counts, scan coverage, skips, signal counts, and memory sampling completeness.

| GitHub runner | Report OS | Python | OS release | Architecture | Logical CPUs | Raw report |
| --- | --- | --- | --- | --- | ---: | --- |
| `ubuntu-latest` | Linux | 3.12.15 | 7.0.0-1017-azure | x86_64 | 4 | [JSON](../../reports/benchmark/repository-scan-performance-ubuntu-2026-10-31.json) |
| `windows-latest` | Windows | 3.12.10 | 2025Server | AMD64 | 4 | [JSON](../../reports/benchmark/repository-scan-performance-windows-2026-10-31.json) |
| `macos-latest` | Darwin | 3.12.10 | 25.6.0 | arm64 | 3 | [JSON](../../reports/benchmark/repository-scan-performance-macos-2026-10-31.json) |

## Results

Each timing cell gives the median of three measured scans and the median absolute deviation (MAD), in seconds.

| Selected scope | Linux median (MAD) | Windows median (MAD) | macOS median (MAD) | Files scanned / selected | Skips | Native analysis | Candidate signals |
| --- | ---: | ---: | ---: | ---: | --- | --- | ---: |
| Apache Mynewt Core | 7.586 (0.003) | 5.490 (0.010) | 6.508 (0.046) | 3,354 / 3,355 | 1 too large | Partial | 0 |
| Mbed TLS | 1.544 (0.002) | 0.948 (0.002) | 1.234 (0.025) | 121 / 121 | 0 | Completed | 0 |
| OpenThread | 2.629 (0.041) | 1.930 (0.043) | 2.047 (0.031) | 909 / 909 | 0 | Completed | 5 |
| ESP-IoT-Solution | 5.760 (0.022) | 4.791 (0.022) | 4.877 (0.033) | 3,886 / 3,888 | 2 too large | Partial | 19 |

The input fingerprint, pinned source commits, selected and scanned file counts, source-byte totals, skipped-file reasons, native-analysis status, and raw signal counts match across the three reports. All 12 scope reports recorded complete RSS sampling with zero inaccessible process samples.

The next table reports the median of the three per-run peak process-tree RSS values, with the minimum and maximum in parentheses, in MiB.

| Selected scope | Linux median (range) | Windows median (range) | macOS median (range) |
| --- | ---: | ---: | ---: |
| Apache Mynewt Core | 51.86 (51.83 to 52.01) | 52.77 (52.02 to 52.78) | 69.12 (68.73 to 70.00) |
| Mbed TLS | 43.86 (43.86 to 43.87) | 43.76 (43.73 to 44.95) | 53.84 (53.28 to 54.28) |
| OpenThread | 45.54 (45.41 to 45.55) | 46.70 (46.16 to 46.97) | 56.23 (54.73 to 58.09) |
| ESP-IoT-Solution | 66.45 (66.32 to 66.56) | 58.22 (57.63 to 58.32) | 92.77 (88.83 to 95.52) |

An earlier run matched file counts but had a larger Windows OpenThread byte total because `core.eol=native` produced CRLF checkout files. The preparer now forces LF and refuses to reuse checkouts without the normalized settings. Two scopes were partial on every host because selected files exceeded FUSE's configured size limit. The 24 OpenThread and ESP-IoT-Solution signals are candidate matches, not confirmed vulnerabilities.

## Interpretation and limits

- There was one hosted runner per operating system. CPU architecture, runner image, operating-system release, Python patch version, available CPU allocation, and cache state differed. The medians must not be read as a controlled speed comparison.
- Three measured repetitions after one warm-up describe within-run timing and sampled RSS spread only. They do not estimate long-term variance or cold-cache performance. Process monitoring adds overhead to the wall-time measurement.
- RSS is the sum of process and descendant resident sets. Shared pages can be counted more than once, 20 ms sampling can miss brief peaks, and filesystem cache and other system memory are excluded. CPU utilization, firmware execution, device behavior, and hardware-in-the-loop measurements were not collected.
- The selected scopes are not full repository scans. Skipped oversized files remain visible, and partial analysis is not described as a completed full scan.
- Candidate signal counts do not measure precision, recall, exploitability, vulnerability prevalence, or whether any configuration reaches a deployed product.

## Reproduction

From the FUSE repository root, run:

```sh
gh workflow run repository-performance.yml --ref main
```

The workflow validates and uploads one schema-checked report per platform. The checked-in JSON files are the reviewed artifacts from run `41130740188`; the workflow itself does not commit or publish reports.

## Outcome

The pinned cohort was reproducible across the three runner operating systems after normalizing manifest hashes and target checkout line endings. This supports the reproducibility score recorded in [`REPOSITORY_AUDIT.md`](../REPOSITORY_AUDIT.md). RSS samples describe these hosted runners and do not establish a cross-platform memory ranking or detector accuracy.
