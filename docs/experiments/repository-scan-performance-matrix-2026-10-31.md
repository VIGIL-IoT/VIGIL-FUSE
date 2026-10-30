# Cross-platform pinned repository scan performance

- Date: 2026-10-31
- Workflow run: [41129068118](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41129068118)
- FUSE version: 0.2.0
- FUSE revision: `b033594881046eb35ddb6d1597a15ac97bd1e0ef`
- Manifest SHA-256: `cb75e3de0a9e5d7b3e97a3bd844dd9b5857f868e0cae4f4adff6a6732a30cfd1`

## Question

Can the same FUSE revision scan the same four pinned embedded and IoT repository scopes on GitHub-hosted Linux, Windows, and macOS runners while reporting consistent input and coverage metadata?

This is a reproducibility check. Its runner timings are descriptive samples, not a controlled ranking of operating systems or hardware.

## Inputs and method

The workflow used the four repositories and selected include patterns in [`fresh-validation-next/manifest.json`](../../reports/repository-scans/fresh-validation-next/manifest.json). Each target was sparsely checked out at its recorded commit. The preparer sets `core.autocrlf=false` and `core.eol=lf` before checkout, so text files use LF on every host. The manifest digest normalizes line endings, so equivalent manifest content has the same fingerprint across hosts.

Each scope received one warm-up and three measured scans. Network, SBOM generation, vulnerability database queries, firmware analysis, and Git history analysis were disabled. Native rules and static inventory checks were enabled. Every report passed the checked-in JSON Schema and was reviewed for source revision, manifest digest, repository commits, selected file counts, scan coverage, skips, and signal counts.

| GitHub runner | Report OS | Python | OS release | Architecture | Logical CPUs | Raw report |
| --- | --- | --- | --- | --- | ---: | --- |
| `ubuntu-latest` | Linux | 3.12.15 | 7.0.0-1017-azure | x86_64 | 4 | [JSON](../../reports/benchmark/repository-scan-performance-ubuntu-2026-10-31.json) |
| `windows-latest` | Windows | 3.12.10 | 2025Server | AMD64 | 4 | [JSON](../../reports/benchmark/repository-scan-performance-windows-2026-10-31.json) |
| `macos-latest` | Darwin | 3.12.10 | 25.6.0 | arm64 | 3 | [JSON](../../reports/benchmark/repository-scan-performance-macos-2026-10-31.json) |

## Results

Each timing cell gives the median of three measured scans and the median absolute deviation (MAD), in seconds.

| Selected scope | Linux median (MAD) | Windows median (MAD) | macOS median (MAD) | Files scanned / selected | Skips | Native analysis | Candidate signals |
| --- | ---: | ---: | ---: | ---: | --- | --- | ---: |
| Apache Mynewt Core | 5.427 (0.031) | 9.529 (0.069) | 6.051 (0.100) | 3,354 / 3,355 | 1 too large | Partial | 0 |
| Mbed TLS | 1.203 (0.008) | 1.696 (0.001) | 1.281 (0.023) | 121 / 121 | 0 | Completed | 0 |
| OpenThread | 1.966 (0.006) | 3.247 (0.020) | 2.250 (0.149) | 909 / 909 | 0 | Completed | 5 |
| ESP-IoT-Solution | 4.052 (0.019) | 8.135 (0.019) | 4.871 (0.230) | 3,886 / 3,888 | 2 too large | Partial | 19 |

The input fingerprint, pinned source commits, selected and scanned file counts, source-byte totals, skipped-file reasons, native-analysis status, and raw signal counts match across the three reports. An earlier run matched file counts but had a larger Windows OpenThread byte total because `core.eol=native` produced CRLF checkout files. The preparer now forces LF and refuses to reuse checkouts without the normalized settings. Two scopes were partial on every host because selected files exceeded FUSE's configured size limit. The 24 OpenThread and ESP-IoT-Solution signals are candidate matches, not confirmed vulnerabilities.

## Interpretation and limits

- There was one hosted runner per operating system. CPU architecture, runner image, operating-system release, Python patch version, available CPU allocation, and cache state differed. The medians must not be read as a controlled speed comparison.
- Three measured repetitions after one warm-up describe within-run timing spread only. They do not estimate long-term variance or cold-cache performance.
- No memory, CPU utilization, firmware execution, device behavior, or hardware-in-the-loop measurements were collected.
- The selected scopes are not full repository scans. Skipped oversized files remain visible, and partial analysis is not described as a completed full scan.
- Candidate signal counts do not measure precision, recall, exploitability, vulnerability prevalence, or whether any configuration reaches a deployed product.

## Reproduction

From the FUSE repository root, run:

```sh
gh workflow run repository-performance.yml --ref main
```

The workflow validates and uploads one schema-checked report per platform. The checked-in JSON files are the reviewed artifacts from run `41129068118`; the workflow itself does not commit or publish reports.

## Outcome

The pinned cohort was reproducible across the three runner operating systems after normalizing manifest hashes and target checkout line endings. This supports the reproducibility score update recorded in [`REPOSITORY_AUDIT.md`](../REPOSITORY_AUDIT.md). It does not establish a cross-platform performance ranking or detector accuracy.
