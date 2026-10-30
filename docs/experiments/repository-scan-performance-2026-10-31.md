# Pinned repository scan performance cohort

- Date: 2026-10-31
- FUSE version: 0.2.0
- FUSE revision: `0f11e7c7b47b6ba25ff80f41fab458253ad0cac9`
- Machine: Windows 11, AMD64, 16 logical CPUs
- Python: 3.14.7

## Question

Measure repeatability and wall time for FUSE native scans over selected, pinned embedded and IoT repository scopes. This is a descriptive performance check, not a detector-accuracy study or a claim that any candidate signal is exploitable.

## Inputs and method

The cohort is defined in [`fresh-validation-next/manifest.json`](../../reports/repository-scans/fresh-validation-next/manifest.json). Its SHA-256 is `54b20ddf020082931efb8699fce070547dfe0c808b47441e7ea127670fac24cf`. Each local checkout was verified clean and at its pinned commit before measurement. The complete recorded output, including repository commit IDs and all timing samples, is [`repository-scan-performance.json`](../../reports/benchmark/repository-scan-performance.json).

FUSE ran one warm-up followed by three measured scans for each of four selected scopes. The report counts process startup and temporary report writing in wall time. Network access, SBOM generation, vulnerability database queries, firmware analysis, and Git history analysis were disabled. Native rules and the enabled static inventory checks ran. Counts, bytes, findings, discovery status, native-analysis status, skip reasons, and exit status remained stable across each scope's measured repetitions.

Reproduce from the repository root after checking out the manifest's pinned repositories:

```powershell
python scripts/benchmark_repository_cohort.py `
  --manifest reports/repository-scans/fresh-validation-next/manifest.json `
  --checkouts ..\fuse-scan-targets-fresh-validation-next `
  --warmups 1 `
  --repetitions 3 `
  --output reports/benchmark/repository-scan-performance.json
```

## Results

| Selected scope | Files scanned | Source bytes | Measured wall time samples | Median | MAD | Candidate signals | Skipped files | Native analysis | Exit |
| --- | ---: | ---: | --- | ---: | ---: | ---: | --- | --- | ---: |
| Apache Mynewt Core | 3,354 | 23,149,934 | 13.349, 13.918, 13.404 s | 13.404 s | 0.055 s | 0 | 1 too large | Partial | 2 |
| Mbed TLS | 121 | 3,062,060 | 2.498, 2.538, 2.401 s | 2.498 s | 0.040 s | 0 | 0 | Completed | 0 |
| OpenThread | 909 | 13,485,203 | 5.224, 5.305, 5.377 s | 5.305 s | 0.072 s | 5 | 0 | Completed | 0 |
| ESP-IoT-Solution | 3,885 | 37,088,151 | 11.258, 10.538, 10.558 s | 10.558 s | 0.020 s | 21 | 3 too large | Partial | 2 |

Discovery completed for all four scopes. Mynewt Core and ESP-IoT-Solution each skipped selected files because they exceeded FUSE's configured per-file size limit. Their native analysis status is partial, and the CLI returned status 2. Complete discovery means FUSE finished enumerating the configured scope. It does not mean every selected file was analyzed.

OpenThread and ESP-IoT-Solution produced 26 raw candidate signals combined. These have not been adjudicated by this experiment and are not confirmed vulnerabilities. Zero signals in the other scopes do not establish that those projects are secure.

## Limits

- Only the manifest's selected paths and pinned revisions were measured, not each repository's complete contents.
- One Windows machine was measured. These numbers are not a cross-platform comparison or a general speed claim.
- One warm-up reduces first-run effects but does not establish cold-cache performance. The experiment did not control the operating system's file cache.
- Memory use, CPU utilization, build time, device runtime, firmware behavior, and hardware were not measured.
- Network-dependent and optional external analyzers were disabled.
- Candidate signal counts describe scan output. No false-positive, recall, exploitability, reachability, or accuracy conclusion follows from them.
- Two scopes were partial due to oversized files. The full skip details and native-analysis status are retained in the versioned JSON report.

## Outcome

FUSE completed repeatable native analysis of the configured scopes on this machine, with measured medians from 2.498 to 13.404 seconds. The report now retains enough coverage detail to distinguish completed native analysis from complete file discovery. Cross-platform performance measurement and independent finding adjudication remain future work.
