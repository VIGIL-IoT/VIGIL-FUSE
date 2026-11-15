# ESP-IDF configuration applicability review protocol

Status: protocol frozen before selecting the configuration review sample.

## Purpose and limits

This is a post-scan emitted-candidate supplement for FUSE006 and FUSE007. The earlier ESP-IoT-Solution scan and its candidate findings already exist, so this is not a blind holdout, an independent accuracy evaluation, or a representative estimate of field precision or recall. This protocol separates the presence of a rule condition from whether a configuration is effective for a built or deployed product.

## Pinned source and prior scan

- Repository: `espressif/esp-iot-solution`
- Source commit: `35b831cfa84d132d66cb88f7b6f131632ed4f726`
- Prior report: `reports/repository-scans/fresh-validation-next/reports/esp-iot-solution/findings.json`
- Prior scan manifest: `reports/repository-scans/fresh-validation-next/manifest.json`
- Existing FUSE revision: the historical report identifies version 0.2.0 and a dirty source tree. The exact dirty tree was not archived, so exact scan replay and exact detector revision verification are unavailable.

## Population and selection

The population is every source-controlled file at the pinned commit whose basename is `sdkconfig.defaults` or begins with `sdkconfig.defaults.`. Generated `sdkconfig` build outputs are a separate stratum. Include every emitted FUSE006 or FUSE007 candidate path from the prior report. From the remaining population, select up to eight unsuffixed defaults and up to eight target-specific defaults. Select each control stratum by ascending SHA-256 of `fuse-2026-11-15-esp-idf-config-applicability-v1`, a NUL byte, and the repository-relative POSIX path. Break a hash tie by path. If a stratum has fewer than eight files, include every file in it. Record the full population counts and selected file hashes before running any new FUSE scan.

No generated effective configuration was included in the source-only prior scan. Record whether any generated `sdkconfig` is tracked at this commit. Do not infer that a `sdkconfig.defaults` candidate is effective for a release build. If no generated configuration exists in the pinned source, the generated-configuration stratum remains empty and applicability remains unknown until a build configuration is reviewed.

## Review procedure

Review the full pinned repository context for each selected file. For each case, assess FUSE006 and FUSE007 separately, including cases without a prior finding. Record the narrow condition decision, source line evidence, confidence, and applicability as separate fields. Applicability choices are `effective`, `candidate`, `not applicable`, or `unknown`; give repository or build evidence for any choice other than `unknown`. A default file alone supports at most `candidate`. Do not infer deployed vulnerability from a setting or an example configuration.

Two reviewers must work independently and leave no unresolved fields when submitting. Keep both reviewer forms blank until reviewers complete them. Adjudication stays blank until both forms are locked. No reviewer decision or accuracy metric is supplied by this protocol.

## Reproduction and preservation

Use the stored selection manifest, case list, and hashes to reproduce the sample. Do not alter the November 14 evaluation, its holdout selection, or its reviewer packets. Keep this supplement separate. Any later rule tuning based on its reviews removes even the supplement's qualitative independence. This sample cannot support field precision or recall because it is an enriched, post-scan sample and has no independent adjudication yet.
