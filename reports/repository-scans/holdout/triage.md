# Independent holdout scan triage

Scan date: 2026-10-28. FUSE 0.2.0 scanned four repositories that do not appear in the rule-refinement manifest. Exact checkout commits and selected scopes are in [`manifest.json`](manifest.json); raw per-scope reports are under [`reports/`](reports/).

This is a purposive qualitative holdout, not an accuracy benchmark. No rules were changed in response to these results. No project was built, no release configuration was resolved, and no device or runtime behavior was tested. A static finding is a review signal, not a confirmed vulnerability.

## Snapshot

| Measure | Result |
| --- | ---: |
| Repositories | 4 |
| Scan scopes | 4 |
| Supported files discovered | 13,065 |
| Files selected by scope | 13,057 |
| Files scanned | 13,050 |
| Files skipped | 7 |
| Raw signals | 13 |
| High severity signals | 3 |
| Medium severity signals | 10 |
| Filename-matched hardware artifacts in selected sparse scopes | 1 |

The seven skipped files were three non-UTF-8 files and four files above FUSE's 2 MiB per-file limit. All reports are marked partial because those files were not analyzed. The single hardware filename match is described below and is a false positive. This inventory covers the selected sparse checkout paths, not every path in the full repositories.

| Repository | Files scanned | Signals | Status |
| --- | ---: | ---: | --- |
| RIOT-OS/RIOT | 7,513 | 0 | Partial |
| contiki-ng/contiki-ng | 2,189 | 4 | Partial |
| bitcraze/crazyflie-firmware | 737 | 2 | Partial |
| MarlinFirmware/Marlin | 2,611 | 7 | Partial |

Rule counts were FUSE001: 10, FUSE002: 2, FUSE003: 1, FUSE004: 0, FUSE005: 0, FUSE006: 0, and FUSE007: 0. Severity and confidence remain separate in each raw finding. These counts do not estimate precision or recall.

## Manual signal review

- **Contiki-NG, FUSE002, two private-key markers:** both markers occur in `examples/lwm2m-ipso-objects/project-conf-dtls.h` at lines 131 and 155, inside a DTLS example configuration. Marker detection is accurate, but the key material appears to be example material and the scan cannot establish build selection or deployment. Treat as a review candidate, not a confirmed exposed production key.
- **Contiki-NG, FUSE001, two credential-like literals:** matches occur in `examples/mqtt-client/mqtt-client.c:93` and `examples/mqtt-client/project-conf.h:73`. Both are in an MQTT example's token configuration. The example comments describe cleartext transport, which makes the context worth reviewing. FUSE cannot establish whether the literal values are valid credentials, placeholders, or used by a shipped build.
- **Crazyflie firmware, FUSE001, two matches:** `.token` is a parser token field for GPS sentence parsing, not an authentication credential. These are false positives caused by a generic credential-name heuristic.
- **Marlin, FUSE001, six matches:** `PASSWORD` appears in printer UI message identifiers and translated interface labels. No credential value is assigned. These are false positives caused by matching the identifier without enough semantic context.
- **Marlin, FUSE003, one match:** `verify=false` is a default boolean parameter for bed-tramming probe behavior. It does not configure TLS. This is a false positive caused by a generic verification-bypass pattern.
- **RIOT, hardware inventory, one match:** `drivers/Kconfig.net` was classified as an electronic netlist from its `.net` suffix. It is a Kconfig network-driver menu, not a hardware netlist. This is a filename-classification false positive.
- **RIOT, zero findings:** this means the enabled rules matched no selected input. It is not evidence that RIOT is secure or that the rules cover all relevant RIOT security issues.

## Refinement candidates for a later cycle

The initial holdout surfaced three false-positive patterns: credential-like identifiers used for parser tokens or UI labels, generic `verify=false` booleans unrelated to TLS, and `.net` filenames used by Kconfig. The reports and [`pre-refinement-manifest.json`](pre-refinement-manifest.json) preserve the original scanner snapshot. Follow-up changes add negative fixtures and are labeled as regression validation, not as a fresh blind holdout.

| Measure | Initial snapshot | Regression recheck |
| --- | ---: | ---: |
| Raw signals | 13 | 4 |
| FUSE001 | 10 | 2 |
| FUSE002 | 2 | 2 |
| FUSE003 | 1 | 0 |
| Hardware filename matches | 1 | 0 |
| Files scanned | 13,050 | 13,050 |

The eight removed FUSE001 signals were six UI-language constants and two NMEA parser tokens. The FUSE003 match was a bed-tramming parameter, not TLS. The hardware match was `drivers/Kconfig.net`, not a netlist. The four remaining signals are two credential-like assignments and two PEM markers in Contiki-NG examples. Their values and build/deployment applicability were not validated.

Missed-check rates cannot be inferred from this pass. The generic profile does not resolve active builds, selected boards, generated configuration, or runtime reachability. FUSE004 through FUSE007 had no matches in these scopes, but there were no controlled vulnerable examples in the holdout to measure those rules' recall. The hardware inventory is filename-based and limited to the sparse paths selected in the manifest.

## Reproduce and summarize

From the FUSE repository root:

```powershell
py scripts\run_repository_scan_pilot.py ..\fuse-scan-targets-holdout `
  --manifest reports\repository-scans\holdout\manifest.json `
  --report-root reports\repository-scans\holdout\reports

py scripts\build_holdout_scan_summary.py
```

The summary and SVG plots in this folder are kept out of the training corpus aggregate and website data.
