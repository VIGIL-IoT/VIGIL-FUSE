# FUSE multi-repository evaluation, 14 November 2026

A VIGIL Project. This is a source-only regression replay of four previously reviewed scopes, selected for autopilot, RTOS, embedded Linux, and radio-firmware diversity. It is not a blind sample or an accuracy benchmark.

## Evidence and results

- [Manifest](manifest.json): pinned upstream commits, include paths, profiles and clean scanner-source provenance.
- [Raw reports](reports/): original JSON, text and SARIF outputs.
- [Publication source](publication/report.tex), [generated metrics](publication/metrics.json), and Matplotlib charts.
- [Hosted PDF](https://vigil-iot.github.io/VIGIL-FUSE/report.pdf), rebuilt by the report-pages workflow.

| Project | Scanned / selected | Raw findings | Coverage |
| --- | ---: | ---: | --- |
| ArduPilot | 260 / 260 | 0 | Complete for selected scope |
| RT-Thread | 2,126 / 2,127 | 1 | Partial, size cap |
| OpenBMC | 230 / 230 | 0 | Complete for selected scope |
| Meshtastic | 1,731 / 1,731 | 2 | Partial, unresolved metadata interpolation |

Total: 4,347 / 4,348 selected files, three candidate findings. Severity: one high, two medium. Confidence is separate. Findings remain unchanged from the 12 November replay. The PlatformIO fix increases Meshtastic's inventoried configuration files from 32 to 217 and declared environments from 22 to 277. None of those environments or boards was built or tested. Unknown interpolation remains explicitly partial.

## Run record and controls

Scanner source commit: `933137804087` (full revision and source hash in manifest). Windows, Python 3.14, Matplotlib 3.10.8. The manifest and selected scopes were frozen before scanning. Existing upstream checkouts were verified clean and at the recorded commits; they were not updated. No target code, build scripts, firmware, or optional analyzers ran. Scans used the existing offline runner. The prior 12 November reports are the baseline. Metrics are descriptive counts, with no accuracy or timing inference.

Regression checks: 354 tests and 157 subtests passed, one skipped. PlatformIO tests cover common sections, override order, multiline defaults, cycles, unexpanded variables and a 200-environment matrix. Ruff and strict Mypy passed for the engine change. The raw signals were previously source-reviewed; this replay does not provide a new independent adjudication. Missing-vulnerability rates remain unknown.

## Reproduce

Use clean checkouts named by repository ID inside `<checkouts>` at the exact manifest commits. From the FUSE repository root:

```sh
python -m pip install -e ".[test]"
python scripts/run_repository_scan_pilot.py <checkouts> --manifest reports/repository-scans/multi-repository-2026-11-14/manifest.json --report-root reports/repository-scans/multi-repository-2026-11-14/reports
python -m pip install matplotlib==3.10.8
python scripts/build_multi_repository_report.py
cd reports/repository-scans/multi-repository-2026-11-14/publication
pdflatex -no-shell-escape -interaction=nonstopmode -halt-on-error report.tex
pdflatex -no-shell-escape -interaction=nonstopmode -halt-on-error report.tex
```

The runner refreshes scanner provenance on reruns. Save new runs separately to retain this historical evidence. Figures and tables read recorded reports; the publication workflow does not silently rescan upstream repositories. The PDF workflow runs on relevant pushes, pull requests and manual dispatch. Pull requests produce a downloadable artifact; main publishes the PDF to GitHub Pages. TeX auxiliary files remain build artifacts.

## Research sources

- [PlatformIO inheritance](https://docs.platformio.org/en/latest/projectconf/sections/env/options/advanced/extends.html): literal common-section and ordered parent behavior.
- [PlatformIO extra configurations](https://docs.platformio.org/en/latest/projectconf/sections/platformio/options/generic/extra_configs.html): shared configuration and override behavior.
- [PlatformIO interpolation](https://docs.platformio.org/en/latest/projectconf/interpolation.html): values may depend on host environment or other settings; unexpanded values cannot establish effective configuration.
- Official project repositories are linked in the manifest. The same scopes appeared in the previous [release replay](../release-0.3.0-transfer-2026-11-12/README.md).
- [GitHub Pages custom workflows](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages) documents artifact deployment and required permissions.

The preceding research pass retrieved official documentation through Crawl4AI 0.9.5 using HTTPS fetch followed by raw HTML parsing. Source hashes and collection dates are preserved in [research-sources.json](research-sources.json); retrieved dates precede this replay. Raw third-party documentation is not republished.
