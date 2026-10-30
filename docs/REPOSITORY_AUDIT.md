# Repository audit

**Audit date:** 2026-10-31
**Repository:** VIGIL-IoT/VIGIL-FUSE
**Code baseline before this increment:** `953b786`
**Scope:** Source, package metadata, tests, CI, documentation, reports, static site, figures, tags, license, badges, and locally available validation tools.

## Repository overview

FUSE is a CLI-first Python tool for bounded static inspection of embedded and IoT project source, configuration, selected build metadata, hardware artifacts, dependency inventories, and firmware candidates. It is part of VIGIL-IoT and complements SPECTRA-32's controlled lab experiments. FUSE does not itself build projects, execute scanned source or firmware, contact devices, or validate physical hardware.

The package has no required runtime dependencies, seven native rules, schema-versioned reports, optional external analyzer adapters, a static project site, and pinned repository scan evidence. The project is alpha software, version `0.2.0`, under a custom source-available restricted-use license. It is not OSI-approved open-source software.

## Initial condition

At the start of this audit pass, the workspace already contained substantial local engineering changes from the preceding improvement pass: hardened KiCad parsing and terminal output, the FUSE003 Python AST check, focused analyzer modules, a synthetic fixture scorecard, expanded tests, a 70% branch coverage gate, and release and threat-model documentation. The current baseline was stronger than the public tagged source alone.

Remaining gaps at the start of this pass were primarily project-level traceability and governance: no consolidated requirements and objective record, no end-to-end methodology, no dedicated limitations or benchmark overview, no requirement-to-evidence matrix, no ADR set, no formal evaluation protocol, no citation metadata, no root contribution guidance, and no automated local-link or Mermaid-block check.

## Major problems found

- The rich implementation and research evidence were spread across README, roadmap, architecture notes, and report folders, making it difficult to distinguish requirements, measured results, and planned work.
- No single traceability table connected objectives to code, tests, and evidence.
- There was no consolidated limitations page or experiment-style record for the repository scan cohort.
- Mermaid diagrams and local Markdown links had no repository validation gate.
- Citation metadata and GitHub issue/PR templates were absent.
- The current license restricts redistribution and package-registry uploads without written permission. This is a substantive release blocker, not a code defect.
- The public latest release endpoint reports `v0.2.0`, matching the local tag.

## Architecture findings

The `src/vigil_fuse/` package separates CLI, discovery, models, rule execution, native rules, platform context, hardware and firmware inventories, optional analyzers, and reporters. The `analyzers.py` compatibility facade preserves public import paths while optional tool implementations live in focused modules. The local CLI is the deployment boundary; `site/` is a static informational site, not a FUSE service.

FUSE's core analysis is bounded and read-only. Native rules operate on decoded selected text in a worker process with timeouts. Context adapters read selected metadata. Optional external programs are invoked only when selected and are not sandboxed by FUSE. Findings separate severity, confidence, applicability, and validation state. New Mermaid diagrams document the actual input, processing, reporting, and hardware boundaries.

## Improvements implemented

- Added project identity, problem, scope, functional and nonfunctional requirements, measurable objectives, assumptions, constraints, technology stack, and maturity boundaries.
- Added implementation methodology, explicit limitations, benchmark interpretation, repository structure, SBOM instructions, and requirements traceability.
- Added a dated descriptive repository-scan evaluation record that distinguishes observations from controlled experiments and field accuracy.
- Added four retrospective ADRs. Each identifies its rationale as retrospective rather than claiming unavailable historical intent.
- Added Mermaid system, sequence, module dependency, static-site configuration, and hardware-software boundary diagrams. The six diagrams were rendered and visually reviewed. No separate Diagram Design or ManimGX artifact was added because the editable Mermaid views, Archify scan flow, and Anatomy finding illustration already cover the repository's current explanatory needs.
- Added `CITATION.cff`, a root `CONTRIBUTING.md`, GitHub issue forms, and a pull request template without changing the license.
- Added `scripts/validate_docs.py` and tests for local links and Mermaid fence structure; CI runs this documentation validation.
- Added a generated Anatomy-style finding model in dark and light SVG, plus a self-contained interactive view. It shows severity, confidence, applicability, and validation as separate fields. The locally vendored drawing kit is pinned in `scripts/vendor/anatomy/NOTICE.md`.
- Replaced the single README CI badge with verified Shields.io CI, release, Python-version, and custom-license badges. No PyPI or coverage badge is shown because those would imply unsupported publication or reporting setup.
- Added an Unreleased changelog section and roadmap horizons for immediate, short-term, medium-term, and long-term work.
- Added weekly Dependabot checks for pip and GitHub Actions, plus a separate dependency-audit workflow using pip-audit. The first audit identified the vulnerable pytest 8.x range and led to raising the test floor to 9.0.3.
- Updated the static site to describe FUSE's present analysis scope, remove the planned external lab handoff, and use a shared vertical-spacing scale across major sections.
- Added Mypy 2.4.1 as a development dependency and a strict type-checking CI gate across all 44 source modules plus four benchmark/preparation scripts. Strict Mypy passes without suppressing diagnostics.
- Added deterministic synthetic and pinned-repository performance harnesses with versioned report schemas, repeated wall-time samples, and sampled process-tree RSS for real repository scans. CI verifies both benchmark paths. The measurements are descriptive and make no general speed or accuracy claim.
- Added a manifest-driven sparse-checkout preparer and a manually dispatched Ubuntu, Windows, and macOS workflow for the same four pinned repository scopes. Runs `41130740188` and `41136062930` each passed all three platform jobs; both normalized, memory-sampled result sets are checked in and compared in a same-day repeat record.
- Added a CI gate that renders every Markdown Mermaid block with a pinned Mermaid CLI container image and validates the generated SVG XML, so diagram syntax errors are caught before merge.
- Added a manually dispatched [Ubuntu and Windows workflow](../.github/workflows/binwalk-adapter.yml) that builds Binwalk v3.1.0 from a pinned upstream commit and runs the adapter's gzip positive, clean control, and no-extraction checks. The first build attempt exposed upstream warnings promoted to errors by the Rust setup action; after disabling that warning promotion, [run 41134907521](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41134907521) passed on both systems. The [experiment record](experiments/binwalk-v3.1-cross-platform-2026-10-31.md) limits this to one synthetic signature.
- Verified Syft 1.55.0 and OSV-Scanner 2.7.0 against positive, clean, and no-package-source fixtures. Fixed the OSV adapter's handling of the real CLI's exit-128 no-source response and added a repeatable harness plus experiment record.
- Verified the Binwalk v2.3.3 identification adapter in WSL2 with a synthetic gzip positive and clean control. Added bounded help-banner version detection, a repeatable smoke harness, a regression test, and an experiment record. This is not a firmware-accuracy study.
- Hardened optional analyzer timeout and output-limit cleanup to terminate a dedicated POSIX process group or request Windows child-tree termination through the system `taskkill` utility. Regression tests check that delayed descendants do not survive either path. This is best-effort cleanup, not process isolation or a sandbox.
- Manually reviewed the 23 signals in the separately pinned second fresh-validation snapshot. Added grouped, source-context dispositions while preserving redaction and stating that the review is not independent accuracy evidence. Placeholder-looking defaults remain candidates because an unchanged example can still be built.
- Preserved earlier engineering changes already in the workspace: analyzer module split, XML hardening, terminal control handling, subprocess input isolation, FUSE003 AST analysis, fixture benchmark, and stronger CI/package checks.

## Files added

- `CITATION.cff`, `CONTRIBUTING.md`, `.github/dependabot.yml`, `.github/workflows/dependency-audit.yml`
- `.github/ISSUE_TEMPLATE/bug_report.yml`, `.github/ISSUE_TEMPLATE/feature_request.yml`, `.github/PULL_REQUEST_TEMPLATE.md`
- `docs/REPOSITORY_AUDIT.md`, `docs/requirements.md`, `docs/methodology.md`, `docs/limitations.md`, `docs/traceability.md`, `docs/benchmarks.md`, `docs/repository-structure.md`, `docs/sbom.md`
- `docs/experiments/pilot-scan-2026-10.md`, `docs/experiments/dependency-adapters-e2e-2026-10-31.md`, `docs/experiments/binwalk-adapter-e2e-2026-10-31.md`, `docs/experiments/binwalk-v3.1-cross-platform-2026-10-31.md`, `docs/experiments/repository-scan-performance-matrix-2026-10-31.md`, `docs/experiments/repository-scan-performance-repeat-2026-10-31.md`, `reports/repository-scans/fresh-validation-next/triage.md`
- `docs/decisions/ADR-0001-cli-first-package.md`, `ADR-0002-bounded-non-executing-analysis.md`, `ADR-0003-normalized-findings-and-coverage.md`, `ADR-0004-optional-tool-adapters.md`
- `scripts/validate_docs.py`, `scripts/verify_dependency_adapters.py`, `scripts/verify_binwalk_adapter.py`, `scripts/prepare_repository_benchmark_cohort.py`, `tests/test_docs_validation.py`, `tests/test_dependency_policy.py`, `tests/test_repository_performance_workflow.py`, `tests/test_binwalk_adapter_workflow.py`, `tests/test_binwalk_verification.py`, `.github/workflows/repository-performance.yml`, `.github/workflows/binwalk-adapter.yml`
- `scripts/benchmark_scan.py`, `scripts/benchmark_process.py`, `tests/test_performance_benchmark.py`, `reports/benchmark/scan-performance.json`, `reports/benchmark/scan-performance.schema.json`
- `reports/benchmark/repository-scan-performance-ubuntu-2026-10-31.json`, `repository-scan-performance-windows-2026-10-31.json`, `repository-scan-performance-macos-2026-10-31.json`
- `reports/benchmark/repository-scan-performance-ubuntu-repeat-2026-10-31.json`, `repository-scan-performance-windows-repeat-2026-10-31.json`, `repository-scan-performance-macos-repeat-2026-10-31.json`
- `scripts/build_finding_model_figure.mjs`, `scripts/vendor/anatomy/iso-kit.mjs`, `scripts/vendor/anatomy/LICENSE`, `scripts/vendor/anatomy/NOTICE.md`
- `docs/figures/fuse-finding-model.svg`, `docs/figures/fuse-finding-model-light.svg`, `site/diagrams/fuse-finding-model.html`
- Earlier workspace additions include focused analyzer modules, the native-rule fixture evaluator, rule fixtures, and `reports/benchmark/native-rule-fixtures.json`.

## Files modified

- `README.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `.github/workflows/ci.yml`, `.github/workflows/repository-performance.yml`, `.github/workflows/binwalk-adapter.yml`, `pyproject.toml`, `scripts/benchmark_scan.py`, `scripts/benchmark_repository_cohort.py`, `scripts/benchmark_process.py`, `src/vigil_fuse/analyzer_runtime.py`, `tests/test_analyzers.py`, `docs/architecture.md`, `docs/benchmarks.md`, `docs/traceability.md`, `docs/limitations.md`, `docs/threat-model.md`, `docs/experiments/repository-scan-performance-2026-10-31.md`, `docs/experiments/repository-scan-performance-repeat-2026-10-31.md`, `reports/benchmark/repository-scan-performance.json`, `reports/benchmark/repository-scan-performance.schema.json`, `tests/test_performance_benchmark.py`, `tests/test_repository_benchmark.py`, `tests/test_repository_performance_workflow.py`, `tests/test_binwalk_adapter_workflow.py`, `tests/test_binwalk_verification.py`, `docs/contributing.md`, `docs/experiments/binwalk-v3.1-cross-platform-2026-10-31.md`, `docs/methodology.md`, `docs/requirements.md`, `docs/repository-structure.md`, `docs/sbom.md`, `docs/roadmap.md`, `docs/website.md`, and the static site files under `site/`
- The prior increments modified the Binwalk adapter and its verification docs; this increment adds manual review in `reports/repository-scans/fresh-validation-next/triage.md` and updates the cohort README, `docs/detection-benchmark.md`, and this audit record. Earlier engineering changes also touch `.gitignore`, `SECURITY.md`, `pyproject.toml`, scanner and analyzer modules, native TLS rule, reporting, terminal safety, parser and product context code, related tests, and report-building scripts.
- `LICENSE` was not modified.

## Testing performed

- FUSE CI run [41134897292](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41134897292) passed all eight jobs on `d873da6`, including strict Mypy, pinned Mermaid rendering, documentation and path checks, package smoke, self-scan, and cross-platform tests. The separate Binwalk adapter run [41134907521](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41134907521) passed on Ubuntu and native Windows. Performance repeat run [41136062930](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41136062930) passed on Ubuntu, Windows, and macOS, and its three reports passed schema validation before upload.
- Analyzer process-tree regression checks spawn delayed descendants and verify that timeout and output-limit cleanup stop them before they write to disk. FUSE CI run [41137996788](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41137996788) passed these checks on Windows, Ubuntu Python 3.11 through 3.14, and macOS.

- The Syft/OSV adapter increment passed local `unittest` discovery with 182 test methods, Ruff lint and formatting across 76 files, Markdown validation across 55 files, and the path audit across 504 tracked files and Git history. This Python environment did not include pytest or Mypy, so the configured CI jobs remain authoritative for those gates.
- The Binwalk increment passed local `unittest` discovery with 183 test methods, Ruff lint and formatting across `src`, `tests`, and `scripts`, Markdown validation across 56 files, and the path audit across 506 tracked files and Git history. The real Binwalk v2.3.3 WSL2 smoke check passed before this documentation refresh; its temporary package extraction is not currently on `PATH`.
- FUSE CI run `41118660790` passed all eight jobs for `bd471b1`, including Ubuntu, Windows, and macOS test jobs, strict Mypy, repository path checks, documentation validation, package installation, and branch coverage. The second fresh-validation cohort's 23 findings were manually reviewed against clean checkouts at their pinned commits; this is a source-context review, not an independent evaluation.
- FUSE CI run `41119431946` passed all eight jobs for `953b786`, including the manual-triage documentation links, repository path check, package installation, platform tests, strict Mypy, and branch coverage.
- This documentation increment passed Markdown validation across 57 files, the repository path audit across 509 tracked files and Git history, and `git diff --check`.
- The pinned repository cohort increment passed 202 local pytest tests plus 81 subtests, Ruff, strict Mypy, fixture benchmark validation, documentation validation, report-schema validation, and the personal-path audit. Its three sequential commits each passed their FUSE CI workflow.
- Cross-platform workflow runs `41125057256` and `41125641349` exposed package-install and line-ending reproducibility defects. Run `41127695206` passed all three jobs, but later review found its Windows OpenThread byte total differed because `core.eol=native` checked out CRLF despite `core.autocrlf=false`. The preparer now sets `core.eol=lf`, rejects reused checkouts without both normalized settings, and has regression coverage. Run `41129068118` confirmed identical input and coverage metadata. Run `41130740188` added process-tree RSS measurements; all three platforms reported matching source bytes and coverage and complete memory samples with zero inaccessible process readings.
- Code validation at commit `a9ada02`: 209 pytest tests and 91 subtests, Ruff formatting and lint, strict Mypy across 47 files, 58 Markdown files, fixture benchmark, Git diff check, and personal-path audit. The same commit passed FUSE CI run `41127682418`. The line-ending follow-up at `b033594` passed 12 focused tests, 17 subtests, Ruff, FUSE CI run `41129056946`, and cross-platform benchmark run `41129068118`. The memory-sampling follow-up at `fa600e0` passed 20 focused tests, 20 subtests, Ruff, strict Mypy across 48 files, FUSE CI run `41130729326`, and cross-platform benchmark run `41130740188`.
- Full pytest suite, including dependency policy and docs validation tests, plus the focused security and input-handling subset.
- Branch-aware coverage report and threshold check.
- Ruff lint and focused formatting check.
- Synthetic native-rule fixture benchmark.
- Local Markdown path and Mermaid block validation.
- Mermaid rendering follow-up on 2026-10-31: rendered the one README diagram and all five diagrams in `docs/architecture.md` with Mermaid 12.0.0 in headless Chromium. All six produced SVGs and were visually inspected at desktop width. Labels and connectors were legible, with no clipping. GitHub's architecture page lazy-loads its diagram frames; after scrolling and waiting for hydration, all five diagrams rendered.
- Gitleaks history adapter end-to-end check on 2026-10-31: verified the official Gitleaks 8.30.0 Windows x64 release asset by SHA-256, then ran a synthetic positive fixture and clean control. The positive case returned two redacted signals, the clean control returned none, and the generated value was absent from every report and captured output. The reproducible harness and limits are in [the experiment record](experiments/gitleaks-adapter-e2e-2026-10-31.md) and [verification script](../scripts/verify_gitleaks_adapter.py).
- Syft and OSV-Scanner end-to-end check on 2026-10-31: verified the official Syft 1.55.0 and OSV-Scanner 2.7.0 Windows x64 asset SHA-256 digests, then ran a vulnerable dependency, a clean dependency control, and a no-package-source project through FUSE. The first two produced 11 and zero OSV findings with completed adapter status. The no-source case produced the expected partial OSV status, no fabricated results artifact, and CLI exit code 2. See the [experiment record](experiments/dependency-adapters-e2e-2026-10-31.md) and [verification script](../scripts/verify_dependency_adapters.py).
- YAML parsing for workflow and issue-form configuration; citation metadata YAML parsing.
- Package wheel and source distribution build, Twine metadata check, clean virtual environment wheel install, CLI version/doctor/help checks, and installed-package scan smoke test.
- FUSE local self-scan with network and optional external analyzers disabled: discovery completed across 235 selected files with zero findings; the report inventoried three hardware artifacts.
- pip-audit against an isolated virtual environment created from the declared development extras.
- Git diff whitespace check and changed-file punctuation review.
- Anatomy generator syntax, generated inline JavaScript parsing, SVG XML structure, and Shields.io badge response checks.
- Static-site screenshots reviewed at 1440, 768, and 390 pixel widths. The browser reported no console errors or horizontal overflow. The desktop full-page inspector returned a load timeout after producing screenshots; its separate style heuristics still report 8 failures and 5 warnings, including the intentionally scrollable report-fragment row.
- Website visual follow-up on 2026-10-30: raised the small text scale, removed chart index labels and excess metric dividers, improved tablet metric layout and dark-theme link contrast, and corrected the scan date context. The scoped Taste linter reports 0 failures and 0 warnings. Browser review at 1440x900, 768x1024, and 390x844 found no page overflow or console errors. The theme toggle, report carousel, repository and capability disclosures, and embedded dark Archify workflow were exercised. The separate finding model was rendered in dark and light themes, its severity and confidence controls were changed independently, and its mobile corner-label overlap was fixed in the generator. The full-page Taste inspector saved screenshots but stalled before writing its report, so no automated visual score is claimed.
- Strict Mypy checking of all 44 source modules and four benchmark/preparation scripts using the same configuration run by CI.
- Deterministic 128-file scan benchmark with one warm-up, five measured runs, complete discovery, zero findings, and sampled process-tree RSS.
- JSON Schema validation of the saved performance report and process-free schema validation in the benchmark test.

## Test results

For the preceding dependency adapter increment, local `python -m unittest discover -s tests` passed 182 test methods, including the no-package regression test. The real-tool harness passed with Syft 1.55.0 and OSV-Scanner 2.7.0, returning 11 positive findings, zero clean-control findings, and the expected partial status for a project without package sources. The Binwalk increment added one regression test and passed all 183 local test methods. Its real-tool harness passed with Binwalk v2.3.3, detecting the gzip signature in the positive control only, recording the version, and producing no extraction output. FUSE CI run `41118660790` passed all eight jobs for `bd471b1`. The second fresh-validation cohort contained 23 signals; all were reviewed against pinned source context and categorized without asserting exploitability, credential validity, or release applicability. FUSE CI run `41119431946` then passed all eight jobs for `953b786`, including the docs-only triage increment.

The full suite passes locally with **225 tests** and **93 subtests** on Windows and Python 3.14.7 using pytest 9.2.0; one upstream AnyIO deprecation warning remains. Workflow run #231 on `ee957cf` passed all eight jobs, all **187 tests**, and measured **75%** branch-aware coverage against the 70% gate. Adding PyYAML to the test extra enabled all four ESP-IDF YAML checks in CI. The synthetic fixture benchmark reports 16 cases across seven native rules, all matching their labels; these are synthetic fixtures and do not measure field accuracy. The documentation validator uses Git's tracked and non-ignored untracked file list, so local validation covers 61 Markdown files at the current documentation state. Package build and clean-install smoke checks passed on `dd1c043`. Run #232 on `1ade772` passed all eight jobs with **190 tests**, **73 subtests**, and **75%** branch-aware coverage. Its quality job scanned 206 files with zero findings, validated 53 Markdown files, and passed the path audit over 497 tracked files and Git history. The Python dependency audit found no known vulnerabilities in the resolved development dependencies and skipped the editable FUSE checkout itself. Runs #237 on `5bf4d69`, #238 on `54e9359`, #239 on `afaa7ad`, #240 on `c6f7f5d`, and #241 on `17cd1ff` passed all eight CI jobs; corresponding Vercel checks succeeded for the website changes and latest revision. Run #239 passed strict Mypy on the 10 native-rule modules. Run #241 passed strict Mypy on the 11 configured source files, and all 14 baseline-focused tests passed locally. The separate dependency audit for `17cd1ff` passed. The Anatomy builder reports 56 named parts; the generator, inline JavaScript, and both SVG files pass structural checks. Type-checking increments through run #255 on `2a9d548` passed FUSE CI and the separate Python dependency audit. Run #256 on `683c190` passed with the expanded 23-file strict Mypy gate. Run #257 on `d451213` passed with strict Mypy covering all 44 source modules, and dependency audit #19 for the same revision also succeeded. Run #260 on `b2f971a` passed the platform test matrix, the benchmark smoke check, strict Mypy on the 44 source modules plus the benchmark script, the 70% coverage gate, package smoke, path and documentation validation, and the self-scan. Python dependency audit #20 for the same revision passed. FUSE CI runs #41106198114 for `1b9acdb` and #41109722395 for `2c5afa8` each passed all eight configured jobs across Ubuntu, Windows, and macOS. Commit `a9ada02` passed the current 209-test suite, strict Mypy over 47 files, and FUSE CI run `41127682418`. Cross-platform benchmark run `41129068118` passed on all three operating systems with equal per-scope byte totals and coverage metadata. The current FUSE self-scan completed discovery across 235 selected files with zero findings. The analyzer process-tree increment added two regression cases, and the full local Windows suite now passes 225 tests and 93 subtests. Strict Mypy passes all 49 source files, Ruff checks and formatting pass, Markdown validation covers 61 files, and the path audit passes across 532 tracked files and Git history.

FUSE CI run [41134897292](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41134897292) passed all eight jobs on d873da6, including the 49-file strict Mypy gate, pinned Mermaid rendering, path and documentation checks, package smoke, self-scan, and cross-platform test matrix. The separate Binwalk adapter run [41134907521](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41134907521) passed on Ubuntu and native Windows.

FUSE CI run [41137996788](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41137996788) passed all eight jobs on `7bcacbf`. This run includes the new optional-analyzer descendant cleanup checks on Windows, Ubuntu Python 3.11 through 3.14, and macOS, along with strict Mypy, documentation and path validation, package smoke, self-scan, and branch-aware coverage.

The saved synthetic performance baseline is pinned to `00bb3f2`, Windows 11 build `10.0.26300`, Python 3.14.7, and psutil 7.2.2. It scans 128 generated files and 8,990 bytes with one warm-up and five measured runs. Median wall time was **1.192724 seconds**, with **107.317 files/second** and maximum sampled process-tree RSS of **52,838,400 bytes**. Discovery completed and no findings were produced. These are descriptive measurements for one synthetic input on one machine, not field performance claims. The report and its JSON Schema are checked in under `reports/benchmark/`.

The original full-tree Ruff check identified 42 files for reformatting. Four were formatted with the path fix, and the remaining 38 are formatted in `121c74e`. CI now checks formatting across all Python files under `src`, `tests`, and `scripts`. Run #226 on `0f8d4ef` failed documentation validation because the README linked to supporting docs not yet in that commit. The docs increment resolved those links, and run #227 on `dd1c043` succeeded. Run #228 on `d219d1e` exercised the new Windows and macOS Python 3.11 jobs and exposed path-alias failures in four tests on each OS. The fix uses file identity to recognize OS aliases to the project root, checks in-target path components for symlinks, and adds regression cases for both behaviors. Run #229 on `fd15878` passed all eight jobs across Ubuntu Python 3.11 to 3.14, Windows Python 3.11, macOS Python 3.11, quality, and package smoke. The next run on `121c74e` also passed all eight jobs, including full-tree formatting and YAML-enabled tests. The subsequent website and finding-model browser checks are recorded above.

FUSE CI run [41133270780](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41133270780) for `c483140` passed all eight jobs. Its quality job rendered all six Mermaid diagrams with the pinned renderer image, ran strict Mypy and Ruff, passed the documentation and path checks, completed the FUSE self-scan, and met the 70% branch coverage gate. The package build/install smoke job and the Ubuntu, Windows, and macOS test jobs also passed.

## Security findings

- No license changes or credentials were introduced by this pass. FUSE's own self-scan and focused security tests are part of local validation.
- pip-audit found `PYSEC-2026-1845` / `CVE-2025-71176` in pytest 8.4.2. The [GitHub-reviewed advisory](https://github.com/advisories/GHSA-6w46-j5rx-g56g) marks versions below 9.0.3 affected, and [pytest 9.0.3 release notes](https://github.com/pytest-dev/pytest/releases/tag/9.0.3) list the fix. FUSE's test and development extras now require pytest `>=9.0.3,<10`.
- KiCad XML parsing rejects DTD/entity declarations and enforces size, element, and depth limits. Terminal output escapes control and bidi characters. Optional analyzer subprocesses receive no inherited interactive stdin.
- The rule and scan reports are candidate evidence. They do not prove exploitability, reachability, or deployed-product applicability.
- External analyzers parse their own inputs and are not sandboxed. Gitleaks 8.30.0, Syft 1.55.0, OSV-Scanner 2.7.0, and Binwalk v2.3.3 passed bounded local smoke checks with synthetic fixtures. The v2.3.3 check covered WSL2 Ubuntu; v3.1.0 passed one synthetic gzip smoke on hosted Ubuntu and native Windows. These checks do not establish detector accuracy, credential validity, exploitability, or reachability.
- The custom license permits commercial use but restricts sharing and redistribution, including package registry uploads without written permission. Do not treat the successful package build as distribution authorization.

## Dependency findings

The core runtime dependency list is empty. `pyproject.toml` declares Python `>=3.11`, setuptools as the PEP 517 build backend, an optional PyYAML extra for ESP-IDF lock parsing, and bounded test/development dependency ranges. Mypy is a development-only tool and is not installed for end users. The isolated pip-audit run checked resolved development distributions and reported no known advisories after the pytest floor was raised. FUSE was installed editable and skipped as expected. Syft, OSV-Scanner, Binwalk, and Gitleaks are external executables, not Python runtime dependencies, and are outside pip-audit coverage. Official Windows x64 SHA-256 digests were verified for the Gitleaks, Syft, and OSV-Scanner release assets used in the recorded checks.

The Python development environment has a clean point-in-time pip-audit result. System libraries, external analyzer binaries, malicious-package behavior, and all optional dependency configurations are not covered by that scan. The [PyPI JSON endpoint for `vigil-fuse`](https://pypi.org/pypi/vigil-fuse/json) returned HTTP 404 when checked on 2026-10-29. This is only a point-in-time name availability observation and neither reserves the name nor grants permission to publish. Recheck before any future release review.

## Documentation improvements

The README now summarizes alpha status, implemented scope, and major boundaries. Supporting pages cover requirements, methodology, architecture, threat model, limitations, traceability, benchmark evidence, repository structure, release process, and SBOM handling. Every new claim points to implementation or evidence where possible. No SDG alignment file was created: the repository demonstrates software engineering activity but has no measured societal outcome or evidence that supports a specific SDG impact claim.

## Research improvements

The repository scan is described as a pinned, descriptive evaluation. It records its question, dataset, method, variables, measures, scope, failure cases, and threats to validity. Synthetic fixtures, repository regression data, and separately maintained holdout cohorts remain distinct. No field precision, recall, or vulnerability prevalence is claimed. There is no comparative benchmark against other products.

## Reproducibility improvements

The new methodology page gives install, scan, test, and fixture-check commands. Existing manifests pin repositories and scopes. The package workflow builds wheel and sdist, checks metadata, installs into a clean environment, and runs CLI smoke checks. Gitleaks has a repeatable synthetic positive and negative smoke harness. Syft and OSV-Scanner have a repeatable positive, clean, and no-source adapter harness. Binwalk has a repeatable gzip-positive and clean-control identification harness, and the v3.1.0 workflow passed on hosted Ubuntu and native Windows. No static SBOM is committed, avoiding a stale generated inventory.

## Traceability status

`docs/traceability.md` maps requirements to objectives, decisions, implementation files, verification, and evidence. Optional executable integrations and the non-execution guarantee are marked partially verified where local evidence does not justify a stronger claim. The matrix does not equate test success with product security.

## Remaining limitations

- No representative independent ground-truth corpus or field accuracy estimate.
- The Markdown validator checks local link targets, fenced code blocks, and Mermaid diagram types. The pinned Mermaid renderer gate verifies syntax and SVG XML in CI, while visual layout and consistency with the current architecture still require human review. The six current Mermaid diagrams passed that review.
- No compiler-semantic C/C++ analysis, general firmware extraction, device testing, or hardware-in-the-loop validation.
- Gitleaks 8.30.0, Syft 1.55.0, and OSV-Scanner 2.7.0 passed local Windows smoke checks. Binwalk v2.3.3 passed a WSL2 Ubuntu smoke check, while v3.1.0 passed one synthetic gzip case on hosted Ubuntu and native Windows. Broader signatures and real firmware remain untested. Analyzer process-tree cleanup is best-effort and does not provide privilege, memory, or network isolation. These checks do not measure field precision, recall, exploitability, reachability, or the validity of real credentials.
- Performance evidence includes a synthetic C baseline and a pinned cohort across four selected embedded/IoT repository scopes on GitHub-hosted Linux, Windows, and macOS. Two same-day workflow runs each had one warm-up and three measured scans per scope; reports share the same source commits, input fingerprint, coverage counts, statuses, byte totals, and signal counts. Their absolute median timing shifts range from 20.7% to 37.9%, with all four Linux and macOS scopes faster on repeat and all four Windows scopes slower. The cause is unknown, so the repeat record does not establish thresholds or long-term variance. Reports also record 20 ms process-tree RSS samples. Mynewt and ESP-IoT-Solution remain partial because selected files exceeded the scanner's size limit. Controlled hardware comparisons remain unmeasured. RSS can double-count shared pages and miss brief peaks.
- Strict Mypy covers all 44 source modules and five benchmark/preparation/verification scripts; the 49-file check passed locally and in FUSE CI run `41134897292`. Dependency audit #20 passed on its recorded revision. pip-audit covers only the resolved Python development environment and does not assess system packages or external analyzer binaries.
- The Markdown validator checks local link targets, code fences, and Mermaid block types. CI also renders all six current Mermaid diagrams with the pinned Mermaid CLI image and parses the generated SVG XML. This catches renderer errors but does not verify visual layout or whether diagram content still matches the implementation. The diagrams passed manual visual review. The finding-model SVGs passed structural validation and the interactive figure received browser review.
- Custom license and distribution terms require owner and qualified legal review before registry or release distribution.

## Initial maturity score

Scores use the weights from the master prompt. The initial assessment is the workspace state at the start of this audit pass, which already included the previous local engineering improvements. Scores are qualitative engineering judgment, not a formal certification.

| Dimension | Weight | Initial score | Evidence at audit start |
| --- | ---: | ---: | --- |
| Architecture & Modularity | 15 | 13 | Modular Python package and architecture notes; no Mermaid operational views or ADRs |
| Documentation | 15 | 11 | Extensive README and specialist docs; requirements, limitations, methodology, and traceability were fragmented or absent |
| Code Quality | 15 | 12 | Ruff lint, bounded components, and typed data models; no type-checking gate and formatting debt remained |
| Testing | 15 | 12 | Existing test suite, fixture benchmark, and CI; no docs-link validation gate |
| Security | 10 | 9 | Threat model, bounded inputs, explicit coverage, and security tests; external tool sandboxing and broad third-party audit absent |
| Reproducibility | 10 | 8 | Pinned scan manifests and package workflow; no consolidated methodology, SBOM record, or complete cross-platform evidence |
| Open Source Governance | 10 | 4 | Security and release docs existed; citation and root contribution guidance absent, and custom license restricts redistribution |
| Research Rigor & Traceability | 10 | 8 | Pinned scans, synthetic benchmark, holdout notes, and research docs; no unified traceability or experiment protocol |
| **Total** | **100** | **77** | |

## Final maturity score

| Dimension | Weight | Final score | Evidence and remaining gap |
| --- | ---: | ---: | --- |
| Architecture & Modularity | 15 | 14 | Mermaid data flow and hardware boundary plus four ADRs; hardware and product applicability remain limited |
| Documentation | 15 | 14 | Requirements, methods, limitations, benchmarks, structure, and audit are explicit; no SDG impact claim is supported |
| Code Quality | 15 | 14 | Full-tree Ruff checks and strict Mypy over 44 source modules plus five benchmark/preparation/verification scripts; CI run #41134897292 passed on `d873da6`. External tools have only bounded smoke evidence |
| Testing | 15 | 15 | FUSE CI run #41134897292 passed eight jobs, including cross-platform tests, the 70% coverage gate, package build/install smoke checks, and pinned rendering of all six Mermaid diagrams. Binwalk v3.1.0 also passed its separate Ubuntu and native Windows smoke workflow. Detector field accuracy is scored under research rigor |
| Security | 10 | 9 | Parser and output hardening retained; Gitleaks, Syft, OSV-Scanner, and Binwalk have bounded real-tool smoke checks, and optional analyzer timeouts attempt process-tree cleanup. External tools remain unsandboxed |
| Reproducibility | 10 | 10 | Pinned manifests, package build/install checks, repeatable analyzer harnesses, and two schema-checked same-day measurement runs for four pinned scopes on Linux, Windows, and macOS. Their substantial timing shifts show unresolved run-to-run variability; broader accuracy remains unverified |
| Open Source Governance | 10 | 6 | Citation, contribution boundaries, issue forms, PR checklist, and release gates added; custom license and enforcement policy remain unresolved |
| Research Rigor & Traceability | 10 | 9 | Evidence types, limitations, cohort method, and 23-signal source-context triage are documented; the triage is not independent adjudication and there is no representative accuracy estimate or product comparison |
| **Total** | **100** | **91** | |

## Recommended next actions

1. Resolve the license and allowed distribution channels with the owner and qualified legal review before publishing a release or package.
2. Extend Binwalk smoke evidence to additional signatures and pinned real firmware samples, and keep positive and clean controls for Gitleaks, Syft, and OSV-Scanner reproducible.
3. Extend independent, manually reviewed fixtures and retain difficult negatives before claiming field accuracy.
4. Repeat cross-platform performance and memory measurements on additional dates and runner generations to characterize variance beyond the two same-day runs. Keep timing thresholds deferred until they have stable, controlled measurements.
5. Defer device, hardware, and firmware-extraction claims until controlled hardware or isolated extraction environments are available.

## Evidence update, 2026-10-31

Commits `0acde65` and `0f11e7c` add a repeatable performance harness and measured results for four selected pinned repository scopes. CI run #41122163492 passed all eight jobs on `0f11e7c`. The [single-host experiment record](experiments/repository-scan-performance-2026-10-31.md) and [versioned JSON report](../reports/benchmark/repository-scan-performance.json) preserve the inputs, three-run samples, coverage status, and skipped-file reasons. At that checkpoint, the maturity assessment was 89/100 because evidence covered one Windows machine and did not supply independent finding adjudication, Linux/macOS measurements, or a representative accuracy corpus.

The manually dispatched [cross-platform workflow](../.github/workflows/repository-performance.yml) has a reviewed, line-ending-normalized, memory-sampled snapshot from [run 41130740188](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41130740188). The [matrix experiment record](experiments/repository-scan-performance-matrix-2026-10-31.md) and three checked-in reports show the same input fingerprint, source commits, scope and byte counts, skips, statuses, candidate-signal counts, and complete RSS sampling across Linux, Windows, and macOS. The reproducibility score increases from 9 to 10, bringing the maturity assessment from 89 to 90. FUSE CI run [41133270780](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41133270780) then rendered all six Mermaid diagrams with the pinned container and passed all eight jobs. The testing score increases from 14 to 15, bringing the current maturity assessment to 91/100. Remaining gaps include unmeasured field accuracy, broader Binwalk formats and real firmware/device behavior, external-tool isolation limits, and unresolved redistribution terms.

A second same-day cross-platform run, [41136062930](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41136062930), passed for the same four pinned scopes. Its three schema-validated reports and the [repeat experiment record](experiments/repository-scan-performance-repeat-2026-10-31.md) show matching measured inputs and coverage, but median timings shifted by 20.7% to 37.9% in absolute terms, with opposite directions across Windows versus Linux and macOS. The cause is unknown. This increases the amount of reproducibility evidence but does not change the qualitative score or the 91/100 maturity assessment; more dates and runner generations are required to characterize variability.
