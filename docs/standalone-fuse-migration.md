> Superseded by [the final migration report](standalone-fuse-final-migration.md) and [machine-readable parity ledger](../migration/full-parity-ledger.json). This document is an earlier checkpoint; its SHA, check, publication, and push state are historical and are not the completion result.

# Standalone FUSE migration ledger

This final ledger records the competition repository and its feature branches as adapted into canonical VIGIL-FUSE. It includes source snapshots, branch dispositions, test evidence, documentation updates, and exclusions.

## Protected repositories and snapshots

| Item | Snapshot |
| --- | --- |
| Canonical repository | `https://github.com/VIGIL-IoT/VIGIL-FUSE` |
| Donor repository | `https://github.com/ShivuXD/FUSE` |
| VIGIL local main at migration start | `2a42fac91acc8f832eb00d91da2211b83830a051` |
| Fetched VIGIL `origin/main` at migration start | `fccc900ccba2aa0f5f64926909ba08026e8af789` |
| Donor `main` at migration start | `816898f7e9390a4a491b66c0722d5d59e7110abe` |
| Safety ref | `backup/pre-standalone-adaptation` |
| Integration branch | `integration/standalone-fuse-full-adaptation` |

The local VIGIL main was clean and 11 commits ahead of fetched `origin/main`. Those local commits are preserved as the starting point. The donor and destination histories have no merge base, so this work uses reviewed feature-level changes. No history rewrite or push is planned.

## Donor branch accounting

| Donor ref | Head at inspection | Meaningful work and disposition |
| --- | --- | --- |
| main | 816898f7e9390a4a491b66c0722d5d59e7110abe | Main consolidation snapshot. The capability ledger below records each feature and its final VIGIL disposition. |
| `feat/adaptive-analysis` | `1d66d14f20faa20e1ea1796ac8ee4e92c108f6b6` | Merged into donor main. Include passive inspection and bounded analysis routing. |
| `feat/cyber-physical-frontier` | `1bfe18593565365d2177a0e403c05e1f5e8940d5` | Merged into donor main. Include the stable cyber-physical, hardware, cFE, SVD, and digital-twin work. |
| `feat/polyglot-platform-foundation` | `b1742200fc1b8f2d13fd8786eac83a210eee39e1` | Merged into donor main. Include the Go execution contract and research-only language decisions. |
| `codex/release-0.5.0` | `ff273da9c8bd5c5d949cfba093d89cd65c34f5ab` | Release-preparation history. Preserve relevant package checks; do not publish because PyPI is paused. |
| `codex/separate-vulnerable-lab` | `73060d7a4a998dfa07ec8c4509105474714b05b8` | The lab removal/separation decision is represented in donor main. |
| cliui | 527e9186ae471e8e6fa63eb66293593936d991e7 | Not an ancestor of donor main. Its terminal artwork, prompt framing, progress, and PDF behavior were compared with VIGIL and adapted. The target command combines show and change behavior. |
| feat/armaan-contributor-and-ci-hardening | 3543644e2df883d75f921461fe60883f8362d6ba | Not in donor main. Contributor names and CI hardening were adapted. The public email was omitted. Comparative claims are kept only in an archived, unverified draft. |
| `demo/vulnerable-lab` | `c2dd2bb343c96a625ce22e1aa550e71b61d4df4a` | Intentionally excluded. The user confirmed this was only a demonstration scan target and is not needed in canonical production main. |

Branch-only reconciliation:

- The donor cliui branch changed terminal artwork and prompt framing. Equivalent progress, PDF prompting, command completion, and narrow-terminal behavior are integrated in VIGIL's terminal. The single /target command provides both show and change behavior; separate /pwd and /cd aliases are not needed.
- The contributor and CI hardening branch's names are retained in author metadata. Its public email address was not copied. Pinned workflow updates and Twine 7 checks were adapted. Its comparative claims are archived with an unverified disclaimer.
- The release branch's local build and metadata checks are retained. Donor notes for 0.5.0 and 0.5.1 are preserved in `docs/archive/competition/CHANGELOG.md`; the local `v0.5.0` and `v0.5.1` tags point to donor snapshots, not canonical VIGIL releases. The separate vulnerable-lab branch is excluded as confirmed by the user.

## Release and page status

The canonical GitHub release page and PyPI still show 0.4.0 as the latest VIGIL-FUSE release. The PyPI page is available, and the Vercel homepage returned HTTP 200 on 2026-11-22. No package was published and no site deployment was performed during this migration. The Vercel content remains a legacy snapshot and is not the canonical project documentation. GitHub repository topics now include `embedded-security`, `firmware-analysis`, `iot-security`, `static-analysis`, `hardware-security`, `supply-chain-security`, and `fpga-security`.

## Feature parity ledger

`Baseline assessment` records what was present at VIGIL start. `Final status` remains pending until the implementation and its checks are complete.

| Feature | Standalone source | VIGIL source at start | Baseline assessment and required adaptation | Tests | Docs | Final status |
| --- | --- | --- | --- | --- | --- | --- |
| Core deterministic scanner | `src/vigil_fuse/scanner.py`, `rule_execution.py`, `rule_worker.py` | Same modules | Present. Preserve budgets, isolation, timeouts, path and symlink controls, coverage, and non-execution guarantees. | Scanner and rule tests | Architecture, limitations | ALREADY_PRESENT_IN_VIGIL |
| Native security rules | `src/vigil_fuse/rules/` | Same rule modules | Present. Confirm the full credential, key, TLS, HTTP, MQTT, and ESP-IDF validation family remains unchanged. | Rule fixtures and tests | Rule guidance | ALREADY_PRESENT_IN_VIGIL |
| Interactive and non-interactive CLI | `src/vigil_fuse/cli.py`, `cliui/`, `terminal.py` | Same commands and shell modules | Present, with donor updates to reconcile. Verify help, doctor, pwd, cd, scan, baseline, version, clear, exit, and non-interactive commands. | CLI and terminal tests | README and usage | ADAPTED_TO_VIGIL |
| Reports and schemas | `reporting.py`, `sarif.py`, `report_pdf.py`, packaged report schemas | Same report modules and schema 1.12 | Present. Reconcile schema consumers, coverage, inventories, artifact hashes, SARIF, text, JSON, and optional PDF without dropping older schemas. | Report/schema tests | Finding schema and usage | ALREADY_PRESENT_IN_VIGIL |
| Finding model | `model.py`, `reporting.py` | Same model | Present. Keep severity, confidence, applicability, validation, and coverage separate; a signal is not proof of exploitability. | Finding/report tests | Finding schema | ALREADY_PRESENT_IN_VIGIL |
| Baselines | `baseline.py` | Same module | Present. Preserve stable identity, suppression rationale, thresholds, unsuppression, and incomplete-scan safeguards. | Baseline tests | Usage | ALREADY_PRESENT_IN_VIGIL |
| Build context | `build_context.py`, `zephyr_hardening.py` | Same modules | Present. Verify ESP-IDF, generated config, defaults provenance, Zephyr hardenconfig, and PlatformIO metadata stay bounded and non-executing. | Build-context tests | Build-context docs | ALREADY_PRESENT_IN_VIGIL |
| Compilation database inventory | `clang_analyzer.py` and compilation database fixtures | No semantic analyzer at start | Adapt bounded `compile_commands.json` inventory. Commands remain data and are never executed. | Clang analyzer tests | C/C++ analysis guide | ALREADY_PRESENT_IN_VIGIL |
| C/C++ Clang semantic layer | `native/clang-analyzer/`, `src/vigil_fuse/clang_analyzer.py` | No Clang semantic layer at start | Adapt strict compiler-argument filtering and bounded AST observations. Python remains the decision authority. | C/C++ fixtures and semantic tests | C/C++ analysis guide and benchmark | ADAPTED_TO_VIGIL |
| Firmware analysis | `firmware_inventory.py`, `firmware_analyzer.py` | Same modules | Present. Verify size bounds, Binwalk/Ghidra adapters, signatures, metadata, strings, imports/exports, functions, and selected cross references. | Firmware and Ghidra tests | Firmware and Ghidra guides | ALREADY_PRESENT_IN_VIGIL |
| Ghidra Java bridge | Packaged `FuseExport.java` resource and Ghidra schemas | Same resource and schemas | Present. Verify packaging, validation, artifact contract, and optional-tool boundaries. | Ghidra tests | Ghidra guide | ALREADY_PRESENT_IN_VIGIL |
| Software supply chain | SBOM, vulnerability, Gitleaks, VEX and provenance modules | Same modules | Present. Verify Syft, OSV-Scanner, CycloneDX, SPDX, Gitleaks, VEX, and subject/digest context. Advisory matches stay distinct from reachable vulnerabilities. | Adapter and schema tests | SBOM and integrations guides | ALREADY_PRESENT_IN_VIGIL |
| GitHub Actions analysis | `github_actions.py` | Same analyzer | Present. Verify only the documented static checks and avoid claims of general YAML taint analysis. | Workflow fixtures and tests | GitHub Actions guide | ALREADY_PRESENT_IN_VIGIL |
| Hardware and KiCad | `hardware.py`, `hardware_bom.py`, `hardware_netlist.py` | Same inventory and BOM modules | Present, with donor topology changes to reconcile. Keep `net connection` separate from physical accessibility. | Hardware, BOM, and netlist tests | Hardware guide | ADAPTED_TO_VIGIL |
| Device Tree, SVD, flight bus, resilience, and twin foundations | `device_tree.py`, `svd.py`, `flight_bus.py`, `seu_analysis.py`, `digital_twin.py`, `renode_export.py` | These modules were absent from local main | Adapt bounded parsing and evidence foundations. Keep physical activity and runtime behavior unknown without evidence. | Device-tree, SVD, bus, SEU, twin tests | Cyber-physical guides | ADAPTED_TO_VIGIL |
| RTL and FPGA analysis | `rtl_analysis.py`, Verilog/SystemVerilog fixtures | Same RTL analyzer | Present. Preserve bounded structure checks and `present` vs synthesized vs implemented vs active distinctions. | RTL tests and fixtures | RTL guide and support matrix | ALREADY_PRESENT_IN_VIGIL |
| Rego / OPA policy engine | `policy.py`, packaged Rego and schemas | Same policy engine | Present. Keep policy results separate from security findings and preserve PASS/FAIL/UNKNOWN. | Policy tests | Policy guide | ALREADY_PRESENT_IN_VIGIL |
| Local LLM reasoning | `reasoning/` | Same optional reasoning engine | Present. Verify report grounding, loopback-only Ollama, no model download, and strict JSON rejection behavior. | Reasoning tests | Local reasoning guide | ALREADY_PRESENT_IN_VIGIL |
| Reasoning context contract | `reasoning/context.py` and schema | Same bounded context module | Present. Verify sanitation, size limits, canonical finding IDs, relevant evidence only, and UNKNOWN retention. | Context tests | Reasoning guide | ALREADY_PRESENT_IN_VIGIL |
| Setup and tool provisioning | `setup/manager.py`, `setup/tools.json` | Same setup subsystem | Present. Preserve explicit setup, dry-run, version/hash checks, user-local install, reuse, and no model downloads. | Setup tests and installed-wheel verifier | Installation and Windows setup guides | ALREADY_PRESENT_IN_VIGIL |
| PowerShell bootstrap | Packaged `FuseBootstrap.psm1`, `fuse-setup.ps1` | No packaged bootstrap at start | Adapt as optional Windows helper. Keep PowerShell 5.1 compatibility and no mandatory Python dependency. | Pester tests | Windows setup guide | ADAPTED_TO_VIGIL |
| Go / Kubernetes foundation | `cluster/fuse-operator/`, execution contracts | No cluster foundation at start | Adapt bounded probe/orchestration only. Python remains security authority; orchestration success is not a verdict. | Go and contract tests | Operator and execution guides | ADAPTED_TO_VIGIL |
| R research layer | `research/R/` | No R research files at start | Adapt offline, reproducible research workflows only; do not make R a scan dependency or claim field accuracy. | R assertions/workflows | R README | ADAPTED_TO_VIGIL |
| Julia research layer | `research/julia/` | No Julia research files at start | Adapt offline, seeded experiment planning only; no production verdicts or runtime dependency. | Julia tests | Julia research guide | ADAPTED_TO_VIGIL |
| Rust decision and benchmark evidence | `scripts/benchmark_rust_candidates.py`, research docs | No evidence at start | Preserve useful benchmark evidence and `NO_RUST_NEEDED_YET`; do not add a runtime. | Benchmark and evidence checks | Native-engine strategy | ADAPTED_TO_VIGIL |
| Zig decision | Donor decision records | No decision record at start | Preserve `NO_ZIG_NEEDED`; do not add a runtime. | N/A | Migration and strategy docs | ADAPTED_TO_VIGIL |
| Adaptive analysis routing | `analysis_router.py`, `repo_dna.py`, `target_model.py` | No routing modules at start | Adapt passive, bounded repository inspection only. Do not execute arbitrary tools or widen trust boundaries. | Router and repo-DNA tests | Architecture and roadmap | ADAPTED_TO_VIGIL |
| Applicability engine | `applicability.py`, applicability schema | No applicability report at start | Adapt offline analysis and retain UNKNOWN when evidence is insufficient. | Applicability tests | Applicability guide | ADAPTED_TO_VIGIL |
| Support matrix and doctor | `support-matrix.json`, `cli.py`, `setup/manager.py` | Existing support/doctor | Rebuild labels from final code; expose optional tools accurately without making them core failures. | Support and doctor tests | README and installation | ADAPTED_TO_VIGIL |
| NVIDIA regression record | Pinned `edk2-nvidia` snapshot and donor audit | Historical VIGIL record | Preserve the pinned result and caveats; rerun only if scanner changes materially. Never call the candidate a confirmed vulnerability. | Exact target comparison if needed | Migration record | ADAPTED_TO_VIGIL |
| Cross-feature safe integration | `tests/test_consolidation_integration.py` | No equivalent integrated test at start | Adapt the safe scan, reports, baseline, policy UNKNOWN, reasoning context, and grounded mock workflow. | Consolidation integration test | Test documentation | ADAPTED_TO_VIGIL |
| Package boundary and local artifacts | `pyproject.toml`, package resources, wheel verifier | Existing lightweight package | Keep optional runtimes out of core dependencies. Build and test a fresh wheel outside the source tree. | Build, install, CLI smoke | Installation | ADAPTED_TO_VIGIL |
| Contributor and CI hardening branch | `feat/armaan-contributor-and-ci-hardening` | No equivalent branch content | Review useful CI changes and contributor attribution. Keep package publication separate from migration completion. Preserve landscape material as a labeled, unverified research draft. | Workflow/schema/docs checks | Research draft and credits | ADAPTED_TO_VIGIL |
| Website and release status | `site/`, release workflows | Existing site and workflows | Record that PyPI and Vercel are reachable while keeping the package at 0.4.0 and treating deployed site content as a legacy snapshot. Do not publish or deploy as part of this migration. | Docs and workflow checks | Website and release docs | ADAPTED_TO_VIGIL |
| Vulnerable demonstration application | `demo/vulnerable-lab` | Not present in local main | Exclude per the user's clarification: it is an optional scan demonstration and is not needed in the canonical product. | No shipping demo test | Exclusion recorded here | `INTENTIONALLY_EXCLUDED_WITH_STRONG_REASON` |

## NVIDIA regression record

The donor consolidation audit records target NVIDIA/edk2-nvidia at commit cb638768ec174bb2041f87569409c53e4af4292e, describe uefi-202609.1. It selected and scanned 1,223 files, skipped none, and completed discovery. One FUSE001 review candidate remained: medium severity, high confidence, unknown applicability, and not validated. The recorded fingerprint is d81a828a2fbb246ac3f1485b974ae43b55fba56bb3228ecbd7fd93cc28f0a7c1.

This is a historical static candidate, not a confirmed NVIDIA vulnerability. Manual review later established that its literals came from mocked bootstrap credential responses in a `UnitTest` directory, with `MODULE_TYPE = HOST_APPLICATION` and inclusion from `Platform/NVIDIA/HostBasedTests/HostBasedTests.dsc`. The minimal synthetic regression and its limitations are recorded in [the FUSE001 context regression](experiments/fuse001-edk2-nvidia-unittest-context-2026-11-23.md). The rule change generalizes exact unit-test directory spelling in the shared classifier; it does not special-case NVIDIA or establish that every file outside test directories ships in production.

The donor audit also records a live Qwen reasoning smoke that returned valid JSON but failed strict UNKNOWN-acknowledgement validation. FUSE rejected the response, did not change the deterministic report, and did not download a model. The current migration preserved that failure behavior; no live model was run here.

## Final verification record

The following results come from commands run during this adaptation. Optional tools and hosted checks that were not available remain explicitly unverified.

| Check | Result |
| --- | --- |
| Full Python suite | 641 passed, 11 skipped, 208 subtests passed; one third-party pytest deprecation warning. |
| Ruff | Lint passed; format check passed for 186 files. |
| Mypy | Passed with no issues in 96 source files. |
| Schema and documentation validation | Parsed 23 schema JSON files and the 30-capability support matrix; docs validation passed for 140 Markdown files; all 12 workflow YAML files parsed. |
| Repository path audit | Passed across 1,265 tracked files and Git history. The only historical matches were generic test placeholders and a hosted-runner path. |
| Wheel and sdist build | Isolated build produced vigil_fuse-0.4.1.dev0 wheel and sdist; Twine check passed for both. |
| PDF report | Generated and visually inspected; the PDF embeds Times New Roman and its bold face, and the CLI banner appears at the top. |
| Fresh wheel install and CLI smoke | An earlier migration run passed the fresh install, CLI smoke, resource checks, and installed-wheel suite. This was not repeated after the PDF updates. |
| Clang, Go, RTL, OPA, PowerShell, R, Julia | Python semantic, RTL, policy, and execution-contract tests passed. Four native Clang cases skipped because the optional executable is absent; one OPA case skipped because OPA is absent. Pester passed 9 tests. Go, R, and Julia runtimes were unavailable for current reruns. |
| NVIDIA regression | Historical donor result preserved; not rerun because core scanner and rules were unchanged. |
| Working tree and push state | The full suite passed with local `main` clean. Code remains unpushed; hosted CI was not rerun. |

Verification environment notes:

- The first full-suite attempt had five Git subprocess failures because the inherited process environment declared GIT_CONFIG_COUNT=10 while GIT_CONFIG_VALUE_0 was empty. No repository or user Git configuration was changed. Removing process-local GIT_CONFIG_* variables allowed the full suite and installed-wheel suite to pass.
- The 11 full-suite skips are optional native Clang tests, OPA, a Docker fixture image, and explicit Docker/Kubernetes worker integrations requiring a supplied image or disposable cluster.
- The local environment had no Go, R, Rust, or Zig toolchain. Julia resolved only to a WindowsApps alias, not a confirmed runtime. These language-specific suites were not run here.
- A synthetic Rust candidate benchmark completed 19 operations; the documented NO_RUST_NEEDED_YET and NO_ZIG_NEEDED decisions remain unchanged.
