# Standalone FUSE migration ledger

This ledger tracks the competition repository and its feature branches into the canonical VIGIL-FUSE repository. It is the pre-adaptation assessment and will be updated with final code, test, and documentation evidence before integration is declared complete.

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
| `main` | `816898f7e9390a4a491b66c0722d5d59e7110abe` | Main consolidation snapshot. Inventory every capability below and adapt missing features. |
| `feat/adaptive-analysis` | `1d66d14f20faa20e1ea1796ac8ee4e92c108f6b6` | Merged into donor main. Include passive inspection and bounded analysis routing. |
| `feat/cyber-physical-frontier` | `1bfe18593565365d2177a0e403c05e1f5e8940d5` | Merged into donor main. Include the stable cyber-physical, hardware, cFE, SVD, and digital-twin work. |
| `feat/polyglot-platform-foundation` | `b1742200fc1b8f2d13fd8786eac83a210eee39e1` | Merged into donor main. Include the Go execution contract and research-only language decisions. |
| `codex/release-0.5.0` | `ff273da9c8bd5c5d949cfba093d89cd65c34f5ab` | Release-preparation history. Preserve relevant package checks; do not publish because PyPI is paused. |
| `codex/separate-vulnerable-lab` | `73060d7a4a998dfa07ec8c4509105474714b05b8` | The lab removal/separation decision is represented in donor main. |
| `cliui` | `527e9186ae471e8e6fa63eb66293593936d991e7` | Not an ancestor of donor main. Verify its interactive progress and PDF prompt behavior against VIGIL main; retain equivalent or better behavior. |
| `feat/armaan-contributor-and-ci-hardening` | `3543644e2df883d75f921461fe60883f8362d6ba` | Not in donor main. Review and adapt its attribution and CI hardening. Preserve its competitive-landscape material only as clearly labeled, unverified research. |
| `demo/vulnerable-lab` | `c2dd2bb343c96a625ce22e1aa550e71b61d4df4a` | Intentionally excluded. The user confirmed this was only a demonstration scan target and is not needed in canonical production main. |

## Feature parity ledger

`Baseline assessment` records what was present at VIGIL start. `Final status` remains pending until the implementation and its checks are complete.

| Feature | Standalone source | VIGIL source at start | Baseline assessment and required adaptation | Tests | Docs | Final status |
| --- | --- | --- | --- | --- | --- | --- |
| Core deterministic scanner | `src/vigil_fuse/scanner.py`, `rule_execution.py`, `rule_worker.py` | Same modules | Present. Preserve budgets, isolation, timeouts, path and symlink controls, coverage, and non-execution guarantees. | Scanner and rule tests | Architecture, limitations | Pending |
| Native security rules | `src/vigil_fuse/rules/` | Same rule modules | Present. Confirm the full credential, key, TLS, HTTP, MQTT, and ESP-IDF validation family remains unchanged. | Rule fixtures and tests | Rule guidance | Pending |
| Interactive and non-interactive CLI | `src/vigil_fuse/cli.py`, `cliui/`, `terminal.py` | Same commands and shell modules | Present, with donor updates to reconcile. Verify help, doctor, pwd, cd, scan, baseline, version, clear, exit, and non-interactive commands. | CLI and terminal tests | README and usage | Pending |
| Reports and schemas | `reporting.py`, `sarif.py`, `report_pdf.py`, packaged report schemas | Same report modules and schema 1.12 | Present. Reconcile schema consumers, coverage, inventories, artifact hashes, SARIF, text, JSON, and optional PDF without dropping older schemas. | Report/schema tests | Finding schema and usage | Pending |
| Finding model | `model.py`, `reporting.py` | Same model | Present. Keep severity, confidence, applicability, validation, and coverage separate; a signal is not proof of exploitability. | Finding/report tests | Finding schema | Pending |
| Baselines | `baseline.py` | Same module | Present. Preserve stable identity, suppression rationale, thresholds, unsuppression, and incomplete-scan safeguards. | Baseline tests | Usage | Pending |
| Build context | `build_context.py`, `zephyr_hardening.py` | Same modules | Present. Verify ESP-IDF, generated config, defaults provenance, Zephyr hardenconfig, and PlatformIO metadata stay bounded and non-executing. | Build-context tests | Build-context docs | Pending |
| Compilation database inventory | `clang_analyzer.py` and compilation database fixtures | No semantic analyzer at start | Adapt bounded `compile_commands.json` inventory. Commands remain data and are never executed. | Clang analyzer tests | C/C++ analysis guide | Pending |
| C/C++ Clang semantic layer | `native/clang-analyzer/`, `src/vigil_fuse/clang_analyzer.py` | No Clang semantic layer at start | Adapt strict compiler-argument filtering and bounded AST observations. Python remains the decision authority. | C/C++ fixtures and semantic tests | C/C++ analysis guide and benchmark | Pending |
| Firmware analysis | `firmware_inventory.py`, `firmware_analyzer.py` | Same modules | Present. Verify size bounds, Binwalk/Ghidra adapters, signatures, metadata, strings, imports/exports, functions, and selected cross references. | Firmware and Ghidra tests | Firmware and Ghidra guides | Pending |
| Ghidra Java bridge | Packaged `FuseExport.java` resource and Ghidra schemas | Same resource and schemas | Present. Verify packaging, validation, artifact contract, and optional-tool boundaries. | Ghidra tests | Ghidra guide | Pending |
| Software supply chain | SBOM, vulnerability, Gitleaks, VEX and provenance modules | Same modules | Present. Verify Syft, OSV-Scanner, CycloneDX, SPDX, Gitleaks, VEX, and subject/digest context. Advisory matches stay distinct from reachable vulnerabilities. | Adapter and schema tests | SBOM and integrations guides | Pending |
| GitHub Actions analysis | `github_actions.py` | Same analyzer | Present. Verify only the documented static checks and avoid claims of general YAML taint analysis. | Workflow fixtures and tests | GitHub Actions guide | Pending |
| Hardware and KiCad | `hardware.py`, `hardware_bom.py`, `hardware_netlist.py` | Same inventory and BOM modules | Present, with donor topology changes to reconcile. Keep `net connection` separate from physical accessibility. | Hardware, BOM, and netlist tests | Hardware guide | Pending |
| Device Tree, SVD, flight bus, resilience, and twin foundations | `device_tree.py`, `svd.py`, `flight_bus.py`, `seu_analysis.py`, `digital_twin.py`, `renode_export.py` | These modules were absent from local main | Adapt bounded parsing and evidence foundations. Keep physical activity and runtime behavior unknown without evidence. | Device-tree, SVD, bus, SEU, twin tests | Cyber-physical guides | Pending |
| RTL and FPGA analysis | `rtl_analysis.py`, Verilog/SystemVerilog fixtures | Same RTL analyzer | Present. Preserve bounded structure checks and `present` vs synthesized vs implemented vs active distinctions. | RTL tests and fixtures | RTL guide and support matrix | Pending |
| Rego / OPA policy engine | `policy.py`, packaged Rego and schemas | Same policy engine | Present. Keep policy results separate from security findings and preserve PASS/FAIL/UNKNOWN. | Policy tests | Policy guide | Pending |
| Local LLM reasoning | `reasoning/` | Same optional reasoning engine | Present. Verify report grounding, loopback-only Ollama, no model download, and strict JSON rejection behavior. | Reasoning tests | Local reasoning guide | Pending |
| Reasoning context contract | `reasoning/context.py` and schema | Same bounded context module | Present. Verify sanitation, size limits, canonical finding IDs, relevant evidence only, and UNKNOWN retention. | Context tests | Reasoning guide | Pending |
| Setup and tool provisioning | `setup/manager.py`, `setup/tools.json` | Same setup subsystem | Present. Preserve explicit setup, dry-run, version/hash checks, user-local install, reuse, and no model downloads. | Setup tests and installed-wheel verifier | Installation and Windows setup guides | Pending |
| PowerShell bootstrap | Packaged `FuseBootstrap.psm1`, `fuse-setup.ps1` | No packaged bootstrap at start | Adapt as optional Windows helper. Keep PowerShell 5.1 compatibility and no mandatory Python dependency. | Pester tests | Windows setup guide | Pending |
| Go / Kubernetes foundation | `cluster/fuse-operator/`, execution contracts | No cluster foundation at start | Adapt bounded probe/orchestration only. Python remains security authority; orchestration success is not a verdict. | Go and contract tests | Operator and execution guides | Pending |
| R research layer | `research/R/` | No R research files at start | Adapt offline, reproducible research workflows only; do not make R a scan dependency or claim field accuracy. | R assertions/workflows | R README | Pending |
| Julia research layer | `research/julia/` | No Julia research files at start | Adapt offline, seeded experiment planning only; no production verdicts or runtime dependency. | Julia tests | Julia research guide | Pending |
| Rust decision and benchmark evidence | `scripts/benchmark_rust_candidates.py`, research docs | No evidence at start | Preserve useful benchmark evidence and `NO_RUST_NEEDED_YET`; do not add a runtime. | Benchmark and evidence checks | Native-engine strategy | Pending |
| Zig decision | Donor decision records | No decision record at start | Preserve `NO_ZIG_NEEDED`; do not add a runtime. | N/A | Migration and strategy docs | Pending |
| Adaptive analysis routing | `analysis_router.py`, `repo_dna.py`, `target_model.py` | No routing modules at start | Adapt passive, bounded repository inspection only. Do not execute arbitrary tools or widen trust boundaries. | Router and repo-DNA tests | Architecture and roadmap | Pending |
| Applicability engine | `applicability.py`, applicability schema | No applicability report at start | Adapt offline analysis and retain UNKNOWN when evidence is insufficient. | Applicability tests | Applicability guide | Pending |
| Support matrix and doctor | `support-matrix.json`, `cli.py`, `setup/manager.py` | Existing support/doctor | Rebuild labels from final code; expose optional tools accurately without making them core failures. | Support and doctor tests | README and installation | Pending |
| NVIDIA regression record | Pinned `edk2-nvidia` snapshot and donor audit | Historical VIGIL record | Preserve the pinned result and caveats; rerun only if scanner changes materially. Never call the candidate a confirmed vulnerability. | Exact target comparison if needed | Migration record | Pending |
| Cross-feature safe integration | `tests/test_consolidation_integration.py` | No equivalent integrated test at start | Adapt the safe scan, reports, baseline, policy UNKNOWN, reasoning context, and grounded mock workflow. | Consolidation integration test | Test documentation | Pending |
| Package boundary and local artifacts | `pyproject.toml`, package resources, wheel verifier | Existing lightweight package | Keep optional runtimes out of core dependencies. Build and test a fresh wheel outside the source tree. | Build, install, CLI smoke | Installation | Pending |
| Contributor and CI hardening branch | `feat/armaan-contributor-and-ci-hardening` | No equivalent branch content | Review useful CI changes and contributor attribution. Do not enable publishing while PyPI is paused. Preserve landscape material as a labeled, unverified research draft. | Workflow/schema/docs checks | Research draft and credits | Pending |
| Website and release status | `site/`, release workflows | Existing site and workflows | Mark the website archived/paused. Keep PyPI publishing paused and do not make either a migration gate. | Docs and workflow checks | Website and release docs | Pending |
| Vulnerable demonstration application | `demo/vulnerable-lab` | Not present in local main | Exclude per the user's clarification: it is an optional scan demonstration and is not needed in the canonical product. | No shipping demo test | Exclusion recorded here | `INTENTIONALLY_EXCLUDED_WITH_STRONG_REASON` |

## Final verification record

This section will be completed from observed commands after adaptation. Untested optional tools and hosted checks will remain explicitly unverified.

| Check | Result |
| --- | --- |
| Full Python suite | Pending |
| Ruff | Pending |
| Mypy | Pending |
| Schema and documentation validation | Pending |
| Wheel and sdist build | Pending |
| Fresh wheel install and CLI smoke | Pending |
| Clang, Go, RTL, OPA, PowerShell, R, Julia | Pending |
| NVIDIA regression | Pending unless scanner changes materially |
| Working tree and push state | Pending |
