# Final FUSE to VIGIL-FUSE migration

> **Release follow-up (2026-11-28):** This report's repository and package snapshots describe the migration checkpoint. The canonical release is now VIGIL-FUSE 0.5.0; see the [GitHub release](https://github.com/VIGIL-IoT/VIGIL-FUSE/releases/tag/v0.5.0) and [PyPI package](https://pypi.org/project/vigil-fuse/0.5.0/). The release keeps the intentionally vulnerable demonstration application excluded from production.

Statements below that describe an unpublished package, an unpushed destination branch, or a pending publication are specific to the frozen migration snapshot and are superseded by this follow-up.

## Scope and snapshots

Canonical destination: [VIGIL-IoT/VIGIL-FUSE](https://github.com/VIGIL-IoT/VIGIL-FUSE). Donor: [ShivuXD/FUSE](https://github.com/ShivuXD/FUSE).

This migration reconciles features and files rather than joining unrelated Git histories. It preserves the local VIGIL main history and makes the reviewed integration branch the merge source for canonical `main`.

| Snapshot | SHA or state |
| --- | --- |
| VIGIL local `main` at task start | `0331960a2cee44cfb7de937648947dd75eb5dc17` |
| VIGIL `origin/main` at task start | `fccc900ccba2aa0f5f64926909ba08026e8af789` |
| Donor `main` | `816898f7e9390a4a491b66c0722d5d59e7110abe` |
| Canonical safety backup | `backup/pre-full-fuse-migration` |
| Integration code checkpoint used for path comparison | `43a02f0` (`fix: share bounded identity inventory with routing`) |

The annotated backup tag was not created because the repository's existing tag names are release tags. The backup branch preserves the local VIGIL starting commit. No history rewrite, reset, force push, or unrelated-history merge was used.

## Full tracked-path reconciliation

The [full parity ledger](../migration/full-parity-ledger.json) records all tracked donor-main paths, source and destination blob IDs, exact classifications, per-path rationales, every donor branch, and feature-level dispositions. Its counts are computed from the final committed integration snapshot.

| Result | Paths |
| --- | ---: |
| Identical path, mode, and blob | 1,200 |
| Equivalent canonical implementation | 11 |
| Newer VIGIL implementation or tests | 50 |
| Donor-only paths superseded as obsolete | 5 |
| Missing or conflicting production paths | 0 |
| Canonical-only paths at comparison | 11 |

The five donor-only paths are:

| Donor-only path | Classification | Reason |
| --- | --- | --- |
| `docs/assets/readme/README.md` | `OBSOLETE` | Old standalone README duplicate; canonical root README is authoritative. |
| `docs/assets/readme/fuse-archify-pipeline.png` | `OBSOLETE` | Historical screenshot tied to standalone branding and old documentation. |
| `docs/assets/readme/fuse-cli.png` | `OBSOLETE` | Old 0.5.x screenshot; the current terminal behavior is in code and tests and the image predates canonical VIGIL identity. |
| `docs/assets/readme/fuse-cli.txt` | `OBSOLETE` | Text capture paired with the stale screenshot, not a fixture or runtime resource. |
| `docs/final-consolidation-audit.md` | `OBSOLETE` | Donor-local worktree snapshot is superseded by this canonical audit and parity ledger. |

The previous checkpoint at [standalone-fuse-migration.md](standalone-fuse-migration.md) is retained as historical context and marked superseded. The comparison checkpoint predates this final report and ledger, which are canonical audit artifacts rather than donor capabilities.

## Donor branch accounting

| Donor ref | SHA | Result | Reconciliation |
| --- | --- | --- | --- |
| `main` | `816898f7e9390a4a491b66c0722d5d59e7110abe` | `ADAPTED` | Every tracked path and retained feature is classified in the ledger. |
| `feat/adaptive-analysis` | `1d66d14f20faa20e1ea1796ac8ee4e92c108f6b6` | `ADAPTED` | Ancestor of donor main. Repository DNA, component graph, target model, and routing now share one bounded identity classifier. |
| `feat/cyber-physical-frontier` | `1bfe18593565365d2177a0e403c05e1f5e8940d5` | `ADAPTED` | Ancestor of donor main. Device Tree, SVD, cFE, resilience, reachability, digital-twin, and Renode evidence are represented with explicit limits. |
| `feat/polyglot-platform-foundation` | `b1742200fc1b8f2d13fd8786eac83a210eee39e1` | `ADAPTED` | Ancestor of donor main. Go, PowerShell, R, Julia, and Rust/Zig decision records are accounted for. |
| `codex/release-0.5.0` | `ff273da9c8bd5c5d949cfba093d89cd65c34f5ab` | `ADAPTED` | Ancestor of donor main. Local release checks and release notes are preserved; no package was published. |
| `codex/separate-vulnerable-lab` | `73060d7a4a998dfa07ec8c4509105474714b05b8` | `ALREADY_PRESENT` | Ancestor of donor main and represents the decision to remove the demo from production. |
| `cliui` | `527e9186ae471e8e6fa63eb66293593936d991e7` | `ALREADY_PRESENT` | Its unique prompt, history, responsive banner, and terminal behavior are represented and covered by VIGIL tests. |
| `feat/armaan-contributor-and-ci-hardening` | `3543644e2df883d75f921461fe60883f8362d6ba` | `ADAPTED` | Contributor names and safe CI/package checks are retained. Public email is omitted. The comparative draft is archived with an unverified warning. |
| `demo/vulnerable-lab` | `c2dd2bb343c96a625ce22e1aa550e71b61d4df4a` | `ADAPTED` | Safe interactive CLI work is retained and tested. The lab application, fake key, insecure workflow, and demo runner are excluded per the user's clarification. |

Donor branch SHAs are preserved here as inventory references. No branch was merged with `--allow-unrelated-histories`.

## Feature-level results

All donor capabilities have one of the required dispositions in the machine-readable ledger. No production feature remains missing or unknown.

| Feature family | Result | Canonical implementation and boundary |
| --- | --- | --- |
| Scanner, native rules, findings, coverage | `ALREADY_PRESENT` | Existing bounded scanner and isolated rule worker remain the security evidence source. |
| CLIUI and interactive shell | `ALREADY_PRESENT` | `/help`, `/scan`, `/doctor`, `/baseline`, `/pwd`, `/cd`, terminal history, responsive prompt and input fallback remain available. |
| Repo DNA, component graph, target model, routing | `ADAPTED` | One bounded repository inventory feeds shared project identity and advisory routing. It does not launch or authorize active tools. |
| Native C++ and Clang | `ADAPTED` | `compile_commands.json` feeds filtered Clang AST observations; Python validates evidence and owns security decisions. |
| Go and Kubernetes | `ADAPTED` | Go provides bounded orchestration and an identity probe. It does not issue a vulnerability verdict. |
| PowerShell bootstrap | `ADAPTED` | Packaged resources retain PowerShell 5.1 compatibility and explicit operator action. They do not make hidden system changes or download models. |
| R research | `ADAPTED` | Offline statistical workflows remain optional research, not a scan dependency or a field-accuracy claim. |
| Julia research | `ADAPTED` | Seeded experiment planning, evidence graphs, simulations, and value-of-information remain research-only. |
| Java and Ghidra | `ALREADY_PRESENT` | The packaged Java exporter, Ghidra adapter, schema checks, and optional-tool boundary remain. |
| Python feature parity | `ALREADY_PRESENT` | Core scan, CLI, platform, hardware, firmware, dependency, history, setup, reasoning, policy, applicability, and reporting capabilities are accounted for path by path. |
| RTL and FPGA evidence | `ALREADY_PRESENT` | `.v`, `.vh`, `.sv`, and `.svh` support remains; file presence, synthesis, implementation, and physical behavior stay distinct. |
| Rego policy engine | `ALREADY_PRESENT` | Policy results remain separate from findings; `FAIL` is not a vulnerability and `UNKNOWN` is retained. |
| Local reasoning | `ALREADY_PRESENT` | Optional loopback reasoning cannot create or mutate findings, severity, confidence, applicability, validation, or coverage. No model download is automatic. |
| Installer, setup, and doctor | `ALREADY_PRESENT` | Explicit dry-run and user-local provisioning remain; heavy tools and models are not silently installed. |
| Report schema and package resources | `ADAPTED` | Schema 1.13 adds identity and attribution; older intended report consumers and packaged resources remain checked. |
| PDF report | `ADAPTED` | PDF starts with the CLI identity block and uses Times New Roman. Tests and a rendered sample verified the title and embedded fonts. |
| Hardware and firmware | `ALREADY_PRESENT` | Inventory, BOM, netlist, firmware, and optional analyzer boundaries remain conservative. |
| Cyber-physical frontier and applicability | `ADAPTED` | Device Tree, SVD, cFE, resilience, digital-twin, Renode, and applicability evidence remain partial and non-physical. |
| CI and contributor metadata | `ADAPTED` | Contributor names, package checks, and pinned workflow updates are retained without the public email address. |
| Competitive landscape draft | `ADAPTED` | Preserved only in the competition archive with an explicit unverified-claims warning. |
| Donor release notes | `ADAPTED` | 0.5.0 and 0.5.1 notes are preserved in the historical competition changelog. |
| Donor release tags | `INTENTIONALLY_EXCLUDED_WITH_REASON` | Donor tags point to donor commits and would mislabel independent VIGIL history. No canonical 0.5.0 or 0.5.1 tag or release was created. |
| Rust and Zig decisions | `ADAPTED` | `NO_RUST_NEEDED_YET` and `NO_ZIG_NEEDED` remain documented; no dead runtime code was added. |
| Vulnerable demo lab | `INTENTIONALLY_EXCLUDED_WITH_REASON` | The user confirmed it was only a scan demonstration target and is not needed in canonical production. Fake key material, intentionally vulnerable firmware, insecure workflow, runner, and demo-only tests are absent. |

## Releases, PyPI, site, and repository topics

The donor source identifies itself as 0.5.1. Canonical source remains `0.4.1.dev0`; the donor 0.5.0 and 0.5.1 release notes are archived, not represented as canonical VIGIL releases. The donor `v0.5.0` and `v0.5.1` tags were not pushed to the canonical repository because their targets belong to donor history. The canonical GitHub releases observed during the migration list 0.4.0 as latest.

The [PyPI project page](https://pypi.org/project/vigil-fuse/) is reachable and lists 0.4.0. PyPI publishing remains paused; this migration built and tested local package artifacts but did not publish a release. The static site is archived and no Vercel deployment was run.

Canonical GitHub repository topics currently include `embedded-security`, `firmware-analysis`, `fpga-security`, `hardware-security`, `iot-security`, `static-analysis`, and `supply-chain-security`. These are repository topics, not release tags.

## Validation record

The code checkpoint passed the full Python suite, Ruff, formatting, and Mypy. The final clean committed integration branch and merged main are checked again before publication. Optional executable availability and live hosted checks are reported separately; unavailable tools are not recorded as passes.

| Check | Current observed result |
| --- | --- |
| Full pytest | 655 passed, 11 skipped, 225 subtests passed; one third-party AnyIO/Pytest deprecation warning. |
| Ruff | Passed for `src`, `tests`, and `scripts`. |
| Ruff format | Passed for 190 files. |
| Mypy | Passed for 98 source files. |
| Project identity/router focused tests | 27 passed, 33 subtests passed; one third-party warning. |
| Documentation | `scripts/validate_docs.py` passed for 141 Markdown files. |
| PDF sample | Generated, rendered, and inspected. Times New Roman regular and bold fonts were embedded; CLI identity is at the top. |
| Wheel and sdist | `python -m build` and Twine checks passed for both 0.4.1.dev0 artifacts. |
| Fresh wheel | Installed outside checkout; version, top-level help, scan help, doctor, setup dry-run, resource checks, and controlled C scan passed. The isolated wheel test suite passed 655 tests, skipped 11, and passed 225 subtests. |
| PowerShell | Pester 3.4.0 passed all 9 Windows bootstrap tests under Windows PowerShell 5.1. |
| Go and Clang | Go, `clang++`, and CMake are not installed. Python contract/fixture tests ran; tool-dependent Clang checks were skipped. |
| R, Julia, OPA, external RTL tools | Rscript and OPA are not installed. Julia resolves to an unverified Windows app alias. Icarus, Verilator, Yosys, and Verible are not installed. Built-in Python RTL and policy tests ran. |
| Java and Ghidra | `javac` is available. Ghidra is optional; the Python adapter, schema, and fixture checks ran, but live Ghidra execution was not performed. |
| NVIDIA pinned target | Historical 1,223-file run retained as an unvalidated candidate; not a confirmed vulnerability. The pinned working target was unavailable because the I: drive is not mounted, so it was not rerun. |
| PyPI and GitHub state | PyPI page reachable at 0.4.0; no package release or site deployment performed. Remote `main` and restored paths are verified after push. |

## Security and scope limits

The project identity classifier is bounded, passive, and heuristic. A score is not a probability. Incomplete traversal yields unknown identity. The Go operator is orchestration, not a security authority. Clang emits observations, not findings. Research scripts are optional and do not affect normal scans. The demo lab remains excluded. No production feature gap remains in the donor-main path ledger.

The final destination `main` commit and remote equality are reported after the normal, non-forced push and remote tree verification.
