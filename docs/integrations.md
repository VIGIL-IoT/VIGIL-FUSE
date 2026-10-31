# Integrations and data flow

FUSE keeps native rules, inventory observations, and optional external analyzers separate. Run `vigil-fuse scan --plan` to preview recognized inputs and stages. The plan does not execute analyzers or project commands.

| Integration | Enabled by | Input and output | Network behavior and limits |
| --- | --- | --- | --- |
| Syft | `--sbom` | Local project inventory to CycloneDX JSON in the output directory | Optional executable. Bounded runtime and captured diagnostics. |
| OSV-Scanner | `--vulnerabilities` | Detected manifests or a supplied SBOM to advisory findings and `osv-results.json` | Network lookup may occur by default. Use the offline database or `--no-network` mode when required. |
| Binwalk | `--firmware` with one firmware image target | Firmware digest and signature identification | Optional executable. Extraction is not requested. Image size and process time are bounded. |
| Gitleaks | `--git-history` | Commits reachable from the target's `HEAD` to redacted history findings | Optional executable. Shallow history is reported as partial. Raw secret values are not saved. |
| ESP-IDF lock parser | ESP-IDF profile and installed `vigil-fuse[esp-idf]` extra | Bounded `dependencies.lock` metadata | PyYAML safe loading. No component manager or build command runs. |
| Zephyr hardening import | Zephyr profile, selected build directory, `--zephyr-hardening-report` | User-generated hardening JSON to candidate findings | FUSE does not run `west`, CMake, or Zephyr's build. |
| GitHub Actions analyzer | Repository scan | Workflow inventory, exact workflow/job `write-all` scalar checks, floating action-ref signals, and a narrow `pull_request_target` plus pull request head checkout candidate | Built in. No workflow executes. It does not perform full YAML semantics, permission-inheritance analysis, or determine whether checked-out untrusted code is built or executed. |
| PlatformIO/build context | Repository scan or selected build metadata | Bounded `platformio.ini` includes and compilation database metadata | Built in. FUSE does not run PlatformIO, project scripts, compilers, or commands stored in `compile_commands.json`. |
| KiCad netlist check | `--hardware-netlist` or one unique recognized netlist | UTF-8 XML connectivity to informational debug-interface candidates | Built in, bounded XML parser. FUSE does not invoke KiCad or infer physical access. |

Optional executables are resolved from the current environment's `PATH`. FUSE passes argument arrays, never shell commands, and records analyzer status, version when available, output artifact hashes, timeouts, and diagnostic-output limit failures. These controls do not sandbox an external tool. Review `threat-model.md` before enabling optional tools on hostile inputs.

Analyzer absence, failure, and partial coverage remain visible in reports. Use `docs/github-actions.md` for the separate workflow that runs FUSE in a repository's CI.

## Gitleaks adapter smoke check

The optional [Gitleaks adapter harness](../scripts/verify_gitleaks_adapter.py) uses temporary local repositories to check one synthetic positive history and one clean control. It verifies completion status and checks that the generated test value is absent from output. It does not contact a credential service or validate detector accuracy. Run it from the repository root with Git and Gitleaks available on `PATH`:

```powershell
python scripts/verify_gitleaks_adapter.py --expected-version 8.30.0
```

The pinned tool version, checksum, observed results, and limits for the 2026-10-31 run are recorded in the [experiment note](experiments/gitleaks-adapter-e2e-2026-10-31.md).

## Syft and OSV-Scanner adapter smoke check

The optional [dependency adapter harness](../scripts/verify_dependency_adapters.py) checks the full Syft to CycloneDX to OSV-Scanner flow with a vulnerable dependency, a clean dependency control, and a project with no dependency sources. It creates temporary manifests and reports, does not install the listed packages, and removes its fixtures when the run ends. OSV-Scanner uses its normal online advisory lookup for the two dependency cases.

Install Syft and OSV-Scanner, make both available on `PATH`, then run from the FUSE repository root:

```powershell
python scripts/verify_dependency_adapters.py --expected-syft-version 1.55.0 --expected-osv-version 2.7.0
```

The harness expects at least one advisory for `urllib3==1.25.2`, no advisory for `idna==3.15` on the recorded database snapshot, and a partial OSV status with no fabricated result artifact when a CycloneDX SBOM has no package components. Advisory data changes over time, so the positive count can vary. The tool versions, release asset hashes, observed outputs, and limitations for the 2026-10-31 run are recorded in the [experiment note](experiments/dependency-adapters-e2e-2026-10-31.md).

## Binwalk adapter smoke check

The [Binwalk adapter harness](../scripts/verify_binwalk_adapter.py) checks `--firmware` against a synthetic gzip image and a clean byte-string control. It confirms that FUSE records the tool version and identification output, detects the gzip signature only in the positive control, and does not create an extraction directory. It does not extract or execute firmware.

Install Binwalk in a Linux or Windows environment, make it available on `PATH`, then run from the FUSE repository root:

```powershell
python scripts/verify_binwalk_adapter.py
```

Use `--expected-version` when a specific executable banner is required. The 2026-10-31 check used Ubuntu's Binwalk package in WSL2; the executable help banner was `Binwalk v2.3.3`. The package hashes, results, and limits are recorded in the [experiment note](experiments/binwalk-adapter-e2e-2026-10-31.md).
