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
| GitHub Actions analyzer | Repository scan | Workflow inventory and narrow static policy signals | Built in. No workflow executes. It does not perform full YAML semantics or event-input taint analysis. |
| PlatformIO/build context | Repository scan or selected build metadata | Bounded `platformio.ini` includes and compilation database metadata | Built in. FUSE does not run PlatformIO, project scripts, compilers, or commands stored in `compile_commands.json`. |
| KiCad netlist check | `--hardware-netlist` or one unique recognized netlist | UTF-8 XML connectivity to informational debug-interface candidates | Built in, bounded XML parser. FUSE does not invoke KiCad or infer physical access. |

Optional executables are resolved from the current environment's `PATH`. FUSE passes argument arrays, never shell commands, and records analyzer status, version when available, output artifact hashes, timeouts, and diagnostic-output limit failures. These controls do not sandbox an external tool. Review `threat-model.md` before enabling optional tools on hostile inputs.

Analyzer absence, failure, and partial coverage remain visible in reports. Use `docs/github-actions.md` for the separate workflow that runs FUSE in a repository's CI.
