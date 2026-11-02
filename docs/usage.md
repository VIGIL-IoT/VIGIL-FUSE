# Using FUSE

FUSE is a local command-line tool for reviewing embedded and IoT project sources, configuration, hardware inventories, dependency inputs, and selected firmware images. It gathers evidence for review. A finding is not proof that a deployed device is vulnerable.

## Install from the repository

FUSE requires Python 3.11 or newer. From the repository root, create and activate a virtual environment, then install the project in editable mode.

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
```

Linux or macOS:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

Check the CLI and available optional tools:

```sh
vigil-fuse --version
vigil-fuse doctor
```

The native scanner has no runtime dependencies. Optional analyzer stages need their own executables on `PATH`.

## Preview a scan

Use `--plan` to preview selected inputs, stages, limits, and optional tools before running analysis:

```sh
vigil-fuse scan path/to/embedded-project --plan
```

Planning does not run analyzers or project commands. Choose a profile when the target needs framework-specific discovery:

```sh
vigil-fuse scan path/to/esp-idf-project --profile esp-idf --plan
vigil-fuse scan path/to/zephyr-project --profile zephyr --plan
vigil-fuse scan path/to/embedded-linux-project --profile embedded-linux --plan
```

Use `generic` for projects without a specific profile. FUSE does not run PlatformIO, `west`, CMake, compilers, or commands listed in `compile_commands.json`.

## Scan a project

Run the scan and write its reports to a folder:

```sh
vigil-fuse scan path/to/embedded-project --output-dir .fuse-results
```

The output folder contains `findings.json`, `findings.txt`, and `findings.sarif`. JSON preserves structured findings and coverage details. Text is convenient for terminal review. SARIF is available for compatible code-scanning tools.

Limit the scope with repeatable path patterns, or select a stable report label that does not contain a local path:

```sh
vigil-fuse scan path/to/embedded-project \
  --include "src/**" \
  --exclude "vendor/**" \
  --target-label organization/repository \
  --output-dir .fuse-results
```

Set `--fail-on high` to return exit status 1 when a finding at high severity or above is present. The default does not fail based on severity.

## Optional analysis stages

Optional analyzers run only when requested. Install and trust the relevant tools before enabling them.

| Option | Tool | What it does |
| --- | --- | --- |
| `--sbom` | Syft | Creates a CycloneDX software inventory. |
| `--vulnerabilities` | OSV-Scanner | Checks detected manifests or a supplied SBOM against advisories. Network access may occur. |
| `--git-history` | Gitleaks | Checks commits reachable from the target's `HEAD` and records redacted finding metadata. |
| `--firmware` | Binwalk | Identifies signatures in one selected firmware image. FUSE does not extract the image. |

### Run optional analyzers in Docker

Host execution is the default. For hostile or untrusted inputs, Docker mode runs each requested analyzer from a separate local image identified by a SHA-256 digest. The image must expose the analyzer as a matching entrypoint or on `PATH`. FUSE uses `--pull=never`, so fetch and inspect images before scanning. A missing image or Docker runtime produces an unavailable analyzer status. FUSE does not fall back to a host executable.

```sh
docker pull anchore/syft:v1.55.0
docker image inspect --format '{{index .RepoDigests 0}}' anchore/syft:v1.55.0

vigil-fuse scan path/to/embedded-project \
  --sbom \
  --analyzer-sandbox docker \
  --sandbox-image syft=anchore/syft@sha256:<64-hex-digest> \
  --output-dir .fuse-results
```

Repeat `--sandbox-image` for each requested tool: `syft`, `osv-scanner`, `binwalk`, and `gitleaks`. A local image can be pinned by its `sha256:<64-hex-digest>` image ID. Only use images you trust. The report records the image reference and the isolation settings used for each completed or failed analyzer stage.

Docker mode sets a non-root user, read-only container root and input mounts, dropped Linux capabilities, `no-new-privileges`, the Docker daemon's seccomp policy, a private PID namespace, private IPC and cgroup namespaces, no devices, no network, one CPU, 1 GiB memory, 64 processes, and a bounded 64 MiB scratch filesystem. The host report directory is never bind-mounted. If it is nested in the scanned directory, FUSE masks that path inside the container with bounded temporary storage. Syft writes CycloneDX JSON to stdout, which FUSE captures under a 50 MiB limit and writes to the report directory only after the container exits. When OSV-Scanner consumes that generated inventory, FUSE mounts only the SBOM file read-only. Other analyzer diagnostics share a 10 MiB capture limit. FUSE rejects a container configured with seccomp unconfined and checks the other created settings before starting the analyzer. The Docker engine and the selected analyzer image remain part of the trusted computing base. On Linux rootless Docker, resource limits require cgroup v2 with the systemd cgroup driver.

Online OSV advisory lookup needs explicit network access for that container:

```sh
vigil-fuse scan path/to/embedded-project \
  --vulnerabilities \
  --analyzer-sandbox docker \
  --sandbox-allow-osv-network \
  --sandbox-image osv-scanner=ghcr.io/google/osv-scanner@sha256:<64-hex-digest> \
  --output-dir .fuse-results
```

This gives bridge networking only to OSV-Scanner. Other analyzer containers remain offline. Do not combine the flag with `--no-network`. Offline vulnerability checks need an OSV database available inside the selected image.

For an offline dependency check, use `--no-network` with the vulnerability stage and a suitable local OSV database:

```sh
vigil-fuse scan path/to/embedded-project \
  --vulnerabilities \
  --no-network \
  --output-dir .fuse-results
```

Offline checks can be incomplete if the local advisory database is missing or stale. The report records stage status and coverage.

Firmware signature analysis uses a single image target:

```sh
vigil-fuse scan path/to/firmware.bin \
  --firmware \
  --output-dir .fuse-firmware-results
```

The result is signature evidence, not proof that a specific device runs the image. FUSE does not extract or execute firmware.

## Hardware inputs

Repository scans inventory recognizable hardware filenames. The inventory indicates that a design or manufacturing file may be present. FUSE does not parse every schematic or PCB format by default, and file presence does not prove a debug interface is accessible.

You can explicitly import a BOM or inspect one KiCad XML netlist:

```sh
vigil-fuse scan path/to/project \
  --hardware-bom path/to/board-bom.csv \
  --hardware-netlist path/to/board-netlist.xml \
  --output-dir .fuse-hardware-results
```

The BOM import creates a CycloneDX hardware inventory. The netlist check reports informational debug-interface candidates only. Review the schematic, PCB, production configuration, and physical device before making an exposure claim.

## Review findings

Each finding includes evidence and location where available. Severity represents potential impact. Confidence represents the strength of the evidence. Applicability and validation are separate fields. Do not combine them into one score or treat a candidate signal as a confirmed vulnerability.

Review scan coverage and optional-stage status along with the findings. An unavailable analyzer, skipped input, or partial scan means the report covers less than the full target.

Keep reports private when they contain project paths, dependency details, hardware inventory, or security findings. Check the output before sharing it.

## Configuration and more detail

Use `--config fuse.example.toml` as a starting point for repeatable scan settings. Command-line options can override supported settings.

Read more about [finding fields](finding-schema.md), [optional integrations](integrations.md), [hardware analysis](hardware-analysis.md), [firmware analysis](firmware-analysis.md), and [rule development](rule-development.md).
