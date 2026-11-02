# Compatibility and validation matrix

This matrix separates tested software combinations from declared package metadata and unverified environments. A CI result applies to the workflow revision and hosted runner used for that run. It does not guarantee compatibility with every distribution or machine.

## Core package

| Operating system and runner | Python versions | Status | Evidence | Notes |
| --- | --- | --- | --- | --- |
| Ubuntu GitHub-hosted runner | 3.11, 3.12, 3.13, 3.14 | CI verified | `.github/workflows/ci.yml`; FUSE CI [run 41457214087](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41457214087) | One hosted runner image per matrix job |
| Windows GitHub-hosted runner | 3.11 | CI verified | `.github/workflows/ci.yml`; FUSE CI [run 41457214087](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41457214087) | Windows path and process behavior also has focused regression tests |
| macOS GitHub-hosted runner | 3.11 | CI verified | `.github/workflows/ci.yml`; FUSE CI [run 41457214087](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41457214087) | The workflow tests Python 3.11 on the current hosted image |
| Windows local environment | 3.14.7 | Locally verified | Full test, editable-install usage-guide smoke, package build, and CLI scan on 2026-11-02 | This is one developer workstation, not a CI support claim |

Package metadata declares Python `>=3.11`. Python versions newer than 3.14 and Python/OS combinations not listed above are untested here. See `pyproject.toml` and the CI workflow for current declarations.

## Optional external analyzers

Optional analyzers have their own executable, parser, network, and platform risks. Their status does not change whether the core FUSE package works.

| Analyzer | Verified version and platform evidence | Status and scope |
| --- | --- | --- |
| Syft | 1.55.0 on Linux, macOS, and Windows, workflow [run 41377700744](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41377700744) | Integration controls passed for declared fixtures and inputs; not a complete software inventory accuracy study |
| OSV-Scanner | 2.7.0 on Linux, macOS, and Windows, workflow [run 41377700744](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41377700744) | Integration controls passed for declared fixtures; advisory freshness and network availability remain external |
| Gitleaks | 8.30.0 on Linux, macOS, and Windows, workflow [run 41377700744](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41377700744) | Integration controls passed for declared fixtures, including redacted output checks; this is not full secret-detection accuracy evidence |
| Binwalk | 3.1.0 on Ubuntu and Windows, workflow [run 41377931313](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41377931313) | Signature integration checks passed for the recorded samples; no extraction or firmware-content validation is claimed |

See the [experiment records](experiments/) and [firmware analysis limits](firmware-analysis.md) for exact inputs and scope. Tools may be absent on a user's machine. `vigil-fuse doctor` reports current local availability.

## Container isolation

The opt-in Docker analyzer path has a dedicated Linux CI job using a pinned fixture base image. Its hosted result is pending. A separate local Windows Docker Desktop smoke check used the official SHA-256-pinned Syft v1.55.0 image and verified two CycloneDX components on a nested report path. Docker mode has not been verified on macOS, Linux rootless Docker, or other daemon versions. Host mode remains the default and has the broader core package compatibility matrix above. See the [maturity closure plan](research/maturity-100-closure-plan-2026-11-02.md) for the security evidence and residual limits.

## Hardware and target projects

FUSE accepts supported source, configuration, build-metadata, BOM, KiCad XML netlist, and selected firmware inputs across the core operating-system matrix. It does not validate a physical board, firmware behavior, device communications, or deployment. Filename inventories and selected netlist findings are candidate evidence. The [support matrix](../src/vigil_fuse/support-matrix.json) and [limitations](limitations.md) define input-specific scope.
