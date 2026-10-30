# Software Bill of Materials

FUSE can use local Syft to create a CycloneDX inventory for a project being scanned. This is an opt-in external stage, not an automatically refreshed SBOM for the FUSE source distribution.

## Generate an SBOM while scanning a project

Install Syft separately and then run:

```powershell
python -m vigil_fuse scan path\to\project --sbom --output-dir .fuse-results
```

FUSE asks Syft to write `components.cdx.json` in the selected report directory and records the analyzer status and artifact hash. The exact Syft version is reported when available. Syft was not installed during the local repository audit, so this optional external stage was not executed there. See [integrations](integrations.md) and [threat model](threat-model.md).

## Generate an SBOM for FUSE itself

With a trusted local Syft installation, generate a CycloneDX JSON SBOM from a reviewed checkout:

```powershell
syft dir:. -o cyclonedx-json=./fuse-sbom.cdx.json
```

Review the output against the package metadata and the exact source revision. Syft inventory depends on what its scanner recognizes in the checkout and environment. It does not create a signed release attestation or verify package provenance.

## Reproducibility and handling

- Record the FUSE commit or source archive digest, Syft version, operating system, and command alongside an SBOM used for an evaluation or release review.
- Regenerate the SBOM when dependencies or package contents change. A checked-in SBOM can become stale.
- Inspect the output before sharing because package paths and versions may reveal implementation details.
- Do not upload or distribute the FUSE package or its artifacts through a registry or download service without resolving the current license restrictions and obtaining any required written permission.
- The core runtime dependency list is empty. Development and optional dependencies are declared in `pyproject.toml`; generated inventories may include environment packages depending on the scan target.
