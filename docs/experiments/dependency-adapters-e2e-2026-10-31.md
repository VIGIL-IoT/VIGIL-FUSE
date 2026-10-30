# Syft and OSV-Scanner adapter end-to-end check

**Date:** 2026-10-31 | **FUSE source:** local worktree based on `b174591`, including the adapter change described here

**Purpose:** Exercise FUSE's dependency inventory and advisory adapters with real Syft and OSV-Scanner executables. The check covers a positive dependency, a clean dependency control, and a project with no recognized package sources.

## Environment and tool provenance

- Windows 11 build `10.0.26300`
- Python `3.14.7`
- [Syft `v1.55.0`](https://github.com/anchore/syft/releases/tag/v1.55.0), Windows x64 release asset
- Syft asset SHA-256: `ada4c9b93af575f479ce80fce6629897272a2d41f300a14bc49bace020767ca2`
- [OSV-Scanner `v2.7.0`](https://github.com/google/osv-scanner/releases/tag/v2.7.0), Windows x64 release asset
- OSV-Scanner asset SHA-256: `9964ed64ec9a387391eb4cc006ad5c531154821aef29b793e02c448de4686438`

Both downloaded asset hashes matched the SHA-256 digests published by the corresponding GitHub release APIs before the tools were run.

## Method

The [repeatable harness](../../scripts/verify_dependency_adapters.py) runs FUSE with `--sbom --vulnerabilities` against three temporary projects:

1. Positive dependency: `urllib3==1.25.2`.
2. Clean dependency control: `idna==3.15`.
3. No-source control: a README-only project with no dependency manifest.

The harness validates the FUSE report, CycloneDX structure, OSV results where available, adapter versions, coverage status, and expected finding behavior. The two dependency cases use OSV-Scanner's normal online advisory lookup. Packages are not installed, project code is not run, and no remote repository is contacted.

Run it from the repository root with both tools on `PATH`:

```powershell
python scripts/verify_dependency_adapters.py --expected-syft-version 1.55.0 --expected-osv-version 2.7.0
```

## Results

| Case | FUSE exit | Syft status | OSV-Scanner status | OSV findings | Interpretation |
| --- | ---: | --- | --- | ---: | --- |
| `urllib3==1.25.2` | 0 | completed | completed | 11 | Positive advisory signal in the database snapshot checked on this date |
| `idna==3.15` | 0 | completed | completed | 0 | No matching advisory in the database snapshot checked on this date |
| README-only project | 2 | completed | partial | 0 | OSV found no package sources, so matching did not run and no OSV result artifact was written |

Both tools emitted the expected artifacts for the dependency cases. Syft produced CycloneDX JSON, OSV-Scanner produced readable JSON results, and FUSE reported both versions. The local FUSE scan returned exit code 2 for the README-only project because analysis was incomplete, while preserving the explanatory partial status in its JSON report.

The empty-project check exposed a behavior mismatch in the adapter: OSV-Scanner 2.7.0 reports `No package sources found` on stderr with exit code 128 and no JSON on stdout. FUSE previously treated that expected no-source condition as malformed JSON. The adapter now records a partial status and does not create an empty artifact that could imply advisory matching completed. A regression test covers this path.

## Interpretation and limits

This is an integration smoke check for executable discovery, Syft output parsing, adapter handoff, OSV result normalization, and empty-input reporting. It is not an accuracy study. The advisory database is mutable, so finding counts can change. The clean control only describes the database snapshot checked on 2026-10-31. The run covered one Windows environment and did not establish cross-platform behavior, broad detector precision or recall, exploitability, or reachability. Binwalk was tested separately in the [firmware adapter experiment](binwalk-adapter-e2e-2026-10-31.md), which also does not measure field accuracy.
