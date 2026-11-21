# Dependency model

FUSE uses the Python standard library for its core scanner, CLI, reports, and setup coordination. `pyproject.toml` is the Python packaging source of truth. Its core `dependencies` list is empty, so `pip install vigil-fuse` does not install system software.

The setup manifest is `src/vigil_fuse/setup/tools.json`, schema version 1. It is packaged in the wheel and stores platform assets, HTTPS publisher URLs, pinned SHA-256 digests, version commands, categories, and manual installation sources. The downloader checks the declared publisher, HTTPS redirect host, size limit, checksum, and extracted executable version before placing a tool in the managed directory.

RECOMMENDED system binaries are offered by `setup`; Python extras are installed only with their named pip extra. The manifest lists only tools detected or integrated by this `main` snapshot. During future branch consolidation, a merged Rust accelerator or Zig runtime helper can be added as `OPTIONAL_HEAVY`, while R and Julia remain `RESEARCH`. OPA or RTL tools should be added only when their analyzers are integrated.

| Category | Tool or package | Why FUSE uses it | Platforms and installation | Version check and fallback |
| --- | --- | --- | --- | --- |
| CORE | Python 3.11+ and FUSE | CLI, local scanning, reports, setup, doctor | Windows, Linux, macOS; Python package | Doctor checks Python and package version. No external analyzer is required for core scans. |
| CORE | Python runtime packages | None | Installed by pip from package metadata; currently no runtime dependencies | Core scanner remains usable without optional extras. |
| RECOMMENDED | Syft | Local CycloneDX inventory | Pinned official releases for Linux and macOS x86_64/arm64 and Windows x86_64; user-local download after consent | `syft --version`, verified baseline 1.55.0; missing Syft skips SBOM generation. |
| RECOMMENDED | OSV-Scanner | Match SBOM components against OSV advisories | Pinned official releases for Linux and macOS x86_64/arm64 and Windows x86_64; user-local download after consent | `osv-scanner --version`, verified baseline 2.7.0; missing scanner skips advisory matching. |
| RECOMMENDED | Gitleaks | Optional Git history secret scanning | Pinned official releases for Linux and macOS x86_64/arm64 and Windows x86_64; user-local download after consent | `gitleaks --version`, verified baseline 8.30.0; missing tool skips history analysis. |
| RECOMMENDED | Git | Read repository history for Gitleaks integration | Official system installer or package manager; setup only detects it | `git --version`; missing Git affects history scans only. |
| OPTIONAL_HEAVY | Binwalk | Firmware signature identification | Manual official installation; platform packaging varies | `binwalk --version` with a help-banner fallback; missing Binwalk skips firmware signature analysis. |
| OPTIONAL_HEAVY | Docker | Run explicitly configured analyzer images | Manual official installation; daemon and image setup are operator-controlled | `docker --version`; FUSE does not install or start Docker. |
| OPTIONAL_HEAVY | Ghidra and Java JDK | Headless firmware binary analysis | Manual official installations; Ghidra is a large download and needs a compatible JDK | Existing Ghidra probe checks installation metadata, launcher, and Java compatibility. Missing Ghidra skips that stage. |
| OPTIONAL_HEAVY | pdfLaTeX | Optional PDF reports | Manual TeX distribution installation | `pdflatex --version`; JSON, text, and SARIF reports do not depend on it. |
| RESEARCH | R, Julia, Rust, Zig | Research branches and experiments, not normal scans | Detected only; install with the official language installer | Version commands are recorded in the manifest. `--recommended` never installs these toolchains. |
| RESEARCH | `jsonschema`, `matplotlib`, `psutil` | Dataset validation, research figures, and benchmark scripts | Optional Python extra: `vigil-fuse[research]` | Not installed by core pip installation or recommended setup. |
| RECOMMENDED | PyYAML extra | ESP-IDF lockfile parsing | Python extra: `vigil-fuse[esp-idf]`; installed only when explicitly selected | Without it, lockfile parsing is unavailable while the rest of FUSE works. |

Only the four requested class names are used for tool categories: `CORE`, `RECOMMENDED`, `OPTIONAL_HEAVY`, and `RESEARCH`. OPA, LLVM/Clang, Zig runtime helpers, RTL, and language-branch analyzers are not claimed as dependencies here because they are not integrated in this `main` snapshot.
