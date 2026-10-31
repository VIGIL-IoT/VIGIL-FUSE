# FUSE threat model

FUSE reads source trees, configuration, build metadata, dependency inventories, optional firmware images, and selected hardware files. It produces local text, JSON, SARIF, inventory, and analyzer artifacts. This document describes the current trust boundaries and residual risks. It is an engineering guide, not a security certification.

## Security goals

- Do not execute scanned source, firmware, build scripts, PlatformIO scripts, or compilation database commands.
- Bound discovery, input size, rule time, analyzer time, and captured analyzer output.
- Keep reports relative to the target by default and redact detected credential and private-key values.
- Report skipped input, unsupported types, analyzer failures, and partial coverage instead of treating missing analysis as a clean result.
- Make unsafe or uncertain evidence visible without claiming reachability, deployment, or exploitability.

## Assets and sensitive data

- Source and firmware contents provided by the user.
- Credentials and cryptographic material that may be present in scanned inputs.
- Relative paths, dependency names, hardware inventory, configuration, and findings in reports.
- Generated SBOM, OSV, firmware-identification, Git-history, and hardware-BOM artifacts.
- The user's environment, optional analyzer executables, and report output directory.

Reports are local artifacts, not automatically safe to publish. Secret values detected by native credential and private-key rules are redacted in evidence. Other metadata can still disclose proprietary project structure, components, firmware names, or configuration. Review reports before sharing.

## Trust boundaries

### Target repository and selected files

Treat every target file name and byte as untrusted. FUSE reads regular files selected by a profile, rejects symbolic links in discovery, ignores generated directories by policy, and applies explicit path, directory, file, source-byte, and wall-clock budgets. The current defaults and hard ceilings are recorded in `src/vigil_fuse/limits.py`. Input files are not executed. A project can still change files while a scan is running, so the input digest is evidence of files actually read, not a transactionally consistent repository snapshot.

### Native rules

Native rules run in a killable Python worker with a per-rule, per-input timeout. The worker boundary limits a hung rule but is not an operating-system sandbox. It does not restrict filesystem access, system calls, memory, or privileges. Rules receive selected source text and normalized relative paths; they do not load project Python modules.

### Optional external analyzers

Syft, OSV-Scanner, Binwalk, and Gitleaks are opt-in subprocess integrations. FUSE passes argument arrays and does not use `shell=True`. Before launch, it removes environment variables whose names match common credential patterns, including tokens, passwords, keys, credentials, and authentication fields. A trusted tool can receive an exact variable through `FUSE_ANALYZER_ENV_ALLOWLIST=tool-name:VARIABLE`; comma-separated entries are supported. The tool name must match the executable basename. An allowlisted variable is sent to every FUSE launch of that executable, including version checks. The allowlist setting itself is not forwarded. Each invocation also gets temporary values for `HOME`, `USERPROFILE`, Windows `HOMEDRIVE` and `HOMEPATH`, Windows application-data paths, XDG config/cache/data paths, and temporary-directory variables. Directories are created for the child and cleaned up on completion where the operating system permits. The default working directory is the same per-run temporary root; adapters that explicitly require another directory, such as Git-history scanning, keep that selected directory.

FUSE limits each analyzer's execution time and combined captured stdout and stderr, and reports tool status and version. Pipe draining is deadline-bound so a descendant that inherits stdout or stderr cannot keep the scan waiting indefinitely. On POSIX, FUSE starts an analyzer in a dedicated process session and uses nonblocking pipe reads. On Windows, it starts the analyzer suspended, assigns it to a kill-on-close Job Object, then resumes it; termination falls back to the system `taskkill /T /F` command when needed. These measures improve cleanup of ordinary child processes but remain best effort. Some detached descendants or OS-level failures can escape cleanup. Temporary default home/config/cache paths reduce accidental use of the caller's normal per-user tool state, but an analyzer can still read any accessible file, follow explicitly configured file paths, and use the network or system resources available to the current user. The environment allowlist, temporary directories, and process cleanup do not provide filesystem, network, memory, or privilege isolation. Firmware parsing is performed by the selected external tool. Use current trusted tools and an isolated environment for hostile firmware.

OSV lookup can use the network when requested. Use the documented offline database or no-network option when network access is not acceptable. Other optional stages have their own data flow and status in the scan report. FUSE does not silently enable them.

### Structured inputs

- CycloneDX and SPDX detection is size bounded. Full input parsing and matching have schema and size limitations documented by the relevant adapter.
- ESP-IDF `dependencies.lock` is size bounded, uses an optional safe PyYAML loader, rejects aliases and duplicate keys, and caps YAML events and nesting.
- KiCad XML netlists must be UTF-8, are capped at 10 MiB, reject DTD and entity declarations during a streaming Expat preflight, and are limited to 100,000 elements and 128 levels before ElementTree builds the tree. The format follows KiCad's documented UTF-8 XML export. FUSE does not invoke KiCad.
- TOML, JSON, VEX, provenance, and Zephyr hardening inputs are parsed as data. They do not invoke commands described by those documents.

### Report output and terminal

Report paths are target relative where applicable. Fixed artifact names are written only under the selected output directory; symbolic-link destinations are rejected. A regular existing report file can be replaced, so choose a dedicated output directory and inspect it before use. Text output escapes control and bidirectional characters so untrusted file names or evidence cannot issue terminal control sequences. JSON and SARIF are serialized as data, not printed as free-form terminal text.

## Threats and current controls

| Threat | Current controls | Residual risk |
| --- | --- | --- |
| Huge trees or files | Configurable discovery, byte, time, and per-file budgets; incomplete coverage is reported | A scan can still consume the configured CPU and memory budget; hard ceilings are not OS resource controls |
| Symlink escape or special files | Discovery skips symlinks and non-regular files; selected metadata inputs validate paths | Files can be swapped between checks and reads; platform-specific race resistance is not equivalent to descriptor-based sandboxing |
| Terminal escape and bidi spoofing | Human-readable report and CLI text escape terminal control and bidi characters | JSON consumers may render text differently; inspect before publishing reports |
| XML entities and parser exhaustion | UTF-8 check, DTD/entity rejection, streaming structural preflight, byte, element, and depth limits | XML parsing still occurs in-process and shares FUSE's memory and privileges |
| Malformed JSON/YAML/configuration | Bounded reads, safe loader, duplicate-key and depth/event checks where applicable, explicit invalid or partial status | Not every format has a complete adversarial corpus or independent parser sandbox |
| Analyzer output flood or hang | Streaming output cap, deadline-bound pipe draining, and best-effort process-tree cleanup; errors become analyzer status | Descendants can escape cleanup; the child process is not a sandbox and OS-level resource use is not fully controlled |
| Host credential exposure through analyzer environment and default user configuration | Common credential-named environment variables are removed; exact tool-specific forwarding is opt-in; default home, XDG config/cache/data, Windows application-data, and temporary paths point to a per-run workspace | Name matching is heuristic; explicit configuration paths and credentials in any readable files remain accessible; this is not an operating-system sandbox |
| Secret exposure in output | Native credential and private-key evidence is redacted; history scanning stores redacted metadata | Secrets may appear in unsupported files, imported artifacts, filenames, external tool data, or other fields; review before sharing |
| Output overwrite or symlink target | Output directory and fixed artifact destinations are checked; symlink report destinations are refused | Existing regular files can be replaced; concurrent filesystem changes can create races |
| Misleading vulnerability claims | Severity, confidence, applicability, validation, and coverage are separate; static findings remain unvalidated by default | Users can still misinterpret findings if they ignore these fields and limitations |

## Safe operating guidance

1. Scan only targets you own or have permission to assess.
2. Run `vigil-fuse scan --plan` first when the target or enabled stages are unfamiliar. Planning does not execute analyzers.
3. Use a dedicated output directory. Keep reports local until their contents are reviewed.
4. Enable optional analyzers explicitly. Use trusted tool installations, forward credentials only through the documented tool-specific allowlist when required, and isolate high-risk firmware analysis.
5. Treat a partial scan or a zero-finding report as incomplete evidence, not proof of security.
6. Do not upload proprietary firmware or reports to public issue trackers.

## Deferred hardening

FUSE does not currently provide a container or OS sandbox, process memory limits, transactional snapshots, or automatic archive extraction. Credential environment filtering and analyzer child-process cleanup are defense in depth and do not replace those controls. Timeouts and output limits trigger best-effort termination through POSIX process groups or Windows Job Objects, with a Windows `taskkill` fallback, but do not guarantee complete descendant containment. FUSE does not perform symbolic execution, complete C/C++ data-flow analysis, physical hardware testing, or firmware execution. Those limits remain visible in the architecture and support matrix.
