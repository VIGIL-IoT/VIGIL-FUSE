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

Syft, OSV-Scanner, Binwalk, Gitleaks, and Ghidra are opt-in integrations. Host execution is the default. FUSE passes argument arrays and does not use `shell=True`. Before host launch, it removes environment variables whose names match common credential patterns, including tokens, passwords, keys, credentials, and authentication fields. A trusted host tool can receive an exact variable through `FUSE_ANALYZER_ENV_ALLOWLIST=tool-name:VARIABLE`; comma-separated entries are supported. The tool name must match the executable basename. An allowlisted variable is sent to every FUSE launch of that executable, including version checks. The allowlist setting itself is not forwarded. Each host invocation also gets temporary values for `HOME`, `USERPROFILE`, Windows `HOMEDRIVE` and `HOMEPATH`, Windows application-data paths, XDG config/cache/data paths, and temporary-directory variables. Directories are created for the child and cleaned up on completion where the operating system permits. The default working directory is the same per-run temporary root; adapters that explicitly require another directory, such as Git-history scanning, keep that selected directory.

FUSE limits each analyzer's execution time and combined captured stdout and stderr, and reports tool status and version. Pipe draining is deadline-bound so a descendant that inherits stdout or stderr cannot keep the scan waiting indefinitely. On POSIX, FUSE starts a host analyzer in a dedicated process session and uses nonblocking pipe reads. On Windows, it starts a host analyzer suspended, assigns it to a kill-on-close Job Object, then resumes it; termination falls back to the system `taskkill /T /F` command when needed. Host cleanup remains best effort. Some detached descendants or OS-level failures can escape cleanup.

`--analyzer-sandbox docker` is an explicit alternative. Each requested tool uses its own user-supplied SHA-256-pinned local image, and FUSE never pulls an image during a scan. The container has a read-only root filesystem, a read-only target mount, a read-only temporary Gitleaks configuration mount when history scanning is enabled, and a 64 MiB `noexec` tmpfs at `/tmp`. The host report directory is never bind-mounted. If it is nested in the scanned directory, FUSE masks that path with bounded tmpfs storage. Syft emits CycloneDX JSON on stdout. FUSE captures it under a 50 MiB limit and writes it into the report directory after the container exits. If OSV-Scanner consumes that generated inventory, FUSE mounts only the SBOM file read-only. Other analyzer output is captured under the default 10 MiB combined stdout and stderr limit. The container runs as a non-root user with all Linux capabilities dropped and `no-new-privileges` set. The Docker daemon's seccomp policy applies, and FUSE rejects a container explicitly configured with seccomp unconfined. PID, IPC, and cgroup namespaces are private, the container gets no devices, and networking is disabled. One CPU, 1 GiB memory, and 64 processes are requested. FUSE inspects the created container settings and refuses to start it when a required setting is absent. If Docker or an image is unavailable, the analyzer stage is unavailable and FUSE does not fall back to a host executable. Online OSV lookup requires `--sandbox-allow-osv-network`, which grants bridge networking to OSV-Scanner only.

The Docker daemon, host kernel, and user-selected analyzer image remain trusted components. A digest pins image identity but does not establish that its contents are safe. Do not use an image from an untrusted publisher. Containers are not virtual machines. Host mode remains unsandboxed. Docker Desktop and other runtimes can differ; rootless Linux resource flags require cgroup v2 with the systemd cgroup driver. Firmware parsing is performed by the selected external tool. Use a current trusted image and review the report's analyzer status and isolation detail.

OSV lookup can use the network when requested. Use the documented offline database or no-network option when network access is not acceptable. Other optional stages have their own data flow and status in the scan report. FUSE does not silently enable them.

Ghidra is not supported by the Docker analyzer adapter. A requested Ghidra stage in Docker mode is reported unsupported, and FUSE does not launch a host fallback. In host mode, the integration copies one regular input file into a generated temporary filename, hashes while staging, caps it at 128 MiB, invokes only the installed Ghidra 12.2 Headless Analyzer and the packaged FUSE-owned `FuseExport.java` script, and applies a wall-time limit. The script caps record counts and its JSON output at 8 MiB. FUSE caps captured process diagnostics at 10 MiB, validates the artifact against its structure and input digest, and deletes the temporary project with the workspace. Java option override variables are filtered for this child. Ghidra's parser still has the current user's permissions and may contain parser defects; process-tree cleanup is best effort and does not provide OS-level isolation. No target-provided scripts, extensions, Ghidra Server, or network project are used.

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
| Malicious or malformed executable parsed by Ghidra | Explicit opt-in, one staged file, 128 MiB input cap, Ghidra per-file timeout, FUSE wall-time limit, one CPU, bounded script records and artifact, diagnostic cap, temporary project cleanup | Ghidra is a complex host parser, not a sandbox; host file access and privileges remain available, and process cleanup is best effort |
| Analyzer output flood or hang | Output capture and wall-time limits; Docker mode removes the container after each invocation; host mode uses process-tree cleanup | Runtime or daemon failures can interrupt cleanup; host mode remains unsandboxed |
| Host file or credential access by an analyzer | Docker mode mounts selected inputs read-only, masks a nested report path with bounded tmpfs, captures bounded stdout, drops capabilities, and disables networking by default | Host mode can read files available to the user; Docker daemon, kernel, and selected image remain trusted; a malicious image can falsify the returned artifact |
| Resource limits ignored by rootless Docker | FUSE requires cgroup v2 and systemd for rootless resource limits and checks the created container configuration | Runtime configuration inspection cannot prove every host kernel enforces every limit identically |
| Secret exposure in output | Native credential and private-key evidence is redacted; history scanning stores redacted metadata | Secrets may appear in unsupported files, imported artifacts, filenames, external tool data, or other fields; review before sharing |
| Output overwrite or symlink target | Output directory and fixed artifact destinations are checked; symlink report destinations are refused | Existing regular files can be replaced; concurrent filesystem changes can create races |
| Misleading vulnerability claims | Severity, confidence, applicability, validation, and coverage are separate; static findings remain unvalidated by default | Users can still misinterpret findings if they ignore these fields and limitations |

## FMEA-lite: operational failure modes

This table focuses on failures that can change scan coverage or report durability. It complements the security threat table and does not add guarantees beyond the implementation.

| Failure mode | Likely cause | Effect | Detection | Mitigation and recovery | Residual risk |
| --- | --- | --- | --- | --- | --- |
| Discovery or scan budget is exhausted | Large tree, oversized files, or slow storage | Some files are skipped or analysis stops before the full target is checked | Coverage fields and skipped-file reasons identify partial analysis | Narrow the profile or path scope, then rerun against a stable target. Change limits only within hard ceilings | A partial report can still be mistaken for a complete review if coverage is ignored |
| Structured input is malformed or unsupported | Truncated, adversarial, newer, or unrecognized file format | The relevant context or analyzer stage may fail or be skipped | Parse and stage status appear in the report | Validate the input with its producer, export a supported format, or disable the affected optional stage | Unsupported semantics can remain outside FUSE's observations |
| Optional analyzer is missing or returns an error | Tool not installed, version mismatch, network failure, or invalid input | Dependency, firmware, or history results are missing | `doctor` reports availability; scan report records unavailable or failed status | Install a trusted compatible tool, repair the input, or rerun without the optional stage and review coverage | A report from other stages does not replace the missing analysis |
| Optional analyzer times out or exceeds output limits | Large or hostile input, slow tool, or excessive diagnostics | The stage is terminated and results may be incomplete | Timeout or output-limit status is reported | Reduce the target scope and rerun in an independently isolated environment | Process-tree cleanup is best effort and FUSE does not sandbox the analyzer |
| Report output cannot be written | Unwritable directory, insufficient disk space, unsafe path, or filesystem error | One or more reports or analyzer artifacts may be absent | CLI error, missing artifact, or incomplete artifact list | Use a dedicated writable output directory with adequate space and verify the artifact list before sharing | Existing regular files in the chosen output directory may be replaced |
| Target changes during a scan | Concurrent edits, generated files, or branch movement | The result can contain observations from more than one target state | Per-file digests record observed content, but a normal scan does not identify a transactional snapshot | Pin a revision and use a clean checkout for repeatable evaluation; rerun after changes settle | A local scan can still mix file states without detecting the change |

## Safe operating guidance

1. Scan only targets you own or have permission to assess.
2. Run `vigil-fuse scan --plan` first when the target or enabled stages are unfamiliar. Planning does not execute analyzers.
3. Use a dedicated output directory. Keep reports local until their contents are reviewed.
4. Enable optional analyzers explicitly. Use trusted tool installations, forward credentials only through the documented tool-specific allowlist when required, and isolate high-risk firmware analysis.
5. Treat a partial scan or a zero-finding report as incomplete evidence, not proof of security.
6. Do not upload proprietary firmware or reports to public issue trackers.

## Deferred hardening

FUSE provides an opt-in Docker boundary for selected external analyzers, but host mode remains unsandboxed and Docker is not a virtual machine. The current Docker integration has local Windows Docker Desktop evidence; Linux CI evidence and wider runtime coverage remain pending. The host process path does not provide privilege or memory isolation. FUSE does not provide transactional scan snapshots or automatic archive extraction. Host analyzer timeout cleanup remains best effort and may not contain detached descendants. FUSE does not perform symbolic execution, complete C/C++ data-flow analysis, physical hardware testing, or firmware execution. Those limits remain visible in the architecture and support matrix.
