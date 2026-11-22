# Windows setup

FUSE supports Windows with Python 3.11 or newer. The Python setup coordinator works with Windows PowerShell 5.1 and PowerShell 7. It does not invoke downloaded scripts, change execution policy, request elevation, install WSL or Docker, or change the machine PATH.

## Install and inspect

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install .
vigil-fuse doctor
```

After installing this checkout or its locally built wheel, use:

```powershell
vigil-fuse setup --recommended
vigil-fuse doctor
```

FUSE detects existing tools on `PATH` first and reuses healthy installations. Approved managed downloads are stored under `%LOCALAPPDATA%\Vigil-FUSE\Tools`. FUSE resolves its own managed copies directly, so it does not need to edit PATH. To choose another user-writable volume, set `VIGIL_FUSE_TOOLS_DIR` for the process before setup, for example:

```powershell
$env:VIGIL_FUSE_TOOLS_DIR = 'I:\Security Tools\Vigil FUSE'
vigil-fuse setup --recommended --dry-run
```

Paths with spaces are supported. `--dry-run` performs no network request and makes no machine changes. A real recommended setup asks before downloading; `--yes` is explicit consent for the pinned user-local binaries only. It does not authorize system changes or heavy tools.

## Existing installations and recovery

If a tool is already available and reports a supported version, setup reuses it. If the system copy is broken or too old, setup leaves it untouched and prints the official recovery source. `--upgrade` applies only to a copy managed under the selected FUSE tools directory.

PowerShell discovery is informational. Python remains the cross-platform coordinator, and Windows bootstrap actions do not depend on a PowerShell version-specific installation script.

## Optional packaged PowerShell bootstrap


FUSE's scanner remains a Python application with no required PowerShell runtime. The packaged PowerShell layer is optional Windows installation and diagnostic glue. It does not contain scan rules or security decisions, and normal FUSE use on Linux and macOS does not depend on it.

## Commands

From a repository checkout, run the script with Windows PowerShell 5.1 or PowerShell 7:

```powershell
$setup = '.\src\vigil_fuse\resources\powershell\fuse-setup.ps1'
powershell.exe -NoProfile -File $setup doctor
powershell.exe -NoProfile -File $setup plan
```

Both commands write one compact JSON object to standard output. The object has `schemaVersion: 1`; `doctor` includes platform, PowerShell and environment checks, tool versions, executable paths, and PATH diagnostics. The `plan` command is read-only and marks that no changes were made. A failed command writes a JSON error and exits with code 1. Python can capture and parse this output without parsing terminal formatting.

The Python `vigil-fuse setup` coordinator and these explicitly invoked PowerShell helpers are separate interfaces. Normal `doctor` and `scan` remain Python commands.

## Dependency categories

The plan does not install tools automatically. It reports these categories:

| Category | Tools | Use |
| --- | --- | --- |
| `CORE` | Python, `vigil-fuse` | FUSE's runtime and CLI |
| `RECOMMENDED` | Syft, OSV-Scanner, Binwalk, Gitleaks | Optional FUSE analyzer integrations |
| `OPTIONAL_HEAVY` | Ghidra, Docker | Larger reverse-engineering or container tools |
| `RESEARCH` | `kubectl`, Clang/LLVM, OPA | Discovery only; not required for a normal scan |

Tool discovery uses `PATH`, plus `GHIDRA_INSTALL_DIR` for Ghidra. Version probes have a five-second timeout and a 64 KiB combined output limit. Ghidra's version is read from its local `application.properties` file. A tool's presence does not prove that its service, plugins, or scan configuration work.

## Verified user-local installs

`install` accepts an explicit tool name, versioned HTTPS release URL, SHA-256 digest, and executable path inside the archive. For example, substitute a current release URL and digest obtained from the tool's official release channel:

```powershell
powershell.exe -NoProfile -File $setup install `
  -ToolName Gitleaks `
  -Version 8.30.0 `
  -Uri 'https://github.com/gitleaks/gitleaks/releases/download/v8.30.0/gitleaks_8.30.0_windows_x64.zip' `
  -Sha256 '<64 hexadecimal characters>' `
  -ExecutableRelativePath 'gitleaks.exe' `
  -ArtifactFormat zip `
  -DryRun
```

Remove `-DryRun` to install. Interactive calls ask before writing. Use `-Yes` for a noninteractive install. The default destination is `%LOCALAPPDATA%\Vigil-FUSE\tools\<tool>\<version>`; `-InstallRoot 'I:\FUSE Tools'` selects a different local directory. Repeated installs verify the recorded version, release digest, executable path, and installed file tree before reusing an existing copy.

Downloads require HTTPS, a version in the URL, a 64-character SHA-256 digest, and a URL without credentials, query parameters, or fragments. Redirects must remain on HTTPS. ZIP extraction rejects path traversal and symbolic links and is limited to 10,000 entries and 2 GiB expanded data. Direct-file installs are also supported. The module never executes downloaded files or scripts and never overwrites an existing destination.

The module does not currently ship a curated release manifest. The operator must supply a trusted official source URL and digest. Use the install helper only when those values are verified against the publisher's release data. Docker, kubectl, Windows installer packages, and other tools that require a vendor installer or service setup are discovered but are not silently provisioned by this helper.

No install command elevates privileges, edits user or machine `PATH`, changes execution policy, disables security software, installs WSL or Docker, or deletes user files. Temporary downloads and staging directories are removed after success or failure. The helper writes only into the selected install root and its own uniquely named temporary directory.

## Platform scope

This stage targets Windows PowerShell 5.1 and PowerShell 7. The Python coordinator supplies cross-platform discovery and pinned user-local provisioning. This separate PowerShell helper is not invoked automatically by Python setup; its explicit URI, version and digest arguments remain operator supplied.
