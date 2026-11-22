# Windows setup

FUSE supports Windows with Python 3.11 or newer. The Python setup coordinator works with Windows PowerShell 5.1 and PowerShell 7. It does not invoke downloaded scripts, change execution policy, request elevation, install WSL or Docker, or change the machine PATH.

## Install and inspect

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install vigil-fuse
vigil-fuse doctor
```

The setup command is part of the upcoming installer branch, not the currently published 0.4.0 package. When available in a release, use:

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
