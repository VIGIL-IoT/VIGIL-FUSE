Set-StrictMode -Version Latest

$script:FuseTools = @(
    [pscustomobject]@{ Name = 'vigil-fuse'; Executable = 'vigil-fuse.exe'; Category = 'CORE'; VersionArgs = @('--version'); VersionSource = 'process' },
    [pscustomobject]@{ Name = 'Python'; Executable = 'python.exe'; Category = 'CORE'; VersionArgs = @('--version'); VersionSource = 'process' },
    [pscustomobject]@{ Name = 'Syft'; Executable = 'syft.exe'; Category = 'RECOMMENDED'; VersionArgs = @('version'); VersionSource = 'process' },
    [pscustomobject]@{ Name = 'OSV-Scanner'; Executable = 'osv-scanner.exe'; Category = 'RECOMMENDED'; VersionArgs = @('version'); VersionSource = 'process' },
    [pscustomobject]@{ Name = 'Binwalk'; Executable = 'binwalk.exe'; Category = 'RECOMMENDED'; VersionArgs = @('--version'); VersionSource = 'process' },
    [pscustomobject]@{ Name = 'Gitleaks'; Executable = 'gitleaks.exe'; Category = 'RECOMMENDED'; VersionArgs = @('version'); VersionSource = 'process' },
    [pscustomobject]@{ Name = 'Ghidra'; Executable = 'analyzeHeadless.bat'; Category = 'OPTIONAL_HEAVY'; VersionArgs = @(); VersionSource = 'ghidra' },
    [pscustomobject]@{ Name = 'Docker'; Executable = 'docker.exe'; Category = 'OPTIONAL_HEAVY'; VersionArgs = @('--version'); VersionSource = 'process' },
    [pscustomobject]@{ Name = 'kubectl'; Executable = 'kubectl.exe'; Category = 'RESEARCH'; VersionArgs = @('version', '--client=true'); VersionSource = 'process' },
    [pscustomobject]@{ Name = 'Clang/LLVM'; Executable = 'clang.exe'; Category = 'RESEARCH'; VersionArgs = @('--version'); VersionSource = 'process' },
    [pscustomobject]@{ Name = 'OPA'; Executable = 'opa.exe'; Category = 'RESEARCH'; VersionArgs = @('version'); VersionSource = 'process' }
)

$script:MaximumDownloadBytes = 1GB
$script:MaximumExpandedBytes = 2GB
$script:MaximumArchiveEntries = 10000
$script:MaximumVersionOutputBytes = 65536
$script:VersionTimeoutSeconds = 5

function Get-FusePlatform {
    $architecture = $env:PROCESSOR_ARCHITEW6432
    if ([string]::IsNullOrWhiteSpace($architecture)) { $architecture = $env:PROCESSOR_ARCHITECTURE }
    $architecture = if ([string]::IsNullOrWhiteSpace($architecture)) { 'unknown' } else {
        switch ($architecture.ToUpperInvariant()) {
            { $_ -in 'AMD64', 'X64', 'X86_64' } { 'x64'; break }
            { $_ -in 'ARM64', 'AARCH64' } { 'ARM64'; break }
            { $_ -in 'X86', 'I386', 'I686' } { 'x86'; break }
            default { 'unknown' }
        }
    }

    [pscustomobject]@{
        operatingSystem = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { 'Windows' } else { [Environment]::OSVersion.Platform.ToString() }
        architecture = $architecture
        powerShellVersion = $PSVersionTable.PSVersion.ToString()
    }
}

function Get-FuseToolCatalog {
    return @($script:FuseTools | ForEach-Object {
        [pscustomobject]@{ name = $_.Name; category = $_.Category; executable = $_.Executable }
    })
}

function Get-FusePathDiagnostics {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [string]$CurrentPath = $env:PATH,
        [string]$UserPath = [Environment]::GetEnvironmentVariable('Path', 'User'),
        [string]$MachinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    )

    $resolved = [IO.Path]::GetFullPath($Directory.Trim().Trim('"'))
    $normalize = {
        param([string]$Value)
        if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
        $path = [IO.Path]::GetFullPath($Value.Trim().Trim('"'))
        $root = [IO.Path]::GetPathRoot($path)
        $path = $path.TrimEnd([char[]]@('\', '/'))
        if ($path.Length -lt $root.Length) { return $root }
        return $path
    }
    $contains = {
        param([string]$Value)
        foreach ($entry in ($Value -split ';')) {
            if ([string]::IsNullOrWhiteSpace($entry)) { continue }
            try {
                if ((& $normalize $entry) -ieq (& $normalize $resolved)) { return $true }
            }
            catch { }
        }
        return $false
    }

    [pscustomobject]@{
        directory = $resolved
        exists = [IO.Directory]::Exists($resolved)
        inProcessPath = [bool](& $contains $CurrentPath)
        inUserPath = [bool](& $contains $UserPath)
        inMachinePath = [bool](& $contains $MachinePath)
    }
}

function Get-FuseVersionProbe {
    param([string]$Executable, [string[]]$Arguments)

    if ($Arguments.Count -eq 0) { return $null }
    $token = [Guid]::NewGuid().ToString('N')
    $stdout = Join-Path ([IO.Path]::GetTempPath()) "fuse-version-$token.out"
    $stderr = Join-Path ([IO.Path]::GetTempPath()) "fuse-version-$token.err"
    $process = $null
    $status = 'available'
    $version = $null
    try {
        $process = Start-Process -FilePath $Executable -ArgumentList $Arguments -PassThru -NoNewWindow `
            -RedirectStandardOutput $stdout -RedirectStandardError $stderr -ErrorAction Stop
        $timer = [Diagnostics.Stopwatch]::StartNew()
        while ($true) {
            $process.Refresh()
            if ($process.HasExited) { break }
            $outputBytes = 0L
            foreach ($file in @($stdout, $stderr)) {
                if ([IO.File]::Exists($file)) { $outputBytes += ([IO.FileInfo]::new($file)).Length }
            }
            if ($outputBytes -gt $script:MaximumVersionOutputBytes) { $status = 'output-limit'; break }
            if ($timer.Elapsed.TotalSeconds -ge $script:VersionTimeoutSeconds) { $status = 'timeout'; break }
            Start-Sleep -Milliseconds 50
        }
        if ($status -eq 'available') {
            $outputBytes = 0L
            foreach ($file in @($stdout, $stderr)) {
                if ([IO.File]::Exists($file)) { $outputBytes += ([IO.FileInfo]::new($file)).Length }
            }
            if ($outputBytes -gt $script:MaximumVersionOutputBytes) { $status = 'output-limit' }
        }
        if (-not $process.HasExited) {
            try { $process.Kill(); $process.WaitForExit(1000) | Out-Null } catch { }
        }
        if ($status -eq 'available') {
            $lines = @()
            foreach ($file in @($stdout, $stderr)) {
                if ([IO.File]::Exists($file)) { $lines += [IO.File]::ReadAllLines($file) }
            }
            $version = $lines | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1
            if ($version) { $version = $version.Trim() }
            else { $status = 'version-unavailable' }
        }
    }
    catch { $status = 'version-unavailable' }
    finally {
        if ($process) { $process.Dispose() }
        foreach ($file in @($stdout, $stderr)) {
            if ([IO.File]::Exists($file)) { try { [IO.File]::Delete($file) } catch { } }
        }
    }
    [pscustomobject]@{ status = $status; version = $version }
}

function Get-FuseGhidraVersion {
    param([string]$Executable)
    $installRoot = $null
    if (-not [string]::IsNullOrWhiteSpace($env:GHIDRA_INSTALL_DIR)) {
        $installRoot = $env:GHIDRA_INSTALL_DIR
    }
    else {
        $installRoot = Split-Path -Parent (Split-Path -Parent $Executable)
    }
    $properties = Join-Path $installRoot 'Ghidra\application.properties'
    if (-not [IO.File]::Exists($properties)) { return $null }
    if (([IO.FileInfo]::new($properties)).Length -gt 256KB) { return $null }
    $match = Get-Content -LiteralPath $properties -ErrorAction SilentlyContinue |
        Where-Object { $_ -match '^\s*application\.version\s*=\s*(.+?)\s*$' } | Select-Object -First 1
    if (-not $match) { return $null }
    [pscustomobject]@{ status = 'available'; version = ([regex]::Match($match, '^\s*application\.version\s*=\s*(.+?)\s*$').Groups[1].Value) }
}

function Get-FuseToolStatus {
    [CmdletBinding()]
    param([string[]]$ToolName = @($script:FuseTools | ForEach-Object { $_.Name }))

    foreach ($name in $ToolName) {
        $definition = $script:FuseTools | Where-Object { $_.Name -ieq $name } | Select-Object -First 1
        if (-not $definition) { throw "Unknown FUSE dependency: $name" }
        $path = $null
        if ($definition.Name -eq 'Ghidra' -and -not [string]::IsNullOrWhiteSpace($env:GHIDRA_INSTALL_DIR)) {
            $candidate = Join-Path $env:GHIDRA_INSTALL_DIR 'support\analyzeHeadless.bat'
            if ([IO.File]::Exists($candidate)) { $path = [IO.Path]::GetFullPath($candidate) }
        }
        if (-not $path) {
            $command = Get-Command -Name $definition.Executable -CommandType Application -ErrorAction SilentlyContinue |
                Select-Object -First 1
            if ($command) { $path = $command.Source }
        }
        $version = $null
        $status = 'missing'
        $pathDiagnostics = $null
        if ($path) {
            $probe = if ($definition.VersionSource -eq 'ghidra') { Get-FuseGhidraVersion -Executable $path } else { Get-FuseVersionProbe -Executable $path -Arguments $definition.VersionArgs }
            $status = if ($probe) { $probe.status } else { 'version-unavailable' }
            if ($probe) { $version = $probe.version }
            $pathDiagnostics = Get-FusePathDiagnostics -Directory (Split-Path -Parent $path)
        }
        [pscustomobject]@{
            name = $definition.Name
            category = $definition.Category
            status = $status
            executable = $path
            version = $version
            path = $pathDiagnostics
        }
    }
}

function Test-FuseEnvironment {
    param([object[]]$Tools)
    $platform = Get-FusePlatform
    if (-not $Tools) { $Tools = @(Get-FuseToolStatus -ToolName 'Python') }
    $python = $Tools | Where-Object { $_.name -eq 'Python' } | Select-Object -First 1
    $pythonVersion = if ($python -and $python.version) { [regex]::Match($python.version, '(?i)\bPython\s+(\d+)\.(\d+)') } else { $null }
    $pythonSupported = [bool]($python -and $python.status -eq 'available' -and $pythonVersion -and
        ([int]$pythonVersion.Groups[1].Value -gt 3 -or
        ([int]$pythonVersion.Groups[1].Value -eq 3 -and [int]$pythonVersion.Groups[2].Value -ge 11)))
    $pythonDetail = if ($python -and $python.version) { $python.version } else { 'Python 3.11 or newer was not found or its version is unknown.' }
    $checks = @(
        [pscustomobject]@{ name = 'windows'; passed = ($platform.operatingSystem -eq 'Windows'); detail = $platform.operatingSystem },
        [pscustomobject]@{ name = 'powershell'; passed = ($PSVersionTable.PSVersion -ge [Version]'5.1'); detail = $platform.powerShellVersion },
        [pscustomobject]@{ name = 'python'; passed = $pythonSupported; detail = $pythonDetail },
        [pscustomobject]@{ name = 'local-app-data'; passed = (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)); detail = $env:LOCALAPPDATA }
    )
    [pscustomobject]@{ valid = -not [bool]($checks | Where-Object { -not $_.passed }); checks = $checks }
}

function Get-FuseDoctorReport {
    $tools = @(Get-FuseToolStatus)
    [pscustomobject]@{
        schemaVersion = 1
        platform = Get-FusePlatform
        environment = Test-FuseEnvironment -Tools $tools
        tools = $tools
    }
}

function Get-FuseSetupPlan {
    $report = Get-FuseDoctorReport
    [pscustomobject]@{
        schemaVersion = 1
        mode = 'plan'
        changesMade = $false
        environment = $report.environment
        tools = $report.tools
        guidance = 'FUSE core is Python-only. Optional tools are never installed by the plan command.'
    }
}

function Test-FuseVersionString {
    param([string]$Observed, [string]$Expected)
    if ([string]::IsNullOrWhiteSpace($Observed) -or [string]::IsNullOrWhiteSpace($Expected)) { return $false }
    return [regex]::IsMatch($Observed, '(?<![0-9])v?' + [regex]::Escape($Expected) + '(?![0-9.])', [Text.RegularExpressions.RegexOptions]::IgnoreCase)
}

function Test-FuseInstallRequest {
    param([string]$ToolName, [string]$Version, [uri]$Uri, [string]$Sha256, [string]$ExecutableRelativePath)
    if (-not ($script:FuseTools | Where-Object { $_.Name -ieq $ToolName })) { throw "Unknown FUSE dependency: $ToolName" }
    Test-FusePinnedDownload -Version $Version -Uri $Uri -Sha256 $Sha256
    if ([string]::IsNullOrWhiteSpace($ExecutableRelativePath)) { throw 'ExecutableRelativePath is required.' }
    if ($ExecutableRelativePath.Replace('\', '/') -ieq '.fuse-install.json') { throw 'ExecutableRelativePath uses a reserved install receipt path.' }
}

function Test-FusePinnedDownload {
    param([string]$Version, [uri]$Uri, [string]$Sha256)
    if ($Version -notmatch '^\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9.-]+)?$') { throw 'Version must be an explicit numeric release version.' }
    if (-not $Uri -or -not $Uri.IsAbsoluteUri -or $Uri.Scheme -ne 'https' -or $Uri.UserInfo -or $Uri.Query -or $Uri.Fragment) { throw 'Download URI must be an absolute HTTPS URL without credentials, query, or fragment.' }
    if ($Uri.AbsolutePath -match '(?i)(^|/)latest(/|$)' -or -not [regex]::IsMatch([uri]::UnescapeDataString($Uri.AbsolutePath), '(?i)(?<![0-9a-z])v?' + [regex]::Escape($Version) + '(?![0-9a-z.])')) { throw 'Download URI must identify the requested pinned version and cannot use latest.' }
    if ($Sha256 -notmatch '^[0-9a-fA-F]{64}$') { throw 'Expected SHA-256 must contain exactly 64 hexadecimal characters.' }
}

function Invoke-FuseHttpDownload {
    param([uri]$Uri, [string]$Destination)
    $current = $Uri
    $response = $null
    $output = $null
    $source = $null
    $created = $false
    try {
        for ($redirect = 0; $redirect -le 5; $redirect++) {
            $request = [Net.HttpWebRequest]::Create($current)
            $request.AllowAutoRedirect = $false
            $request.Timeout = 60000
            $request.ReadWriteTimeout = 10000
            $request.UserAgent = 'VIGIL-FUSE-PowerShell/1.0'
            try { $response = [Net.HttpWebResponse]$request.GetResponse() }
            catch [Net.WebException] {
                if ($_.Exception.Response) { $response = [Net.HttpWebResponse]$_.Exception.Response }
                else { throw }
            }
            $code = [int]$response.StatusCode
            if ($code -ge 300 -and $code -lt 400) {
                $location = $response.Headers['Location']
                $response.Close()
                $response = $null
                if ([string]::IsNullOrWhiteSpace($location) -or $redirect -eq 5) { throw 'Download redirect was missing or exceeded the redirect limit.' }
                $current = [uri]::new($current, $location)
                if ($current.Scheme -ne 'https') { throw 'Download redirect attempted to leave HTTPS.' }
                continue
            }
            if ($code -lt 200 -or $code -ge 300) { throw "Download returned HTTP $code." }
            if ($response.ContentLength -gt $script:MaximumDownloadBytes) { throw 'Download exceeds the 1 GiB limit.' }
            $source = $response.GetResponseStream()
            try {
                $output = [IO.FileStream]::new($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
                $created = $true
                $buffer = New-Object byte[] (1024 * 1024)
                $total = 0L
                $timer = [Diagnostics.Stopwatch]::StartNew()
                while (($read = $source.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $total += $read
                    if ($total -gt $script:MaximumDownloadBytes) { throw 'Download exceeds the 1 GiB limit.' }
                    if ($timer.Elapsed.TotalSeconds -gt 600) { throw 'Download exceeded the 10 minute time limit.' }
                    $output.Write($buffer, 0, $read)
                }
            }
            finally {
                if ($output) { $output.Dispose(); $output = $null }
                if ($source) { $source.Dispose() }
            }
            return
        }
        throw 'Download redirect limit exceeded.'
    }
    catch {
        if ($created -and [IO.File]::Exists($Destination)) { [IO.File]::Delete($Destination) }
        throw
    }
    finally { if ($response) { $response.Close() } }
}

function Save-FuseVerifiedDownload {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][uri]$Uri, [Parameter(Mandatory = $true)][string]$Version,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256, [Parameter(Mandatory = $true)][string]$Destination)

    Test-FusePinnedDownload -Version $Version -Uri $Uri -Sha256 $ExpectedSha256
    if ([IO.File]::Exists($Destination) -or [IO.Directory]::Exists($Destination)) { throw 'Refusing to overwrite an existing download path.' }
    $parent = Split-Path -Parent ([IO.Path]::GetFullPath($Destination))
    if (-not [IO.Directory]::Exists($parent)) { throw 'Download parent directory does not exist.' }
    try {
        Invoke-FuseHttpDownload -Uri $Uri -Destination $Destination
        $actual = (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash
        if ($actual -ine $ExpectedSha256) { throw 'SHA-256 mismatch for the pinned download.' }
    }
    catch {
        if ([IO.File]::Exists($Destination)) { [IO.File]::Delete($Destination) }
        throw
    }
    Get-Item -LiteralPath $Destination
}

function Resolve-FuseArchivePath {
    param([string]$Root, [string]$EntryName)
    $name = $EntryName.Replace('\', '/')
    if ([string]::IsNullOrWhiteSpace($name) -or $name.StartsWith('/') -or $name.Contains(':') -or $name -match '(^|/)\.\.?(/|$)' -or $name -match '//') { throw "Unsafe archive path: $EntryName" }
    if ($name.TrimEnd('/').Split('/') | Where-Object { $_.EndsWith('.') -or $_.EndsWith(' ') -or $_ -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$' }) { throw "Windows-reserved archive path: $EntryName" }
    if ($name.TrimEnd('/') -ieq '.fuse-install.json') { throw 'Archive uses the reserved FUSE install receipt path.' }
    $relative = $name.TrimEnd('/') -replace '/', [IO.Path]::DirectorySeparatorChar
    $resolvedRoot = [IO.Path]::GetFullPath($Root)
    $path = [IO.Path]::GetFullPath((Join-Path $resolvedRoot $relative))
    $prefix = $resolvedRoot.TrimEnd([char[]]@('\', '/')) + [IO.Path]::DirectorySeparatorChar
    if (-not $path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw "Archive path escapes destination: $EntryName" }
    $path
}

function Expand-FuseVerifiedZip {
    param([string]$ArchivePath, [string]$Destination)
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($ArchivePath)
    $totalBytes = 0L
    try {
        if ($archive.Entries.Count -gt $script:MaximumArchiveEntries) { throw 'Archive exceeds the 10,000 entry limit.' }
        foreach ($entry in $archive.Entries) {
            $outputPath = Resolve-FuseArchivePath -Root $Destination -EntryName $entry.FullName
            $unixType = ($entry.ExternalAttributes -shr 16) -band 0xF000
            if ($unixType -eq 0xA000) { throw "Symbolic links are not accepted in archives: $($entry.FullName)" }
            if ($entry.FullName.EndsWith('/') -or $entry.FullName.EndsWith('\')) {
                [void][IO.Directory]::CreateDirectory($outputPath)
                continue
            }
            $totalBytes += $entry.Length
            if ($totalBytes -gt $script:MaximumExpandedBytes) { throw 'Archive exceeds the 2 GiB expanded-size limit.' }
            $parent = Split-Path -Parent $outputPath
            [void][IO.Directory]::CreateDirectory($parent)
            $source = $entry.Open()
            $target = $null
            try {
                $target = [IO.FileStream]::new($outputPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
                $buffer = New-Object byte[] (1024 * 1024)
                $written = 0L
                while (($read = $source.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $written += $read
                    if ($written -gt $entry.Length -or $written -gt $script:MaximumExpandedBytes) { throw 'Archive entry exceeded its declared size.' }
                    $target.Write($buffer, 0, $read)
                }
                if ($written -ne $entry.Length) { throw 'Archive entry size did not match its declaration.' }
            }
            finally {
                if ($target) { $target.Dispose() }
                $source.Dispose()
            }
        }
    }
    finally { $archive.Dispose() }
}

function Get-FuseInstallTreeHash {
    param([string]$Root)
    $rootItem = Get-Item -LiteralPath $Root -Force
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Installation root is a reparse point.' }
    $directories = @(Get-ChildItem -LiteralPath $Root -Directory -Recurse -Force)
    if ($directories | Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 }) { throw 'Installation contains a reparse-point directory.' }
    $files = @(Get-ChildItem -LiteralPath $Root -File -Recurse -Force | Where-Object { $_.FullName -ine (Join-Path $Root '.fuse-install.json') } | Sort-Object FullName)
    if ($files.Count -gt $script:MaximumArchiveEntries) { throw 'Installation exceeds the file-count verification limit.' }
    $total = 0L
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $rootPrefix = [IO.Path]::GetFullPath($Root).TrimEnd([char[]]@('\', '/')) + [IO.Path]::DirectorySeparatorChar
    foreach ($directory in $directories | Sort-Object FullName) {
        $relativeDirectory = $directory.FullName.Substring($rootPrefix.Length).Replace('\', '/')
        $lines.Add("D|$relativeDirectory")
    }
    foreach ($file in $files) {
        if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Installation contains a reparse-point file.' }
        $total += $file.Length
        if ($total -gt $script:MaximumExpandedBytes) { throw 'Installation exceeds the 2 GiB verification limit.' }
        $relative = $file.FullName.Substring($rootPrefix.Length).Replace('\', '/')
        $digest = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        $lines.Add("F|$relative|$($file.Length)|$digest")
    }
    $bytes = [Text.Encoding]::UTF8.GetBytes([string]::Join("`n", $lines.ToArray()))
    $sha = [Security.Cryptography.SHA256]::Create()
    try { [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Remove-FuseBootstrapTemp {
    param([string]$Path)
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([char[]]@('\', '/')) + [IO.Path]::DirectorySeparatorChar
    $resolved = [IO.Path]::GetFullPath($Path)
    $leaf = Split-Path -Leaf $resolved
    if (-not $resolved.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or $leaf -notmatch '^vigil-fuse-bootstrap-[a-f0-9]{32}$') { throw 'Refusing to remove a path outside the FUSE-owned temporary directory.' }
    if ([IO.Directory]::Exists($resolved)) { Remove-Item -LiteralPath $resolved -Recurse -Force }
}

function Install-FuseToolArchive {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ToolName,
        [Parameter(Mandatory = $true)][string]$Version,
        [Parameter(Mandatory = $true)][uri]$Uri,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        [Parameter(Mandatory = $true)][string]$ExecutableRelativePath,
        [string]$ArtifactPath,
        [ValidateSet('zip', 'file')][string]$ArtifactFormat = 'zip',
        [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA 'Vigil-FUSE\tools'),
        [switch]$Yes,
        [switch]$DryRun
    )

    Test-FuseInstallRequest -ToolName $ToolName -Version $Version -Uri $Uri -Sha256 $ExpectedSha256 -ExecutableRelativePath $ExecutableRelativePath
    $definition = $script:FuseTools | Where-Object { $_.Name -ieq $ToolName } | Select-Object -First 1
    $toolDirectory = Join-Path ([IO.Path]::GetFullPath($InstallRoot)) ($definition.Name -replace '[^A-Za-z0-9._-]', '-')
    $destination = Join-Path $toolDirectory $Version
    $expectedSha256 = $ExpectedSha256.ToLowerInvariant()

    if ([IO.Directory]::Exists($destination)) {
        $receiptPath = Join-Path $destination '.fuse-install.json'
        if (-not [IO.File]::Exists($receiptPath)) { throw 'A destination already exists without a FUSE install receipt; refusing to overwrite it.' }
        $receipt = Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json
        $treeHash = Get-FuseInstallTreeHash -Root $destination
        if ($receipt.schemaVersion -eq 1 -and $receipt.tool -eq $definition.Name -and $receipt.version -eq $Version -and
            $receipt.archiveSha256 -eq $expectedSha256 -and $receipt.source -eq $Uri.AbsoluteUri -and
            $receipt.executableRelativePath -eq $ExecutableRelativePath -and $receipt.treeSha256 -eq $treeHash) {
            return [pscustomobject]@{ status = 'reused'; tool = $definition.Name; version = $Version; path = $destination; changesMade = $false }
        }
        throw 'Existing installation failed receipt or integrity verification; refusing to overwrite it.'
    }

    $existing = Get-FuseToolStatus -ToolName $definition.Name
    if ($existing.status -ne 'missing') {
        if (Test-FuseVersionString -Observed $existing.version -Expected $Version) {
            return [pscustomobject]@{ status = 'reused'; tool = $definition.Name; version = $Version; path = $existing.executable; changesMade = $false }
        }
        throw "A different or unverifiable $($definition.Name) is already available; refusing to shadow it."
    }

    if ($DryRun) { return [pscustomobject]@{ status = 'planned'; tool = $definition.Name; version = $Version; destination = $destination; source = $Uri.AbsoluteUri; changesMade = $false } }
    if (-not $Yes) {
        $answer = Read-Host "Install $($definition.Name) $Version to '$destination'? [y/N]"
        if ($answer -notin @('y', 'yes')) { return [pscustomobject]@{ status = 'cancelled'; tool = $definition.Name; version = $Version; changesMade = $false } }
    }

    $createdDirectories = New-Object 'System.Collections.Generic.List[string]'
    $directory = $toolDirectory
    while (-not [IO.Directory]::Exists($directory)) {
        $createdDirectories.Add($directory)
        $parent = Split-Path -Parent $directory
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $directory) { break }
        $directory = $parent
    }
    $temporary = $null
    $stage = Join-Path $toolDirectory ('.installing-' + [Guid]::NewGuid().ToString('N'))
    try {
        [void][IO.Directory]::CreateDirectory($toolDirectory)
        $item = Get-Item -LiteralPath $toolDirectory -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Refusing to install through a reparse-point directory.' }
        [void][IO.Directory]::CreateDirectory($stage)
        if ([string]::IsNullOrWhiteSpace($ArtifactPath)) {
            $temporary = Join-Path ([IO.Path]::GetTempPath()) ('vigil-fuse-bootstrap-' + [Guid]::NewGuid().ToString('N'))
            [void][IO.Directory]::CreateDirectory($temporary)
            $artifact = Join-Path $temporary 'download'
            Save-FuseVerifiedDownload -Uri $Uri -Version $Version -ExpectedSha256 $expectedSha256 -Destination $artifact | Out-Null
        }
        else {
            $artifact = [IO.Path]::GetFullPath($ArtifactPath)
            if (-not [IO.File]::Exists($artifact)) { throw 'Verified artifact path does not exist.' }
            $artifactItem = Get-Item -LiteralPath $artifact -Force
            if (($artifactItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Artifact path is a reparse point.' }
            if ((Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash -ine $expectedSha256) { throw 'SHA-256 mismatch for the pinned artifact.' }
        }
        if ($ArtifactFormat -eq 'zip') { Expand-FuseVerifiedZip -ArchivePath $artifact -Destination $stage }
        else {
            $executable = Resolve-FuseArchivePath -Root $stage -EntryName $ExecutableRelativePath
            [void][IO.Directory]::CreateDirectory((Split-Path -Parent $executable))
            $source = [IO.File]::OpenRead($artifact)
            $target = $null
            try {
                if ($source.Length -gt $script:MaximumExpandedBytes) { throw 'Executable exceeds the 2 GiB install limit.' }
                $target = [IO.FileStream]::new($executable, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
                $source.CopyTo($target)
            }
            finally { if ($target) { $target.Dispose() }; $source.Dispose() }
        }
        $installedExecutable = Resolve-FuseArchivePath -Root $stage -EntryName $ExecutableRelativePath
        if (-not [IO.File]::Exists($installedExecutable)) { throw 'Verified artifact did not contain the declared executable.' }
        $treeHash = Get-FuseInstallTreeHash -Root $stage
        $receipt = [pscustomobject]@{
            schemaVersion = 1; tool = $definition.Name; version = $Version; source = $Uri.AbsoluteUri
            archiveSha256 = $expectedSha256; executableRelativePath = $ExecutableRelativePath; treeSha256 = $treeHash
        }
        $receiptJson = ConvertTo-Json -InputObject $receipt -Depth 4
        [IO.File]::WriteAllText((Join-Path $stage '.fuse-install.json'), $receiptJson, [Text.UTF8Encoding]::new($false))
        [IO.Directory]::Move($stage, $destination)
        [pscustomobject]@{ status = 'installed'; tool = $definition.Name; version = $Version; path = $destination; changesMade = $true }
    }
    finally {
        if ([IO.Directory]::Exists($stage)) { Remove-Item -LiteralPath $stage -Recurse -Force }
        if ($temporary) { Remove-FuseBootstrapTemp -Path $temporary }
        foreach ($createdDirectory in $createdDirectories) {
            if ([IO.Directory]::Exists($createdDirectory)) { try { [IO.Directory]::Delete($createdDirectory) } catch { } }
        }
    }
}

Export-ModuleMember -Function Get-FusePlatform, Get-FuseToolCatalog, Get-FusePathDiagnostics, Get-FuseToolStatus, Test-FuseEnvironment, Get-FuseDoctorReport, Get-FuseSetupPlan, Test-FuseVersionString, Save-FuseVerifiedDownload, Install-FuseToolArchive
