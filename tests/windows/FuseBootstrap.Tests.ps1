$modulePath = Join-Path $PSScriptRoot '..\..\src\vigil_fuse\resources\powershell\FuseBootstrap.psm1'
$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('vigil-fuse-pester-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($fixtureRoot)
$global:FuseBootstrapTestArchive = Join-Path $fixtureRoot 'synthetic.zip'

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$fixtureArchive = [IO.Compression.ZipFile]::Open($global:FuseBootstrapTestArchive, [IO.Compression.ZipArchiveMode]::Create)
try {
    $entry = $fixtureArchive.CreateEntry('syft.exe')
    $stream = $entry.Open()
    try {
        $payload = [Text.Encoding]::UTF8.GetBytes('synthetic executable')
        $stream.Write($payload, 0, $payload.Length)
    }
    finally { $stream.Dispose() }
}
finally { $fixtureArchive.Dispose() }

$global:FuseBootstrapTestSha256 = (Get-FileHash -LiteralPath $global:FuseBootstrapTestArchive -Algorithm SHA256).Hash.ToLowerInvariant()
$global:FuseBootstrapTestUri = [uri]'https://github.com/anchore/syft/releases/download/v1.2.3/syft_windows_amd64.zip'
$global:FuseBootstrapTestFailure = $false

function Assert-FuseThrows {
    param([scriptblock]$Action)
    $threw = $false
    try { & $Action | Out-Null } catch { $threw = $true }
    $threw | Should Be $true
}

try {
    Describe 'FUSE PowerShell bootstrap' {
        BeforeEach { Import-Module $modulePath -Force -ErrorAction Stop }

        It 'detects Windows and classifies dependencies' {
            (Get-FusePlatform).operatingSystem | Should Be 'Windows'
            $catalog = @(Get-FuseToolCatalog)
            ($catalog | Where-Object { $_.category -notin @('CORE', 'RECOMMENDED', 'OPTIONAL_HEAVY', 'RESEARCH') }).Count | Should Be 0
            ($catalog | Where-Object { $_.name -eq 'Ghidra' }).category | Should Be 'OPTIONAL_HEAVY'
        }

        It 'validates the minimum Python runtime' {
            $supported = @(Test-FuseEnvironment -Tools @([pscustomobject]@{ name = 'Python'; status = 'available'; version = 'Python 3.11.0' }))
            $unsupported = @(Test-FuseEnvironment -Tools @([pscustomobject]@{ name = 'Python'; status = 'available'; version = 'Python 3.10.14' }))
            $missing = @(Test-FuseEnvironment -Tools @([pscustomobject]@{ name = 'Python'; status = 'missing'; version = $null }))
            ($supported.checks | Where-Object { $_.name -eq 'python' }).passed | Should Be $true
            ($unsupported.checks | Where-Object { $_.name -eq 'python' }).passed | Should Be $false
            ($missing.checks | Where-Object { $_.name -eq 'python' }).passed | Should Be $false
        }

        It 'reports missing PATH entries including drive and space paths' {
            $diagnostic = Get-FusePathDiagnostics -Directory 'I:\FUSE Tools' -CurrentPath '' -UserPath '' -MachinePath ''
            $diagnostic.directory | Should Be 'I:\FUSE Tools'
            $diagnostic.inProcessPath | Should Be $false
            $diagnostic.inUserPath | Should Be $false
            $diagnostic.inMachinePath | Should Be $false
        }

        It 'rejects unpinned, non-HTTPS, and malformed downloads' {
            Assert-FuseThrows { Save-FuseVerifiedDownload -Uri 'http://github.com/tool/releases/download/v1.2.3/tool.zip' -Version '1.2.3' -ExpectedSha256 $global:FuseBootstrapTestSha256 -Destination (Join-Path $fixtureRoot 'invalid') }
            Assert-FuseThrows { Save-FuseVerifiedDownload -Uri 'https://github.com/tool/releases/latest/tool.zip' -Version '1.2.3' -ExpectedSha256 $global:FuseBootstrapTestSha256 -Destination (Join-Path $fixtureRoot 'latest') }
            Assert-FuseThrows { Save-FuseVerifiedDownload -Uri $global:FuseBootstrapTestUri -Version '1.2' -ExpectedSha256 $global:FuseBootstrapTestSha256 -Destination (Join-Path $fixtureRoot 'wrong-version') }
        }

        It 'verifies a mocked download and removes a checksum mismatch' {
            Mock Invoke-FuseHttpDownload -ModuleName FuseBootstrap -MockWith {
                param($Uri, $Destination)
                if ($global:FuseBootstrapTestFailure) {
                    [IO.File]::WriteAllText($Destination, 'partial')
                    throw 'synthetic download failure'
                }
                [IO.File]::Copy($global:FuseBootstrapTestArchive, $Destination, $false)
            }
            $destination = Join-Path $fixtureRoot 'verified.download'
            Save-FuseVerifiedDownload -Uri $global:FuseBootstrapTestUri -Version '1.2.3' -ExpectedSha256 $global:FuseBootstrapTestSha256 -Destination $destination | Out-Null
            (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant() | Should Be $global:FuseBootstrapTestSha256

            $badDestination = Join-Path $fixtureRoot 'mismatch.download'
            Assert-FuseThrows { Save-FuseVerifiedDownload -Uri $global:FuseBootstrapTestUri -Version '1.2.3' -ExpectedSha256 ('0' * 64) -Destination $badDestination }
            (Test-Path -LiteralPath $badDestination) | Should Be $false
            $global:FuseBootstrapTestFailure = $true
            $failedDestination = Join-Path $fixtureRoot 'partial.download'
            Assert-FuseThrows { Save-FuseVerifiedDownload -Uri $global:FuseBootstrapTestUri -Version '1.2.3' -ExpectedSha256 $global:FuseBootstrapTestSha256 -Destination $failedDestination }
            (Test-Path -LiteralPath $failedDestination) | Should Be $false
            $global:FuseBootstrapTestFailure = $false
        }

        It 'installs to a path with spaces, reuses an intact version, and does not redownload' {
            $oldPath = $env:PATH
            $env:PATH = $fixtureRoot
            try {
                Mock Invoke-FuseHttpDownload -ModuleName FuseBootstrap -MockWith {
                    param($Uri, $Destination)
                    [IO.File]::Copy($global:FuseBootstrapTestArchive, $Destination, $false)
                }
                $installRoot = Join-Path $fixtureRoot 'local tools with spaces'
                $arguments = @{
                    ToolName = 'Syft'; Version = '1.2.3'; Uri = $global:FuseBootstrapTestUri
                    ExpectedSha256 = $global:FuseBootstrapTestSha256; ExecutableRelativePath = 'syft.exe'
                    ArtifactPath = $global:FuseBootstrapTestArchive; InstallRoot = $installRoot; Yes = $true
                }
                $first = Install-FuseToolArchive @arguments
                $second = Install-FuseToolArchive @arguments
                $first.status | Should Be 'installed'
                $second.status | Should Be 'reused'
                (Test-Path -LiteralPath (Join-Path $first.path 'syft.exe')) | Should Be $true
            }
            finally { $env:PATH = $oldPath }
        }

        It 'returns a dry-run plan without downloading or creating an install root' {
            $oldPath = $env:PATH
            $env:PATH = $fixtureRoot
            try {
                Mock Invoke-FuseHttpDownload -ModuleName FuseBootstrap -MockWith { throw 'synthetic download failure' }
                $installRoot = Join-Path $fixtureRoot 'failed install'
                $arguments = @{
                    ToolName = 'Syft'; Version = '1.2.3'; Uri = $global:FuseBootstrapTestUri
                    ExpectedSha256 = $global:FuseBootstrapTestSha256; ExecutableRelativePath = 'syft.exe'
                    InstallRoot = $installRoot; Yes = $true
                }
                $plan = Install-FuseToolArchive @arguments -DryRun
                $plan.status | Should Be 'planned'
                (Test-Path -LiteralPath $installRoot) | Should Be $false
            }
            finally { $env:PATH = $oldPath }
        }

        It 'detects a damaged existing installation and version mismatch' {
            $oldPath = $env:PATH
            $env:PATH = $fixtureRoot
            try {
                Mock Invoke-FuseHttpDownload -ModuleName FuseBootstrap -MockWith {
                    param($Uri, $Destination)
                    [IO.File]::Copy($global:FuseBootstrapTestArchive, $Destination, $false)
                }
                $installRoot = Join-Path $fixtureRoot 'integrity test'
                $arguments = @{
                    ToolName = 'Syft'; Version = '1.2.3'; Uri = $global:FuseBootstrapTestUri
                    ExpectedSha256 = $global:FuseBootstrapTestSha256; ExecutableRelativePath = 'syft.exe'
                    ArtifactPath = $global:FuseBootstrapTestArchive; InstallRoot = $installRoot; Yes = $true
                }
                $installed = Install-FuseToolArchive @arguments
                Set-Content -LiteralPath (Join-Path $installed.path 'syft.exe') -Value 'changed' -NoNewline
                Assert-FuseThrows { Install-FuseToolArchive @arguments }
                (Test-FuseVersionString -Observed 'Gitleaks version 8.30.0' -Expected '8.30.0') | Should Be $true
                (Test-FuseVersionString -Observed 'Gitleaks version 8.29.0' -Expected '8.30.0') | Should Be $false
                (Test-FuseVersionString -Observed 'Syft 1.2.3' -Expected '1.2') | Should Be $false
            }
            finally { $env:PATH = $oldPath }
        }

        It 'rejects archive traversal and removes the incomplete staging directory' {
            $unsafeArchive = Join-Path $fixtureRoot 'unsafe.zip'
            $zip = [IO.Compression.ZipFile]::Open($unsafeArchive, [IO.Compression.ZipArchiveMode]::Create)
            try {
                $entry = $zip.CreateEntry('../escape.txt')
                $stream = $entry.Open()
                try { $stream.WriteByte(1) } finally { $stream.Dispose() }
            }
            finally { $zip.Dispose() }
            $unsafeUri = [uri]'https://github.com/anchore/syft/releases/download/v1.2.4/syft_windows_amd64.zip'
            $unsafeHash = (Get-FileHash -LiteralPath $unsafeArchive -Algorithm SHA256).Hash
            $oldPath = $env:PATH
            $env:PATH = $fixtureRoot
            try {
                $installRoot = Join-Path $fixtureRoot 'unsafe install'
                Assert-FuseThrows {
                    Install-FuseToolArchive -ToolName 'Syft' -Version '1.2.4' -Uri $unsafeUri -ExpectedSha256 $unsafeHash `
                        -ExecutableRelativePath 'syft.exe' -ArtifactPath $unsafeArchive -InstallRoot $installRoot -Yes
                }
                (Test-Path -LiteralPath $installRoot) | Should Be $false
                (Test-Path -LiteralPath (Join-Path $fixtureRoot 'escape.txt')) | Should Be $false
            }
            finally { $env:PATH = $oldPath }
        }
    }
}
finally {
    Remove-Module FuseBootstrap -Force -ErrorAction SilentlyContinue
    if ([IO.Directory]::Exists($fixtureRoot)) { Remove-Item -LiteralPath $fixtureRoot -Recurse -Force }
    Remove-Variable FuseBootstrapTestArchive, FuseBootstrapTestSha256, FuseBootstrapTestUri, FuseBootstrapTestFailure -Scope Global -ErrorAction SilentlyContinue
}
