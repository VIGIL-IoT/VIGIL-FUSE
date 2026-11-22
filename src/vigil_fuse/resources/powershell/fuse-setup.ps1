param(
    [Parameter(Position = 0)][string]$Command = 'doctor',
    [string]$ToolName,
    [string]$Version,
    [string]$Uri,
    [string]$Sha256,
    [string]$ExecutableRelativePath,
    [ValidateSet('zip', 'file')][string]$ArtifactFormat = 'zip',
    [string]$InstallRoot,
    [switch]$Yes,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
Import-Module (Join-Path $PSScriptRoot 'FuseBootstrap.psm1') -Force -ErrorAction Stop

try {
    switch ($Command) {
        'doctor' { $result = Get-FuseDoctorReport }
        'plan' { $result = Get-FuseSetupPlan }
        'install' {
            if ([string]::IsNullOrWhiteSpace($ToolName) -or [string]::IsNullOrWhiteSpace($Version) -or
                [string]::IsNullOrWhiteSpace($Uri) -or [string]::IsNullOrWhiteSpace($Sha256) -or [string]::IsNullOrWhiteSpace($ExecutableRelativePath)) {
                throw 'install requires -ToolName, -Version, -Uri, -Sha256, and -ExecutableRelativePath.'
            }
            try { $downloadUri = [uri]$Uri } catch { throw 'Uri must be an absolute HTTPS URL.' }
            $arguments = @{
                ToolName = $ToolName
                Version = $Version
                Uri = $downloadUri
                ExpectedSha256 = $Sha256
                ExecutableRelativePath = $ExecutableRelativePath
                ArtifactFormat = $ArtifactFormat
                Yes = $Yes
                DryRun = $DryRun
            }
            if (-not [string]::IsNullOrWhiteSpace($InstallRoot)) { $arguments.InstallRoot = $InstallRoot }
            $result = Install-FuseToolArchive @arguments
        }
        default { throw "Unknown setup command: $Command" }
    }
    ConvertTo-Json -InputObject $result -Depth 12 -Compress
}
catch {
    $errorResult = [pscustomobject]@{
        schemaVersion = 1
        status = 'failed'
        command = $Command
        message = $_.Exception.Message
        changesMade = $false
    }
    ConvertTo-Json -InputObject $errorResult -Depth 4 -Compress
    exit 1
}
