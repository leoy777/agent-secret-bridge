param(
    [string]$InstallDirectory = "$env:LOCALAPPDATA\Programs\AgentSecretBridge"
)

$ErrorActionPreference = "Stop"
$destination = Join-Path $InstallDirectory "asb.exe"
if (-not (Test-Path -LiteralPath $destination -PathType Leaf)) {
    Write-Host "ASB is not installed at $destination"
    exit 0
}

$answer = Read-Host "Remove $destination? [y/N]"
if ($answer -notin @("y", "Y")) {
    Write-Host "Cancelled"
    exit 0
}
Remove-Item -LiteralPath $destination
Write-Host "Credential stores, configuration, and audit logs were left untouched."
