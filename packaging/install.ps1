param(
    [string]$SourceBinary = ".\asb.exe",
    [string]$InstallDirectory = "$env:LOCALAPPDATA\Programs\AgentSecretBridge"
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path -LiteralPath $SourceBinary -PathType Leaf)) {
    throw "ASB binary not found: $SourceBinary"
}

New-Item -ItemType Directory -Force -Path $InstallDirectory | Out-Null
$destination = Join-Path $InstallDirectory "asb.exe"
Copy-Item -LiteralPath $SourceBinary -Destination $destination -Force
Write-Host "Installed ASB to $destination"
Write-Host "Add this directory to your user PATH, then run: asb --version"
