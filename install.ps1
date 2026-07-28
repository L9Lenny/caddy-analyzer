# caddy-analyze static binary installer for Windows PowerShell
$ErrorActionPreference = 'Stop'

$Repo = "L9Lenny/caddy-analyzer"
$BinaryName = "caddy-analyze.exe"

$Arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { $Arch = "arm64" }

$LatestRelease = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest"
$Tag = $LatestRelease.tag_name
if (-not $Tag) { $Tag = "v0.2.0" }

$VersionNum = $Tag.TrimStart('v')
$Url = "https://github.com/$Repo/releases/download/$Tag/caddy-analyze_${VersionNum}_windows_${Arch}.zip"

$InstallDir = "$env:LOCALAPPDATA\caddy-analyze"
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir | Out-Null
}

$ZipPath = Join-Path $env:TEMP "caddy-analyze.zip"
Write-Host "⚡ Downloading caddy-analyze $Tag ($Arch) for Windows..." -ForegroundColor Cyan

Invoke-WebRequest -Uri $Url -OutFile $ZipPath
Expand-Archive -Path $ZipPath -DestinationPath $InstallDir -Force
Remove-Item -Path $ZipPath -Force

$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$UserPath;$InstallDir", "User")
    Write-Host "✔ Added $InstallDir to User PATH." -ForegroundColor Green
}

Write-Host "✔ Success! caddy-analyze $Tag installed to $InstallDir\$BinaryName" -ForegroundColor Green
Write-Host "Restart your terminal and run 'caddy-analyze --help' to get started." -ForegroundColor Yellow
