# andvari — build the Windows MSI installer. Run on a Windows box with JDK 17 + WiX.
# See ops/windows-build.md for prerequisites. Produces dist\andvari-<version>.msi + sha256.
$ErrorActionPreference = "Stop"

$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

Write-Host "[build-windows] packaging MSI (gradlew :app-desktop:packageMsi)…"
& .\gradlew.bat :app-desktop:packageMsi --console=plain
if ($LASTEXITCODE -ne 0) { throw "gradle packageMsi failed" }

$msi = Get-ChildItem -Path "app-desktop\build\compose\binaries\main\msi\*.msi" | Select-Object -First 1
if (-not $msi) { throw "no MSI produced" }

# Read the packaged version from the build file so dist naming matches.
$version = (Select-String -Path "app-desktop\build.gradle.kts" -Pattern 'packageVersion\s*=\s*"([^"]+)"').Matches[0].Groups[1].Value
New-Item -ItemType Directory -Force -Path dist | Out-Null
$dest = "dist\andvari-$version.msi"
Copy-Item $msi.FullName $dest -Force

$sha = (Get-FileHash $dest -Algorithm SHA256).Hash.ToLower()
Write-Host "[build-windows] $dest"
Write-Host "[build-windows] sha256 $sha"
Write-Host "[build-windows] To publish: see the 'Publish' section of ops/windows-build.md"
