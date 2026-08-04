$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Push-Location $Root
try {
    & .\scripts\verify-central-packages.ps1
    & .\scripts\ensure-frontend-toolchain.ps1
    dotnet test .\DevSecOpsSentinel.slnx --configuration Release
    Push-Location .\src\devsecops-sentinel-web
    try { npm test } finally { Pop-Location }
    Write-Host "v1.0 tests passed." -ForegroundColor Green
}
finally { Pop-Location }
