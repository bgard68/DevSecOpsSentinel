$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Push-Location $Root
try {
    & .\scripts\verify-central-packages.ps1
    & .\scripts\ensure-frontend-toolchain.ps1
    dotnet restore .\DevSecOpsSentinel.slnx
    dotnet build .\DevSecOpsSentinel.slnx --configuration Release --no-restore
    Push-Location .\src\devsecops-sentinel-web
    try { npm run typecheck; npm run build } finally { Pop-Location }
    Write-Host "v1.0 build passed." -ForegroundColor Green
}
finally { Pop-Location }
