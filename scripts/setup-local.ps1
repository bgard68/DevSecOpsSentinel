$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) { throw ".NET 10 SDK is required." }
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) { throw "Node.js and npm are required." }
Push-Location $Root
try {
    & .\scripts\verify-central-packages.ps1
    dotnet restore .\DevSecOpsSentinel.slnx
    & .\scripts\ensure-frontend-toolchain.ps1
    Write-Host "Local dependencies restored and verified." -ForegroundColor Green
}
finally { Pop-Location }
