$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot

function Invoke-Native {
    param([Parameter(Mandatory)][string]$Command, [Parameter(ValueFromRemainingArguments)][string[]]$Arguments)
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Command failed with exit code $LASTEXITCODE." }
}

Push-Location $Root
try {
    & .\scripts\verify-central-packages.ps1
    & .\scripts\ensure-frontend-toolchain.ps1

    Invoke-Native dotnet restore .\DevSecOpsSentinel.slnx
    Invoke-Native dotnet build .\DevSecOpsSentinel.slnx --configuration Release --no-restore
    Invoke-Native dotnet test .\DevSecOpsSentinel.slnx --configuration Release --no-build

    Push-Location .\src\devsecops-sentinel-web
    try {
        Invoke-Native npm audit
        Invoke-Native npm test
        Invoke-Native npm run build
    }
    finally { Pop-Location }

    & .\scripts\verify-release-package.ps1
    & .\scripts\check-repository.ps1
    & .\scripts\audit-packages.ps1
    & .\scripts\smoke-test-api.ps1 -StartApi

    Write-Host "Local release gates passed." -ForegroundColor Green
}
finally { Pop-Location }
