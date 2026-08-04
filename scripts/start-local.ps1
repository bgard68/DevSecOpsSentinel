$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot

$api = Start-Process dotnet -ArgumentList @(
    "run", "--project", "$Root\src\DevSecOpsSentinel.Api\DevSecOpsSentinel.Api.csproj"
) -PassThru

# npm.cmd, not npm: Start-Process needs the real executable, and npm on Windows
# is a batch shim rather than a Win32 image.
$web = Start-Process npm.cmd -ArgumentList @("run", "dev") `
    -WorkingDirectory "$Root\src\devsecops-sentinel-web" -PassThru

Write-Host "API process: $($api.Id)" -ForegroundColor Cyan
Write-Host "Web process: $($web.Id)" -ForegroundColor Cyan
Write-Host "API: https://localhost:7001" -ForegroundColor Green
Write-Host "Web: http://localhost:5173" -ForegroundColor Green
