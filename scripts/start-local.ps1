$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot

$api = Start-Process dotnet -ArgumentList @(
    "run", "--project", "$Root\src\DevSecOpsSentinel.Api\DevSecOpsSentinel.Api.csproj"
) -PassThru

$web = Start-Process npm -ArgumentList @("run", "dev") `
    -WorkingDirectory "$Root\src\devsecops-sentinel-web" -PassThru

Write-Host "API process: $($api.Id)" -ForegroundColor Cyan
Write-Host "Web process: $($web.Id)" -ForegroundColor Cyan
Write-Host "API: https://localhost:7001" -ForegroundColor Green
Write-Host "Web: http://localhost:5173" -ForegroundColor Green
