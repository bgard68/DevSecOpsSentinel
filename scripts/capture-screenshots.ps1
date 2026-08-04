<#
.SYNOPSIS
    Regenerates the product screenshots in docs/assets/screenshots.

.DESCRIPTION
    Starts the API and the frontend dev server, drives the application with
    Playwright, then stops both.

    Unlike the release gate, this deliberately runs the real integrations: the
    two AI screenshots are named for live mode and a Mock capture would show a
    canned explanation while claiming otherwise. That means the run needs
    OpenAI and GitHub configured in User Secrets, and it spends a small amount
    of OpenAI credit.
#>
[CmdletBinding()]
param(
    [string]$BaseUrl = "https://localhost:7001",
    [string]$WebUrl = "http://localhost:5173"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Root = Split-Path -Parent $PSScriptRoot
$Web = Join-Path $Root "src\devsecops-sentinel-web"
$LogDirectory = [System.IO.Path]::GetTempPath()

$ApiProcess = $null
$WebProcess = $null

function Wait-ForEndpoint {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][System.Diagnostics.Process]$Process,
        [Parameter(Mandatory)][string]$Description,
        [string]$LogPath,
        [int]$TimeoutSeconds = 120
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)

    while ((Get-Date) -lt $deadline) {
        if ($Process.HasExited) {
            $detail = if ($LogPath -and (Test-Path $LogPath)) {
                (Get-Content $LogPath -Tail 15) -join [Environment]::NewLine
            } else { "(no output captured)" }

            throw "$Description exited with code $($Process.ExitCode).`n$detail"
        }

        try {
            Invoke-WebRequest -Uri $Uri -SkipCertificateCheck -TimeoutSec 5 -UseBasicParsing | Out-Null
            return
        }
        catch { Start-Sleep -Seconds 2 }
    }

    throw "$Description did not become available within $TimeoutSeconds seconds."
}

function Stop-Tree {
    param([System.Diagnostics.Process]$Process)

    if ($null -eq $Process) { return }

    # npm and dotnet run both launch the real server as a child, so stopping
    # only the launcher would leave the port held.
    try {
        Get-CimInstance Win32_Process -Filter "ParentProcessId = $($Process.Id)" -ErrorAction SilentlyContinue |
            ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    } catch { }

    try { $Process | Stop-Process -Force -ErrorAction SilentlyContinue } catch { }
}

if (-not $env:PLAYWRIGHT_BROWSERS_PATH) {
    <#
        Node cannot spawn an executable whose path contains characters such as
        # or !, which a Windows profile name may well contain. Playwright's
        default browser cache lives under the profile, so the launch fails with
        ENOENT even though the file is plainly there. Relocating the cache to a
        path without those characters is the fix.
    #>
    $env:PLAYWRIGHT_BROWSERS_PATH = "C:/ms-playwright"
}

Push-Location $Root
try {
    # Idempotent: downloads only when the browser is absent, so a fresh clone
    # needs no separate setup step.
    Push-Location $Web
    try {
        Write-Host "Ensuring the Playwright browser is installed..." -ForegroundColor Cyan
        npx playwright install chromium 2>&1 | Select-Object -Last 1
        if ($LASTEXITCODE -ne 0) { throw "Playwright browser installation failed." }
    }
    finally { Pop-Location }

    $apiLog = Join-Path $LogDirectory "sentinel-screenshots-api.log"
    $webLog = Join-Path $LogDirectory "sentinel-screenshots-web.log"

    Write-Host "Starting the API..." -ForegroundColor Cyan
    $ApiProcess = Start-Process dotnet `
        -ArgumentList @("run", "--project", (Join-Path $Root "src\DevSecOpsSentinel.Api\DevSecOpsSentinel.Api.csproj")) `
        -WindowStyle Hidden `
        -RedirectStandardOutput $apiLog `
        -RedirectStandardError "$apiLog.err" `
        -PassThru

    Wait-ForEndpoint -Uri "$BaseUrl/api/health" -Process $ApiProcess -Description "The API" -LogPath $apiLog

    $status = Invoke-RestMethod -Uri "$BaseUrl/api/ai/status" -SkipCertificateCheck
    Write-Host "  API ready. OpenAI mode: $($status.mode), configured: $($status.configured)" -ForegroundColor Cyan

    if ($status.mode -ne "Live") {
        Write-Warning "OpenAI is in $($status.mode) mode. Screenshots 02 and 03 are named for live mode."
    }

    Write-Host "Starting the frontend..." -ForegroundColor Cyan
    # npm.cmd, not npm: Start-Process needs the real executable, and npm on
    # Windows is a batch shim rather than a Win32 image.
    $WebProcess = Start-Process npm.cmd `
        -ArgumentList @("run", "dev") `
        -WorkingDirectory $Web `
        -WindowStyle Hidden `
        -RedirectStandardOutput $webLog `
        -RedirectStandardError "$webLog.err" `
        -PassThru

    Wait-ForEndpoint -Uri $WebUrl -Process $WebProcess -Description "The frontend" -LogPath $webLog
    Write-Host "  Frontend ready." -ForegroundColor Cyan

    Write-Host "Capturing..." -ForegroundColor Cyan
    Push-Location $Web
    try {
        $env:SENTINEL_WEB_URL = $WebUrl
        npm run screenshots
        if ($LASTEXITCODE -ne 0) { throw "Screenshot capture failed with exit code $LASTEXITCODE." }
    }
    finally { Pop-Location }

    Write-Host "Screenshots regenerated in docs/assets/screenshots." -ForegroundColor Green
}
finally {
    Write-Host "Stopping servers." -ForegroundColor Cyan
    Stop-Tree -Process $WebProcess
    Stop-Tree -Process $ApiProcess
    Pop-Location
}
