param(
    [string]$BaseUrl = "https://localhost:7001",
    [string]$ApiKey = $env:DEVSECOPS_SENTINEL_API_KEY,

    # Starts the API for the duration of the run and stops it afterwards, so the
    # suite can be part of an automated gate rather than requiring a server that
    # somebody remembered to start.
    [switch]$StartApi
)

$ErrorActionPreference = "Stop"
$Passed = 0
$Failed = 0
$ApiProcess = $null

function Start-ApiForSmokeTest {
    $root = Split-Path -Parent $PSScriptRoot

    # The gate must never spend OpenAI credits or reach GitHub. User Secrets on a
    # developer machine may well say Live; these override it for this run only.
    # The live integrations have their own opt-in scripts.
    $previousMode = $env:OpenAI__Mode
    $previousGitHub = $env:GitHub__Enabled
    $env:OpenAI__Mode = "Mock"
    $env:GitHub__Enabled = "false"

    $script:ApiLogPath = Join-Path ([System.IO.Path]::GetTempPath()) "sentinel-smoke-api.log"

    try {
        # Hidden rather than a console window: a visible window can be closed
        # mid-run, which kills the API and fails the gate for a reason that has
        # nothing to do with the API. Output goes to a log so a genuine startup
        # failure is still diagnosable.
        $process = Start-Process dotnet `
            -ArgumentList @(
                "run", "--project",
                (Join-Path $root "src\DevSecOpsSentinel.Api\DevSecOpsSentinel.Api.csproj")
            ) `
            -WindowStyle Hidden `
            -RedirectStandardOutput $script:ApiLogPath `
            -RedirectStandardError "$script:ApiLogPath.err" `
            -PassThru

        $deadline = (Get-Date).AddSeconds(90)
        while ((Get-Date) -lt $deadline) {
            if ($process.HasExited) {
                $detail = if (Test-Path $script:ApiLogPath) {
                    (Get-Content $script:ApiLogPath -Tail 15) -join [Environment]::NewLine
                } else { "(no output captured)" }

                throw "The API exited with code $($process.ExitCode) before becoming healthy.`n$detail"
            }

            try {
                $health = Invoke-RestMethod -Uri "$BaseUrl/api/health" -SkipCertificateCheck -TimeoutSec 5
                if ($health.status -eq "Healthy") {
                    Write-Host "API started for smoke tests (version $($health.version), OpenAI Mock)." -ForegroundColor Cyan
                    return $process
                }
            }
            catch {
                Start-Sleep -Seconds 2
            }
        }

        try { $process | Stop-Process -Force -ErrorAction SilentlyContinue } catch { }
        throw "The API did not become healthy within 90 seconds."
    }
    finally {
        $env:OpenAI__Mode = $previousMode
        $env:GitHub__Enabled = $previousGitHub
    }
}

$Headers = @{}
if (-not [string]::IsNullOrWhiteSpace($ApiKey)) {
    $Headers["X-API-Key"] = $ApiKey
}

function Invoke-Check {
    param(
        [string]$Name,
        [string]$Method,
        [string]$Path,
        [int]$Expected,
        [object]$Body,
        [string]$ContentType = "application/json",
        [switch]$Public
    )

    try {
        $Parameters = @{
            Uri = "$BaseUrl$Path"
            Method = $Method
            SkipHttpErrorCheck = $true
            SkipCertificateCheck = $true
        }

        if (-not $Public -and $Headers.Count -gt 0) {
            $Parameters.Headers = $Headers
        }

        if ($null -ne $Body) {
            $Parameters.ContentType = $ContentType
            $Parameters.Body = if ($Body -is [string]) {
                $Body
            } else {
                $Body | ConvertTo-Json -Depth 8
            }
        }

        $Response = Invoke-WebRequest @Parameters
        if ([int]$Response.StatusCode -eq $Expected) {
            Write-Host "PASS $Name [$Expected]" -ForegroundColor Green
            $script:Passed++
        } else {
            Write-Host "FAIL $Name expected $Expected got $($Response.StatusCode)" -ForegroundColor Red
            $script:Failed++
        }
    } catch {
        Write-Host "FAIL $Name $($_.Exception.Message)" -ForegroundColor Red
        $script:Failed++
    }
}

if ($StartApi) {
    $ApiProcess = Start-ApiForSmokeTest
}

try {

$SecurityStatus = Invoke-RestMethod `
    -Uri "$BaseUrl/api/security/status" `
    -SkipCertificateCheck

if ($SecurityStatus.required -and [string]::IsNullOrWhiteSpace($ApiKey)) {
    throw "This deployment requires an API key. Pass -ApiKey or set DEVSECOPS_SENTINEL_API_KEY."
}

Invoke-Check "Root" GET "/" 200 $null -Public
Invoke-Check "Health" GET "/api/health" 200 $null -Public
Invoke-Check "Health liveness" GET "/api/health/live" 200 $null -Public
Invoke-Check "Health readiness" GET "/api/health/ready" 200 $null -Public
Invoke-Check "Security status" GET "/api/security/status" 200 $null -Public
Invoke-Check "OpenAPI document" GET "/openapi/v1.json" 200 $null -Public
Invoke-Check "Scalar API reference" GET "/scalar" 200 $null -Public
Invoke-Check "Rules" GET "/api/rules" 200 $null
Invoke-Check "AI status" GET "/api/ai/status" 200 $null
Invoke-Check "GitHub status" GET "/api/github/status" 200 $null
Invoke-Check "GitHub allowlist boundary" GET "/api/github/repositories/bgard68/ToDoApp/workflows" 403 $null
Invoke-Check "Scenarios" GET "/api/scenarios" 200 $null
Invoke-Check "Known scenario" GET "/api/scenarios/unpinned-action" 200 $null
Invoke-Check "Missing scenario" GET "/api/scenarios/not-real" 404 $null
Invoke-Check "Vulnerable workflow" POST "/api/workflows/analyze" 200 @{
    fileName = "build.yml"
    content = "name: Build`non:`n  push:`npermissions: write-all`njobs:`n  build:`n    runs-on: ubuntu-latest`n    steps:`n      - uses: actions/checkout@v4`n"
}
Invoke-Check "Empty workflow" POST "/api/workflows/analyze" 400 @{
    fileName = ""
    content = ""
}
Invoke-Check "Malformed JSON" POST "/api/workflows/analyze" 400 '{"fileName":'
Invoke-Check "Malformed YAML" POST "/api/workflows/analyze" 422 @{
    fileName = "bad.yml"
    content = "not yaml"
}
Invoke-Check "Wrong content type" POST "/api/workflows/analyze" 415 "fileName=x" "text/plain"
Invoke-Check "Oversized workflow" POST "/api/workflows/analyze" 413 @{
    fileName = "huge.yml"
    content = "x" * 100001
}

# When GitHub is not configured the repository listing must say the integration
# is unavailable rather than return an empty list, which would read as "no
# repositories" instead of "not connected".
$GitHubStatusParameters = @{
    Uri = "$BaseUrl/api/github/status"
    SkipCertificateCheck = $true
}
if ($Headers.Count -gt 0) { $GitHubStatusParameters.Headers = $Headers }

$GitHubStatus = Invoke-RestMethod @GitHubStatusParameters
$ExpectedRepositoryStatus = if ($GitHubStatus.configured) { 200 } else { 503 }

Invoke-Check "GitHub repositories availability" GET "/api/github/repositories" $ExpectedRepositoryStatus $null

$explainContent = "name: Build`non:`n  push:`npermissions: write-all`njobs:`n  build:`n    runs-on: ubuntu-latest`n    steps:`n      - uses: actions/checkout@v4`n"
Invoke-Check "AI explanation" POST "/api/workflows/explain" 200 @{
    fileName = "mock.yml"
    content = $explainContent
    useAi = $true
}
Invoke-Check "Remediation report" POST "/api/workflows/remediation" 200 @{
    fileName = "mock.yml"
    content = $explainContent
}
Invoke-Check "SARIF export" POST "/api/workflows/remediation/export/sarif" 200 @{
    fileName = "mock.yml"
    content = $explainContent
}
Invoke-Check "Patch export" POST "/api/workflows/remediation/export/diff" 200 @{
    fileName = "mock.yml"
    content = $explainContent
}

Write-Host "Passed: $Passed  Failed: $Failed" -ForegroundColor Cyan

}
finally {
    if ($null -ne $ApiProcess) {
        Write-Host "Stopping the API started for smoke tests." -ForegroundColor Cyan

        # dotnet run launches the application as a child, so stopping only the
        # launcher would leave the server holding the port.
        try {
            Get-CimInstance Win32_Process -Filter "ParentProcessId = $($ApiProcess.Id)" -ErrorAction SilentlyContinue |
                ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        } catch { }

        try { $ApiProcess | Stop-Process -Force -ErrorAction SilentlyContinue } catch { }
    }
}

if ($Failed -gt 0) { exit 1 }
exit 0
