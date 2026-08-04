param([string]$BaseUrl = "https://localhost:7001")
$ErrorActionPreference = "Stop"
$Passed = 0
$Failed = 0

function Invoke-Check {
    param([string]$Name, [string]$Method, [string]$Path, [int]$Expected, [object]$Body, [string]$ContentType = "application/json")
    try {
        $Parameters = @{ Uri = "$BaseUrl$Path"; Method = $Method; SkipHttpErrorCheck = $true; SkipCertificateCheck = $true }
        if ($null -ne $Body) {
            $Parameters.ContentType = $ContentType
            $Parameters.Body = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 8 }
        }
        $Response = Invoke-WebRequest @Parameters
        if ([int]$Response.StatusCode -eq $Expected) {
            Write-Host "PASS $Name [$Expected]" -ForegroundColor Green; $script:Passed++
        } else {
            Write-Host "FAIL $Name expected $Expected got $($Response.StatusCode)" -ForegroundColor Red; $script:Failed++
        }
    } catch {
        Write-Host "FAIL $Name $($_.Exception.Message)" -ForegroundColor Red; $script:Failed++
    }
}

Invoke-Check "Root" GET "/" 200 $null
Invoke-Check "Health" GET "/api/health" 200 $null
Invoke-Check "Health liveness" GET "/api/health/live" 200 $null
Invoke-Check "Health readiness" GET "/api/health/ready" 200 $null
Invoke-Check "OpenAPI document" GET "/openapi/v1.json" 200 $null
Invoke-Check "Scalar API reference" GET "/scalar" 200 $null
Invoke-Check "Rules" GET "/api/rules" 200 $null
Invoke-Check "AI status" GET "/api/ai/status" 200 $null
Invoke-Check "GitHub status" GET "/api/github/status" 200 $null
Invoke-Check "GitHub allowlist boundary" GET "/api/github/repositories/bgard68/ToDoApp/workflows" 403 $null
Invoke-Check "Scenarios" GET "/api/scenarios" 200 $null
Invoke-Check "Known scenario" GET "/api/scenarios/unpinned-action" 200 $null
Invoke-Check "Missing scenario" GET "/api/scenarios/not-real" 404 $null
Invoke-Check "Vulnerable workflow" POST "/api/workflows/analyze" 200 @{ fileName="build.yml"; content="name: Build`non:`n  push:`npermissions: write-all`njobs:`n  build:`n    runs-on: ubuntu-latest`n    steps:`n      - uses: actions/checkout@v4`n" }
Invoke-Check "Empty workflow" POST "/api/workflows/analyze" 400 @{ fileName=""; content="" }
Invoke-Check "Malformed JSON" POST "/api/workflows/analyze" 400 '{"fileName":' 
Invoke-Check "Malformed YAML" POST "/api/workflows/analyze" 422 @{ fileName="bad.yml"; content="not yaml" }
Invoke-Check "Wrong content type" POST "/api/workflows/analyze" 415 "fileName=x" "text/plain"


$explainContent = "name: Build`non:`n  push:`npermissions: write-all`njobs:`n  build:`n    runs-on: ubuntu-latest`n    steps:`n      - uses: actions/checkout@v4`n"
Invoke-Check "AI explanation" POST "/api/workflows/explain" 200 @{ fileName="mock.yml"; content=$explainContent; useAi=$true }
Invoke-Check "Remediation report" POST "/api/workflows/remediation" 200 @{ fileName="mock.yml"; content=$explainContent }
Invoke-Check "SARIF export" POST "/api/workflows/remediation/export/sarif" 200 @{ fileName="mock.yml"; content=$explainContent }
Invoke-Check "Patch export" POST "/api/workflows/remediation/export/diff" 200 @{ fileName="mock.yml"; content=$explainContent }

Write-Host "Passed: $Passed  Failed: $Failed" -ForegroundColor Cyan
if ($Failed -gt 0) { exit 1 }
exit 0
