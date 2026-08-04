[CmdletBinding()]
param([switch]$EnableLiveOpenAi, [string]$BaseUrl = 'https://localhost:7001')

$ErrorActionPreference = 'Stop'
if (-not $EnableLiveOpenAi) {
    Write-Host 'SKIP Live OpenAI smoke test. Pass -EnableLiveOpenAi to opt in.' -ForegroundColor Yellow
    exit 0
}

$status = Invoke-RestMethod -Uri "$BaseUrl/api/ai/status" -SkipCertificateCheck
if (-not $status.configured -or $status.mode -ne 'Live') {
    throw 'Live OpenAI mode is not configured. The API key is not displayed.'
}

$body = @{ fileName = 'live-smoke.yml'; content = "name: Test`non: push`njobs:`n  build:`n    runs-on: ubuntu-latest`n    steps:`n      - uses: actions/checkout@v4"; useAi = $true } | ConvertTo-Json
$response = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/workflows/explain" -ContentType 'application/json' -Body $body -SkipCertificateCheck -TimeoutSec 45
if (-not $response.analysis -or -not $response.explanation) { throw 'Live OpenAI response was incomplete.' }
Write-Host "PASS Live OpenAI explanation mode: $($response.explanation.mode)" -ForegroundColor Green
