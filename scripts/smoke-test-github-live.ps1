[CmdletBinding()]
param(
    [switch]$EnableLiveGitHub,
    [string]$BaseUrl = 'https://localhost:7001',
    [string]$Owner = 'bgard68',
    [string]$Repository = 'DevSecOpsSentinel-Sandbox'
)

$ErrorActionPreference = 'Stop'
if (-not $EnableLiveGitHub) {
    Write-Host 'SKIP Live GitHub smoke test requires -EnableLiveGitHub.' -ForegroundColor Yellow
    exit 0
}

$status = Invoke-RestMethod -Uri "$BaseUrl/api/github/status" -SkipCertificateCheck
if (-not $status.connected) {
    throw "GitHub is not connected: $($status.message)"
}

$repositories = Invoke-RestMethod -Uri "$BaseUrl/api/github/repositories" -SkipCertificateCheck
if (-not ($repositories.fullName -contains "$Owner/$Repository")) {
    throw 'The allowlisted sandbox repository was not returned.'
}

$workflows = Invoke-RestMethod `
    -Uri "$BaseUrl/api/github/repositories/$Owner/$Repository/workflows" `
    -SkipCertificateCheck
if ($workflows.Count -lt 1) {
    throw 'No GitHub workflow files were returned.'
}

$workflow = $workflows | Select-Object -First 1
$body = @{ path = $workflow.path; reference = 'main'; useAi = $false } | ConvertTo-Json
$result = Invoke-RestMethod `
    -Uri "$BaseUrl/api/github/repositories/$Owner/$Repository/analyze" `
    -Method Post `
    -ContentType 'application/json' `
    -Body $body `
    -SkipCertificateCheck

if ($null -eq $result.result) {
    throw 'GitHub workflow analysis returned no result.'
}

Write-Host "PASS Read-only GitHub integration returned and analyzed $($workflow.path)." -ForegroundColor Green
