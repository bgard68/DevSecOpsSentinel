[CmdletBinding()]
param(
    [switch]$AllHistory
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepositoryRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepositoryRoot

$Gitleaks = Get-Command gitleaks -ErrorAction SilentlyContinue
if (-not $Gitleaks) {
    throw "The 'gitleaks' executable was not found on PATH."
}

$Arguments = @(
    "git",
    "--config=.gitleaks.toml",
    "--redact",
    "--verbose"
)

if ($AllHistory) {
    $Arguments += "--log-opts=--all"
}

& gitleaks @Arguments
if ($LASTEXITCODE -ne 0) {
    throw "Gitleaks detected a potential secret or failed with exit code $LASTEXITCODE."
}

Write-Host "Gitleaks scan passed." -ForegroundColor Green
