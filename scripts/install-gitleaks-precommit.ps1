[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepositoryRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepositoryRoot

if (-not (Test-Path ".git")) {
    throw "Run this script from a cloned DevSecOpsSentinel Git repository."
}

$PreCommit = Get-Command pre-commit -ErrorAction SilentlyContinue

if (-not $PreCommit) {
    throw @"
The 'pre-commit' command was not found.

Install it with one of these supported approaches, then run this script again:

  py -m pip install --user pre-commit

or:

  pipx install pre-commit
"@
}

pre-commit install
if ($LASTEXITCODE -ne 0) {
    throw "pre-commit install failed with exit code $LASTEXITCODE."
}

pre-commit validate-config
if ($LASTEXITCODE -ne 0) {
    throw "pre-commit configuration validation failed with exit code $LASTEXITCODE."
}

Write-Host "Gitleaks pre-commit protection installed." -ForegroundColor Green
Write-Host "Run all hooks manually with: pre-commit run --all-files"
