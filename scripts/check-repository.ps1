<#
.SYNOPSIS
    Verifies that the repository is safe to package and publish.

.DESCRIPTION
    - Must be executed from inside a Git repository.
    - Requires at least one tracked file.
    - Scans tracked files only.
    - Verifies that sensitive files are not tracked.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

Write-Host "Verifying repository protection..." -ForegroundColor Cyan

#
# Ensure we're running inside a Git repository.
#
git rev-parse --git-dir *> $null

if ($LASTEXITCODE -ne 0)
{
    Write-Error "This script must be executed from inside a Git repository."
    exit 1
}

#
# Obtain tracked files.
#
$trackedFiles = git ls-files

if (-not $trackedFiles)
{
    Write-Error "No tracked files were found. Repository protection cannot be verified."
    exit 1
}

#
# Patterns that should never be committed.
#
$blockedPatterns = @(
    '\.pem$',
    '\.pfx$',
    '\.p12$',
    '\.key$',
    '\.snk$',
    'secrets\.json$',
    'appsettings\.Development\.json$',
    '\.env$',
    '\.env\..*$',
    '^\.vs/',
    '^bin/',
    '^obj/'
)

$violations = @()

foreach ($file in $trackedFiles)
{
    foreach ($pattern in $blockedPatterns)
    {
        if ($file -match $pattern)
        {
            $violations += $file
            break
        }
    }
}

if ($violations.Count -gt 0)
{
    Write-Host ""
    Write-Host "Repository protection FAILED." -ForegroundColor Red
    Write-Host ""

    $violations |
        Sort-Object -Unique |
        ForEach-Object {
            Write-Host "  $_" -ForegroundColor Yellow
        }

    exit 1
}

Write-Host ""
Write-Host "Repository protection check passed." -ForegroundColor Green
exit 0
