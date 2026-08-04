[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

$required = @(
    'README.md',
    'ARCHITECTURE.md',
    'PORTFOLIO-WALKTHROUGH.md',
    'DEMO-GUIDE.md',
    'OPERATIONS.md',
    'CHANGELOG.md',
    'RELEASE-NOTES.md',
    'RELEASE-CHECKLIST.md',
    'docs/assets/screenshots/01-connected-dashboard.png',
    'docs/assets/screenshots/02-live-ai-vulnerable-workflow.png',
    'docs/assets/screenshots/03-live-ai-safe-workflow.png'
)

foreach ($relativePath in $required) {
    $path = Join-Path $root $relativePath
    if (-not (Test-Path $path)) {
        throw "Required release artifact missing: $relativePath"
    }
}

$packageJson = Get-Content (Join-Path $root 'src/devsecops-sentinel-web/package.json') -Raw | ConvertFrom-Json
if ($packageJson.version -ne '1.0.0') {
    throw "Frontend version must be 1.0.0; found $($packageJson.version)."
}

$forbiddenExtensions = @('.pem', '.pfx', '.p12', '.key', '.publishsettings')
$forbidden = Get-ChildItem $root -Recurse -Force -File | Where-Object {
    $forbiddenExtensions -contains $_.Extension.ToLowerInvariant()
}
if ($forbidden) {
    throw "Forbidden secret files found: $($forbidden.FullName -join ', ')"
}

Write-Host 'v1.0 release package verification passed.' -ForegroundColor Green
