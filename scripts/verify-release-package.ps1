[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

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
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Required release artifact missing: $relativePath"
    }
}

$directoryBuildPropsPath = Join-Path $root 'Directory.Build.props'
[xml]$directoryBuildProps = Get-Content -LiteralPath $directoryBuildPropsPath -Raw
$versionNode = $directoryBuildProps.SelectSingleNode('/Project/PropertyGroup/Version')

if ($null -eq $versionNode -or [string]::IsNullOrWhiteSpace($versionNode.InnerText)) {
    throw 'Directory.Build.props must define /Project/PropertyGroup/Version.'
}

$expectedVersion = $versionNode.InnerText.Trim()

if ($expectedVersion -notmatch '^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$') {
    throw "Directory.Build.props contains an invalid semantic version: $expectedVersion"
}

$packageJsonPath = Join-Path $root 'src/devsecops-sentinel-web/package.json'
$packageJson = Get-Content -LiteralPath $packageJsonPath -Raw | ConvertFrom-Json

if ([string]$packageJson.version -ne $expectedVersion) {
    throw "Frontend version must match Directory.Build.props ($expectedVersion); found $($packageJson.version)."
}

$packageLockPath = Join-Path $root 'src/devsecops-sentinel-web/package-lock.json'
if (Test-Path -LiteralPath $packageLockPath) {
    $packageLock =
        Get-Content -LiteralPath $packageLockPath -Raw |
        ConvertFrom-Json -AsHashtable

    $lockedVersion = [string]$packageLock['version']

    if (
        -not [string]::IsNullOrWhiteSpace($lockedVersion) -and
        $lockedVersion -ne $expectedVersion
    ) {
        throw "package-lock.json version must match Directory.Build.props ($expectedVersion); found $lockedVersion."
    }

    $packages = $packageLock['packages']
    $rootPackage = if ($null -ne $packages) {
        $packages['']
    }
    else {
        $null
    }

    if ($null -ne $rootPackage) {
        $lockedRootVersion = [string]$rootPackage['version']

        if (
            -not [string]::IsNullOrWhiteSpace($lockedRootVersion) -and
            $lockedRootVersion -ne $expectedVersion
        ) {
            throw "package-lock.json root package version must match Directory.Build.props ($expectedVersion); found $lockedRootVersion."
        }
    }
}

if ($env:GITHUB_REF_TYPE -eq 'tag' -and -not [string]::IsNullOrWhiteSpace($env:GITHUB_REF_NAME)) {
    $tagVersion = $env:GITHUB_REF_NAME.TrimStart('v')

    if ($tagVersion -ne $expectedVersion) {
        throw "Git tag version ($tagVersion) must match Directory.Build.props ($expectedVersion)."
    }
}

$trackedFileOutput = & git -C $root ls-files
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to enumerate tracked files with git ls-files.'
}

$forbiddenExtensions = @('.pem', '.pfx', '.p12', '.key', '.publishsettings')
$forbidden = foreach ($relativePath in $trackedFileOutput) {
    if ([string]::IsNullOrWhiteSpace($relativePath)) {
        continue
    }

    $extension = [System.IO.Path]::GetExtension($relativePath).ToLowerInvariant()
    if ($forbiddenExtensions -contains $extension) {
        $relativePath
    }
}

if ($forbidden) {
    throw "Forbidden secret files found in tracked repository content: $($forbidden -join ', ')"
}

Write-Host "Release package verification passed for version $expectedVersion." -ForegroundColor Green
