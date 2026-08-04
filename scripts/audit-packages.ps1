[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$solution = Join-Path $root 'DevSecOpsSentinel.slnx'

if (-not (Test-Path -LiteralPath $solution)) {
    throw "Solution file not found: $solution"
}

Push-Location $root
try {
    Write-Host 'Restoring NuGet packages...' -ForegroundColor Cyan
    dotnet restore $solution
    if ($LASTEXITCODE -ne 0) { throw "NuGet restore failed with exit code $LASTEXITCODE." }

    Write-Host 'Checking direct and transitive packages for vulnerabilities...' -ForegroundColor Cyan
    $output = dotnet list $solution package --vulnerable --include-transitive 2>&1
    $exitCode = $LASTEXITCODE
    $output | ForEach-Object { Write-Host $_ }
    if ($exitCode -ne 0) { throw "NuGet vulnerability audit failed with exit code $exitCode." }

    $text = $output -join [Environment]::NewLine
    if ($text -match '(?im)^\s*>?\s*(Critical|High|Moderate|Low)\s+') {
        throw 'One or more vulnerable NuGet packages were reported.'
    }

    Write-Host 'NuGet package audit completed successfully.' -ForegroundColor Green
}
finally {
    Pop-Location
}
