$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Web = Join-Path $Root "src\devsecops-sentinel-web"

function Invoke-Native {
    param([Parameter(Mandatory)][string]$Command, [Parameter(ValueFromRemainingArguments)][string[]]$Arguments)
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Command failed with exit code $LASTEXITCODE." }
}

Push-Location $Web
try {
    # Always reconcile package.json with node_modules. This repairs stale or partially
    # extracted installations while preserving npm's normal incremental behavior.
    Invoke-Native npm install --no-audit --no-fund

    $required = @(
        ".\node_modules\typescript\bin\tsc",
        ".\node_modules\vite\bin\vite.js",
        ".\node_modules\vitest\vitest.mjs",
        ".\node_modules\@testing-library\react\dist\index.js",
        ".\node_modules\@testing-library\jest-dom\dist\vitest.mjs"
    )

    $missing = $required | Where-Object { -not (Test-Path $_) }
    if ($missing) {
        Write-Warning "Frontend dependencies are incomplete. Performing a clean reinstall."
        Remove-Item .\node_modules -Recurse -Force -ErrorAction SilentlyContinue
        Invoke-Native npm install --no-audit --no-fund
    }

    $stillMissing = $required | Where-Object { -not (Test-Path $_) }
    if ($stillMissing) {
        throw "Frontend toolchain repair failed. Missing: $($stillMissing -join ', ')"
    }

    Invoke-Native npm run verify:toolchain
    Write-Host "Frontend toolchain verified." -ForegroundColor Green
}
finally { Pop-Location }
