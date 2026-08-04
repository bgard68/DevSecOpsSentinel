$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Push-Location $Root
try {
    $ForbiddenPatterns = @(
        "(^|/)\.claude(/|$)", "(^|/)logs?(/|$)", "(^|/)secrets?(/|$)",
        "\.pem$", "\.pfx$", "\.key$", "\.publishsettings$",
        "(^|/)Azure(Import|Export)s?(/|$)", "(^|/)azure-(import|export)s?(/|$)",
        "(^|/)(token|tokens|credential|credentials|passwords?)\.json$"
    )
    $Failures = foreach ($File in (git ls-files 2>$null)) {
        foreach ($Pattern in $ForbiddenPatterns) {
            if ($File -match $Pattern) { $File; break }
        }
    }
    if ($Failures) {
        Write-Host "Forbidden files are tracked:" -ForegroundColor Red
        $Failures | Sort-Object -Unique | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
        exit 1
    }
    Write-Host "Repository protection check passed." -ForegroundColor Green
    exit 0
}
finally { Pop-Location }
