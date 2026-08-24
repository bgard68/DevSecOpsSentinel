# Fails when a workflow references a third-party action that the repository's Actions policy
# does not permit.
#
# The policy is `allowed_actions: selected` with SHA pinning required, so an action bumped
# past its allowlisted SHA cannot run. GitHub reports that as `startup_failure` before any
# job starts, which produces no logs and names nothing — the workflow appears broken when in
# fact it is disallowed. This turns that silent, post-merge failure into a named CI failure
# on the pull request that introduces it.
#
# Reading the live policy would need an admin token, which CI does not have and should not,
# so .github/allowed-actions.txt mirrors the setting and is the thing compared against.

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$AllowListPath = Join-Path $Root ".github/allowed-actions.txt"
$WorkflowDirectory = Join-Path $Root ".github/workflows"

if (-not (Test-Path -LiteralPath $AllowListPath)) { throw "Missing allowlist: $AllowListPath" }
if (-not (Test-Path -LiteralPath $WorkflowDirectory)) { throw "Missing workflows: $WorkflowDirectory" }

$allowed = Get-Content -LiteralPath $AllowListPath |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ -and -not $_.StartsWith("#") }

# Owner-qualified `uses:` values only. A local path (./.github/...) or a docker:// reference
# is not covered by the actions policy.
$pattern = 'uses:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[A-Za-z0-9_.-]+)'

$violations = @()
$unpinned = @()

foreach ($workflow in Get-ChildItem -LiteralPath $WorkflowDirectory -Filter *.yml) {
    foreach ($match in [regex]::Matches((Get-Content -LiteralPath $workflow.FullName -Raw), $pattern)) {
        $reference = $match.Groups[1].Value
        $owner = $reference.Split('/')[0]

        # github_owned_allowed covers these, so they are outside the list by design.
        if ($owner -in @('actions', 'github')) { continue }

        $sha = $reference.Split('@')[1]
        if ($sha -notmatch '^[0-9a-f]{40}$') {
            $unpinned += "$($workflow.Name): $reference"
            continue
        }

        # Ordinal, case-sensitive: the policy compares the owner/repo as written, so
        # `Azure/login` and `azure/login` are not interchangeable to GitHub.
        if ($allowed -cnotcontains $reference) {
            $violations += "$($workflow.Name): $reference"
        }
    }
}

if ($unpinned.Count -gt 0) {
    Write-Host "Actions referenced by tag or branch rather than a commit SHA:" -ForegroundColor Red
    $unpinned | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    throw "The repository requires SHA pinning; these would be refused at startup."
}

if ($violations.Count -gt 0) {
    Write-Host "Actions referenced but not in .github/allowed-actions.txt:" -ForegroundColor Red
    $violations | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    Write-Host ""
    Write-Host "GitHub will refuse to start these workflows with startup_failure and no logs." -ForegroundColor Yellow
    Write-Host "Fix BOTH, or the deploy still fails:" -ForegroundColor Yellow
    Write-Host "  1. Add the reference to .github/allowed-actions.txt" -ForegroundColor Yellow
    Write-Host "  2. Add it in Settings > Actions > General > Allow specified actions" -ForegroundColor Yellow
    throw "$($violations.Count) action reference(s) outside the allowlist."
}

# The reverse direction. A stale entry is not dangerous, but it is a SHA nobody can account
# for, which is the state the allowlist exists to prevent.
$referenced = @()
foreach ($workflow in Get-ChildItem -LiteralPath $WorkflowDirectory -Filter *.yml) {
    foreach ($match in [regex]::Matches((Get-Content -LiteralPath $workflow.FullName -Raw), $pattern)) {
        $referenced += $match.Groups[1].Value
    }
}

$orphans = $allowed | Where-Object { $referenced -cnotcontains $_ }
if ($orphans) {
    Write-Host "Allowlisted but no longer referenced by any workflow:" -ForegroundColor Yellow
    $orphans | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
    Write-Host "Remove them here and in the repository setting once the bump is confirmed." -ForegroundColor Yellow
}

Write-Host "Action allowlist verified: $($allowed.Count) entries, all referenced actions permitted." -ForegroundColor Green
