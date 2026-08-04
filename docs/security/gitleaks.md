# Gitleaks secret detection

DevSecOps Sentinel uses Gitleaks as defense in depth while GitHub-native push
protection is unavailable for the private repository.

## CI protection

`.github/workflows/gitleaks.yml` scans the full Git history on:

- pushes to `main` and `feature/**`;
- pull requests targeting `main`;
- manual workflow dispatch;
- a weekly scheduled scan.

The workflow has read-only repository permissions. Both GitHub Actions are
pinned to full commit SHAs.

## Local pre-commit protection

The repository uses the standard `pre-commit` framework with Gitleaks pinned in
`.pre-commit-config.yaml`.

Install `pre-commit`, then run:

```powershell
.\scripts\install-gitleaks-precommit.ps1
```

Run every configured hook manually:

```powershell
pre-commit run --all-files
```

The local hook is intentionally paired with CI because local Git hooks are
developer-controlled and can be skipped.

## Direct local scan

When the Gitleaks executable is installed:

```powershell
.\scripts\run-gitleaks.ps1
```

Scan every reachable commit:

```powershell
.\scripts\run-gitleaks.ps1 -AllHistory
```

## Responding to a finding

Do not merely delete the value and retry.

1. Revoke or rotate the credential immediately.
2. Determine whether it exists in Git history, logs, artifacts, or releases.
3. Remove it from the working tree.
4. Rewrite history when appropriate and coordinate any required force push.
5. Re-run Gitleaks locally and in CI.
6. Document the incident without reproducing the secret.

Use narrowly scoped `gitleaks:allow` annotations only for confirmed false
positives. Never allowlist an actual credential.
