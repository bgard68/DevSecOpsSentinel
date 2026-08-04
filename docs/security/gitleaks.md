# Gitleaks secret detection

DevSecOps Sentinel uses Gitleaks as defense in depth while GitHub-native push
protection is unavailable for the private repository.

## Authoritative control

The GitHub Actions Gitleaks workflow is the repository-level backstop. It scans
repository history on pushes, pull requests, manual runs, and scheduled runs.

The CI scan is authoritative because it runs independently of each developer's
local machine and cannot be skipped with Git's `--no-verify` option.

## Local pre-commit convenience

The local Gitleaks hook is optional developer convenience. It provides earlier
feedback before a commit is created, but it is not an enforcement boundary.

Important limitations:

- it must be installed separately in every clone;
- it requires Python because this repository uses the standard `pre-commit`
  framework for hook orchestration;
- it can be bypassed intentionally with `git commit --no-verify`;
- it may be absent on a developer or automation machine;
- CI remains required even when the local hook is installed.

The Python dependency is an explicit trade-off: the standard `pre-commit`
framework provides repeatable installation, isolated hook environments, and a
well-understood cross-platform workflow. A repository-local Git hook could
avoid Python, but would require custom installation and maintenance while
remaining equally bypassable.

## Pinned hook revision

`.pre-commit-config.yaml` pins the Gitleaks repository to the immutable
40-character commit behind Gitleaks `v8.30.1`:

```text
83d9cd684c87d95d656c1458ef04895a7f1cbd8e
```

The version comment remains beside the SHA for readability. Updates must verify
the upstream tag and replace the full commit SHA deliberately.

## Install local protection

Install `pre-commit` with one of the documented approaches:

```powershell
py -m pip install --user pre-commit
```

or:

```powershell
pipx install pre-commit
```

Then install the repository hook:

```powershell
.\scripts\install-gitleaks-precommit.ps1
```

Run every configured hook manually:

```powershell
py -m pre_commit run --all-files
```

Using `py -m pre_commit` avoids relying on the Python Scripts directory being
present on the current PowerShell `PATH`.

## Direct local scan

When the Gitleaks executable is installed:

```powershell
.\scripts\run-gitleaks.ps1
```

Scan every reachable commit:

```powershell
.\scripts\run-gitleaks.ps1 -AllHistory
```

## Screenshot review

Binary screenshots are not a dependable secret-scanning surface. The
`docs/assets/screenshots/` allowlist avoids false handling of generated binary
assets, but it also means visible tokens in screenshots require manual review.

Before committing or publishing screenshots, verify that they contain no:

- API keys or tokens;
- connection strings;
- private repository URLs containing credentials;
- user-specific secrets or environment values;
- browser or terminal output exposing sensitive data.

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
