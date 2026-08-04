# PR #5 — Release Verification Gate

This package wires the existing `scripts/verify-release-package.ps1` gate into
the primary CI workflow.

## Behavior

The release verification runs after the .NET build/tests, dependency audits,
frontend tests, and frontend production build. CI fails when:

- a required release document or screenshot is missing;
- the frontend package version is not `1.0.0`;
- a forbidden private-key or publishing credential file exists in the tree.

## Changed files

- `.github/workflows/ci.yml`

The existing verification script is included unchanged so the package can be
applied safely over the repository.

## Local validation

```powershell
pwsh -File .\scripts\verify-release-package.ps1
```
