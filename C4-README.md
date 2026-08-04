# C4 — Real GitHub Action SHA Resolution

This package removes the forty-zero placeholder SHA.

Behavior:

- `owner/repository[/path]@tag` references are resolved through the GitHub Git Data API.
- Lightweight and annotated tags are supported.
- Branch references are supported as a fallback.
- Already-pinned 40-character SHAs are preserved.
- Local actions (`./path`) and `docker://` references are not resolved.
- If GitHub cannot resolve a reference, the workflow remains unchanged.
- An unresolved GHA001 finding is not added to `AppliedRuleIds`, is not reported as resolved, and does not reduce risk.
- The analysis/remediation pipeline is asynchronous end to end; no `.Result` or `.GetAwaiter().GetResult()` blocking is introduced.

The resolver uses the configured GitHub App installation token when GitHub is configured. When GitHub is disabled, it performs an unauthenticated read against public GitHub repositories.
