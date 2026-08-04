# Phase D.3 acceptance criteria

- [ ] Phase C behavior remains green.
- [ ] GitHub status endpoint returns a safe read-only status.
- [ ] GitHub App JWT uses RS256 and the configured App ID.
- [ ] Installation tokens are short-lived and cached only in memory.
- [ ] Only allowlisted repositories are returned.
- [ ] `.yml` and `.yaml` files are discovered under `.github/workflows`.
- [ ] Workflow content is decoded from GitHub's Base64 response.
- [ ] Retrieved workflows use the existing deterministic analysis pipeline.
- [ ] Optional AI explanation remains explicit opt-in.
- [ ] Non-allowlisted repositories return 403.
- [ ] No GitHub write methods or permissions exist.
- [ ] Standard smoke tests pass without live GitHub access.
- [ ] Optional live sandbox smoke test passes.
- [ ] NuGet and npm vulnerability audits are clean.
- [ ] Repository protection passes.
