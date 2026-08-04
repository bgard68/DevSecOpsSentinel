# v1.0 Release Checklist

- [ ] `setup-local.ps1` passes from a clean extraction
- [ ] Central Package Management verification passes
- [ ] .NET restore, Release build, and all tests pass
- [ ] npm audit reports no high or critical vulnerabilities
- [ ] frontend tests and production build pass
- [ ] repository protection check passes
- [ ] package audit passes
- [ ] standard API smoke suite passes
- [ ] live GitHub smoke test passes when explicitly enabled
- [ ] live OpenAI smoke test passes when explicitly enabled
- [ ] Simulation mode works
- [ ] GitHub Sandbox mode works
- [ ] safe workflow returns zero findings
- [ ] vulnerable workflows return expected deterministic findings
- [ ] remediation plan, comparison, and exports work
- [ ] no write operations exist in GitHub integration
- [ ] no secrets or private keys are included
- [ ] screenshots regenerated **only if the interface changed** — see the note below
- [ ] screenshots contain no secret values — `.gitleaks.toml` allowlists
      `docs/assets/screenshots/`, so automated secret scanning does not cover
      them and this manual check is the only control
- [ ] version is `1.0.0`
- [ ] changelog and release notes are current

## Screenshots

Regenerate with `.\scripts\capture-screenshots.ps1` when the interface changes,
not when the version changes.

The header renders the running version, so a release always leaves the images
showing the previous one. That is accepted. The images exist to show what the
product looks like, and recapturing them for a patch that changed nothing visible
is churn without information. A reader who wants the version reads the release,
not a screenshot.
