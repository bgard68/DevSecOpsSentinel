# Five-Minute Demo Guide

## Preparation

1. Start the API.
2. Start the React frontend.
3. Confirm the header shows API connected, GitHub read-only connected, and either Mock or Live AI mode.
4. Keep the GitHub App restricted to the sandbox repository.

## Demo flow

### 1. Explain the trust model — 45 seconds

Point to the three product boundaries:

- Read-only GitHub App
- Repository allowlist
- Deterministic-first analysis

State that AI explains confirmed findings but cannot create findings, change severity, or apply patches.

### 2. Analyze a vulnerable workflow — 90 seconds

Open **GitHub Sandbox**, select `excessive-permissions.yml`, enable AI explanation, and analyze.

Show:

- deterministic rule ID and severity
- live or mock AI explanation
- recommended action
- remediation plan
- before/after risk reduction
- workflow comparison or unified diff

### 3. Scan a repository the audience picks — 60 seconds

Open **Public repo** and ask for any public repository they work on. Every
workflow file is fetched anonymously and analysed in seconds; nothing is
written and no credential is attached. If they hesitate, scan this repository
itself — the three findings that come back are the documented, test-enforced
exceptions, which is a stronger close than a clean report.

### 4. Show exports — 45 seconds

Export one or two formats, emphasizing:

- SARIF for security tooling
- Markdown for reviews
- patch for manual application
- printable HTML for evidence

### 4. Analyze the safe workflow — 60 seconds

Select `safe.yml` and analyze.

Show that the result is **Clear**, with zero findings and zero auto-fixes. Explain that the AI does not invent vulnerabilities and instead summarizes why the workflow passed configured rules.

### 5. Close with operations — 45 seconds

Mention:

- unit, integration, frontend, and smoke tests
- dependency vulnerability audits
- Central Package Management
- TypeScript toolchain verification
- one-command release gate
- correlation IDs, rate limiting, caching, health endpoints, security headers, and RFC 7807 errors
