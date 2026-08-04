# Changelog

## 1.0.0 — 2026-08-03

### Added

- Deterministic GitHub Actions security analyzer
- Validated remediation previews and risk-reduction reporting
- Read-only GitHub App integration with repository allowlisting
- Optional Mock and Live OpenAI advisory explanations
- Markdown, JSON, SARIF, patch, and printable HTML exports
- React security-operations dashboard
- Correlation IDs, rate limiting, output caching, security headers, health endpoints, and RFC 7807 errors
- Unit, integration, frontend, package-audit, repository-protection, and smoke-test gates
- Central Package Management and frontend toolchain verification
- Portfolio documentation, demo guide, screenshots, release notes, and release checklist

- Automated integration tests run in an isolated Testing environment and always force OpenAI Mock mode, even when local User Secrets use Live mode.

### Release-candidate validation fixes

- Forced malformed JSON responses to use `application/problem+json`, with a safe fallback writer.
- Reconciled frontend dependencies on every release-gate run to repair stale extracted `node_modules` folders.
- Added an explicit frontend test-count gate so a zero-test Vitest run fails the release.
- Updated `run-all.ps1` to stop immediately when any native command returns a non-zero exit code.
