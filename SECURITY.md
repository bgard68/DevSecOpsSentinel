# Security policy

## Supported release

Security fixes are applied to the latest release on `main`.

## Trust boundaries

DevSecOps Sentinel is a read-only GitHub Actions analysis application.

- Deterministic rules are authoritative.
- OpenAI explanations are optional and advisory.
- The GitHub App has read-only repository access.
- No application code creates branches, commits, pull requests, or merges.
- Repository access is restricted by an explicit allowlist.
- Credentials remain server-side and must be supplied through User Secrets,
  environment variables, or a deployment secret store.
- The React client never contains a built-in API key. For a protected private
  demo, a user may enter the deployment access key, which is stored only in
  browser `sessionStorage` for the current tab.

## External services

The deterministic analyzer and bundled scenarios run without live external
services by default.

OpenAI is called only when `OpenAI:Mode` is `Live` and the caller explicitly
requests an AI explanation.

GitHub repository browsing is called only when `GitHub:Enabled` is `true`.
GitHub action tag-to-SHA resolution is a separate opt-in capability controlled
by `GitHub:ResolveActionReferences`. It defaults to `false`; therefore ordinary
local analysis and CI do not make outbound GitHub requests.

## Authentication

Authentication may be disabled only in the `Development` and `Testing`
environments. Every other environment must configure:

```text
Security__Mode=Required
Security__ApiKey=<random secret with at least 32 characters>
Security__HeaderName=X-API-Key
```

A browser-delivered API key is suitable only for a private portfolio demo or
internal deployment. A public multi-user service should use OIDC/OAuth and
per-user authorization instead.

## Secret handling

Never commit credentials, API keys, passwords, personal access tokens, GitHub
App private keys, certificates, Azure publish profiles, Azure imports or
exports, `.claude`, conversation content, production configuration, or logs.

The AI sanitizer removes known token formats, bearer tokens, private-key blocks,
sensitive YAML mappings, shell assignments, and command-line secret arguments
before workflow excerpts are sent to OpenAI. Sanitization is defense in depth;
operators must still avoid submitting real production secrets.

## Secret scanning

Gitleaks scans repository history in CI and through an optional local
pre-commit hook. The repository-managed configuration extends Gitleaks'
maintained default rules. A clean scan reduces risk but does not prove that a
credential has never been exposed.

Local hooks are defense in depth and can be bypassed. CI scanning is therefore
required as the independent repository gate. See
`docs/security/gitleaks.md` for setup and response procedures.

## Credential rotation

If a secret is exposed:

1. Revoke or rotate it immediately.
2. Remove it from the working tree and Git history.
3. Review GitHub Actions logs and application telemetry for misuse.
4. Replace the value in User Secrets or the deployment secret store.
5. Re-run repository and release validation.

For a GitHub App private key, generate a replacement key in the GitHub App
settings, update `GitHub:PrivateKeyPath`, verify connectivity, and then revoke
the old key.

## Reporting

Do not open a public issue containing a live secret or exploit payload. Revoke
any exposed credential first and report the issue privately to the repository
owner.
