# Repository Security Policy

## Purpose

This document records the repository-level security controls used by
DevSecOps Sentinel and distinguishes controls that are technically enforced
from controls that currently rely on documented maintainer discipline.

The application security model is documented separately in
[`SECURITY.md`](../../SECURITY.md).

## Repository governance

The repository follows this change-management process:

1. Start work from the latest `main`.
2. Use a focused feature branch.
3. Open a pull request into `main`.
4. Require all applicable CI and Gitleaks checks to pass before merge.
5. Review dependency-update pull requests individually.
6. Tag releases only from an approved and synchronized `main` branch.

Direct pushes to `main` are avoided as a maintainer practice. This is
procedural rather than platform-enforced while the private repository remains
on GitHub Free.

## Enforced controls

### Full-length SHA pinning

The repository setting **Require actions to be pinned to a full-length commit
SHA** is enabled.

Every third-party and GitHub-authored action referenced by a workflow must use
a verified, full-length commit SHA. Dependabot may propose updates to those
SHAs through its GitHub Actions ecosystem configuration.

### Least-privilege workflow permissions

Workflows declare explicit permissions and use read-only access unless a
documented operation requires more.

Current examples include:

- `contents: read` for source checkout and repository scans;
- `pull-requests: read` for Gitleaks to enumerate pull-request commits;
- no workflow permission to write repository contents.

### CI quality gates

The primary CI workflow enforces:

- repository hygiene checks;
- .NET restore, build, and tests;
- frontend dependency installation, tests, and production build;
- npm and NuGet vulnerability audits;
- release-package verification.

### Secret detection

Gitleaks scans repository history on pushes, pull requests, scheduled runs,
and manual runs. A local pre-commit hook is also available as defense in
depth. Local hooks are developer-controlled and do not replace CI scanning.

See [`gitleaks.md`](gitleaks.md).

### Dependency maintenance

The repository uses:

- Dependency Graph;
- Dependabot alerts;
- Dependabot security updates;
- scheduled Dependabot version updates for NuGet, npm, and GitHub Actions.

Dependency pull requests are reviewed and validated individually before merge.

## Intended Actions allowlist

The repository currently uses only:

- `actions/checkout`;
- `actions/setup-dotnet`;
- `actions/setup-node`;
- `gitleaks/gitleaks-action`.

The intended repository policy is to allow only GitHub-owned actions and the
explicitly approved Gitleaks action. GitHub Actions Policies are visible in
the current UI but are not enforceable for this private repository on GitHub
Free.

## Accepted residual risks

The following controls are unavailable or unenforceable for this private
repository on the current GitHub Free plan:

- branch protection or ruleset enforcement on `main`;
- enforceable GitHub Actions Policies for a selected-action allowlist;
- GitHub secret scanning push protection;
- private-repository CodeQL and Dependency Review features that require an
  eligible GitHub security plan.

The maintainer accepts these residual risks while compensating with:

- feature-branch and pull-request discipline;
- required green CI before merge;
- full-length SHA pinning;
- Gitleaks pre-commit and CI scanning;
- Dependabot and vulnerability audits;
- release-package verification.

## Future hardening

If the repository becomes public or moves to an eligible GitHub Team or
Enterprise organization, enable:

1. branch protection or an enforced ruleset for `main`;
2. required status checks and pull-request review rules;
3. enforceable selected-action policies;
4. GitHub secret scanning and push protection;
5. CodeQL code scanning;
6. Dependency Review for pull requests.

## Review cadence

Review this document whenever:

- repository visibility or GitHub plan changes;
- a workflow introduces a new action;
- CI permissions change;
- a new secret, dependency, or release control is added;
- a security incident reveals a gap in repository governance.
