# Changelog

## Unreleased

### Security and reliability

- Added full-history Gitleaks CI scanning with SHA-pinned actions.
- Added repository-managed Gitleaks configuration and local pre-commit protection.
- Made GitHub action tag-to-SHA resolution an explicit opt-in.
- Removed live GitHub dependencies from integration tests.
- Added session-only browser API-key entry and authenticated smoke-test support.
- Defaulted authentication to required outside Development and Testing.
- Partitioned workflow rate limits by hashed API key or remote IP.
- Replaced per-request configuration binding with `IOptionsMonitor`.
- Surfaced action-reference resolution failures in remediation patches.
- Expanded sanitizer coverage, added CSP, logged external-provider failures,
  aligned the default OpenAI model, restricted default hosts, and generated
  applicable unified diffs with hunk headers.
- Rewrote `SECURITY.md` to describe the current trust boundaries.
- Removed temporary implementation notes from the repository root.

### Detection

- Added GHA005, reporting attacker-controllable workflow expressions
  interpolated into `run:` and `script:` bodies. Contexts that require
  repository write access to influence are excluded, and expressions in `if:`
  and `with:` are not reported, because those are evaluated rather than
  substituted into a shell.
- Added GHA006, reporting `actions/checkout` steps that leave the job token in
  `.git/config` for every later step to read.
- Added GHA007, reporting the pairing that makes `pull_request_target`
  exploitable rather than merely risky: a privileged trigger together with an
  explicit checkout of the pull request's own head.
- Read workflow structure with a real YAML parser, so flow mappings, quoted
  keys, anchors and the YAML 1.1 treatment of `on` as a boolean resolve the way
  GitHub resolves them. Workflows the parser cannot read are now reported as
  invalid instead of being partially analysed.

### Fixed

- Serialized finding severity as its name rather than its integer value. The
  client compares that field to severity names, so the numeric form produced an
  empty findings list and a "Low" risk label on workflows that contained
  high-severity findings.
- Made the exported patch applicable. The diff named `a/workflow.yml`
  regardless of the workflow, and counted a phantom trailing line for any file
  ending in a newline, so `git apply` rejected it. Both are now covered by tests
  that apply the patch with git and compare the result.

### Build and release

- Validated branch work through its pull request rather than on both the branch
  push and the pull request, and added a concurrency group that cancels
  superseded runs, to stay inside the Actions allowance a private repository
  receives.
- Triggered CI on `v*` tags, so the release-tag version comparison in
  `verify-release-package.ps1` is actually reachable.
- Passed workflow expressions through the environment instead of interpolating
  them into a shell body, and stopped change classification aborting when a
  force-push leaves the recorded base commit unreachable.
- Stopped Dependabot proposing individually unmergeable major upgrades for the
  frontend build toolchain, whose majors are coupled through peer dependencies.
- Documented why `AssemblyVersion` is deliberately held at the major.minor
  baseline, and why the screenshot item on the release checklist is the only
  control covering a directory that secret scanning allowlists.
- Removed `MANIFEST.txt`. It had been reduced to a hand-maintained list of file
  paths carrying no hashes, with no generator and no consumer, and had drifted
  from the tracked tree. `git ls-files` reproduces it exactly and cannot go
  stale, and a release tag already commits to a tree hash.

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
