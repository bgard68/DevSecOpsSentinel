# Changelog

## 1.2.0 — 2026-08-04

### Detection

- Added GHA008, reporting a reusable workflow call that forwards the entire
  secret store with `secrets: inherit`.
- Added GHA009, reporting a workflow that declares no token permissions at any
  scope and therefore inherits the repository default, which is a repository
  setting rather than a property of the workflow.
- Added GHA010, reporting a self-hosted runner reachable from a pull-request
  trigger. Self-hosted runners persist between jobs, so anything contributor
  code changes on one outlives the run.
- Added GHA011, reporting a privileged `workflow_run` job that downloads an
  artifact produced by the workflow that triggered it.
- Added a bundled scenario for GHA007, which previously had no way to be
  demonstrated in the application.

### Fixed

- Made the SARIF export conform to the specification. `level` carried severity
  names such as `critical`, but the property is a closed enum of `none`, `note`,
  `warning` and `error`, and the schema key was emitted as `schema` rather than
  `$schema`. Every exported document was therefore rejected by SARIF consumers.
  Findings now map onto the specified levels, the original severity travels as
  `security-severity` on the rule, and a rule table is emitted so rule
  identifiers resolve.
- Included severity, line number, description and recommendation in the Markdown
  and HTML exports. They previously listed only a rule identifier, a title and a
  resolved flag, which is not enough to triage or locate anything reported.
- Rate limited the GitHub read endpoints, which reach GitHub's API on the
  deployment's behalf and were previously unbounded.

### Changed

- Removed the duplicate job model. Patch validation compared job counts taken
  from indentation while the rules read the parsed structure, so the two could
  disagree about what a job is.
- Removed the `Informational` severity, which no rule produced but which
  appeared in the client's ordering and in exports as a category that could
  never be populated.
- Described what the AI integration actually demonstrates: the enforcement
  around the model rather than the prose it returns.

## 1.1.0 — 2026-08-04

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
- Derived the product version from the assembly instead of repeating it as a
  literal. It had appeared in five places and drifted to three different values:
  the health endpoint and the SARIF tool descriptor reported `1.0.0` against a
  `1.0.1` release, two GitHub `User-Agent` headers still said `0.4.0`, and the
  application header advertised `v1.0`. `Directory.Build.props` is now the only
  place a version is written, with the client reading `package.json` through
  Vite.
- Dropped the development `phase` field from the root and health responses.

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
