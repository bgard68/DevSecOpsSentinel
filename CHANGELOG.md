# Changelog

## Unreleased

### Added

- Findings can be accepted in the workflow that carries them:
  `# sentinel:accept GHA002 - reason`. In the workflow rather than a separate
  file of rule/line/reason entries, because line numbers there drift on the
  first edit, the reason ends up far from what it explains, and the file
  outlives the code it was written about. Three refusals keep it a judgement
  recorder rather than a mute button: an acceptance with no reason is ignored
  and the finding still reports; acceptance is matched on rule *and* line, so
  one cannot cover a second finding elsewhere; and an acceptance that no longer
  matches a finding is reported as GHA012. Documented in
  `docs/accepting-findings.md`.
- Analysis results carry acknowledgements — what a rule examined and accepted —
  separately from findings. Removing a finding left silence where the reasoning
  used to be, and a workflow reported clean gave no way to tell that a grant was
  examined from the rule never having looked. They are not findings because the
  client reads any finding as action required, and a correct workflow must not
  be pushed into that state by the check that cleared it.

### Changed

- GHA002, GHA004 and GHA006 establish need before reporting. GHA002 knows what
  each of 24 published actions cannot work without, so a CodeQL job holding
  `security-events: write` is no longer reported as excessive — the rule's own
  remediation was already satisfied by the configuration it flagged, and
  following the advice would have broken code scanning. GHA004 is Critical only
  when a job checks out the pull request's head, and Low otherwise. GHA006 stays
  quiet when a script after the checkout, in the same job, pushes with the
  credential.
- GHA002 severity follows what the scope can do once a token is stolen instead
  of being constant: `contents`, `packages` and `actions` High; `security-events`,
  `checks` and `statuses` Low; everything else Medium, including scopes GitHub
  adds later. Rating a scope that can push code the same as one that can hide an
  alert flattens the difference a severity exists to express.
- `RepositoryWorkflowsTests` measures this repository the way the product
  reports, acceptances included. It previously called the rules directly, which
  bypassed the service where acceptance is applied and held this repository to a
  stricter standard than the tool applies to anyone else's. Its exemption table
  is now empty: two entries are recognised by the rule itself, and the third is
  stated in `prune-runs.yml`.

## 1.4.0 — 2026-08-05

### Added

- `Security:Mode` accepts a third value, `Public`: deterministic analysis is open
  to anyone, and the key still guards GitHub reads and Live explanations.
  Production previously accepted only `Required`, so a public deployment demanded
  a key handed out by hand — a demonstration nobody can run demonstrates nothing.
  `Public` is not a relaxation: it still requires a key of 32 characters or more,
  because the endpoints it guards are the ones that matter.
- `docs/credentials.md`: every key in one place — what it is, whether it is
  actually a secret, how to generate it, where it lives locally and deployed, and
  how to rotate it. It also states plainly that a public client cannot hold a
  secret, and records which values are *not* secrets, because treating an App ID
  as one adds ceremony without protection.

### Changed

- The AI provider is selected per request rather than once at startup. A single
  provider for the whole deployment is fine while every caller presents a key and
  wrong the moment one does not: a deployment configured Live would have spent
  credits for anonymous visitors. An anonymous caller now receives Mock whatever
  the deployment is set to, labelled Mock in the response, and cannot cause an
  outbound request. An invalid key does not promote a caller — it is served as
  anonymous on open endpoints and still refused on privileged ones.
- GHA003, a job without a timeout, is Low rather than Medium. It consumes minutes
  and occupies a self-hosted runner; it exposes nothing, and rating it alongside a
  token left readable on the runner flattened the distinction a severity exists to
  make. This also fills the only severity no rule produced.
- In the client the access key is an upgrade offered from the header rather than a
  gate across the page.

### Fixed

- The access key is verified before being accepted. It was stored unchecked, so a
  wrong key produced a header reading "Lock API" as though it had worked and the
  only symptom was GitHub quietly staying unavailable.
- A refused privileged call no longer empties the workspace. The three start-up
  resources were loaded with `Promise.all`, which rejects on any rejection and
  discards the successes, so a 401 from `/api/github/status` — the designed answer
  for an anonymous caller — threw away the scenarios that had already arrived.
- The smoke suite asserted that the API documentation is exposed. `/openapi` and
  `/scalar` are served only in Development and Testing, so the suite demanded the
  opposite of the property the application holds and would have failed against
  every correct production deployment.

### Documentation

- Three invariants are now asserted rather than described: every severity is
  produced by some rule, every rule declares a severity the scale defines, and
  rule identifiers are unique. `WorkflowSeverity` had documented the first in its
  own summary for as long as it had been false.
- `docs/scripts.md` covers `provision-azure.ps1`, and the engineering log reaches
  eighteen entries and a sixth pattern: a fix can take away the signal something
  else was relying on — one of these defects was created by the fix for the
  previous one, within the hour.

## 1.3.0 — 2026-08-05

### Added

- `scripts/provision-azure.ps1` creates the free-tier Azure resources and wires
  GitHub OIDC federation. Nothing is typed or pasted: the OpenAI key and the App
  private key are read from the user secrets already on the machine, the PEM is
  base64-encoded in memory so the multi-line form survives an application
  setting, and `Security:ApiKey` is generated. Nobody sees that key, which also
  closes a detection gap — a bare random string has no shape a secret scanner
  could match if it ever reached a file.
- The provisioning script sets the security posture explicitly and then reads it
  back, failing if any assertion did not take. Current App Service defaults
  already produce all of it; defaults are not guarantees, and nothing would have
  noticed a change. Disabling basic authentication on the SCM and FTP endpoints
  is what makes OIDC the only thing that *can* deploy.
- A deploy workflow for both halves, each gated on the same `classify-changes`
  outputs the build uses, so a documentation commit deploys nothing. It refuses
  to ship an artifact containing working-tree directories.
- A keep-warm workflow, standing in for the Always On that the free tier does not
  have. It costs about one CPU-second a day against a 60 CPU-minute allowance and
  needs no secret, because the health endpoint is exempt from authentication.
- `RepositoryWorkflowsTests` runs this project's rules against this project's own
  workflows. Nothing had ever done so; it found seven real GHA006 findings and
  two rules reporting a workflow for being correct.
- The GitHub App private key can be supplied as configuration, as PEM text or
  base64-encoded PEM. Reading it only from a filesystem path is what prevented
  this application being deployed: App Service settings and Key Vault references
  deliver values, not files. `GitHub:PrivateKeyPath` remains for local use, and
  configuration wins when both are present so a stale file on a host cannot serve
  a deployment.
- Documented what the publish artifact contains, and that the deployment must be
  that artifact rather than the working tree. Deploying the repository would push
  `node_modules`, tests and history into the site directory; the artifact is
  roughly 8 MB across 29 files and carries no credentials. The API serves no
  static content, so the client cannot collide with it.
- Added `docs/deployment/azure.md`, covering App Service and Static Web Apps,
  Key Vault references including a vault in another resource group, OIDC for the
  deployment identity, and what a degraded integration looks like.

### Changed

- The client resolves the API through `VITE_API_BASE_URL`, empty locally. It
  previously called relative `/api` paths and relied on the Vite dev proxy, which
  meant every call would have 404'd once deployed — Static Web Apps cannot proxy
  to an external backend on the Free tier.
- Removed the duplicate `DevSecOpsSentinel.sln`. It listed the same eight
  projects as the `.slnx` and made a bare `dotnet restore` ambiguous, which is
  what stopped the first real deployment. `.slnx` is the format for .NET 10.
- Readiness answers whether the instance can serve requests, rather than failing
  when an optional integration is misconfigured. Deterministic analysis depends
  on nothing external, so reporting the whole application as unready over GitHub
  or OpenAI would take a healthy instance out of rotation for a feature most
  requests never touch. Integration state is reported in the response body and on
  the status endpoints instead.
- The client now says **why** the model was not used. It previously showed
  "Deterministic fallback" with no way to distinguish a missing key from a
  timeout from a response that failed validation, even though the reason was
  already on the wire.
- The application warns at startup when `AllowedHosts` or
  `Security:AllowedOrigins` still name localhost outside Development. Host
  filtering rejects every request with a 400 that explains nothing, and blocked
  CORS looks like a broken API rather than a setting. It warns rather than
  refusing to start, because a wrong host is fixed by editing one setting whereas
  an application that will not start has to be diagnosed through deployment logs.

### Fixed

- GHA006 across all four existing workflows: none set `persist-credentials`, so
  every job left the token in `.git/config` for anything later in the job to
  read.
- GHA009 could not tell `permissions: {}` from no permissions block at all,
  because both leave zero entries. The first is the strongest statement a
  workflow can make; the rule called it an omission and recommended `read-all`,
  which would have widened a grant that was already empty.
- GHA002 reported `id-token: write`. That grants no access to the repository —
  only the right to request an OIDC token — and it is what removes a stored
  publish credential from a deploy pipeline. The offered remediation settled it:
  there is no useful `id-token: read`, so the advice could not be taken without
  breaking the workflow.
- The federated-identity subject is read from GitHub rather than assembled.
  GitHub issues subjects carrying immutable numeric ids, and a credential built
  from owner and repository names never matches. The credential check also
  compared names rather than subjects, so a credential with a stale subject
  looked correct and re-running could not repair it.
- The deploy workflow waits for the app before running the smoke suite. App
  Service recycles after a deployment, and the suite asserted against an app that
  had not finished starting — failing a deployment that had worked.
- The private key is read once rather than on every installation-token refresh.
- The private key tests generate a key at run time rather than embedding one. A
  literal PEM in source is indistinguishable from a leaked key to a scanner, and
  the pre-commit hook correctly refused the first attempt. Generating it makes
  the test stronger as well, because the value is a real key and the import is
  exercised rather than a shape being matched.

### Documentation

- Recorded three defects that surfaced only when the project first ran somewhere
  real: an Actions allowlist that blocks a third-party action before any job
  starts and writes no log, GitHub's immutable OIDC subject format, and the
  post-deploy restart race. None is visible in the repository tree, so no linter,
  test or review of the diff could have found them.

## 1.2.3 — 2026-08-04

### Documentation

- Recorded that screenshots are regenerated when the interface changes, not when
  the version changes. The header renders the running version, so a release
  always leaves the images showing the previous one; recapturing for a patch that
  changed nothing visible is churn without information.

- Restructured the documentation. The root now holds only what GitHub surfaces
  specially — README, SECURITY, CONTRIBUTING, CODE_OF_CONDUCT, LICENSE — plus the
  changelog. Everything else moved under `docs/`, indexed by `docs/README.md`.
  The README had grown to 224 lines doing five jobs at once; it is now a summary
  that routes onward.
- Added `docs/engineering-log.md`, recording eleven defects found after the
  project was first considered complete: what was wrong, how each surfaced, what
  changed, and what prevents recurrence. Four patterns run through them, the
  sharpest being that a test which cannot fail proves nothing.
- Added `docs/scripts.md`, explaining every script and why it exists, including
  the failures that bought several of their details.
- Added `docs/getting-started.md` and `docs/configuration.md`, covering setup,
  every setting, Mock and Live behaviour, and where credentials belong in each
  environment.
- Added `docs/architecture/program-flow.md` and `docs/architecture/rules.md`,
  describing what happens on a request across both halves, and all eleven rules.
- Added `docs/ci-cd.md`, describing the four workflows, path-selective builds and
  the release sequence.
- Rewrote `docs/architecture/README.md`, which still described four rules and
  predated the move to structural YAML parsing.
- Widened the required-file list in `verify-release-package.ps1` to match the new
  layout, so a document being moved or deleted fails the release rather than
  going unnoticed.

### Fixed

- Sanitised request-supplied values before they reach a log entry. The request
  path is chosen by the caller, and a path containing a carriage return or line
  feed splits one entry into several, so a caller could fabricate entries that
  look as though the application emitted them. Control characters are now
  replaced rather than removed, so a request that attempted the injection is
  still visible as having done so, and an over-long value is truncated.
- Refused a scenario file name that resolves outside the scenario directory.
  `Path.Combine` silently discards the directory when a later argument is rooted
  or climbs out of it. The metadata ships with the application rather than
  arriving from a request, so this is defence in depth — but a bundled file is
  exactly the kind of input that stops being trusted once someone makes it
  configurable.
- Disposed the request message in `GitHubRepositoryReader`. The two other GitHub
  clients already did; this one was the exception.
- Rewrote the block scalar indicator check as three named predicates. It
  expressed a simple rule — an optional indentation digit and an optional
  chomping indicator, in either order — as one condition that could not be read.

### Testing

- Ran the API smoke suite in CI. It previously ran only from `run-all.ps1` on a
  developer machine, so a pull request could break one of its twenty-five checks
  and merge clean.
- Made `smoke-test-api.ps1` cross-platform. It assumed a Windows path separator,
  a window style that exists only on Windows, and `Win32_Process` for finding the
  child the launcher spawns.

### Security

- Added CodeQL code scanning for C# and TypeScript, on pull requests, on `main`,
  and weekly. The weekly sweep matters because a push-triggered scan never
  re-examines code against rules added to the CodeQL packs afterwards.
- Added dependency review on pull requests, refusing a change that introduces a
  dependency with a known high-severity vulnerability. This is distinct from the
  existing audits: those report on the dependency set as it stands, so a
  vulnerable package arrives on `main` first and is caught only when the audit
  next runs. Dependency review refuses the change itself.
- Both workflows pin every action to a commit SHA, which the repository's own
  GHA001 rule requires and which its Actions policy now enforces.
- Enabled private vulnerability reporting, so the reporting instruction in this
  policy names a mechanism rather than an intention.

## 1.2.2 — 2026-08-04

### Changed

- Replaced "Enterprise-ready security operations" in the application header with
  "GitHub Actions supply-chain analysis". The former was the only claim in the
  project the work did not support: a single-developer analyser with no
  deployment is not enterprise-ready, and the phrase invited a reader to
  discount everything around it. The replacement names the domain the rules
  actually cover — pinning, secrets, artifacts and runners are supply-chain
  concerns — and states nothing that has to be taken on trust.
- Split CI into separate API and frontend jobs, selected by which paths a change
  touches. A frontend-only commit no longer builds and tests the .NET solution,
  and an API-only commit no longer installs and builds the client. A change
  spanning both still runs both, in one pipeline, so a contract that crosses the
  boundary cannot be verified one half at a time.
- Added a terminal `gate` job that always runs and reports the outcome of the
  selective jobs. Branch protection cannot require a job that is sometimes
  skipped, because a skipped required check blocks a merge rather than passing
  it; requiring the gate keeps selective builds compatible with a protected
  branch.

## 1.2.1 — 2026-08-04

### Tooling

- Added `scripts/capture-screenshots.ps1`, which starts the API and the frontend,
  drives the application with Playwright, and regenerates the product
  screenshots. They had gone stale twice in a day — once when severity
  serialization was fixed and the risk label changed, once when the release
  version moved into the header — because they were captured by hand.
- Fixed `Start-Process npm` in `start-local.ps1`. npm on Windows is a batch shim
  rather than a Win32 image, so the call failed with "%1 is not a valid Win32
  application" and the frontend never started.

### Testing

- Covered the rejection paths the API advertises but nothing exercised: 413 for
  an oversized workflow, 429 when the request budget is exhausted, and 503 when
  the GitHub integration is unconfigured. A boundary case just under the size
  limit guards the other side of 413.
- Made `smoke-test-api.ps1` able to start and stop the API itself with
  `-StartApi`, and wired it into `run-all.ps1`. The suite previously required a
  server somebody remembered to start, so it protected nothing automatically.
  The gate forces OpenAI Mock and disables GitHub, so it never spends credits or
  reaches the network; the live integrations keep their own opt-in scripts.

### Fixed

- Made the request budget configurable at runtime. `WorkflowRequestLimitPerMinute`
  was read into a local while `Program.cs` executed, so configuration supplied
  later in host building never reached the limiter. The setting was documented as
  configurable but was fixed at whatever the base configuration said, and the
  rejection path could not be reached without firing the full production budget.

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
