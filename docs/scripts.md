# Scripts

Every script in the repository, what it does, and why it exists.

They are PowerShell because the project is developed on Windows, and `pwsh` is
present on the GitHub-hosted Linux runners, so the same script runs in both
places. Where a script had to work on both, the platform-specific parts are
conditional rather than assumed.

---

## Deployment

### `provision-azure.ps1`

Creates the free-tier Azure resources and wires GitHub OIDC federation. Safe to
re-run: every resource is created only if absent, and `-WhatIf` prints the plan
without creating anything.

**Everything is discovered rather than supplied.** Subscription and tenant come
from `az login`, the repository from the git remote, and the application's own
configuration from the .NET user secrets already on the machine. That is why it
takes almost no parameters — the values exist, and asking for them again invites
a typo.

**No secret is typed, pasted, echoed or written to disk.** The OpenAI key and the
App private key are read from user secrets; the PEM is base64-encoded in memory,
so the multi-line form survives an application setting and you never handle the
encoded string. `Security:ApiKey` is generated here and sent straight to the app
and to a GitHub secret — nobody ever sees it, which also closes a real detection
gap, because a bare random string has no shape a secret scanner could match if it
reached a file.

Settings travel to Azure in a temporary file in the OS temp directory, deleted
immediately, rather than as `az --settings K=V` arguments — which would put every
value in the machine's process list for the duration of the call.

It **sets the security posture explicitly and then reads it back**, failing if
any assertion did not take: HTTPS-only, TLS 1.2, FTPS disabled, and basic
publishing credentials disabled on both the SCM and FTP endpoints. Current App
Service defaults already produce all of it. Defaults are not guarantees, they
change, and nothing here would have noticed. Disabling basic auth is also what
makes a publish profile unusable, so OIDC is not a convention the deploy workflow
follows but the only thing that can work.

Two details bought by failure:

- The **federated-identity subject is read from GitHub**, not assembled. GitHub
  issues subjects carrying immutable numeric ids, and a credential built from
  owner and repository names never matches — reported as `AADSTS700213`, which
  names the symptom rather than the cause.
- The credential check compares the **subject**, not the credential's name. A
  credential with a stale subject looks perfectly present, so matching on name
  meant re-running could never repair one.

```powershell
./scripts/provision-azure.ps1 -WhatIf     # print the plan, create nothing
./scripts/provision-azure.ps1             # Public mode: the scanner is open
./scripts/provision-azure.ps1 -Private    # Required mode: everything needs the key
./scripts/provision-azure.ps1 -Mode Live  # deploy the OpenAI key as well
```

See [credentials.md](credentials.md) for what each value is and where it ends up.

---

## Gates

These decide whether the repository is in a releasable state. `run-all.ps1` runs
all of them; CI runs most of them individually.

### `run-all.ps1`

The complete local gate, in the order a release depends on. Verifies central
package management, repairs the frontend toolchain, restores, builds and tests
the .NET solution, audits both dependency sets, builds the frontend, verifies the
release package and repository protection, and finally runs the API smoke suite
against a server it starts itself.

Run this before tagging. If it passes, CI will too.

### `check-repository.ps1`

Refuses to package or publish a repository that tracks something it should not:
private keys, certificates, `.env` files, `secrets.json`, build output.

It **fails if it is not inside a git repository**, and **fails if no tracked
files are found**. Both guards exist because it once passed on a directory with
no `.git` in it — `git ls-files` produced nothing, the loop found no violations,
and it reported success. A check that cannot fail is not a check.

### `verify-release-package.ps1`

Holds the release consistent with itself:

- Required documentation and screenshots exist.
- `Directory.Build.props` is the single source of the version, and
  `package.json` and `package-lock.json` agree with it.
- When run on a tag, the tag matches that version.
- No forbidden file extension is tracked.

The version check reads tracked files only, via `git ls-files`, after an earlier
version recursed the whole working tree and would have failed the build on a test
certificate shipped inside `node_modules`.

### `verify-central-packages.ps1`

Confirms Central Package Management is switched on, that no nested
`Directory.Packages.props` shadows the root one, and — by asking MSBuild rather
than reading the file — that the root file is actually being imported. A package
version pinned in a file nobody imports is not pinned.

### `audit-packages.ps1`

Restores and runs `dotnet list package --vulnerable --include-transitive`,
failing the build if any severity is reported. Transitive packages are included
because that is where vulnerabilities usually arrive.

---

## Smoke tests

These drive a running server over real HTTP. They exist because the integration
tests boot the application through `WebApplicationFactory` with test
configuration, so nothing in them proves the application starts normally.

### `smoke-test-api.ps1`

Twenty-five checks against a running API, eight of which are failure conditions:
403 for a repository outside the allowlist, 404, 400 for an empty body, 400 for
malformed JSON, 422 for unparseable YAML, 415 for the wrong content type, 413 for
an oversized workflow, and 503 when GitHub is unconfigured.

With `-StartApi` it starts and stops the API itself, which is how it runs in the
local gate and in CI. That run forces Mock mode and disables GitHub, so a gate
never spends credit or reaches the network.

Five details in it were bought with failures:

- The API is started **windowless with output redirected**. A visible console
  window can be closed mid-run, which kills the server and fails the gate for a
  reason unconnected to the code.
- Teardown stops the **child** process as well as the launcher, because
  `dotnet run` launches the application as a child and stopping only the launcher
  leaves the port held.
- Paths, window style and process lookup are conditional on the platform, so the
  script runs on the Linux CI runner as well as on Windows.
- The expectation for `/openapi` and `/scalar` is **derived from the reported
  mode**, not fixed. Those endpoints are served only in Development and Testing,
  so the suite previously demanded 200 — true locally and false on every correct
  deployment. It now asserts they are *unreachable* wherever a key is in use,
  which is worth confirming.
- The key guard asks whether the deployment **uses** a key, not whether one is
  required to enter. `Public` mode reports `required: false`, so asking the
  narrower question let a run proceed without a key and then fail on the GitHub
  checks, which still need one.

The deploy workflow waits for `/api/health/live` before invoking this, because
App Service recycles after a deployment and the suite asserts rather than waits.
Without that it read 404 from an app that was still starting and failed a
deployment that had worked.

### `smoke-test-github-live.ps1`

Proves the read-only GitHub App path end to end against the sandbox repository.
Opt-in behind `-EnableLiveGitHub`, because it needs real credentials.

### `smoke-test-openai-live.ps1`

Proves the live OpenAI path returns a valid structured explanation. Opt-in behind
`-EnableLiveOpenAi`.

Both are separate from the gate on purpose. The gate must be reproducible and
must not depend on a third party being reachable; these prove the integrations
work when you want to know.

---

## Local development

### `setup-local.ps1`

First run after cloning. Checks for the .NET SDK and npm, verifies central
package management, restores the solution, and installs the frontend toolchain.

### `start-local.ps1`

Starts the API and the frontend dev server together and prints both URLs.

### `build-all.ps1` and `test-all.ps1`

Build or test both halves in one command, without the full gate. `run-all.ps1` is
what you run before a release; these are for the loop.

### `ensure-frontend-toolchain.ps1`

Reconciles `node_modules` with `package.json`, then verifies the specific
binaries the build needs are actually present. If any are missing it removes
`node_modules` and reinstalls once.

This exists because a partially extracted install fails later, in a place that
does not mention installation — a type error in a file nobody touched. Repairing
it up front is cheaper than diagnosing it downstream.

---

## Security

### `run-gitleaks.ps1`

Runs Gitleaks over the working tree, or over the whole history with
`-AllHistory`. The repository-managed `.gitleaks.toml` is used in both cases so
local and CI results agree.

### `install-gitleaks-precommit.ps1`

Installs the Gitleaks pre-commit hook.

The hook is **convenience, not enforcement**. It is per-clone, it can be bypassed
with `git commit --no-verify`, and it requires Python because the project uses the
standard `pre-commit` framework. The CI workflow is the boundary that actually
holds, and GitHub push protection sits behind that.

---

## Screenshots

### `capture-screenshots.ps1`

Starts the API and the frontend, drives the application with Playwright, captures
the three product screenshots, and stops both.

Unlike the gate this runs the **real** integrations, because two of the images are
named for live AI and a Mock capture would show a canned explanation while
claiming otherwise.

It exists because the images went stale twice in a single day — once when
severity serialisation was fixed and the risk label changed, once when the
release version moved into the header — and hand-captured images do not track the
application.

Two details, again bought with failures:

- `Start-Process npm` does not work on Windows. npm is a batch shim rather than a
  Win32 image, so it fails with *"%1 is not a valid Win32 application"*.
  `start-local.ps1` had the same defect and would never have started the
  frontend.
- Node cannot spawn an executable whose path contains characters such as `#` or
  `!`. Playwright's browser cache defaults to a location under the user profile,
  so on a profile containing those characters the launch fails with `ENOENT` on a
  file that is plainly present. The script relocates the cache.

---

## Frontend helpers

Under `src/devsecops-sentinel-web/scripts/`, invoked through npm scripts.

### `verify-toolchain.mjs`

Asserts the TypeScript, Vite and Vitest binaries exist before a build or test run,
and prints the command to repair the install if they do not. It turns a confusing
downstream failure into a clear one.

### `run-tests.mjs`

Runs Vitest and then asserts the run actually contained tests. A Vitest
invocation that matches no files exits zero, so without this a configuration
mistake that stopped collecting tests would read as a passing gate.

### `capture-screenshots.mjs`

The Playwright script driven by `capture-screenshots.ps1`. Addresses controls by
element id rather than label, because "Workflow file" labels a text input in
Simulation mode and a select in GitHub mode, and waits for the workflow content
to load rather than for the control that merely precedes it.
