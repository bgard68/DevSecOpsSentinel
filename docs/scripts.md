# Scripts

Every script in the repository, what it does, and why it exists.

They are PowerShell because the project is developed on Windows, and `pwsh` is
present on the GitHub-hosted Linux runners, so the same script runs in both
places. Where a script had to work on both, the platform-specific parts are
conditional rather than assumed.

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

Three details in it were bought with failures:

- The API is started **windowless with output redirected**. A visible console
  window can be closed mid-run, which kills the server and fails the gate for a
  reason unconnected to the code.
- Teardown stops the **child** process as well as the launcher, because
  `dotnet run` launches the application as a child and stopping only the launcher
  leaves the port held.
- Paths, window style and process lookup are conditional on the platform, so the
  script runs on the Linux CI runner as well as on Windows.

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
