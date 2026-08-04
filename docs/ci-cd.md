# Continuous integration

Four workflows. Every action is pinned to a commit SHA, which the repository's
own GHA001 rule requires and which GitHub enforces through
`sha_pinning_required`.

| Workflow | Runs on |
| --- | --- |
| **CI** | push to `main`, `v*` tags, pull requests |
| **CodeQL** | push to `main`, pull requests, weekly |
| **Dependency Review** | pull requests |
| **Gitleaks** | push to `main`, pull requests, weekly, manual |

---

## CI

Five jobs. Two of them run only when the change touches their half of the
repository.

```
classify-changes ─┐
                  ├──▶ api        (if api == true)      ──┐
repository-       ┤                                       ├──▶ gate
validation ───────┘──▶ frontend   (if frontend == true) ──┘
(always)                                                    (always)
```

### `classify-changes`

Diffs the change and emits two booleans. Every changed path falls into one
bucket:

| Path | Selects |
| --- | --- |
| `src/devsecops-sentinel-web/**` | frontend |
| `src/DevSecOpsSentinel.*`, `tests/**`, `*.slnx`, `Directory.*.props`, `global.json` | api |
| `*.md`, `docs/**`, `LICENSE`, `.gitignore`, `.gitattributes` | neither |
| anything else | **both** |

Unrecognised paths select both deliberately. A new file type should not silently
skip a build.

Two overrides: a **release tag builds everything**, because a release is a claim
about the repository rather than about what last changed; and an unresolvable
base commit, which a force-push can produce, also builds everything rather than
failing on a diff it cannot compute.

Workflow expressions reach the script through `env:` rather than being
interpolated into the shell body. The values are GitHub-supplied commit SHAs and
were never exploitable, but direct `${{ }}` expansion inside `run:` is the
injection pattern this project's own rules exist to discourage.

### `repository-validation`

Always runs, on every change including documentation-only ones. Runs
`check-repository.ps1` and `verify-release-package.ps1`, so secret hygiene and
version consistency are checked even when nothing is built.

This is why it is not gated: the changes most likely to break the required-files
check are documentation changes.

### `api` and `frontend`

`api` restores, builds, tests, audits NuGet packages, and then runs the smoke
suite against a server it starts itself.

`frontend` installs from the lockfile, verifies the toolchain, tests, audits and
builds.

### `gate`

Always runs, reflects the other four, and treats `skipped` as a pass.

It exists because **branch protection cannot require a job that sometimes
skips** — a skipped required check blocks a merge rather than passing it.
Requiring `gate` instead keeps selective builds compatible with a protected
branch. It is one of the four required checks on `main`.

### Why the smoke suite is in the pipeline

Most of what it asserts is also asserted by the integration tests. What is not
duplicated is that the application starts.

The integration tests boot it through `WebApplicationFactory` with the
environment set to Testing and configuration supplied in memory. Nothing in them
exercises `appsettings.json`, `ValidateOnStart`, the scenario files being copied
to the output directory, or HTTPS redirection. Every one of them can pass on an
application that will not run.

CI creates an HTTPS development certificate first, because Kestrel binds over
TLS. Trust is not needed — the client skips validation — and keeping HTTPS means
the suite exercises the transport the application actually serves.

---

## CodeQL

C# and TypeScript, with the `security-and-quality` queries.

Uses `build-mode: none`, analysing source directly rather than observing a
compilation. That avoids reproducing both builds a second time and removes a
class of failure where the scan breaks because the build did, not because the
code is wrong.

The **weekly schedule** is the point of the cron. A push-triggered scan never
re-examines a commit against rules added to the CodeQL packs afterwards.

Its first run found a real defect — request paths reaching loggers unsanitised,
allowing forged log entries. See
[engineering-log.md](engineering-log.md#10-log-entries-could-be-forged-by-a-request).

---

## Dependency Review

Refuses a pull request introducing a dependency with a known high-severity
vulnerability.

**This is not what the audits already do.** `npm audit` and `dotnet list package
--vulnerable` report on the dependency set as it stands, so a vulnerable package
added by a pull request reaches `main` first and is caught only when the audit
next runs. Dependency review compares the pull request against its base and
refuses the change itself.

---

## Gitleaks

Scans the working tree on every push and pull request, and the **full history**
weekly. The repository-managed `.gitleaks.toml` is used everywhere so local and
CI results agree.

It is one layer of three. GitHub push protection blocks a secret at push time; a
pre-commit hook gives earlier feedback but is per-clone and bypassable; this
workflow is the boundary that holds.

`docs/assets/screenshots/` is allowlisted, because a scanner cannot read a PNG.
That makes the manual screenshot check on the release checklist the only control
covering those files, which is why it stays on the list.

---

## Branch protection

`main` requires four checks: **CI Gate**, **Secret Scan**, **CodeQL** and
**Review Dependency Changes**. Zero approvals, administrators included, no
force-push, no deletion.

Zero approvals is deliberate for a single-maintainer repository: the value is in
the checks running and history staying linear, not in approving one's own pull
requests.

---

## Releasing

1. `.\scripts\run-all.ps1` — the full local gate
2. Bump `Directory.Build.props`, `package.json`, `package-lock.json`
3. `.\scripts\capture-screenshots.ps1` if anything visible changed
4. Date the changelog section
5. Pull request, merge
6. Tag `vX.Y.Z` — the tag build re-runs release verification **against the tag**
7. Publish the release

Step 6 matters. `verify-release-package.ps1` compares the tag to the version in
the tree, so a tag cut before the version bump fails the build. That check exists
because `v1.0.1` was once tagged on a commit whose version markers read `1.0.0`.
