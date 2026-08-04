# DevSecOps Sentinel

[![CI](https://github.com/bgard68/DevSecOpsSentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/bgard68/DevSecOpsSentinel/actions/workflows/ci.yml)
[![CodeQL](https://github.com/bgard68/DevSecOpsSentinel/actions/workflows/codeql.yml/badge.svg)](https://github.com/bgard68/DevSecOpsSentinel/actions/workflows/codeql.yml)
[![Gitleaks](https://github.com/bgard68/DevSecOpsSentinel/actions/workflows/gitleaks.yml/badge.svg)](https://github.com/bgard68/DevSecOpsSentinel/actions/workflows/gitleaks.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A GitHub Actions supply-chain analyser. Deterministic rules find the problems;
an optional AI layer explains them and provably cannot invent them.

Built with .NET 10, React and TypeScript, a read-only GitHub App, and the OpenAI
API.

![Connected dashboard](docs/assets/screenshots/01-connected-dashboard.png)

---

## The idea

Most security tools that use a language model let the model decide what is
vulnerable. This one does the opposite, and enforces it:

1. **Deterministic rules identify findings and severity.** They are the only
   source of truth.
2. **The model's response is schema-constrained**, and the rule identifiers it
   returns must match the deterministic set *exactly*. A reply that invents a
   finding, drops one, or renames a rule is rejected and replaced with a
   deterministic fallback.
3. **Proposed fixes are re-analysed** before being shown as valid. A patch that
   introduces a finding is refused.
4. **GitHub access is read-only**, restricted by the App's own permissions and
   again by an allowlist the application checks independently.

The interesting part is not the prose the model returns — the rules already carry
a description and a recommendation, and the fallback produces comparable text
with no model call. It is the enforcement around it. That constraint is what
makes live AI defensible in a security tool at all.

---

## What it detects

Eleven rules covering pinning, permissions, timeouts, privileged triggers,
script injection, credential persistence, untrusted checkout, secret
forwarding, self-hosted runners and artifact poisoning.

| | | |
| --- | --- | --- |
| GHA001 unpinned action | GHA005 script injection | GHA009 undeclared permissions |
| GHA002 excessive permissions | GHA006 persisted credentials | GHA010 self-hosted runner |
| GHA003 missing timeout | GHA007 untrusted checkout | GHA011 artifact poisoning |
| GHA004 `pull_request_target` | GHA008 inherited secrets | |

Full descriptions in [docs/architecture/rules.md](docs/architecture/rules.md).

---

## Try it

```powershell
git clone https://github.com/bgard68/DevSecOpsSentinel.git
cd DevSecOpsSentinel
.\scripts\setup-local.ps1
.\scripts\start-local.ps1
```

Open <http://localhost:5173>, pick a scenario, analyse it. **No credentials
required** — GitHub is off by default and OpenAI defaults to Mock.

Full setup, including the optional integrations, in
[docs/getting-started.md](docs/getting-started.md).

---

## Seeing the constraint work

Select **Script injection**, tick *Include AI explanation*, analyse.

![Live AI explaining a critical finding](docs/assets/screenshots/02-live-ai-vulnerable-workflow.png)

One Critical finding. The model explains it and supplies the `env:` binding that
fixes it — a remediation the deterministic engine deliberately will not apply
itself.

Then select the safe workflow.

![Safe workflow returning nothing](docs/assets/screenshots/03-live-ai-safe-workflow.png)

Zero findings, and the model declines to invent any. That is the claim the whole
design exists to support.

---

## Documentation

| | |
| --- | --- |
| [Getting started](docs/getting-started.md) | Prerequisites, running it, secrets |
| [Architecture](docs/architecture/README.md) | Layers and trust boundaries |
| [Program flow](docs/architecture/program-flow.md) | What happens on a request |
| [Detection rules](docs/architecture/rules.md) | All eleven, and how to add one |
| [Engineering log](docs/engineering-log.md) | Defects found after "complete", and what prevents them now |
| [CI/CD](docs/ci-cd.md) | Four workflows, path-selective builds |
| [Scripts](docs/scripts.md) | Every script and why it exists |
| [Full index](docs/README.md) | Everything else |

---

## How it is built

- **.NET 10** minimal APIs, layered so dependencies point inward
- **React 19 + TypeScript 5.9**, Vite
- **YamlDotNet** for document structure, with a line model retained for content
  inside block scalars and for line-indexed patching
- **117 .NET tests, 4 frontend tests**, and a 25-check smoke suite that drives a
  real server over HTTP
- **CodeQL, Gitleaks, dependency review, Dependabot**, secret scanning with push
  protection, and SHA-pinned actions enforced by policy
- Path-selective CI: a frontend change does not build the .NET solution, and a
  change spanning both still builds both, in one pipeline

The project passes its own analyser. Its workflows are SHA-pinned,
least-privilege, timeout-bounded, and free of the injection pattern GHA005
reports.

---

## Deliberate exclusions

It creates no branches, commits, pull requests or merges. It does not scan on a
schedule. It stores no history. Each would need a separate threat model, stronger
authentication, and new GitHub permissions — so each is absent rather than
half-built.

---

## Something worth reading

[docs/engineering-log.md](docs/engineering-log.md) records eleven defects found
*after* this project was first considered finished — including findings that
never rendered in the interface, an exported patch `git apply` refused, a SARIF
document no consumer would accept, and a protection gate that passed because it
had nothing to check.

Each entry covers how it surfaced and what now prevents it. The defects are more
instructive than the features.

---

## License

MIT. See [LICENSE](LICENSE).
