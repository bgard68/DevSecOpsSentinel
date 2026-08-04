# Documentation

## Start here

| | |
| --- | --- |
| [getting-started.md](getting-started.md) | Prerequisites, running it, where secrets live |
| [configuration.md](configuration.md) | Every setting, Mock and Live, deployment checklist |

## How it works

| | |
| --- | --- |
| [architecture/README.md](architecture/README.md) | Layers, trust boundaries, deliberate exclusions |
| [architecture/program-flow.md](architecture/program-flow.md) | What happens on a request, backend and frontend |
| [architecture/rules.md](architecture/rules.md) | The eleven detection rules, and how to add one |

## Engineering

| | |
| --- | --- |
| [engineering-log.md](engineering-log.md) | Defects found after "complete": how each surfaced, what prevents recurrence |
| [ci-cd.md](ci-cd.md) | The four workflows, path-selective builds, releasing |
| [scripts.md](scripts.md) | Every script, what it does, why it exists |
| [operations.md](operations.md) | Running it, health endpoints, rotation |

## Integrations

| | |
| --- | --- |
| [integrations/openai.md](integrations/openai.md) | Optional. Mock is the default |
| [integrations/github-app.md](integrations/github-app.md) | Optional, read-only, allowlisted |

## Security

| | |
| --- | --- |
| [../SECURITY.md](../SECURITY.md) | Policy, trust boundaries, reporting |
| [security/repository-security-policy.md](security/repository-security-policy.md) | Repository governance and residual risks |
| [security/gitleaks.md](security/gitleaks.md) | Secret scanning, and why the hook is not the boundary |
| [security/ai-security-boundaries.md](security/ai-security-boundaries.md) | What the model may and may not do |
| [security/ai-cost-controls.md](security/ai-cost-controls.md) | Explicit opt-in, Mock by default |
| [security/secure-remediation.md](security/secure-remediation.md) | Why patches are previews |
| [security/security-model.md](security/security-model.md) | Threat model summary |

## Decisions

[`adr/`](adr/) records the choices that shaped the design, including why
deterministic rules are authoritative and why the AI is not a source of truth.

## Demonstrating it

| | |
| --- | --- |
| [demo-guide.md](demo-guide.md) | A five-minute walkthrough |
| [portfolio-walkthrough.md](portfolio-walkthrough.md) | Design decisions and discussion points |
| [release-checklist.md](release-checklist.md) | What is verified before a release |

## History

[`history/`](history/) holds point-in-time records: phase acceptance notes,
per-change implementation notes, and the 1.0.0 release notes. Kept because they
show how the project got here, not because they describe how it works now.
