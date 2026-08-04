# Getting started

The application runs with no credentials at all. GitHub integration is off by
default, OpenAI defaults to Mock, and the bundled scenarios need neither. Set up
the integrations only when you want to see them work.

---

## Prerequisites

| | |
| --- | --- |
| .NET SDK | 10.0.100 or later (`global.json` pins the feature band) |
| Node.js | 22 or later |
| PowerShell | 7+ (`pwsh`) |
| Git | any recent version |

---

## Run it

```powershell
git clone https://github.com/bgard68/DevSecOpsSentinel.git
cd DevSecOpsSentinel

.\scripts\setup-local.ps1
.\scripts\start-local.ps1
```

Then open:

- Application — <http://localhost:5173>
- API — <https://localhost:7001>
- API reference — <https://localhost:7001/scalar>

Pick a scenario from the **Simulation** tab and analyse it. That path uses no
network and no credentials.

---

## Secrets

**Nothing sensitive belongs in the repository.** `appsettings.json` contains no
credentials and is not where they go. `.gitignore` excludes `.env`, `*.pem`,
`secrets.json` and similar, Gitleaks scans every commit and the full history
weekly, and GitHub push protection blocks a secret at push time.

Where credentials actually live, by environment:

| Environment | Mechanism |
| --- | --- |
| Local development | .NET User Secrets — stored in your user profile, outside the repository |
| Azure App Service | Application settings, or Key Vault references |
| CI | Nothing. The gate forces Mock mode and disables GitHub |

User Secrets are keyed to the `UserSecretsId` in the API project file and stored
in your profile, so they are never in the working tree and cannot be committed by
accident.

```powershell
cd src\DevSecOpsSentinel.Api
dotnet user-secrets list          # shows keys and values for this project
```

Two rules that matter more than the mechanism:

- **Never paste a real value into a document, an issue, a commit message, or a
  screenshot.** Use a placeholder such as `<APP_ID>`.
- **If a credential is ever committed, rotate it first, then rewrite history.**
  Deleting the file in a later commit does not remove it. See
  [`SECURITY.md`](../SECURITY.md).

---

## Optional: OpenAI

Not required. Mock mode returns a canned explanation, consumes no credit, and
exercises the same code path through the application.

See [integrations/openai.md](integrations/openai.md) for the full setup,
including what Live mode changes and what it does not.

---

## Optional: GitHub App

Not required. Without it the **GitHub Sandbox** tab reports the integration as
disabled and everything else works.

The App is read-only and constrained twice: by the permissions granted at
installation, and by an allowlist in configuration that the application checks
independently. See [integrations/github-app.md](integrations/github-app.md).

---

## Verify your setup

```powershell
.\scripts\run-all.ps1
```

Builds and tests both halves, audits both dependency sets, verifies the release
package and repository protection, and runs the API smoke suite against a server
it starts itself. If this passes, CI will pass too.

For what each script does and why it exists, see [scripts.md](scripts.md).

---

## Where to go next

| | |
| --- | --- |
| How it fits together | [architecture/README.md](architecture/README.md) |
| What happens on a request | [architecture/program-flow.md](architecture/program-flow.md) |
| The detection rules | [architecture/rules.md](architecture/rules.md) |
| Settings and modes | [configuration.md](configuration.md) |
| The pipeline | [ci-cd.md](ci-cd.md) |
| Defects found and fixed | [engineering-log.md](engineering-log.md) |
