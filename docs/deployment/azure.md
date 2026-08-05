# Deploying to Azure

The application is two pieces: an ASP.NET Core API and a static client. They
deploy separately.

Azure Static Web Apps is not a fit for the whole thing — it hosts a static
frontend plus Azure Functions, and this is a long-running ASP.NET Core service.
The workable shapes are:

| Component | Service |
| --- | --- |
| API | App Service, or Container Apps |
| Client | Static Web Apps, or served as static files by the API |

---

## Before anything else

**Set a spending limit on the OpenAI account.** Application rate limiting bounds
how fast a caller can spend; only the account limit bounds how much.

**Decide Mock or Live.** For a public deployment, Mock is the better default: a
visitor arriving during a quota failure sees a working application rather than a
broken one. Live demonstrates the integration, including the constraint system
that Mock never exercises. See
[../configuration.md](../configuration.md#mock-and-live).

---

## Required settings

`Security:Mode` **must** be `Required` or `Public` outside Development and
Testing — the application refuses to start on `Disabled`. That is deliberate: the
failure mode of a missing configuration section is refusal rather than an open
API.

**For a public deployment, `Public` is the mode you want.** Deterministic
analysis opens to anyone; the key still guards GitHub and Live explanations. A
demonstration nobody can run demonstrates nothing, and rule evaluation has
nothing to protect — no outbound call, no credential, no state. An anonymous
caller gets Mock explanations whatever the deployment is configured for, so they
cannot spend anything. See [../configuration.md](../configuration.md#security).

| Setting | Value |
| --- | --- |
| `ASPNETCORE_ENVIRONMENT` | `Production` |
| `Security__Mode` | `Public`, or `Required` to keep the deployment private |
| `Security__ApiKey` | 32 characters or more |
| `Security__AllowedOrigins__0` | the client's origin |
| `AllowedHosts` | the deployed host name |

`AllowedHosts` ships as `localhost;127.0.0.1`. Left at that, host filtering
rejects every request with a 400 before it reaches a route, and nothing in the
response says why — it reads like a routing or proxy fault. The application logs
a warning at startup when it detects this, but the warning is a safety net, not
a substitute for setting it.

---

## Secrets

Never in `appsettings.json`, never in the client bundle, never in a tracked file.
Two options, both fine:

**App Service application settings.** Encrypted at rest, sufficient for this.

**Key Vault references.** Adds rotation and audit, at the cost of one more
dependency.

[credentials.md](../credentials.md) is the full reference — every value, how to
generate it, and how to rotate it. What follows is the deployment-specific part.

### What is a secret, and what is only configuration

Three values are secrets. Everything else is ordinary configuration and can sit
in plain application settings.

| Secret | Purpose |
| --- | --- |
| `Security__ApiKey` | Gates the whole API. Without it a deployment refuses to start |
| `GitHub__PrivateKey` | Signs the GitHub App JWT |
| `OpenAI__ApiKey` | Live AI explanations only |

```
Security__ApiKey   = @Microsoft.KeyVault(SecretUri=https://<vault>.vault.azure.net/secrets/sentinel-api-key/)
GitHub__PrivateKey = @Microsoft.KeyVault(SecretUri=https://<vault>.vault.azure.net/secrets/github-app-private-key/)
OpenAI__ApiKey     = @Microsoft.KeyVault(SecretUri=https://<vault>.vault.azure.net/secrets/openai-api-key/)
```

Omitting the version means rotation takes effect without a redeploy.

| Not a secret | Notes |
| --- | --- |
| `GitHub__AppId`, `GitHub__InstallationId` | Identifiers, not credentials. They authorise nothing on their own |
| `GitHub__AllowedRepositories__0` | The allowlist. Visible by design |
| `GitHub__Enabled`, `OpenAI__Mode`, `Security__Mode` | Switches |
| `AllowedHosts`, `Security__AllowedOrigins__0` | Host and origin |

`OpenAI__ApiKey` and `Security__ApiKey` need no special handling — they are
single-line configuration values, so a reference resolves straight into them.
Only the private key needed work, because it was the one credential read from a
file rather than from configuration.

### The private key

`GitHub:PrivateKey` takes the key material itself, not a path. A path works on a
developer machine and cannot work here, because App Service settings and Key
Vault references deliver values rather than files. `GitHub:PrivateKeyPath`
remains for local use, and configuration wins when both are present so a stale
file on the host cannot serve a deployment.

**Store the private key base64-encoded.** A PEM is multi-line, and the tooling around
deployment settings handles line breaks inconsistently — a key pasted into a
setting frequently arrives with them stripped and then fails to import for a
reason that looks nothing like the cause. The application accepts either form
and decodes base64 automatically.

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("path\to\key.pem")) | Set-Clipboard
```

### A vault in another resource group

Resource group does not matter. Key Vault references are not scoped by it. Three
things do:

- **Tenant.** The vault and the App Service must be in the same Entra tenant.
  A different subscription is fine.
- **Identity.** Give the App Service a managed identity and grant it
  **`Key Vault Secrets User` at the vault's scope**. The grant lives on the
  vault, wherever the vault lives. `get` is sufficient — it never needs `list`
  or `set`.
- **Network.** If the vault is firewalled or behind a private endpoint, the App
  Service has to reach it, which needs VNet integration. **The Free tier does
  not support VNet integration.** On F1 the vault must be reachable over public
  networking with firewall exceptions, or the plan has to move up.

Managed identity itself works on F1, so a publicly reachable vault is fine there.

---

## What actually gets deployed

Deploy the **publish artifact**, never the repository.

```powershell
dotnet publish src\DevSecOpsSentinel.Api -c Release -o .\publish
```

That produces roughly 8 MB across 29 files: four application assemblies, their
dependencies, `appsettings.json` holding defaults and no credentials, `web.config`,
and the `Scenarios` folder the bundled examples are read from.

It does **not** contain source, tests, documentation, git history, or
`node_modules`. The client's dependencies are build-time only and never ship.

The failure worth avoiding is deploying the working tree instead. Local Git
deployment and zipping the repository folder both do exactly that, pushing
hundreds of megabytes of `node_modules` and every test into `site\wwwroot`.
Publish first, deploy the output directory.

### The client does not go into the API's wwwroot

The API serves no static content — there is no `UseStaticFiles`, no SPA
fallback, and no route serving `index.html`. The client is deployed separately,
to Static Web Apps or any static host, and reaches the API across origins with
CORS.

That is why `Security:AllowedOrigins` must name the client's origin. It also
means the two cannot collide in one directory, and either can be redeployed
without the other.

If you would rather serve both from App Service, that is a deliberate change:
copy the client's `dist` into the API's `wwwroot`, add `UseStaticFiles` and a
fallback route, and drop the CORS origin because the client becomes same-origin.
Nothing in the application assumes it today.

---

## Deployment identity

Use **OIDC federated credentials** for the GitHub Actions deploy identity, not a
stored publish profile. A federated credential is a trust relationship rather
than a secret, so there is nothing in the repository to leak or rotate.

`provision-azure.ps1` goes further and disables basic authentication on the SCM
and FTP endpoints, which makes a publish profile unusable. OIDC is then not a
convention the workflow follows but the only thing that can deploy.

Whatever runs the deployment should be a separate workflow gated on the same
`classify-changes` outputs the build uses, so an API change deploys the API and a
client change deploys the client. See [../ci-cd.md](../ci-cd.md).

### The subject is GitHub's to decide, not yours to construct

GitHub presents federated-identity subjects carrying **immutable numeric ids**:

```
repo:owner@30295154/repository@1322411111:ref:refs/heads/main
```

not the older `repo:owner/repository:ref:refs/heads/main`. A credential built
from the names simply never matches, and Entra reports that as:

> `AADSTS700213: No matching federated identity record found for presented
> assertion subject ...`

which names the symptom and not the cause. The subject GitHub actually sent is
printed in the workflow log immediately above the error — read that rather than
the error.

The provisioning script asks for the prefix rather than assembling it:

```powershell
gh api "repos/$repoSlug/actions/oidc/customization/sub" --jq ".sub_claim_prefix"
```

It also compares the **subject** of an existing credential rather than its name,
because a credential with a stale subject looks perfectly present, and matching
on name means re-running can never repair it.

---

## The repository must allow the actions the workflow uses

If Actions is set to *"Allow specified actions and reusable workflows"*, the
three Azure actions have to be listed. They are not GitHub-owned, so
`github_owned_allowed` does not cover them:

```
azure/login@<sha>
azure/webapps-deploy@<sha>
Azure/static-web-apps-deploy@<sha>
```

**A blocked action fails the run before any job starts, with no log.** The
symptom is `startup_failure` on a workflow that parses correctly, passes
`actionlint`, resolves every pinned SHA, and is listed as `active`. Nothing in
the repository tree is wrong, so nothing in the repository tree can tell you.

Check the policy before re-reading the YAML:

```bash
gh api repos/<owner>/<repo>/actions/permissions/selected-actions
```

This is the control working, not failing. An action that can authenticate to your
subscription should be approved deliberately rather than arriving with a merge.

---

## What degraded looks like

The application does not stop working because an integration is
misconfigured, and it does not misreport one that is.

`/api/health/ready` answers one question: can this instance serve requests?
Deterministic analysis depends on nothing external, so the answer is yes whenever
the process started. GitHub and OpenAI state is reported in the body, and on
`/api/github/status` and `/api/ai/status`, but a degraded integration does not
make the application unready — that would take a healthy instance out of
rotation over a feature most requests never touch.

**Nothing silently becomes Mock.** An OpenAI integration configured for Live and
unable to reach the service returns `mode: "Live"`, `generatedByAi: false`, and a
`fallbackReason`, which the client displays. Mock means canned text was used on
purpose; relabelling a failure as Mock would let a viewer read simulated output
as real.

---

## Free tier

**Static Web Apps Free** suits the client well — free TLS, custom domain, no
meaningful limits at this scale.

**App Service F1** has two constraints worth knowing before choosing it:

- **60 CPU-minutes per day.** Beyond that the app returns 503 for the remainder
  of the day.
- **No Always On.** The app sleeps, so the first request after an idle period
  takes roughly thirty seconds.

For a portfolio deployment the cold start is the bigger problem — first
impressions happen in the first ten seconds. B1 removes both. That is the one
place free tier is worth reconsidering.

---

## After deploying

```powershell
.\scripts\smoke-test-api.ps1 -BaseUrl https://<app>.azurewebsites.net -ApiKey <key>
```

Twenty-five checks including eight failure conditions. It reads
`/api/security/status` first and refuses to run without a key when the deployment
requires one.

**Wait for the app before asserting.** App Service recycles after a deployment,
and on F1 the restart plus cold start runs to most of a minute. A smoke suite
invoked immediately reads 404 from an app that is merely still starting, and
fails a deployment that worked. The deploy workflow polls `/api/health/live`
first, which keeps the smoke test's job assertion rather than patience.

Then confirm `/api/health/ready` reports the integration states you expect. If
GitHub reads `Unavailable` while enabled, the private key is not reaching the
application — check the Key Vault reference resolved, and that the managed
identity has the role at the vault's scope.
