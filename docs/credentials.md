# Credentials

Every secret and identifier this project uses: what it is, where it comes from,
where it belongs, and how to replace it.

Five values are involved. **Three are secrets. Two are not**, and treating them
as if they were adds ceremony without protection while making it harder to see
which ones actually matter.

| Value | Secret | Where it lives when deployed |
| --- | --- | --- |
| `Security:ApiKey` | **yes** | App Service application setting |
| `GitHub:PrivateKey` | **yes** | App Service application setting |
| `OpenAI:ApiKey` | **yes** | App Service application setting, Live mode only |
| `GitHub:AppId`, `GitHub:InstallationId` | no | Application settings, plainly |
| `GitHub:AllowedRepositories` | no | Application setting. Visible by design |

**Nothing here belongs in the repository, in `appsettings.json`, or in the client
bundle.** `.env*` and `*.local` are gitignored, Gitleaks runs as a pre-commit
hook and again in CI, and GitHub push protection is enabled. Three gates, none of
which is a substitute for not writing the value down.

---

## The one thing that cannot be secured

**A public client cannot hold a secret.** Not in a Vite environment variable, not
injected at build time, not obfuscated. Anything the browser receives, a visitor
can read from the bundle, the network tab, or storage.

This matters because it is the intuitive place to want to put the access key, and
there is no configuration that makes it safe. The answers are to make the
endpoint anonymous when it has nothing to protect — which is what
`Security:Mode=Public` does for the scanner — or to authenticate the person and
issue them something short-lived.

A Google OAuth **client ID** would be safe in the bundle, because it is not a
credential: it names which application is asking, and the identity provider
verifies everything that matters. The distinction is between naming yourself and
proving yourself.

---

## `Security:ApiKey`

Gates the API. In `Required` mode it guards everything; in `Public` mode it
guards GitHub reads and Live explanations while the scanner stays open.

**Generated, not chosen.** `provision-azure.ps1` creates it and sends it straight
to the App Service setting and to a GitHub secret for the smoke test. No human
sees it, which is deliberate: a bare random string has no distinctive shape, so
no secret scanner would catch it if it ever reached a file. The protection is
that it never does.

To create one by hand:

```powershell
$bytes = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
-join ($bytes | ForEach-Object { $_.ToString("x2") })   # 64 characters
```

| Where | How |
| --- | --- |
| Deployed | App Service setting `Security__ApiKey` |
| CI smoke test | GitHub secret `SENTINEL_API_KEY` |
| Local | Not needed — `Security:Mode` is `Disabled` in Development |

**Reading it back**, without printing it:

```powershell
$key = az webapp config appsettings list -g rg-sentinel -n <app> `
    --query "[?name=='Security__ApiKey'].value | [0]" -o tsv
Set-Clipboard -Value $key
Remove-Variable key
```

**Rotating it** means re-running `provision-azure.ps1`, which regenerates and
redistributes it. Note the limitation: it is one key for everyone, so revoking
one person's access revokes everybody's.

### Who you give it to

**Usually nobody.** In `Public` mode the deployed link is enough: every bundled
scenario, Critical through Low, paste-your-own YAML, findings, remediation
preview and every export format — none of it needs a key.

Hand it over only for the GitHub Sandbox tab, which reads a real repository
through the App's private key and is therefore yours to lend rather than
anyone's to take.

| | No key | With the key |
| --- | --- | --- |
| Scanner, scenarios, remediation, exports | yes | yes |
| AI explanations | Mock | whatever `OpenAI:Mode` is set to |
| GitHub Sandbox | no | yes |

On a Mock deployment the middle row is the same either way, so the key buys
exactly one thing: the Sandbox tab.

This is the only key a person ever receives. The GitHub App private key and the
OpenAI key stay server-side and are never handed to anyone — if either is being
sent to a human, something has gone wrong.

Before sending it to several people, note what rotation costs: one shared key
cannot be revoked for one of them. That is the limitation individual sign-in
would remove, and the first concrete reason to bother.

---

## `GitHub:PrivateKey`

The GitHub App's RSA private key. The API signs a JWT with it, exchanges that for
an installation token, and reads workflow files. **This is the credential that
would matter most if it leaked** — it is the App's identity.

### Creating the App

1. GitHub → Settings → Developer settings → GitHub Apps → New GitHub App
2. Permissions: **Contents: Read-only**, **Actions: Read-only**. Nothing else.
3. No webhook. This project polls; it is never called back.
4. Generate a private key — GitHub downloads a `.pem` once and does not keep it
5. Install the App on the repositories you intend to allow

Note the App ID from the settings page and the installation ID from the
installation URL (`.../installations/<id>`).

### Getting it to Azure

`GitHub:PrivateKey` takes the key **material**, not a path. A path works on a
developer machine and cannot work on a hosted platform, because application
settings and Key Vault references deliver values rather than files. That was the
single change that made this project deployable at all.

**Store it base64-encoded.** A PEM is multi-line, and deployment tooling handles
line breaks inconsistently — a key pasted into a setting frequently arrives with
them stripped and then fails to import for a reason that looks nothing like the
cause. The application accepts either form and decodes base64 automatically.

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("path\to\key.pem")) | Set-Clipboard
```

`provision-azure.ps1` does this for you, reading the file and encoding it in
memory, so you never handle the encoded string.

| Where | How |
| --- | --- |
| Deployed | `GitHub__PrivateKey`, base64 |
| Local | `GitHub:PrivateKeyPath`, a path to the `.pem` outside the repository |

Configuration wins when both are present, so a stale file on a host cannot serve
a deployment.

**Rotating it:** generate a new key in the App settings, deploy it, then delete
the old one from GitHub. In that order — deleting first takes the integration
down until the new key lands.

---

## `OpenAI:ApiKey`

Only Live mode needs one. From
[platform.openai.com/api-keys](https://platform.openai.com/api-keys).

**Set a spending cap on the OpenAI account before enabling Live.** Application
rate limiting bounds how fast a caller can spend; only the account limit bounds
how much. This is the one control that actually caps the bill.

`provision-azure.ps1` writes this setting **only in Live mode**. A Mock
deployment has no OpenAI key in Azure at all — so it is not that spending is
forbidden, it is that there is no credential to spend with. That is a stronger
guarantee than a permission check, and it is worth keeping until you deliberately
choose otherwise.

| Where | How |
| --- | --- |
| Deployed, Live | `OpenAI__ApiKey` |
| Deployed, Mock | **absent** |
| Local | `dotnet user-secrets set "OpenAI:ApiKey" "<value>"` |

---

## The identifiers that are not secrets

`GitHub:AppId` and `GitHub:InstallationId` authorise nothing on their own — they
are meaningless without the private key. `GitHub:AllowedRepositories` is the
allowlist, and being able to see which repositories are permitted is the point of
having one.

Keeping them in plain settings is not carelessness. Treating everything as a
secret makes it harder to see which values would actually hurt you.

---

## Deployment identity: the credential that does not exist

GitHub Actions authenticates to Azure with **OIDC federation**, not a stored
publish profile. GitHub proves its identity per run and nothing is stored, so
there is nothing to leak or rotate. `provision-azure.ps1` also disables basic
authentication on the SCM and FTP endpoints, which makes a publish profile
unusable — OIDC is not a convention the workflow follows but the only thing that
can deploy.

**The subject is GitHub's to decide.** It now carries immutable numeric ids:

```
repo:owner@30295154/repository@1322411111:ref:refs/heads/main
```

A credential built from owner and repository *names* never matches, and Entra
reports that as `AADSTS700213 — no matching federated identity record`, which
names the symptom rather than the cause. The script reads the prefix from
`repos/{owner}/{repo}/actions/oidc/customization/sub` instead of assembling it.

Repository **variables** hold the non-secret wiring: `AZURE_CLIENT_ID`,
`AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, `AZURE_RESOURCE_GROUP`,
`API_APP_NAME`, `API_BASE_URL`, `WEB_BASE_URL`. Repository **secrets** hold two
values: `SENTINEL_API_KEY` and `AZURE_STATIC_WEB_APPS_API_TOKEN`.

---

## Local development

```powershell
cd src\DevSecOpsSentinel.Api
dotnet user-secrets set "GitHub:AppId" "<id>"
dotnet user-secrets set "GitHub:InstallationId" "<id>"
dotnet user-secrets set "GitHub:PrivateKeyPath" "C:\keys\app.pem"
dotnet user-secrets set "GitHub:AllowedRepositories:0" "owner/repo"
dotnet user-secrets set "GitHub:Enabled" "true"
dotnet user-secrets set "OpenAI:ApiKey" "<key>"
dotnet user-secrets set "OpenAI:Mode" "Mock"
```

User secrets live outside the repository, under your profile. `provision-azure.ps1`
reads them, so nothing has to be typed twice — and prints only the key *names*
it found, never the values.

No `Security:ApiKey` is needed locally: `Security:Mode` is `Disabled` in
Development, which is the only environment where that is legal.

---

## Key Vault, if you want it

None of this requires Key Vault. Application settings are encrypted at rest and
gated by RBAC, which is proportionate here. A vault adds rotation without
redeploy, an audit trail, and separation between deploying and reading secrets.

**No code change either way** — the application reads the same configuration key
whether the value is literal or a reference:

```
GitHub__PrivateKey = @Microsoft.KeyVault(SecretUri=https://<vault>.vault.azure.net/secrets/github-app-private-key/)
```

Omitting the version means rotation takes effect without a redeploy. Of the
three, `GitHub:PrivateKey` is the one that earns it — a real private key with a
real rotation story. See
[deployment/azure.md](deployment/azure.md#a-vault-in-another-resource-group) for
a vault in a different resource group, where tenant and RBAC matter and the
resource group does not.

---

## If a secret is ever committed

**Rotate first, then rewrite history.** Deleting the file in a later commit does
not remove it — the object remains reachable, and on a public repository you must
assume it was seen.

Gitleaks has already prevented this once, refusing a commit whose test fixture
embedded a literal PEM. The fix made the test stronger: it now generates a
throwaway key at run time, so the value is real and the import is genuinely
exercised rather than a shape being matched.

**One gap worth knowing:** Gitleaks cannot detect `Security:ApiKey`. It is a bare
random string with no distinctive prefix, so no rule matches it. Detection will
not save you there — only never writing it to a file will, which is why it is
generated and delivered without ever being displayed.
