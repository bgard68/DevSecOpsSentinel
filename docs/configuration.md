# Configuration

Every setting, what it does, and where its value should live.

`appsettings.json` holds defaults only. It contains no credentials and is not
where they go — see [getting-started.md](getting-started.md#secrets).

---

## Defaults

The shipped configuration runs with no external services:

```json
{
  "AllowedHosts": "localhost;127.0.0.1",
  "OpenAI":  { "Mode": "Mock", "Model": "gpt-5-mini" },
  "GitHub":  { "Enabled": false, "ResolveActionReferences": false },
  "Security": { "Mode": "Disabled", "HeaderName": "X-API-Key" }
}
```

---

## `Security`

| Setting | Default | Notes |
| --- | --- | --- |
| `Mode` | `Required` in code | `Required`, `Public` or `Disabled` |
| `ApiKey` | — | At least 32 characters for `Required` and `Public`. Never in the repository |
| `HeaderName` | `X-API-Key` | |
| `AllowedOrigins` | localhost | Origins permitted by CORS |

| Mode | Deterministic analysis | Live AI | GitHub |
| --- | --- | --- | --- |
| `Required` | key | key | key |
| `Public` | **open** | key | key |
| `Disabled` | open | open | open |

**`Disabled` is only valid in `Development` and `Testing`.** Anywhere else the
application refuses to start, through `ValidateOnStart`. The class default is
`Required`, so the failure mode of a missing configuration section is refusal
rather than an open API.

**`Public` is not a relaxation of `Required`** — it is a different statement
about which endpoints need the key, and it still demands one of 32 characters or
more, because the endpoints it guards are the ones that matter.

Rule evaluation is local computation over text: it makes no outbound call, holds
no credential and stores nothing, so a key in front of it protects nothing and
costs a visitor the whole demonstration. GitHub reads spend the App's private
key, and Live explanations spend the OpenAI key, so those stay behind it.

An anonymous caller in `Public` mode receives **Mock explanations whatever the
deployment is configured for**, labelled as such in the response. They are not
refused — they simply cannot cause an outbound request, so they cannot spend
anything.

The React client never contains a built-in key. For a protected private
deployment a user may enter the access key, which is held in browser
`sessionStorage` for the current tab. That is stated as suitable for a private
demo; a public multi-user service should use OIDC and per-user authorisation
instead.

---

## `OpenAI`

| Setting | Default | Notes |
| --- | --- | --- |
| `Mode` | `Mock` | `Mock`, `Live` or `Disabled` |
| `Model` | `gpt-5-mini` | |
| `ApiKey` | — | Live mode only. Never in the repository |
| `TimeoutSeconds` | 30 | Clamped between 5 and 120 |
| `MaximumContextCharacters` | 20000 | Excerpt sent to the model |

### Mock and Live

**Mock** returns a predefined explanation. No request leaves the process. It
demonstrates the application.

**Live** calls the configured model. It demonstrates the integration — including
the constraint system, which Mock never exercises because no response is
validated.

**Live never silently degrades to Mock.** If the key is missing, the request
times out, or the model returns something that fails validation, the result is
reported with `mode: "Live"`, `generatedByAi: false`, and a `fallbackReason`
saying which. A simulated result is never presented as a real one.

For a public deployment, Mock is the better default: a visitor who arrives during
a quota failure sees a working application rather than a broken one. Enable Live
when you intend to demonstrate the integration, and set a spending limit on the
account.

---

## `GitHub`

| Setting | Default | Notes |
| --- | --- | --- |
| `Enabled` | `false` | |
| `AppId`, `InstallationId` | — | Numeric identifiers |
| `PrivateKey` | — | The key material itself, PEM or base64-encoded PEM. What a deployment setting or Key Vault reference supplies. Takes precedence over the path |
| `PrivateKeyPath` | — | Path to the App private key. Convenient locally, unusable on a hosted platform |
| `AllowedRepositories` | empty | `owner/name` entries |
| `ResolveActionReferences` | `false` | See below |

`AllowedRepositories` is a second boundary, independent of what the App
installation permits. Both must allow a repository before it can be read.

**`ResolveActionReferences` defaults to false and matters.** When true, analysis
resolves action tags to commit SHAs through the GitHub API — which means analysing
a pasted workflow makes outbound requests. Left false, deterministic analysis and
the bundled scenarios reach nothing.

---

## `Operational`

| Setting | Default | Notes |
| --- | --- | --- |
| `WorkflowRequestLimitPerMinute` | 30 | Per API key, or per IP when unauthenticated |
| `CorrelationIdHeader` | `X-Correlation-ID` | |

GitHub read endpoints get four times the analysis budget under a separate policy.

This setting is read through `IOptionsMonitor` rather than captured at startup —
it was previously frozen, so the documented setting could not actually be
changed. See [engineering-log.md](engineering-log.md#5-the-request-rate-limit-was-not-configurable).

---

## Environment variables

Any setting can be supplied as an environment variable, with `__` for the
separator. This is how a deployment and the CI gate override configuration
without touching a file:

```
Security__Mode=Required
Security__ApiKey=<value>
OpenAI__Mode=Mock
GitHub__Enabled=false
```

---

## Deployment checklist

| Setting | Value |
| --- | --- |
| `Security__Mode` | `Public` for a demonstration anyone should be able to run, `Required` to keep it private. Either needs a key of 32+ characters |
| `Security__AllowedOrigins` | the deployed client origin |
| `AllowedHosts` | the deployed host — the default is localhost only |
| `OpenAI__Mode` | `Mock` unless you intend to demonstrate the integration |
| `GitHub__Enabled` | `true` only with credentials in a secret store |

Secrets belong in App Service application settings or Key Vault. Not in
`appsettings.json`, not in the client bundle, not in a tracked file.

Full deployment guidance, including a Key Vault in another resource group, is in
[deployment/azure.md](deployment/azure.md).

---

## Test isolation

The integration tests force `OpenAI:Mode=Mock`, blank the key, disable GitHub,
and replace the action reference resolver with a stub. A developer machine
configured for Live cannot cause a test run to spend credit or reach the network.

The CI smoke run does the same through environment variables.
