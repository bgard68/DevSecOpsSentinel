# C6 — API Authentication and Deployment Hardening

## What changed

- Health endpoints and `/` remain public.
- OpenAPI and Scalar remain public only in Development and Testing.
- All workflow, remediation, GitHub, rules, scenarios, and AI endpoints require `X-API-Key` when security mode is `Required`.
- API-key comparison uses SHA-256 plus constant-time comparison.
- Unauthorized responses use RFC 7807 Problem Details.
- Production startup fails unless `Security:Mode=Required`.
- Production enables HSTS.
- Kestrel request bodies are limited to 256 KiB.
- CORS is restricted to configured frontend origins.
- Integration tests cover public endpoints, missing keys, incorrect keys, and valid keys.

## Local development

Existing behavior is preserved because the default mode is `Disabled`.

To explicitly disable authentication locally:

```powershell
dotnet user-secrets set "Security:Mode" "Disabled" --project .\src\DevSecOpsSentinel.Api
```

## Production configuration

Set these through the deployment secret/configuration system:

```text
Security__Mode=Required
Security__ApiKey=<random value of at least 32 characters>
Security__HeaderName=X-API-Key
Security__AllowedOrigins__0=https://your-frontend.example
AllowedHosts=your-api.example
```

Generate a key locally:

```powershell
$bytes = [byte[]]::new(48)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
[Convert]::ToBase64String($bytes)
```

Do not commit the generated key.

## Important browser limitation

An API key embedded in a public React application is visible to users and is not a durable identity control. This mode is appropriate for a private portfolio demo, internal deployment, or server-to-server client. A public multi-user deployment should replace it with OIDC/OAuth authentication and per-user authorization.
