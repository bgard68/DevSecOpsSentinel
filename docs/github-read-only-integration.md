# Phase D.3 — Read-only GitHub integration

DevSecOps Sentinel authenticates as a GitHub App, exchanges a short-lived JWT for an installation token, and reads workflow files only from explicitly allowlisted repositories.

## Security boundaries

- GitHub App permission: repository contents read-only.
- Installation scope: `bgard68/DevSecOpsSentinel-Sandbox` only.
- Application allowlist: the same sandbox repository only.
- Installation tokens are cached in memory and refreshed shortly before expiration.
- Tokens, private keys, workflow contents, and provider responses are not logged.
- No branch, commit, file-update, pull-request, merge, or webhook APIs exist in Phase D.3.

## User Secrets

```powershell
dotnet user-secrets set "GitHub:Enabled" "true" --project .\src\DevSecOpsSentinel.Api
dotnet user-secrets set "GitHub:AppId" "<APP_ID>" --project .\src\DevSecOpsSentinel.Api
dotnet user-secrets set "GitHub:InstallationId" "<INSTALLATION_ID>" --project .\src\DevSecOpsSentinel.Api
dotnet user-secrets set "GitHub:PrivateKeyPath" "C:\Secure\DevSecOpsSentinel\github-app-private-key.pem" --project .\src\DevSecOpsSentinel.Api
dotnet user-secrets set "GitHub:AllowedRepositories:0" "bgard68/DevSecOpsSentinel-Sandbox" --project .\src\DevSecOpsSentinel.Api
```

## Endpoints

- `GET /api/github/status`
- `GET /api/github/repositories`
- `GET /api/github/repositories/{owner}/{repository}/workflows`
- `GET /api/github/repositories/{owner}/{repository}/workflows/content?path=...&reference=main`
- `POST /api/github/repositories/{owner}/{repository}/analyze`

## Live validation

With the API running and User Secrets configured:

```powershell
.\scripts\smoke-test-github-live.ps1 -EnableLiveGitHub
```
