# Operations Guide

## Local setup

```powershell
pwsh -ExecutionPolicy Bypass
cd C:\DevSecOpsSentinel
.\scripts\setup-local.ps1
```

## Complete local release gate

```powershell
.\scripts\run-all.ps1
```

The script validates Central Package Management, repairs or verifies the frontend toolchain, restores, builds, tests, audits packages, and checks repository protections.

## Start services

API:

```powershell
dotnet run --project .\src\DevSecOpsSentinel.Api
```

Frontend:

```powershell
cd .\src\devsecops-sentinel-web
npm run dev
```

## Health endpoints

- `/api/health`
- `/api/health/live`
- `/api/health/ready`

## User Secrets

Typical local keys:

```text
GitHub:Enabled
GitHub:AppId
GitHub:InstallationId
GitHub:PrivateKeyPath
GitHub:AllowedRepositories:0
OpenAI:ApiKey
OpenAI:Mode
OpenAI:Model
```

Never paste secret values into documentation, logs, screenshots, or Git.

## Cost controls

- Keep `OpenAI:Mode` set to `Mock` for routine demos.
- Live OpenAI requires explicit UI opt-in.
- No background AI requests are made.
- Use prepaid billing with auto-reload disabled.

## Troubleshooting

### Central Package Management errors

```powershell
.\scripts\verify-central-packages.ps1
```

### Missing TypeScript compiler

```powershell
.\scripts\ensure-frontend-toolchain.ps1
```

### PowerShell scripts are blocked

Start PowerShell 7 with:

```powershell
pwsh -ExecutionPolicy Bypass
```

### GitHub configuration incomplete

Verify all GitHub User Secrets and confirm that `GitHub:PrivateKeyPath` points to the exact PEM filename.


## Protected deployment smoke tests

For environments where API authentication is required:

```powershell
$env:DEVSECOPS_SENTINEL_API_KEY = "<deployment access key>"
.\scripts\smoke-test-api.ps1 -BaseUrl "https://your-api.example"
```

The same environment variable is supported by the live GitHub and OpenAI smoke
tests. Never place the key in a script or commit it to the repository.

Authentication must be `Required` in every environment except `Development`
and `Testing`. Configure `AllowedHosts` and `Security:AllowedOrigins` with the
actual deployed API and frontend hosts.

Action reference resolution is disabled by default. Set
`GitHub:ResolveActionReferences=true` only when the deployment should make
outbound GitHub Git Data API calls during remediation generation.
