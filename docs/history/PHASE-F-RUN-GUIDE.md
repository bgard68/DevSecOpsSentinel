# Phase F Run Guide

```powershell
pwsh -ExecutionPolicy Bypass
cd C:\DevSecOpsSentinel
.\scripts\setup-local.ps1
.\scripts\run-all.ps1
```

Start API:

```powershell
dotnet run --project .\src\DevSecOpsSentinel.Api
```

Start frontend in a second terminal:

```powershell
cd C:\DevSecOpsSentinel\src\devsecops-sentinel-web
npm run dev
```

With the API running:

```powershell
cd C:\DevSecOpsSentinel
.\scripts\smoke-test-api.ps1
.\scripts\smoke-test-github-live.ps1 -EnableLiveGitHub
```

Operational endpoints:

- `/api/health`
- `/api/health/live`
- `/api/health/ready`
