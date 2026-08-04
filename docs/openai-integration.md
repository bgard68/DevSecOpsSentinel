# OpenAI integration

Phase C uses the official `OpenAI` .NET package through an Infrastructure implementation of `IWorkflowAiProvider`.

## Modes

- `Disabled`: no provider request; deterministic fallback only.
- `Mock`: realistic explanations without API credits.
- `Live`: a single explicit request to OpenAI.

The deterministic scanner owns rule IDs, severities, locations, and patch validity. OpenAI may explain existing findings but may not create or change them.

## Local configuration

```powershell
dotnet user-secrets set "OpenAI:ApiKey" "<key>" --project .\src\DevSecOpsSentinel.Api
dotnet user-secrets set "OpenAI:Mode" "Live" --project .\src\DevSecOpsSentinel.Api
```

Do not place the key in source files, `appsettings.json`, React environment variables, scripts, logs, or Git.
