# Contributing

## Standards

- Keep deterministic security rules independent of AI providers.
- Preserve the read-only GitHub boundary unless a separately reviewed phase changes the threat model.
- Add or update tests for every behavior change.
- Do not commit secrets, PEM files, tokens, logs, `.claude`, or Azure import/export artifacts.
- Use conventional, focused commit messages.

## Validation

Before opening a pull request:

```powershell
pwsh -ExecutionPolicy Bypass
.\scripts\run-all.ps1
```

With the API running, also run the relevant smoke tests.
