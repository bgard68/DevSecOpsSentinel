# Validation

## Packaging-environment checks completed

- JSON files parsed successfully
- MSBuild XML files parsed successfully
- Required Phase G documentation and screenshots are present
- Frontend and .NET version markers are set to `1.0.0`
- No PEM, PFX, P12, KEY, or publish-settings files are included
- Release manifest generated with SHA-256 hashes
- ZIP integrity verified after packaging

## Runtime release gates

The packaging environment does not provide the .NET SDK or the project npm registry. Run the following on the target Windows development machine before publishing the release:

```powershell
pwsh -ExecutionPolicy Bypass
cd C:\DevSecOpsSentinel
.\scripts\setup-local.ps1
.\scripts\run-all.ps1
```

With the API running, also run the standard, live GitHub, and optional live OpenAI smoke tests.

- Automated integration tests run in an isolated Testing environment and always force OpenAI Mock mode, even when local User Secrets use Live mode.
