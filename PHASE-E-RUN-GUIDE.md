# Phase E validation sequence

```powershell
pwsh -ExecutionPolicy Bypass
cd C:\DevSecOpsSentinel

dotnet restore .\DevSecOpsSentinel.slnx
dotnet build .\DevSecOpsSentinel.slnx --configuration Release
dotnet test .\DevSecOpsSentinel.slnx --configuration Release --no-build
```

Frontend:

```powershell
cd C:\DevSecOpsSentinel\src\devsecops-sentinel-web
npm install
npm audit
npm test
npm run build
```

Run the app in separate terminals:

```powershell
cd C:\DevSecOpsSentinel
dotnet run --project .\src\DevSecOpsSentinel.Api
```

```powershell
cd C:\DevSecOpsSentinel\src\devsecops-sentinel-web
npm run dev
```

Final checks:

```powershell
cd C:\DevSecOpsSentinel
.\scripts\check-repository.ps1
.\scripts\audit-packages.ps1
.\scripts\smoke-test-api.ps1
.\scripts\smoke-test-github-live.ps1 -EnableLiveGitHub
```
