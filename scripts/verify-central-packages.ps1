$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Props = Join-Path $Root "Directory.Packages.props"
if (-not (Test-Path -LiteralPath $Props)) { throw "Missing root Directory.Packages.props: $Props" }
[xml]$xml = Get-Content -LiteralPath $Props -Raw
$enabled = $xml.Project.PropertyGroup.ManagePackageVersionsCentrally
if ($enabled -ne "true") { throw "ManagePackageVersionsCentrally must be true." }
$duplicates = Get-ChildItem $Root -Recurse -Filter Directory.Packages.props | Where-Object FullName -ne $Props
if ($duplicates) { throw "Nested Directory.Packages.props files found: $($duplicates.FullName -join ', ')" }
$value = dotnet msbuild (Join-Path $Root "src\DevSecOpsSentinel.Api\DevSecOpsSentinel.Api.csproj") -getProperty:ManagePackageVersionsCentrally
if (($value | Out-String).Trim() -ne "true") { throw "MSBuild is not importing Central Package Management from the repository root." }
Write-Host "Central Package Management verified." -ForegroundColor Green
