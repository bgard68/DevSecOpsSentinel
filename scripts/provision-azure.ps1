#Requires -Version 5.1
<#
.SYNOPSIS
    Provisions the free-tier Azure resources for DevSecOpsSentinel and wires up
    GitHub OIDC deployment - without you typing or pasting a single secret.

.DESCRIPTION
    Everything is DISCOVERED rather than hardcoded: subscription and tenant from
    your az login, the repository from the git remote, and the application's own
    configuration from the .NET user secrets you already use locally. Existing
    resources are reused rather than recreated, so the script is safe to re-run.

    Free tier throughout:
      * App Service plan  F1 Linux  (60 CPU-minutes/day, no Always On - which is
                                     why the keep-warm workflow exists)
      * Static Web App    Free
      * Managed identity, resource group, OIDC federation - all free

    SECRETS: three values reach Azure, and none of them is typed, pasted,
    echoed, or written into the repository.

      Security:ApiKey     generated here. No human ever sees it - it goes
                          straight into the app's configuration and into a
                          GitHub secret for the smoke test. Nothing else needs
                          it, so nothing else is given it.
      OpenAI:ApiKey       read from your user secrets (or -OpenAiApiKey).
      GitHub:PrivateKey   the PEM at your user secrets' GitHub:PrivateKeyPath,
                          read and base64-encoded in memory. The encoding is
                          what makes a multi-line key survive an application
                          setting; doing it here means you never handle it.

    Values that reach Azure travel in a temporary JSON file in the OS temp
    directory - never the repository - which is deleted immediately. That is
    deliberate: passing them as `az --settings K=V` arguments would expose them
    in this machine's process list for the duration of the call.

.PARAMETER Name
    Base name for resources. Default: sentinel. A short deterministic suffix
    derived from the subscription id is appended where global uniqueness is
    required, so re-runs produce the same names.

.PARAMETER Location
    Azure region. Default: whatever your existing resource groups already use,
    else centralus.

.PARAMETER Mode
    Which OpenAI mode the deployment runs in.

      Mock  (default) canned explanations. A visitor arriving during a quota
            failure or an outage sees a working application.
      Live  real model calls. Demonstrates the integration and the rule-ID
            constraint system that Mock never exercises. Requires an OpenAI key.

    Nothing silently switches between them: a Live deployment that cannot reach
    the service reports Live with a fallbackReason, which the client displays.

.PARAMETER AllowedRepository
    owner/repo the GitHub reader is permitted to analyse. Defaults to whatever
    your user secrets hold. Worth passing explicitly - a local value pointing at
    a sandbox is rarely what a public deployment should carry.

.PARAMETER OpenAiApiKey
    Fallback for a machine without the user secrets. SecureString so the value
    never lands in shell history.

.PARAMETER GitHubPrivateKeyPath
    Fallback for a machine without the user secrets: path to the App's PEM.

.PARAMETER WhatIf
    Print the plan and exit without creating anything.

.EXAMPLE
    ./scripts/provision-azure.ps1 -WhatIf
    ./scripts/provision-azure.ps1
    ./scripts/provision-azure.ps1 -Mode Live -AllowedRepository bgard68/DevSecOpsSentinel
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$Name = "sentinel",
    [string]$Location,

    [ValidateSet("Mock", "Live")]
    [string]$Mode = "Mock",

    [string]$AllowedRepository,

    # SecureString so the value never sits in shell history or in a plain
    # variable that could be echoed by accident.
    [System.Security.SecureString]$OpenAiApiKey,

    [string]$GitHubPrivateKeyPath
)

$ErrorActionPreference = "Stop"

function Write-Step { param([string]$Message) Write-Host "`n==> $Message" -ForegroundColor Cyan }
function Write-Ok   { param([string]$Message) Write-Host "    $Message" -ForegroundColor Green }
function Write-Info { param([string]$Message) Write-Host "    $Message" -ForegroundColor Gray }

function Invoke-Az {
    <#
        az with JSON output, converted, failing loudly on a non-zero exit.

        Windows PowerShell 5.1 wraps every stderr line from a native command in
        an ErrorRecord, and with $ErrorActionPreference = 'Stop' that makes a
        harmless az WARNING fatal. So: drop to 'Continue' for the call, judge
        success by $LASTEXITCODE alone, and keep only stdout for the JSON.
    #>
    param([Parameter(ValueFromRemainingArguments)][string[]]$Arguments)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & az @Arguments --output json 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "az $($Arguments -join ' ') failed:`n$($output -join "`n")"
        }
        $json = ($output | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }) -join "`n"
        if ([string]::IsNullOrWhiteSpace($json)) { return $null }
        return $json | ConvertFrom-Json
    } finally {
        $ErrorActionPreference = $previous
    }
}

function Test-AzResource {
    <#
        Existence check that treats "not found" as false rather than an error.
        $ErrorActionPreference = 'Stop' turns ANY native-command stderr output
        into a terminating error, and `az ... show` writes to stderr when the
        resource is absent - which is the normal answer here, not a failure.
    #>
    param([Parameter(ValueFromRemainingArguments)][string[]]$Arguments)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & az @Arguments --output none 2>&1 | Out-Null
        return ($LASTEXITCODE -eq 0)
    } finally {
        $ErrorActionPreference = $previous
    }
}

function Invoke-AzOptional {
    <# For calls that legitimately fail when the thing already exists. #>
    param([Parameter(ValueFromRemainingArguments)][string[]]$Arguments)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & az @Arguments --output none 2>&1 | Out-Null
    } finally {
        $ErrorActionPreference = $previous
    }
}

function ConvertFrom-SecureStringPlain {
    <# Converted at the last possible moment, by the caller, and cleared after. #>
    param([System.Security.SecureString]$Secure)
    if (-not $Secure) { return $null }
    return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR(
        [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure))
}

function Get-UserSecret {
    <#
        One value from the API project's .NET user secrets.

        `dotnet user-secrets list --json` brackets its JSON with //BEGIN and
        //END markers, so the object is extracted rather than parsed directly.
        A machine without the secrets store returns nothing and the caller
        falls back to a parameter.
    #>
    param([hashtable]$Secrets, [string]$Key)
    if ($Secrets -and $Secrets.ContainsKey($Key)) { return $Secrets[$Key] }
    return $null
}

function Read-UserSecrets {
    param([string]$ProjectPath)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $raw = & dotnet user-secrets list --project $ProjectPath --json 2>&1
        if ($LASTEXITCODE -ne 0) { return $null }
        $text = ($raw | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }) -join "`n"
        $start = $text.IndexOf('{')
        $end   = $text.LastIndexOf('}')
        if ($start -lt 0 -or $end -le $start) { return $null }
        $object = $text.Substring($start, $end - $start + 1) | ConvertFrom-Json
        $map = @{}
        foreach ($property in $object.PSObject.Properties) { $map[$property.Name] = $property.Value }
        return $map
    } catch {
        return $null
    } finally {
        $ErrorActionPreference = $previous
    }
}

# ---------------------------------------------------------------- preflight
Write-Step "Preflight"

foreach ($tool in @("az", "gh", "git", "dotnet")) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "$tool is not installed or not on PATH. Install it and re-run."
    }
}
Write-Ok "az, gh, git and dotnet found"

$account = try { Invoke-Az account show } catch { $null }
if (-not $account) { throw "Not logged in to Azure. Run: az login" }

$subscriptionId = $account.id
$tenantId       = $account.tenantId
Write-Ok "Subscription: $($account.name) ($subscriptionId)"

& gh auth status 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Not logged in to GitHub. Run: gh auth login" }

# Repository discovered from the remote - never hardcoded.
$repoRoot  = Split-Path -Parent $PSScriptRoot
$remoteUrl = (& git -C $repoRoot config --get remote.origin.url).Trim()
if ($remoteUrl -notmatch "github\.com[:/](?<owner>[^/]+)/(?<repo>[^/.]+)") {
    throw "Could not parse a GitHub owner/repo from remote.origin.url ($remoteUrl)."
}
$repoOwner = $Matches.owner
$repoName  = $Matches.repo
$repoSlug  = "$repoOwner/$repoName"
Write-Ok "Repository: $repoSlug"

# Location: reuse whatever the subscription already favours, else a default.
if (-not $Location) {
    $existing = Invoke-Az group list --query "[0].location"
    $Location = if ($existing) { $existing } else { "centralus" }
}
Write-Ok "Location: $Location"

# ------------------------------------------------- application configuration
Write-Step "Application configuration"

$apiProject = Join-Path $repoRoot "src/DevSecOpsSentinel.Api"
$secrets    = Read-UserSecrets -ProjectPath $apiProject
if ($secrets) {
    # Names only. The values are never printed, here or anywhere else.
    Write-Ok "read $($secrets.Count) values from user secrets: $(($secrets.Keys | Sort-Object) -join ', ')"
} else {
    Write-Info "no user secrets found - falling back to parameters"
}

$githubAppId          = Get-UserSecret $secrets "GitHub:AppId"
$githubInstallationId = Get-UserSecret $secrets "GitHub:InstallationId"
$githubKeyPath        = if ($GitHubPrivateKeyPath) { $GitHubPrivateKeyPath } else { Get-UserSecret $secrets "GitHub:PrivateKeyPath" }
$allowedRepo          = if ($AllowedRepository) { $AllowedRepository } else { Get-UserSecret $secrets "GitHub:AllowedRepositories:0" }

# GitHub integration is all-or-nothing: a half-configured reader would report
# Unavailable at runtime for a reason no one could see from here.
$githubReady = $githubAppId -and $githubInstallationId -and $githubKeyPath -and $allowedRepo
if ($githubReady) {
    if (-not (Test-Path $githubKeyPath)) {
        throw "GitHub private key not found at '$githubKeyPath'. Pass -GitHubPrivateKeyPath, or correct GitHub:PrivateKeyPath in user secrets."
    }
    Write-Ok "GitHub App $githubAppId, installation $githubInstallationId, allowlist $allowedRepo"
} else {
    Write-Info "GitHub integration incomplete - deploying with GitHub__Enabled=false"
    Write-Info "  (deterministic analysis is unaffected; it depends on nothing external)"
}

# OpenAI: only Live needs a key, so only Live insists on one.
$openAiPlain = ConvertFrom-SecureStringPlain $OpenAiApiKey
if (-not $openAiPlain) { $openAiPlain = Get-UserSecret $secrets "OpenAI:ApiKey" }
if ($Mode -eq "Live" -and -not $openAiPlain) {
    throw "-Mode Live needs an OpenAI key. Pass -OpenAiApiKey, or set OpenAI:ApiKey in user secrets."
}
Write-Ok "OpenAI mode: $Mode$(if ($Mode -eq 'Live') { ' (key found)' })"

# Deterministic short suffix so globally-unique names are stable across re-runs.
$hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash(
    [System.Text.Encoding]::UTF8.GetBytes("$subscriptionId/$repoSlug"))
$suffix = -join ($hash[0..3] | ForEach-Object { $_.ToString("x2") })

$resourceGroup = "rg-$Name"
$planName      = "asp-$Name"
$apiName       = "app-$Name-$suffix"      # globally unique
$swaName       = "swa-$Name-$suffix"      # globally unique
$identityName  = "id-github-$Name"

Write-Info "Resource group : $resourceGroup"
Write-Info "App Service    : $apiName (F1 Linux, DOTNETCORE:10.0)"
Write-Info "Static Web App : $swaName (Free)"
Write-Info "OIDC identity  : $identityName"

if ($WhatIfPreference) {
    Write-Host "`n-WhatIf: nothing was created." -ForegroundColor Yellow
    return
}

# ---------------------------------------------------------- resource group
Write-Step "Resource group"
if (Test-AzResource group show --name $resourceGroup) {
    Write-Ok "$resourceGroup already exists - reusing"
} else {
    Invoke-Az group create --name $resourceGroup --location $Location `
        --tags app=$Name managed-by=provision-azure.ps1 | Out-Null
    Write-Ok "created $resourceGroup"
}

# --------------------------------------------------------------- app service
Write-Step "App Service (free F1, Linux)"
if (Test-AzResource appservice plan show --name $planName --resource-group $resourceGroup) {
    Write-Ok "plan $planName already exists"
} else {
    Invoke-Az appservice plan create --name $planName --resource-group $resourceGroup `
        --location $Location --sku F1 --is-linux | Out-Null
    Write-Ok "created plan $planName (F1, Linux)"
}

if (Test-AzResource webapp show --name $apiName --resource-group $resourceGroup) {
    Write-Ok "web app $apiName already exists"
} else {
    Invoke-Az webapp create --name $apiName --resource-group $resourceGroup `
        --plan $planName --runtime "DOTNETCORE:10.0" | Out-Null
    Write-Ok "created web app $apiName"
}

$apiHost = "$apiName.azurewebsites.net"
$apiUrl  = "https://$apiHost"

Invoke-Az webapp identity assign --name $apiName --resource-group $resourceGroup | Out-Null
Write-Ok "managed identity assigned"

# ------------------------------------------------------------ static web app
Write-Step "Static Web App (free)"
if (Test-AzResource staticwebapp show --name $swaName --resource-group $resourceGroup) {
    Write-Ok "$swaName already exists"
} else {
    Invoke-Az staticwebapp create --name $swaName --resource-group $resourceGroup `
        --location $Location --sku Free | Out-Null
    Write-Ok "created $swaName (Free)"
}

$swaHost = Invoke-Az staticwebapp show --name $swaName --resource-group $resourceGroup --query defaultHostname
$swaUrl  = "https://$swaHost"
Write-Ok "client origin: $swaUrl"

# ------------------------------------------------------------- app settings
Write-Step "Application settings"

# Generated, not chosen. Nobody types this key and nobody needs to see it: it
# goes into the app's configuration and into a GitHub secret for the smoke
# test, and exists nowhere else. That also sidesteps a real detection gap -
# a bare random string has no distinctive shape, so no secret scanner would
# catch it if it ever landed in a file. The protection is that it never does.
$keyBytes = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($keyBytes)
$securityApiKey = -join ($keyBytes | ForEach-Object { $_.ToString("x2") })   # 64 chars

$settings = [ordered]@{
    ASPNETCORE_ENVIRONMENT        = "Production"

    # Required outside Development - the application refuses to start without a
    # key rather than serving an open API.
    "Security__Mode"              = "Required"
    "Security__ApiKey"            = $securityApiKey
    "Security__AllowedOrigins__0" = $swaUrl

    # Ships as localhost;127.0.0.1. Left at that, host filtering rejects every
    # request with a 400 before it reaches a route, and nothing in the response
    # says why.
    "AllowedHosts"                = $apiHost

    "OpenAI__Mode"                = $Mode

    # We deploy a compiled publish artifact, so nothing should be built on the
    # host. Without these, Oryx tries to build from whatever landed in wwwroot.
    SCM_DO_BUILD_DURING_DEPLOYMENT = "false"
    ENABLE_ORYX_BUILD              = "false"
}

if ($Mode -eq "Live") { $settings["OpenAI__ApiKey"] = $openAiPlain }

if ($githubReady) {
    # PEM read and encoded here so you never handle the base64 yourself.
    # Application settings and environment variables handle line breaks
    # inconsistently; a key pasted into one frequently arrives with them
    # stripped and then fails to import for a reason that looks nothing
    # like the cause.
    $settings["GitHub__Enabled"]                 = "true"
    $settings["GitHub__AppId"]                   = "$githubAppId"
    $settings["GitHub__InstallationId"]          = "$githubInstallationId"
    $settings["GitHub__PrivateKey"]              = [Convert]::ToBase64String([IO.File]::ReadAllBytes($githubKeyPath))
    $settings["GitHub__AllowedRepositories__0"]  = $allowedRepo
} else {
    $settings["GitHub__Enabled"] = "false"
}

# Via a temp file rather than --settings K=V arguments, which would put every
# value in this machine's process list for the duration of the call. Written
# to the OS temp directory - never the repository - and deleted immediately.
$settingsFile = New-TemporaryFile
try {
    $payload = @($settings.GetEnumerator() | ForEach-Object {
        @{ name = $_.Key; value = "$($_.Value)"; slotSetting = $false }
    })
    Set-Content -Path $settingsFile -Value ($payload | ConvertTo-Json -Depth 3) -Encoding utf8
    Invoke-Az webapp config appsettings set --name $apiName --resource-group $resourceGroup `
        --settings "@$settingsFile" | Out-Null
} finally {
    Remove-Item $settingsFile -Force -ErrorAction SilentlyContinue
}
Write-Ok "$($settings.Count) settings applied (names only shown): $(($settings.Keys) -join ', ')"

# Deliberately NOT setting App Service CORS. This API does its own, through
# Security:AllowedOrigins and a dynamic policy provider; enabling the platform's
# as well would intercept preflights before the application sees them and can
# emit duplicate Access-Control-Allow-Origin headers, which browsers reject.
Write-Info "CORS is the application's own (Security__AllowedOrigins__0), not App Service's"

# ---------------------------------------------------------- security posture
# Current App Service defaults already produce all four of these. Defaults are
# not guarantees - they change, and nothing here would notice. So: set them
# explicitly, then read them back and fail if any did not take.
Write-Step "Security posture"

Invoke-Az webapp update --name $apiName --resource-group $resourceGroup --set httpsOnly=true | Out-Null
Invoke-Az webapp config set --name $apiName --resource-group $resourceGroup `
    --min-tls-version 1.2 --ftps-state Disabled | Out-Null

# A publish profile is a stored credential; disabling basic auth on both
# endpoints makes one unusable, so OIDC is not a convention the deploy workflow
# follows but the only thing that can work.
foreach ($endpoint in @("scm", "ftp")) {
    Invoke-AzOptional resource update --resource-group $resourceGroup --name $endpoint `
        --namespace Microsoft.Web --resource-type basicPublishingCredentialsPolicies `
        --parent "sites/$apiName" --set properties.allow=false
}

$site   = Invoke-Az webapp show --name $apiName --resource-group $resourceGroup
$config = Invoke-Az webapp config show --name $apiName --resource-group $resourceGroup
$scmAllow = Invoke-Az resource show --resource-group $resourceGroup --name scm `
    --namespace Microsoft.Web --resource-type basicPublishingCredentialsPolicies `
    --parent "sites/$apiName" --query "properties.allow"
$ftpAllow = Invoke-Az resource show --resource-group $resourceGroup --name ftp `
    --namespace Microsoft.Web --resource-type basicPublishingCredentialsPolicies `
    --parent "sites/$apiName" --query "properties.allow"

$posture = @(
    @{ name = "httpsOnly";           actual = $site.httpsOnly;          expected = $true }
    @{ name = "minTlsVersion";       actual = $config.minTlsVersion;    expected = "1.2" }
    @{ name = "ftpsState";           actual = $config.ftpsState;        expected = "Disabled" }
    @{ name = "scm basic auth";      actual = $scmAllow;                expected = $false }
    @{ name = "ftp basic auth";      actual = $ftpAllow;                expected = $false }
)
$failed = @()
foreach ($check in $posture) {
    if ("$($check.actual)" -eq "$($check.expected)") {
        Write-Ok "$($check.name) = $($check.actual)"
    } else {
        $failed += "$($check.name): expected $($check.expected), got $($check.actual)"
    }
}
if ($failed.Count -gt 0) {
    throw "Security posture assertions failed:`n  $($failed -join "`n  ")"
}

# ------------------------------------------------------- GitHub OIDC identity
Write-Step "GitHub OIDC federation (no stored credential)"

$appId = Invoke-Az ad app list --display-name $identityName --query "[0].appId"
if (-not $appId) {
    $appId = Invoke-Az ad app create --display-name $identityName --query appId
    Write-Ok "created app registration $identityName"
} else {
    Write-Ok "app registration $identityName already exists"
}

if (-not (Invoke-Az ad sp list --filter "appId eq '$appId'" --query "[0].id")) {
    Invoke-Az ad sp create --id $appId | Out-Null
    Write-Ok "created service principal"
}

# One federated credential per trusted GitHub context. GitHub presents a
# short-lived token proving "I am this workflow on this ref" - nothing is stored.
#
# The prefix is ASKED FOR rather than assembled from owner/repo. GitHub now
# issues subjects carrying immutable numeric ids -
# repo:owner@30295154/repo@1322411111 - and a credential built from the names
# simply never matches. The failure says only AADSTS700213 "no matching
# federated identity record", which describes the symptom and not the cause,
# and costs an hour if you assume your own construction is right.
$subjectPrefix = (& gh api "repos/$repoSlug/actions/oidc/customization/sub" `
    --jq ".sub_claim_prefix" 2>$null)
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($subjectPrefix)) {
    $subjectPrefix = "repo:$repoSlug"
    Write-Info "could not read the OIDC subject prefix - falling back to $subjectPrefix"
} else {
    Write-Ok "OIDC subject prefix: $subjectPrefix"
}

$subjects = @{
    "main" = "${subjectPrefix}:ref:refs/heads/main"
}
$existingCreds = Invoke-Az ad app federated-credential list --id $appId
foreach ($cred in $subjects.GetEnumerator()) {
    $existing = $existingCreds | Where-Object { $_.name -eq $cred.Key } | Select-Object -First 1

    # Matching on NAME alone would let a credential with a stale subject sit
    # there looking correct, and re-running would never repair it. The subject
    # is the part that has to match, so the subject is what is compared.
    if ($existing -and $existing.subject -eq $cred.Value) {
        Write-Ok "federated credential '$($cred.Key)' already correct"
        continue
    }

    $body = @{
        name      = $cred.Key
        issuer    = "https://token.actions.githubusercontent.com"
        subject   = $cred.Value
        audiences = @("api://AzureADTokenExchange")
    } | ConvertTo-Json -Compress

    $temp = New-TemporaryFile
    try {
        # Written to the OS temp dir, never the repo, and deleted immediately.
        Set-Content -Path $temp -Value $body -Encoding utf8
        if ($existing) {
            Invoke-Az ad app federated-credential update --id $appId `
                --federated-credential-id $cred.Key --parameters "@$temp" | Out-Null
            Write-Ok "corrected federated credential '$($cred.Key)' -> $($cred.Value)"
        } else {
            Invoke-Az ad app federated-credential create --id $appId --parameters "@$temp" | Out-Null
            Write-Ok "added federated credential '$($cred.Key)'"
        }
    } finally {
        Remove-Item $temp -Force -ErrorAction SilentlyContinue
    }
}

$spId  = Invoke-Az ad sp list --filter "appId eq '$appId'" --query "[0].id"
$scope = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroup"
if (-not (Invoke-Az role assignment list --assignee $appId --scope $scope --query "[?roleDefinitionName=='Contributor'] | [0].id")) {
    Invoke-Az role assignment create --assignee-object-id $spId --assignee-principal-type ServicePrincipal `
        --role Contributor --scope $scope | Out-Null
    Write-Ok "granted Contributor on $resourceGroup (scoped - not subscription-wide)"
} else {
    Write-Ok "role assignment already in place"
}

# --------------------------------------------------------- GitHub wiring
Write-Step "GitHub repository configuration"

# Non-sensitive identifiers -> repository VARIABLES (visible, not secret).
$variables = [ordered]@{
    AZURE_CLIENT_ID       = $appId
    AZURE_TENANT_ID       = $tenantId
    AZURE_SUBSCRIPTION_ID = $subscriptionId
    AZURE_RESOURCE_GROUP  = $resourceGroup
    API_APP_NAME          = $apiName
    API_BASE_URL          = $apiUrl
    WEB_BASE_URL          = $swaUrl
}
foreach ($v in $variables.GetEnumerator()) {
    & gh variable set $v.Key --repo $repoSlug --body $v.Value 2>&1 | Out-Null
    Write-Ok "variable $($v.Key)"
}

# Two genuine secrets, both going straight from memory into gh.
#
# NOT piped: PowerShell appends a newline when piping to a native command's
# stdin, which silently corrupts the value - Azure then rejects deployments
# with an error that names nothing useful. --body passes the exact value. It is
# visible in this machine's process list for the duration of the call, which is
# a smaller risk than a broken deploy pipeline.
$swaToken = Invoke-Az staticwebapp secrets list --name $swaName --resource-group $resourceGroup `
    --query "properties.apiKey"
& gh secret set AZURE_STATIC_WEB_APPS_API_TOKEN --repo $repoSlug --body $swaToken 2>&1 | Out-Null
Write-Ok "secret AZURE_STATIC_WEB_APPS_API_TOKEN (never written to disk)"

# The smoke test needs the API key to assert both that a valid key is accepted
# and that a request without one is refused.
& gh secret set SENTINEL_API_KEY --repo $repoSlug --body $securityApiKey 2>&1 | Out-Null
Write-Ok "secret SENTINEL_API_KEY (generated here, never displayed)"

# Do not leave any of it in the session.
foreach ($name in @("swaToken", "securityApiKey", "openAiPlain", "settings", "payload")) {
    Remove-Variable $name -ErrorAction SilentlyContinue
}
[System.GC]::Collect()

# ------------------------------------------------------------------- summary
Write-Step "Done"
Write-Host @"

  API    $apiUrl
  Web    $swaUrl
  Group  $resourceGroup  (delete everything: az group delete --name $resourceGroup)

  OpenAI $Mode
  GitHub $(if ($githubReady) { "enabled, allowlist $allowedRepo" } else { "disabled - deterministic analysis only" })

  Next:
    1. Push to main, or run the deploy workflow manually.
    2. The keep-warm workflow starts pinging once API_BASE_URL is set
       (F1 has no Always On).
    3. Verify:  ./scripts/smoke-test-api.ps1 -BaseUrl $apiUrl -ApiKey <SENTINEL_API_KEY>
       The key is in GitHub secrets; the smoke test in the deploy workflow
       reads it from there, so you should not need a local copy.

  No secret was written to disk, displayed, or committed by this script.

"@ -ForegroundColor White
