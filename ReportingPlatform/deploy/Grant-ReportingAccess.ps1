<#
.SYNOPSIS
    The privileged steps of the reporting platform deployment, for an administrator to run
    when the person deploying doesn't hold the roles themselves.

.DESCRIPTION
    Reads what it needs from the settings file Deploy-ReportingPlatform.ps1 saved (pass it
    with -SettingsPath), so the admin doesn't have to answer the questions again. Uses the
    Azure CLI: sign in first with 'az login --tenant <tenant>'.

    -Stage SignInApp
        Creates or updates the portal's sign-in app registration and enterprise app (redirect
        URI, ID tokens, assignment required, reader group assigned, consent for sign-in
        scopes) and writes its client ID back to the settings file.
        Needs: Cloud Application Administrator or Application Administrator.

    -Stage Permissions
        Grants the managed identity:
          * read-only Microsoft Graph application permissions (Directory.Read.All,
            AuditLog.Read.All, Application.Read.All, Policy.Read.All, RoleManagement.Read.Directory)
            - needs Privileged Role Administrator (or Global Administrator)
          * Azure Reader at the chosen scope (tenant root / management group / subscriptions)
            - needs Owner, User Access Administrator or Role Based Access Control Administrator there
        Use -GraphOnly or -AzureOnly when different people hold those roles.

    Idempotent: re-running only adds what's missing.

.EXAMPLE
    ./Grant-ReportingAccess.ps1 -Stage Permissions -SettingsPath ./settings.json

.EXAMPLE
    ./Grant-ReportingAccess.ps1 -Stage Permissions -GraphOnly -ManagedIdentityPrincipalId 33333333-3333-3333-3333-333333333333
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('SignInApp', 'Permissions')][string]$Stage,
    [string]$SettingsPath = (Join-Path $PSScriptRoot 'settings.json'),

    # Permissions (override / instead of the settings file)
    [string]$ManagedIdentityPrincipalId,
    [switch]$GraphOnly,
    [switch]$AzureOnly,
    [string]$ManagementGroupId,
    [string[]]$SubscriptionId,
    [switch]$IncludeUserAuthenticationMethodRead,

    # SignInApp (override / instead of the settings file)
    [string]$FunctionAppHostName,
    [string]$ReaderGroupId,
    [string]$ClientId,
    [string]$DisplayName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'ReportingDeploy.psm1') -Force

$S = if (Test-Path $SettingsPath) { ConvertTo-Hashtable (Get-Content -Raw $SettingsPath | ConvertFrom-Json) } else { $null }
$get = { param([string[]]$Path) $o = $S; foreach ($p in $Path) { if ($null -eq $o) { return $null }; $o = Get-Prop $o $p }; $o }

$account = Invoke-AzCli @('account', 'show') -AllowFailure
if (-not $account) { throw "Sign in first: az login --tenant $(& $get 'tenantId')" }
$tenant = & $get 'tenantId'
if ($tenant -and $account.tenantId -ne $tenant) { throw "The Azure CLI is signed in to tenant $($account.tenantId), but the platform is in $tenant. Run: az login --tenant $tenant" }
Write-Host "Signed in as $($account.user.name) (tenant $($account.tenantId))." -ForegroundColor Cyan
$roles = @(if ($account.user.type -eq 'user') { Get-MyEntraRoles })

if ($Stage -eq 'SignInApp') {
    if (-not (Test-HasEntraRole $roles 'GlobalAdministrator', 'ApplicationAdministrator', 'CloudApplicationAdministrator')) {
        Write-Attention "You don't have Cloud Application Administrator / Application Administrator active; this only works if you own the app registration."
    }
    $hostName = if ($FunctionAppHostName) { $FunctionAppHostName } elseif (& $get 'deployed', 'functionAppHostName') { & $get 'deployed', 'functionAppHostName' }
                elseif (& $get 'namePrefix') { "func-$(& $get 'namePrefix')-$(& $get 'environmentName')-reports.azurewebsites.net" } else { $null }
    $group = if ($ReaderGroupId) { $ReaderGroupId } else { & $get 'signIn', 'readerGroupId' }
    if (-not $hostName -or -not $group) { throw 'Need the Function App host name and the reader group: pass -SettingsPath, or -FunctionAppHostName and -ReaderGroupId.' }
    $r = Set-SignInApp -ClientId $(if ($ClientId) { $ClientId } else { & $get 'signIn', 'clientId' }) `
        -DisplayName $(if ($DisplayName) { $DisplayName } elseif (& $get 'signIn', 'displayName') { & $get 'signIn', 'displayName' } else { 'Identity & Azure Reports' }) `
        -HostNames @($hostName) -ReaderGroupId $group
    if ($S) {
        $S.signIn.clientId = $r.ClientId; $S.signIn.mode = 'existing'
        $S | ConvertTo-Json -Depth 10 | Set-Content -Path $SettingsPath -Encoding utf8NoBOM
        Write-Done "Client ID saved to $SettingsPath."
    }
    Write-Host "Sign-in app client ID: $($r.ClientId)" -ForegroundColor Green
    return
}

# --- Permissions
$principal = if ($ManagedIdentityPrincipalId) { $ManagedIdentityPrincipalId } else { & $get 'deployed', 'managedIdentityPrincipalId' }
if (-not $principal) { throw 'Need the managed identity: pass -SettingsPath (after the platform is deployed) or -ManagedIdentityPrincipalId.' }

if (-not $AzureOnly) {
    if (-not (Test-HasEntraRole $roles 'GlobalAdministrator', 'PrivilegedRoleAdministrator')) {
        throw 'Granting Graph application permissions needs Privileged Role Administrator (or Global Administrator) - activate it in PIM, or run with -AzureOnly.'
    }
    Write-Step 'Microsoft Graph application permissions...'
    Grant-GraphReadPermissions -PrincipalId $principal -IncludeUserAuthenticationMethodRead:($IncludeUserAuthenticationMethodRead -or [bool](& $get 'permissions', 'includeUserAuthenticationMethodRead'))
}

if (-not $GraphOnly) {
    $scopes = @(if ($ManagementGroupId) { @("/providers/Microsoft.Management/managementGroups/$ManagementGroupId") }
              elseif ($SubscriptionId) { @($SubscriptionId | ForEach-Object { "/subscriptions/$_" }) }
              elseif ($S) { @(Get-ReaderScopes $S) }
              else { @("/providers/Microsoft.Management/managementGroups/$($account.tenantId)") })
    Write-Step 'Azure Reader...'
    if (-not $scopes.Count) { Write-Note 'No scope chosen in the settings (azureReaderScope = none).' }
    foreach ($scope in $scopes) { Grant-AzureReader -PrincipalId $principal -Scope $scope }
}
Write-Host ''
Write-Host 'Done. New Graph permissions can take a few minutes to reach the identity''s tokens.' -ForegroundColor Green
