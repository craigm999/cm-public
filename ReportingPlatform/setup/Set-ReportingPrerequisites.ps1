<#
.SYNOPSIS
    One-off, privileged setup for the reporting platform: the sign-in app registration and the
    managed identity's directory / Azure permissions. Run interactively by an administrator.

.DESCRIPTION
    These steps are kept out of the pipeline on purpose: granting Microsoft Graph application
    permissions needs AppRoleAssignment.ReadWrite.All, which would let the pipeline identity
    grant itself (or anything else) any permission in the tenant.

    -Stage AppRegistration   (before the first Terraform run)
        Roles: Cloud Application Administrator (or Application Administrator).
        * Creates/updates the 'Identity & Azure Reports' app registration used for sign-in:
          single tenant, web redirect URI https://<function-app>.azurewebsites.net/.auth/login/aad/callback,
          ID token issuance on, no client secret.
        * Requires assignment on the enterprise app and assigns the reader group, so only
          members of that group can sign in.
        * Grants tenant-wide consent for openid, profile, email and User.Read so users
          aren't prompted.
        Outputs the client ID for Terraform (easy_auth_client_id).

    -Stage Permissions       (after the first Terraform run creates the managed identity)
        Roles: Privileged Role Administrator (Graph app roles) and Owner / User Access
        Administrator / RBAC Administrator on the management group (Azure Reader).
        * Grants the managed identity these read-only Graph application permissions:
          Directory.Read.All, AuditLog.Read.All, Application.Read.All, Policy.Read.All,
          RoleManagement.Read.Directory.
        * Grants Azure Reader at the management group (default: tenant root group) for the
          Azure changes report.
        * Warns about (but doesn't remove) any write permissions the identity already has.

    Both stages are idempotent; re-running them only adds what's missing. Supports -WhatIf.

.PARAMETER FunctionAppName
    Function App name (Terraform output function_app_name, or the name it will have:
    func-<name_prefix>-<environment>-reports).

.PARAMETER ReaderGroup
    Object ID or display name of the security group allowed to use the portal.

.PARAMETER ManagedIdentityPrincipalId
    Principal (object) ID of the managed identity (Terraform output managed_identity_principal_id).

.PARAMETER IncludeUserAuthenticationMethodRead
    Also grant UserAuthenticationMethod.Read.All, needed only if the authentication methods
    report runs with IncludeDisabledUserMethods (reports.json parameters) to read disabled
    users' methods.

.PARAMETER ManagementGroupId
    Management group to grant Azure Reader at. Defaults to the tenant root group.

.EXAMPLE
    ./Set-ReportingPrerequisites.ps1 -Stage AppRegistration -FunctionAppName func-idrpt-prd-reports -ReaderGroup 'SG-Identity-Reports-Readers'

.EXAMPLE
    ./Set-ReportingPrerequisites.ps1 -Stage Permissions -ManagedIdentityPrincipalId 33333333-3333-3333-3333-333333333333
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidateSet('AppRegistration', 'Permissions')][string]$Stage,
    [string]$TenantId,

    # AppRegistration
    [string]$FunctionAppName,
    [string]$ReaderGroup,
    [string]$DisplayName = 'Identity & Azure Reports',

    # Permissions
    [string]$ManagedIdentityPrincipalId,
    [string]$ManagementGroupId,
    [switch]$IncludeUserAuthenticationMethodRead,
    [switch]$SkipAzureReader
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$GraphAppId = '00000003-0000-0000-c000-000000000000'
$AppTag = 'identity-azure-reporting-portal'
$GraphReadPermissions = @('Directory.Read.All', 'AuditLog.Read.All', 'Application.Read.All', 'Policy.Read.All', 'RoleManagement.Read.Directory')
$SignInScopes = @('openid', 'profile', 'email', 'User.Read')
$ReaderRoleDefinitionId = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'

function Invoke-Graph {
    param([string]$Method = 'GET', [string]$Path, $Body)
    $p = @{ Method = $Method; Uri = "https://graph.microsoft.com/v1.0$Path"; OutputType = 'Hashtable' }
    if ($null -ne $Body) { $p.Body = ($Body | ConvertTo-Json -Depth 10); $p.ContentType = 'application/json' }
    Invoke-MgGraphRequest @p
}

function Get-GraphServicePrincipal {
    $r = Invoke-Graph -Path "/servicePrincipals?`$filter=appId eq '$GraphAppId'&`$select=id,appRoles,oauth2PermissionScopes"
    return $r['value'][0]
}

function Connect-Graph([string[]]$Scopes) {
    if (-not (Get-Module -ListAvailable Microsoft.Graph.Authentication)) { throw 'Install-Module Microsoft.Graph.Authentication -Scope CurrentUser' }
    Import-Module Microsoft.Graph.Authentication
    $p = @{ Scopes = $Scopes; NoWelcome = $true }
    if ($TenantId) { $p.TenantId = $TenantId }
    Connect-MgGraph @p
    return Get-MgContext
}

# =====================================================================================
if ($Stage -eq 'AppRegistration') {
    if (-not $FunctionAppName -or -not $ReaderGroup) { throw '-FunctionAppName and -ReaderGroup are required for -Stage AppRegistration.' }
    $null = Connect-Graph @('Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All', 'DelegatedPermissionGrant.ReadWrite.All', 'Group.Read.All')

    $hostName = "$FunctionAppName.azurewebsites.net"
    $redirect = "https://$hostName/.auth/login/aad/callback"
    $graphSp = Get-GraphServicePrincipal
    $scopeIds = foreach ($s in $SignInScopes) {
        $match = $graphSp['oauth2PermissionScopes'] | Where-Object { $_['value'] -eq $s }
        if (-not $match) { throw "Graph scope $s not found." }
        @{ id = $match['id']; type = 'Scope' }
    }
    $web = @{
        redirectUris          = @($redirect)
        logoutUrl             = "https://$hostName/.auth/logout"
        implicitGrantSettings = @{ enableIdTokenIssuance = $true; enableAccessTokenIssuance = $false }
    }

    # --- App registration
    $existing = @((Invoke-Graph -Path "/applications?`$filter=displayName eq '$($DisplayName -replace "'", "''")'&`$select=id,appId,tags,web,identifierUris")['value'] |
        Where-Object { $_['tags'] -contains $AppTag })
    if ($existing.Count -gt 1) { throw "More than one app registration named '$DisplayName' is tagged $AppTag; remove the duplicates." }
    if ($existing.Count -eq 0) {
        if ($PSCmdlet.ShouldProcess($DisplayName, 'Create app registration')) {
            $app = Invoke-Graph -Method POST -Path '/applications' -Body @{
                displayName            = $DisplayName
                signInAudience         = 'AzureADMyOrg'
                tags                   = @($AppTag)
                web                    = $web
                requiredResourceAccess = @(@{ resourceAppId = $GraphAppId; resourceAccess = @($scopeIds) })
            }
            Invoke-Graph -Method PATCH -Path "/applications/$($app['id'])" -Body @{ identifierUris = @("api://$($app['appId'])") } | Out-Null
            Write-Host "Created app registration $DisplayName ($($app['appId']))" -ForegroundColor Green
        }
    } else {
        $app = $existing[0]
        $uris = @($app['web']['redirectUris']) + $redirect | Select-Object -Unique
        if ($PSCmdlet.ShouldProcess($DisplayName, 'Update redirect URI, ID token issuance and permissions')) {
            Invoke-Graph -Method PATCH -Path "/applications/$($app['id'])" -Body @{
                web                    = @{ redirectUris = @($uris); logoutUrl = $web.logoutUrl; implicitGrantSettings = $web.implicitGrantSettings }
                requiredResourceAccess = @(@{ resourceAppId = $GraphAppId; resourceAccess = @($scopeIds) })
            } | Out-Null
            Write-Host "Updated app registration $DisplayName ($($app['appId']))"
        }
    }
    if (-not (Get-Variable app -ErrorAction SilentlyContinue) -or -not $app) { return }   # -WhatIf on first run

    # --- Enterprise app: assignment required
    $sp = (Invoke-Graph -Path "/servicePrincipals?`$filter=appId eq '$($app['appId'])'&`$select=id,appRoleAssignmentRequired")['value'] | Select-Object -First 1
    if (-not $sp -and $PSCmdlet.ShouldProcess($DisplayName, 'Create enterprise application')) {
        $sp = Invoke-Graph -Method POST -Path '/servicePrincipals' -Body @{ appId = $app['appId']; tags = @('WindowsAzureActiveDirectoryIntegratedApp') }
    }
    if ($sp -and -not $sp['appRoleAssignmentRequired'] -and $PSCmdlet.ShouldProcess($DisplayName, 'Require user assignment')) {
        Invoke-Graph -Method PATCH -Path "/servicePrincipals/$($sp['id'])" -Body @{ appRoleAssignmentRequired = $true } | Out-Null
        Write-Host 'Enterprise app now requires assignment.'
    }

    # --- Reader group assignment
    $group = if ($ReaderGroup -match '^[0-9a-fA-F-]{36}$') { Invoke-Graph -Path "/groups/$ReaderGroup`?`$select=id,displayName" }
             else { @((Invoke-Graph -Path "/groups?`$filter=displayName eq '$($ReaderGroup -replace "'", "''")'&`$select=id,displayName")['value']) | Select-Object -First 1 }
    if (-not $group) { throw "Group '$ReaderGroup' not found." }
    $assigned = @((Invoke-Graph -Path "/servicePrincipals/$($sp['id'])/appRoleAssignedTo")['value'] | Where-Object { $_['principalId'] -eq $group['id'] })
    if (-not $assigned -and $PSCmdlet.ShouldProcess($group['displayName'], 'Assign group to the enterprise app')) {
        Invoke-Graph -Method POST -Path "/servicePrincipals/$($sp['id'])/appRoleAssignedTo" -Body @{
            principalId = $group['id']; resourceId = $sp['id']; appRoleId = '00000000-0000-0000-0000-000000000000'
        } | Out-Null
        Write-Host "Assigned group $($group['displayName'])."
    }

    # --- Tenant-wide consent for the sign-in scopes
    $grant = @((Invoke-Graph -Path "/oauth2PermissionGrants?`$filter=clientId eq '$($sp['id'])' and consentType eq 'AllPrincipals' and resourceId eq '$($graphSp['id'])'")['value']) | Select-Object -First 1
    $scopeString = $SignInScopes -join ' '
    if (-not $grant) {
        if ($PSCmdlet.ShouldProcess('Microsoft Graph', "Consent to '$scopeString' for all users")) {
            Invoke-Graph -Method POST -Path '/oauth2PermissionGrants' -Body @{ clientId = $sp['id']; consentType = 'AllPrincipals'; resourceId = $graphSp['id']; scope = $scopeString } | Out-Null
        }
    } elseif (@($SignInScopes | Where-Object { $_ -notin ($grant['scope'] -split ' ') }).Count) {
        if ($PSCmdlet.ShouldProcess('Microsoft Graph', "Update consent to '$scopeString'")) {
            Invoke-Graph -Method PATCH -Path "/oauth2PermissionGrants/$($grant['id'])" -Body @{ scope = $scopeString } | Out-Null
        }
    }

    Write-Host ''
    Write-Host 'Add this to your Terraform variables:' -ForegroundColor Cyan
    Write-Host "  easy_auth_client_id = `"$($app['appId'])`""
    [pscustomobject]@{ ClientId = $app['appId']; ObjectId = $app['id']; EnterpriseAppId = $sp['id']; ReaderGroupId = $group['id'] }
    return
}

# =====================================================================================
if ($Stage -eq 'Permissions') {
    if (-not $ManagedIdentityPrincipalId) { throw '-ManagedIdentityPrincipalId is required for -Stage Permissions (Terraform output managed_identity_principal_id).' }
    $ctx = Connect-Graph @('AppRoleAssignment.ReadWrite.All', 'Application.Read.All')
    if ($IncludeUserAuthenticationMethodRead) { $GraphReadPermissions += 'UserAuthenticationMethod.Read.All' }

    $mi = Invoke-Graph -Path "/servicePrincipals/$ManagedIdentityPrincipalId`?`$select=id,displayName,servicePrincipalType"
    if ($mi['servicePrincipalType'] -ne 'ManagedIdentity') { throw "$ManagedIdentityPrincipalId is not a managed identity (type $($mi['servicePrincipalType']))." }
    Write-Host "Managed identity: $($mi['displayName'])"

    $graphSp = Get-GraphServicePrincipal
    $current = @((Invoke-Graph -Path "/servicePrincipals/$($mi['id'])/appRoleAssignments")['value'] | Where-Object { $_['resourceId'] -eq $graphSp['id'] })
    foreach ($perm in $GraphReadPermissions) {
        $role = $graphSp['appRoles'] | Where-Object { $_['value'] -eq $perm -and $_['allowedMemberTypes'] -contains 'Application' }
        if (-not $role) { throw "Graph application permission $perm not found." }
        if ($current | Where-Object { $_['appRoleId'] -eq $role['id'] }) { Write-Host "  $perm - already granted"; continue }
        if ($PSCmdlet.ShouldProcess($mi['displayName'], "Grant Microsoft Graph $perm")) {
            Invoke-Graph -Method POST -Path "/servicePrincipals/$($mi['id'])/appRoleAssignments" -Body @{
                principalId = $mi['id']; resourceId = $graphSp['id']; appRoleId = $role['id']
            } | Out-Null
            Write-Host "  $perm - granted" -ForegroundColor Green
        }
    }
    # Flag anything beyond read
    $roleNames = @{}; foreach ($r in $graphSp['appRoles']) { $roleNames[$r['id']] = $r['value'] }
    $extra = @($current | ForEach-Object { $roleNames[$_['appRoleId']] } | Where-Object { $_ -and $_ -notin $GraphReadPermissions })
    foreach ($x in $extra) {
        $level = if ($x -match 'ReadWrite|\.Write|FullControl') { 'WARNING' } else { 'Note' }
        Write-Warning "$level - the identity also has $x, which the reports don't need. Consider removing it."
    }

    if (-not $SkipAzureReader) {
        if (-not (Get-Module -ListAvailable Az.Accounts)) { throw 'Az.Accounts is needed to grant Azure Reader (or use -SkipAzureReader and grant it another way).' }
        Import-Module Az.Accounts
        if (-not (Get-AzContext)) { Connect-AzAccount -TenantId $ctx.TenantId | Out-Null }
        $mg = if ($ManagementGroupId) { $ManagementGroupId } else { $ctx.TenantId }   # tenant root group id = tenant id
        $scope = "/providers/Microsoft.Management/managementGroups/$mg"
        # Deterministic assignment name so re-runs are idempotent
        $md5 = [System.Security.Cryptography.MD5]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$scope|$($mi['id'])|$ReaderRoleDefinitionId"))
        $name = [guid]::new($md5).ToString()
        if ($PSCmdlet.ShouldProcess($scope, "Assign Reader to $($mi['displayName'])")) {
            $body = @{ properties = @{ roleDefinitionId = "$scope/providers/Microsoft.Authorization/roleDefinitions/$ReaderRoleDefinitionId"; principalId = $mi['id']; principalType = 'ServicePrincipal' } } | ConvertTo-Json -Depth 4
            $r = Invoke-AzRestMethod -Method PUT -Path "$scope/providers/Microsoft.Authorization/roleAssignments/$name`?api-version=2022-04-01" -Payload $body
            if ($r.StatusCode -in 200, 201) { Write-Host "Azure Reader granted at $scope" -ForegroundColor Green }
            elseif ($r.StatusCode -eq 409 -and $r.Content -match 'RoleAssignmentExists') { Write-Host "Azure Reader already granted at $scope" }
            else { throw "Reader assignment failed: HTTP $($r.StatusCode) $($r.Content)" }
        }
    }
    Write-Host ''
    Write-Host 'Done. Graph permission changes can take a few minutes to reach new tokens.' -ForegroundColor Cyan
}
