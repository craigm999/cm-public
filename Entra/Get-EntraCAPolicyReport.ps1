<#
.SYNOPSIS
    Exports Entra ID Conditional Access policies, with every inclusion and exclusion
    resolved to a name, to a CSV for overlap / exclusion analysis.

.DESCRIPTION
    Reads all Conditional Access policies from Microsoft Graph and writes one CSV row
    per policy, condition, include/exclude and object, for example:

        PolicyName            Dimension     Direction  ValueName
        Require MFA - admins  Roles         Include    Global Administrator
        Require MFA - admins  Users         Exclude    Break Glass 1 <bg1@contoso.com>
        Require MFA - admins  Applications  Include    All resources (cloud apps)

    Each policy also gets one row with Dimension = 'Policy' so policies without
    conditions are never lost. Policy-level details (state, grant and session
    controls, dates) are repeated on every row.

    User, group, role, application, named location, authentication context and
    workload identity IDs are resolved to display names. References that can no
    longer be resolved (for example a deleted group still excluded from a policy)
    are written with Resolved = False.

    Load the CSV into CAPolicyDashboard.html (in the same folder) to visualise
    overlapping policies and inclusions/exclusions.

    REQUIREMENTS
      * Microsoft.Graph.Authentication module
          Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
      * Permissions: Policy.Read.All, Directory.Read.All, Application.Read.All
      * A role that can read Conditional Access, e.g. Security Reader,
        Conditional Access Administrator or Global Reader.

.PARAMETER TenantId
    Tenant ID or domain to connect to. Optional when already connected.

.PARAMETER OutputPath
    Path for the detailed (one row per condition value) CSV used by the dashboard.

.PARAMETER SummaryPath
    Optional path for a second, human-friendly CSV with one row per policy.

.EXAMPLE
    .\Get-EntraCAPolicyReport.ps1 -TenantId contoso.onmicrosoft.com -OutputPath .\ca.csv

.EXAMPLE
    .\Get-EntraCAPolicyReport.ps1 -OutputPath .\ca.csv -SummaryPath .\ca-summary.csv
#>
[CmdletBinding()]
param(
    [string]$TenantId,
    [string]$OutputPath,
    [string]$SummaryPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Helpers ---------------------------------------------------------------

function Invoke-GraphPaged {
    param([Parameter(Mandatory)][string]$Uri)
    $next = $Uri
    while ($next) {
        $response = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType Hashtable
        if ($response.ContainsKey('value')) { foreach ($item in $response['value']) { $item } }
        $next = if ($response.ContainsKey('@odata.nextLink')) { $response['@odata.nextLink'] } else { $null }
    }
}

function Get-Prop {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $null
    }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Get-List {
    <# Returns a property as an array of non-empty strings. #>
    param($Object, [string]$Name)
    return @(Get-Prop $Object $Name | Where-Object { $null -ne $_ -and "$_" -ne '' } | ForEach-Object { [string]$_ })
}

function Invoke-GraphBatch {
    <#
        Runs GET requests through Graph JSON batching (20 per batch), retrying throttled
        requests. Input: hashtable of id -> relative url. Output: hashtable of id -> response.
    #>
    param([hashtable]$Requests)
    $out = @{}
    $ids = @($Requests.Keys)
    for ($i = 0; $i -lt $ids.Count; $i += 20) {
        $chunk = @($ids[$i..([math]::Min($i + 19, $ids.Count - 1))])
        $attempt = 0
        while ($chunk.Count -gt 0 -and $attempt -lt 5) {
            $attempt++
            $body = @{ requests = @($chunk | ForEach-Object { @{ id = $_; method = 'GET'; url = $Requests[$_] } }) } |
                ConvertTo-Json -Depth 5
            $resp = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/$batch' `
                        -Body $body -ContentType 'application/json' -OutputType Hashtable
            $retry = @(); $wait = 0
            foreach ($r in $resp['responses']) {
                $status = [int]$r['status']
                if ($status -eq 429 -or $status -ge 500) {
                    $retry += [string]$r['id']
                    $ra = Get-Prop (Get-Prop $r 'headers') 'Retry-After'
                    $wait = [math]::Max($wait, $(if ($ra) { [int]$ra } else { 5 }))
                }
                else { $out[[string]$r['id']] = $r }
            }
            $chunk = $retry
            if ($chunk.Count -gt 0) { Start-Sleep -Seconds $wait }
        }
    }
    return $out
}

function Test-Guid([string]$Value) { return $Value -match '^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$' }

#endregion

#region Friendly names for special values ---------------------------------------

$SpecialUsers = @{
    'All'                   = 'All users'
    'None'                  = 'None'
    'GuestsOrExternalUsers' = 'All guests and external users'
}
$SpecialApps = @{
    'All'                   = 'All resources (cloud apps)'
    'None'                  = 'None'
    'Office365'             = 'Office 365'
    'MicrosoftAdminPortals' = 'Microsoft Admin Portals'
}
$SpecialLocations = @{
    'All'                                  = 'Any location'
    'AllTrusted'                           = 'All trusted locations'
    '00000000-0000-0000-0000-000000000000' = 'MFA trusted IPs'
}
$SpecialServicePrincipals = @{
    'ServicePrincipalsInMyTenant' = 'All owned service principals'
    'None'                        = 'None'
}
$GrantNames = @{
    'block'               = 'Block access'
    'mfa'                 = 'Require MFA'
    'compliantDevice'     = 'Require compliant device'
    'domainJoinedDevice'  = 'Require hybrid joined device'
    'approvedApplication' = 'Require approved client app'
    'compliantApplication'= 'Require app protection policy'
    'passwordChange'      = 'Require password change'
    'riskRemediation'     = 'Require risk remediation'
}
$UserActionNames = @{
    'urn:user:registersecurityinfo' = 'Register security information'
    'urn:user:registerdevice'       = 'Register or join devices'
}

#endregion

#region Connect ---------------------------------------------------------------

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    throw "Microsoft.Graph.Authentication module not found. Install it with: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser"
}
Import-Module Microsoft.Graph.Authentication

$requiredScopes = @('Policy.Read.All', 'Directory.Read.All', 'Application.Read.All')
$context = Get-MgContext
$needConnect = -not $context -or ($TenantId -and $context.TenantId -ne $TenantId)
if (-not $needConnect -and $context.PSObject.Properties['AuthType'] -and "$($context.AuthType)" -eq 'Delegated') {
    # An existing session (e.g. from another report) may not have the scopes this one needs
    $have = @($context.Scopes | Where-Object { $_ })
    $missing = @($requiredScopes | Where-Object { $_ -notin $have -and ($_ -replace '\.Read\.', '.ReadWrite.') -notin $have })
    if ($missing.Count) {
        Write-Host "Current Graph session is missing $($missing -join ', '); reconnecting." -ForegroundColor Yellow
        $needConnect = $true
    }
}
if ($needConnect) {
    $connectParams = @{ Scopes = $requiredScopes; NoWelcome = $true }
    if ($TenantId) { $connectParams.TenantId = $TenantId }
    Connect-MgGraph @connectParams
    $context = Get-MgContext
}

#endregion

#region Collect -----------------------------------------------------------------

Write-Host 'Retrieving Conditional Access policies...' -ForegroundColor Cyan
$policies = @(Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies')
Write-Host "  $($policies.Count) policies found."

$names = @{}   # "<kind>:<id>" -> @{ Name; Type }

Write-Host 'Retrieving named locations, authentication contexts and roles...' -ForegroundColor Cyan
foreach ($loc in Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations') {
    $kind = switch (Get-Prop $loc '@odata.type') {
        '#microsoft.graph.ipNamedLocation'          { 'IP range location' }
        '#microsoft.graph.countryNamedLocation'     { 'Country location' }
        default                                     { 'Named location' }
    }
    $names["location:$($loc['id'])"] = @{ Name = $loc['displayName']; Type = $kind }
}
try {
    foreach ($ac in Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/authenticationContextClassReferences') {
        $names["authContext:$($ac['id'])"] = @{ Name = "$($ac['id']) - $($ac['displayName'])"; Type = 'Authentication context' }
    }
}
catch { Write-Verbose "Could not read authentication contexts: $($_.Exception.Message)" }
try {
    foreach ($rd in Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,templateId,displayName') {
        $tid = if (Get-Prop $rd 'templateId') { $rd['templateId'] } else { $rd['id'] }
        $names["role:$tid"] = @{ Name = $rd['displayName']; Type = 'Directory role' }
    }
}
catch {
    Write-Verbose "roleDefinitions unavailable, falling back to directoryRoleTemplates: $($_.Exception.Message)"
    foreach ($rt in Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/directoryRoleTemplates?$select=id,displayName') {
        $names["role:$($rt['id'])"] = @{ Name = $rt['displayName']; Type = 'Directory role' }
    }
}

# Gather the object IDs (users, groups, workload identities) and app IDs that need resolving
$dirIds = [System.Collections.Generic.HashSet[string]]::new()
$appIds = [System.Collections.Generic.HashSet[string]]::new()
foreach ($p in $policies) {
    $c = Get-Prop $p 'conditions'
    $u = Get-Prop $c 'users'
    foreach ($prop in 'includeUsers', 'excludeUsers', 'includeGroups', 'excludeGroups') {
        Get-List $u $prop | Where-Object { Test-Guid $_ } | ForEach-Object { [void]$dirIds.Add($_) }
    }
    $ca = Get-Prop $c 'clientApplications'
    foreach ($prop in 'includeServicePrincipals', 'excludeServicePrincipals') {
        Get-List $ca $prop | Where-Object { Test-Guid $_ } | ForEach-Object { [void]$dirIds.Add($_) }
    }
    $a = Get-Prop $c 'applications'
    foreach ($prop in 'includeApplications', 'excludeApplications') {
        Get-List $a $prop | Where-Object { Test-Guid $_ } | ForEach-Object { [void]$appIds.Add($_) }
    }
}

if ($dirIds.Count) {
    Write-Host "Resolving $($dirIds.Count) users, groups and service principals..." -ForegroundColor Cyan
    $all = @($dirIds)
    for ($i = 0; $i -lt $all.Count; $i += 1000) {
        $chunk = @($all[$i..([math]::Min($i + 999, $all.Count - 1))])
        $body = @{ ids = $chunk; types = @('user', 'group', 'servicePrincipal') } | ConvertTo-Json -Depth 3
        $resp = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/directoryObjects/getByIds' `
                    -Body $body -ContentType 'application/json' -OutputType Hashtable
        foreach ($o in $resp['value']) {
            $id = [string]$o['id']
            switch (Get-Prop $o '@odata.type') {
                '#microsoft.graph.user' {
                    $upn = Get-Prop $o 'userPrincipalName'
                    $names["dir:$id"] = @{ Name = $(if ($upn) { "$($o['displayName']) <$upn>" } else { $o['displayName'] }); Type = 'User' }
                }
                '#microsoft.graph.group'            { $names["dir:$id"] = @{ Name = $o['displayName']; Type = 'Group' } }
                '#microsoft.graph.servicePrincipal' { $names["dir:$id"] = @{ Name = $o['displayName']; Type = 'Service principal' } }
            }
        }
    }
}

if ($appIds.Count) {
    Write-Host "Resolving $($appIds.Count) applications..." -ForegroundColor Cyan
    $req = @{}
    foreach ($id in $appIds) { $req[$id] = "/servicePrincipals(appId='$id')?`$select=appId,displayName" }
    $resp = Invoke-GraphBatch -Requests $req
    foreach ($id in $resp.Keys) {
        if ([int]$resp[$id]['status'] -eq 200) {
            $names["app:$id"] = @{ Name = (Get-Prop $resp[$id]['body'] 'displayName'); Type = 'Application' }
        }
    }
}

#endregion

#region Build rows --------------------------------------------------------------

function Format-GrantControls {
    param($Grant)
    if (-not $Grant) { return '' }
    $parts = @()
    foreach ($b in Get-List $Grant 'builtInControls') { $parts += $(if ($GrantNames.ContainsKey($b)) { $GrantNames[$b] } else { $b }) }
    $strength = Get-Prop $Grant 'authenticationStrength'
    if ($strength) { $parts += "Require authentication strength: $(Get-Prop $strength 'displayName')" }
    foreach ($t in Get-List $Grant 'termsOfUse') { $parts += "Terms of use ($t)" }
    foreach ($f in Get-List $Grant 'customAuthenticationFactors') { $parts += "Custom control: $f" }
    $op = Get-Prop $Grant 'operator'
    $sep = if ($op -eq 'AND') { ' AND ' } else { ' OR ' }
    return ($parts -join $sep)
}

function Format-SessionControls {
    param($Session)
    if (-not $Session) { return '' }
    $parts = @()
    if (Get-Prop (Get-Prop $Session 'applicationEnforcedRestrictions') 'isEnabled') { $parts += 'App enforced restrictions' }
    $mcas = Get-Prop $Session 'cloudAppSecurity'
    if (Get-Prop $mcas 'isEnabled') { $parts += "Conditional Access App Control ($(Get-Prop $mcas 'cloudAppSecurityType'))" }
    $sif = Get-Prop $Session 'signInFrequency'
    if (Get-Prop $sif 'isEnabled') {
        $parts += $(if ((Get-Prop $sif 'frequencyInterval') -eq 'everyTime') { 'Sign-in frequency: every time' }
                    else { "Sign-in frequency: $(Get-Prop $sif 'value') $(Get-Prop $sif 'type')" })
    }
    $pb = Get-Prop $Session 'persistentBrowser'
    if (Get-Prop $pb 'isEnabled') { $parts += "Persistent browser: $(Get-Prop $pb 'mode')" }
    if (Get-Prop $Session 'disableResilienceDefaults') { $parts += 'Resilience defaults disabled' }
    $cae = Get-Prop $Session 'continuousAccessEvaluation'
    if ($cae -and (Get-Prop $cae 'mode')) { $parts += "CAE: $(Get-Prop $cae 'mode')" }
    if (Get-Prop (Get-Prop $Session 'secureSignInSession') 'isEnabled') { $parts += 'Token protection' }
    return ($parts -join '; ')
}

function Format-Guests {
    param($Guests)
    $types = (Get-Prop $Guests 'guestOrExternalUserTypes') -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    $tenants = Get-Prop $Guests 'externalTenants'
    $scope = if ((Get-Prop $tenants 'membershipKind') -eq 'enumerated') {
        "tenants: $((Get-List $tenants 'members') -join ', ')"
    } else { 'all external tenants' }
    return @{ Id = ($types -join ','); Name = "Guests: $($types -join ', ') ($scope)" }
}

$rows = [System.Collections.Generic.List[object]]::new()
$reportTime = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')

foreach ($p in ($policies | Sort-Object { $_['displayName'] })) {
    $c       = Get-Prop $p 'conditions'
    $grant   = Get-Prop $p 'grantControls'
    $session = Get-Prop $p 'sessionControls'
    $builtIn = Get-List $grant 'builtInControls'
    $grantType = if ($builtIn -contains 'block') { 'Block' }
                 elseif ($grant) { 'Grant' }
                 elseif ($session) { 'Session only' }
                 else { 'None' }
    $created  = Get-Prop $p 'createdDateTime'
    $modified = Get-Prop $p 'modifiedDateTime'
    $fmt = { param($d) if ($d -is [datetime]) { $d.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { [string]$d } }
    $base = [ordered]@{
        PolicyId           = $p['id']
        PolicyName         = $p['displayName']
        State              = $p['state']
        GrantType          = $grantType
        GrantControls      = Format-GrantControls $grant
        SessionControls    = Format-SessionControls $session
        CreatedDateTime    = & $fmt $created
        ModifiedDateTime   = & $fmt $modified
    }
    $add = {
        param($Dimension, $Direction, $ValueId, $ValueName, $ValueType, $Resolved = $true)
        $r = [ordered]@{}
        foreach ($k in $base.Keys) { $r[$k] = $base[$k] }
        $r.Dimension          = $Dimension
        $r.Direction          = $Direction
        $r.ValueId            = $ValueId
        $r.ValueName          = $ValueName
        $r.ValueType          = $ValueType
        $r.Resolved           = $Resolved
        $r.ReportGeneratedUtc = $reportTime
        $rows.Add([pscustomobject]$r)
    }
    $lookup = {
        param($Key, $Id, $FallbackType)
        if ($names.ContainsKey($Key)) { return @($names[$Key].Name, $names[$Key].Type, $true) }
        return @("Unknown or deleted ($Id)", $FallbackType, $false)
    }

    & $add 'Policy' '' $p['id'] $p['displayName'] 'Policy'

    # --- Users / groups / roles / guests
    $u = Get-Prop $c 'users'
    foreach ($dir in 'Include', 'Exclude') {
        foreach ($id in Get-List $u "$($dir.ToLower())Users") {
            if ($SpecialUsers.ContainsKey($id)) { & $add 'Users' $dir $id $SpecialUsers[$id] 'Special' }
            else { $n = & $lookup "dir:$id" $id 'User'; & $add 'Users' $dir $id $n[0] $n[1] $n[2] }
        }
        foreach ($id in Get-List $u "$($dir.ToLower())Groups") {
            $n = & $lookup "dir:$id" $id 'Group'; & $add 'Groups' $dir $id $n[0] $n[1] $n[2]
        }
        foreach ($id in Get-List $u "$($dir.ToLower())Roles") {
            $n = & $lookup "role:$id" $id 'Directory role'; & $add 'Roles' $dir $id $n[0] $n[1] $n[2]
        }
        $g = Get-Prop $u "$($dir.ToLower())GuestsOrExternalUsers"
        if ($g) { $gi = Format-Guests $g; & $add 'GuestsOrExternalUsers' $dir $gi.Id $gi.Name 'Guests or external users' }
    }

    # --- Workload identities
    $ca = Get-Prop $c 'clientApplications'
    foreach ($dir in 'Include', 'Exclude') {
        foreach ($id in Get-List $ca "$($dir.ToLower())ServicePrincipals") {
            if ($SpecialServicePrincipals.ContainsKey($id)) { & $add 'WorkloadIdentities' $dir $id $SpecialServicePrincipals[$id] 'Special' }
            else { $n = & $lookup "dir:$id" $id 'Service principal'; & $add 'WorkloadIdentities' $dir $id $n[0] $n[1] $n[2] }
        }
    }
    $spFilter = Get-Prop $ca 'servicePrincipalFilter'
    if ($spFilter) { & $add 'WorkloadIdentityFilter' $(if ((Get-Prop $spFilter 'mode') -eq 'exclude') { 'Exclude' } else { 'Include' }) '' (Get-Prop $spFilter 'rule') 'Filter' }

    # --- Target resources
    $a = Get-Prop $c 'applications'
    foreach ($dir in 'Include', 'Exclude') {
        foreach ($id in Get-List $a "$($dir.ToLower())Applications") {
            if ($SpecialApps.ContainsKey($id)) { & $add 'Applications' $dir $id $SpecialApps[$id] 'Special' }
            else { $n = & $lookup "app:$id" $id 'Application'; & $add 'Applications' $dir $id $(if ($n[2]) { $n[0] } else { "App $id (no service principal in tenant)" }) $n[1] $n[2] }
        }
    }
    foreach ($id in Get-List $a 'includeUserActions') {
        & $add 'UserActions' 'Include' $id $(if ($UserActionNames.ContainsKey($id)) { $UserActionNames[$id] } else { $id }) 'User action'
    }
    foreach ($id in Get-List $a 'includeAuthenticationContextClassReferences') {
        $n = & $lookup "authContext:$id" $id 'Authentication context'; & $add 'AuthenticationContext' 'Include' $id $n[0] $n[1] $n[2]
    }
    $appFilter = Get-Prop $a 'applicationFilter'
    if ($appFilter) { & $add 'ApplicationFilter' $(if ((Get-Prop $appFilter 'mode') -eq 'exclude') { 'Exclude' } else { 'Include' }) '' (Get-Prop $appFilter 'rule') 'Filter' }

    # --- Conditions
    $plat = Get-Prop $c 'platforms'
    foreach ($dir in 'Include', 'Exclude') {
        foreach ($id in Get-List $plat "$($dir.ToLower())Platforms") { & $add 'Platforms' $dir $id $(if ($id -eq 'all') { 'Any platform' } else { $id }) 'Platform' }
    }
    $loc = Get-Prop $c 'locations'
    foreach ($dir in 'Include', 'Exclude') {
        foreach ($id in Get-List $loc "$($dir.ToLower())Locations") {
            if ($SpecialLocations.ContainsKey($id)) { & $add 'Locations' $dir $id $SpecialLocations[$id] 'Special' }
            else { $n = & $lookup "location:$id" $id 'Named location'; & $add 'Locations' $dir $id $n[0] $n[1] $n[2] }
        }
    }
    foreach ($id in Get-List $c 'clientAppTypes')            { & $add 'ClientAppTypes' 'Include' $id $id 'Client app type' }
    foreach ($id in Get-List $c 'signInRiskLevels')          { & $add 'SignInRisk' 'Include' $id $id 'Risk level' }
    foreach ($id in Get-List $c 'userRiskLevels')            { & $add 'UserRisk' 'Include' $id $id 'Risk level' }
    foreach ($id in Get-List $c 'servicePrincipalRiskLevels'){ & $add 'ServicePrincipalRisk' 'Include' $id $id 'Risk level' }
    foreach ($id in Get-List $c 'insiderRiskLevels')         { & $add 'InsiderRisk' 'Include' $id $id 'Risk level' }
    $devFilter = Get-Prop (Get-Prop $c 'devices') 'deviceFilter'
    if ($devFilter) { & $add 'DeviceFilter' $(if ((Get-Prop $devFilter 'mode') -eq 'exclude') { 'Exclude' } else { 'Include' }) '' (Get-Prop $devFilter 'rule') 'Filter' }
    $flows = Get-Prop (Get-Prop $c 'authenticationFlows') 'transferMethods'
    if ($flows) { foreach ($f in ($flows -split ',')) { & $add 'AuthenticationFlows' 'Include' $f.Trim() $f.Trim() 'Authentication flow' } }
}

$unresolved = @($rows | Where-Object { -not $_.Resolved })
if ($unresolved.Count) {
    Write-Warning "$($unresolved.Count) reference(s) could not be resolved (deleted or inaccessible objects) - see rows with Resolved = False."
}

#endregion

#region Output ----------------------------------------------------------------

if ($OutputPath) {
    $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host "Detailed report exported to $((Resolve-Path $OutputPath).Path)" -ForegroundColor Green
}

$summary = foreach ($g in ($rows | Group-Object PolicyId)) {
    $first = $g.Group[0]
    $join = { param($dims, $dir)
        (@($g.Group | Where-Object { $_.Dimension -in $dims -and $_.Direction -eq $dir } | ForEach-Object { $_.ValueName }) -join '; ') }
    [pscustomobject][ordered]@{
        PolicyName        = $first.PolicyName
        State             = $first.State
        IncludeUsers      = & $join @('Users', 'Groups', 'Roles', 'GuestsOrExternalUsers', 'WorkloadIdentities') 'Include'
        ExcludeUsers      = & $join @('Users', 'Groups', 'Roles', 'GuestsOrExternalUsers', 'WorkloadIdentities') 'Exclude'
        IncludeResources  = & $join @('Applications', 'UserActions', 'AuthenticationContext', 'ApplicationFilter') 'Include'
        ExcludeResources  = & $join @('Applications', 'ApplicationFilter') 'Exclude'
        IncludeConditions = (@($g.Group | Where-Object { $_.Dimension -in 'Platforms', 'Locations', 'ClientAppTypes', 'SignInRisk', 'UserRisk', 'ServicePrincipalRisk', 'InsiderRisk', 'DeviceFilter', 'AuthenticationFlows' -and $_.Direction -eq 'Include' } | ForEach-Object { "$($_.Dimension): $($_.ValueName)" }) -join '; ')
        ExcludeConditions = (@($g.Group | Where-Object { $_.Dimension -in 'Platforms', 'Locations', 'DeviceFilter' -and $_.Direction -eq 'Exclude' } | ForEach-Object { "$($_.Dimension): $($_.ValueName)" }) -join '; ')
        GrantControls     = $first.GrantControls
        SessionControls   = $first.SessionControls
        PolicyId          = $first.PolicyId
        ModifiedDateTime  = $first.ModifiedDateTime
    }
}

if ($SummaryPath) {
    $summary | Export-Csv -Path $SummaryPath -NoTypeInformation -Encoding UTF8
    Write-Host "Summary exported to $((Resolve-Path $SummaryPath).Path)" -ForegroundColor Green
}

if (-not $OutputPath -and -not $SummaryPath) { $summary }

#endregion
