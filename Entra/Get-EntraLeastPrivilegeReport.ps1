<#
.SYNOPSIS
    Checks what admins actually did in Entra ID against the directory roles they
    held at the time, to find where least privilege isn't being followed.

.DESCRIPTION
    For every user who held an Entra directory role during the period (standing
    assignment, PIM activation, or via a role-assignable group), the script:

      1. Rebuilds a timeline of when each role was active for that user:
           * current active assignments and activations (roleAssignmentScheduleInstances)
           * PIM activation history (roleAssignmentScheduleRequests: selfActivate /
             selfDeactivate) and assignments removed during the period (adminRemove)
           * roles assigned to groups, expanded to the group's members
      2. Reads the user's actions from the Entra audit log (directoryAudits).
      3. Looks up each activity in LeastPrivilegeActivityMap.csv to find the
         permission (resource action) it needs, then uses the tenant's own role
         definitions to work out:
           * which of the user's roles active at that moment grant it
           * which roles in the tenant could do it, ranked by how privileged they are
           * the least-privileged role (Microsoft's recommended role where known)
      4. Assesses each action (Least privilege / Over-privileged / No role needed /
         Not covered by an active role / Unmapped activity) and each role
         assignment or activation (Appropriate / Over-privileged / Not needed / Not used).

    The output CSV has three kinds of row (RecordType):
      Action      one row per audited action by an admin
      RoleWindow  one row per period a role was active for a user
      Role        the role catalogue with privilege ranking

    Load it into LeastPrivilegeDashboard.html (same folder).

    Some actions need no admin role, e.g. editing your own profile or changing a group
    you own; those are detected where possible (current ownership is used). Activities
    not in the map are reported as "Unmapped activity" - add them to the CSV map to
    include them.

    REQUIREMENTS
      * Microsoft.Graph.Authentication module
      * Graph permissions (delegated or application):
          AuditLog.Read.All, Directory.Read.All, RoleManagement.Read.Directory
        and, for PIM activation history (roleAssignmentScheduleRequests), one of
          RoleAssignmentSchedule.ReadWrite.Directory or RoleManagement.ReadWrite.Directory
        Microsoft Graph offers no read-only permission for PIM request history; the script
        only reads. Add -IncludeActivationHistoryPermission to request it. Without it, past
        activations are rebuilt from the audit log instead.
      * When signed in as a user (delegated), the user also needs one of these Entra roles
        for the PIM APIs: Global Reader, Security Reader, Security Operator, Security
        Administrator or Privileged Role Administrator. Global Reader also covers the
        audit log and directory reads.
      * Entra ID P2 or ID Governance for PIM. Audit logs are kept for 30 days (7 days on
        free tenants), so -Days above 30 returns no extra data.

.PARAMETER TenantId
    Tenant ID or domain to connect to. Optional when already connected.

.PARAMETER Days
    How many days back to analyse. Default 30.

.PARAMETER UserPrincipalName
    Only analyse these admins (UPNs). Default: everyone who held a role in the period.

.PARAMETER IncludeActivationHistoryPermission
    Also request RoleAssignmentSchedule.ReadWrite.Directory when connecting, which Microsoft
    Graph requires to read PIM activation history. The script never writes; this is only
    needed because Graph has no read-only permission for that API.

.PARAMETER MapPath
    Activity-to-permission map. Default: LeastPrivilegeActivityMap.csv next to this script.

.PARAMETER OutputPath
    CSV to write.

.EXAMPLE
    .\Get-EntraLeastPrivilegeReport.ps1 -TenantId contoso.onmicrosoft.com -OutputPath .\least-privilege.csv

.EXAMPLE
    .\Get-EntraLeastPrivilegeReport.ps1 -Days 14 -UserPrincipalName admin1@contoso.com -OutputPath .\lp.csv
#>
[CmdletBinding()]
param(
    [string]$TenantId,
    [ValidateRange(1, 365)][int]$Days = 30,
    [string[]]$UserPrincipalName,
    [switch]$IncludeActivationHistoryPermission,
    [string]$MapPath = (Join-Path $PSScriptRoot 'LeastPrivilegeActivityMap.csv'),
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$GlobalAdminTemplateId = '62e90394-69f5-4237-9190-012177145e10'
# Default roles that are never assigned to admins and shouldn't be suggested
$IgnoredRoleNames = @('User', 'Guest User', 'Restricted Guest User', 'Directory Synchronization Accounts',
    'On Premises Directory Sync Account', 'Device Users', 'Device Join', 'Workplace Device Join',
    'Device Managers', 'Partner Tier1 Support', 'Partner Tier2 Support', 'Directory Writers')
# Used when the tenant's role definitions don't expose isPrivileged
$KnownPrivilegedRoles = @('Global Administrator', 'Privileged Role Administrator', 'Privileged Authentication Administrator',
    'Security Administrator', 'Application Administrator', 'Cloud Application Administrator', 'Authentication Administrator',
    'User Administrator', 'Helpdesk Administrator', 'Password Administrator', 'Conditional Access Administrator',
    'Hybrid Identity Administrator', 'Domain Name Administrator', 'Intune Administrator', 'Exchange Administrator',
    'SharePoint Administrator', 'Cloud Device Administrator', 'External Identity Provider Administrator',
    'Authentication Policy Administrator', 'B2C IEF Keyset Administrator', 'Partner Tier2 Support', 'Security Operator',
    'Directory Writers', 'Global Reader', 'Security Reader', 'Attribute Provisioning Administrator')
$ValidRequestStatus = @('Provisioned', 'Granted', 'Revoked', 'PendingRevocation', 'PendingExpiration', 'ScheduleCreated')

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
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] }; return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function ConvertTo-UtcDate {
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    try {
        return [datetime]::Parse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal)
    } catch { return $null }
}

function Get-Values {
    <# StrictMode-safe property read across a possibly empty collection. #>
    param($Items, [string]$Name)
    return @(@($Items) | Where-Object { $null -ne $_ } | ForEach-Object { $_.$Name })
}

function Format-Date($d) { if ($d) { $d.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' } }

function Test-ActionGranted {
    <#
        Does an allowed resource action (from a role definition) grant a required one?
        Handles allEntities, allProperties and allTasks wildcards, and entity sub-types
        (e.g. 'groups' grants 'groups.security').
    #>
    param([string]$Allowed, [string]$Required)
    $a = $Allowed.ToLowerInvariant().Split('/')
    $r = $Required.ToLowerInvariant().Split('/')
    if ($a.Count -lt 2 -or $r.Count -lt 2) { return $false }
    if ($a[0] -ne $r[0]) { return $false }
    if (-not ($a[1] -eq 'allentities' -or $a[1] -eq $r[1] -or ($r[1].Contains('.') -and $a[1] -eq $r[1].Split('.')[0]))) { return $false }
    $ar = @(if ($a.Count -gt 2) { $a[2..($a.Count - 1)] })
    $rr = @(if ($r.Count -gt 2) { $r[2..($r.Count - 1)] })
    $aj = $ar -join '/'
    if ($aj -eq 'allproperties/alltasks' -or $aj -eq 'alltasks') { return $true }
    if ($ar.Count -eq 2 -and $ar[0] -eq 'allproperties') { return ($rr.Count -ge 1 -and $rr[-1] -eq $ar[1]) }
    return $aj -eq ($rr -join '/')
}

#endregion

#region Connect & load map ------------------------------------------------------

if (-not (Test-Path $MapPath)) { throw "Activity map not found: $MapPath" }
$activityMap = @(Import-Csv -Path $MapPath)
Write-Host "Loaded $($activityMap.Count) activity mappings from $MapPath"

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    throw "Microsoft.Graph.Authentication module not found. Install it with: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser"
}
Import-Module Microsoft.Graph.Authentication
$requiredScopes = @('AuditLog.Read.All', 'Directory.Read.All', 'RoleManagement.Read.Directory')
if ($IncludeActivationHistoryPermission) { $requiredScopes += 'RoleAssignmentSchedule.ReadWrite.Directory' }
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

$now = [datetime]::UtcNow
$periodStart = $now.AddDays(-$Days)

#endregion

#region Role definitions --------------------------------------------------------

Write-Host 'Retrieving role definitions...' -ForegroundColor Cyan
$roleDefs = @()
try {
    $roleDefs = @(Invoke-GraphPaged -Uri 'https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions?$select=id,displayName,isBuiltIn,isPrivileged,templateId,rolePermissions')
} catch {
    Write-Verbose "beta roleDefinitions failed, using v1.0: $($_.Exception.Message)"
    $roleDefs = @(Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName,isBuiltIn,templateId,rolePermissions')
}

$roles = @{}   # roleDefinitionId -> role info (also keyed by templateId)
foreach ($rd in $roleDefs) {
    $actions = @(foreach ($perm in @(Get-Prop $rd 'rolePermissions')) {
        if (Get-Prop $perm 'condition') { continue }   # conditional (e.g. self-only) permissions don't count
        @(Get-Prop $perm 'allowedResourceActions') | Where-Object { $_ }
    })
    $templateId = [string](Get-Prop $rd 'templateId')
    $isGA = $templateId -eq $GlobalAdminTemplateId -or $rd['id'] -eq $GlobalAdminTemplateId
    $isPriv = Get-Prop $rd 'isPrivileged'
    if ($null -eq $isPriv) { $isPriv = $rd['displayName'] -in $KnownPrivilegedRoles }
    # Privilege score: privileged roles rank above non-privileged ones; within a tier,
    # broader roles (more actions, wildcards weighted heavily) rank higher.
    $breadth = 0
    foreach ($act in $actions) {
        $breadth += if ($act -match '/allEntities/') { 50 } elseif ($act -match 'allProperties/allTasks$|/allTasks$') { 20 } else { 1 }
    }
    $score = if ($isGA) { 1000000000 } else { ([int][bool]$isPriv) * 100000 + $breadth }
    $info = [pscustomobject]@{
        Id = $rd['id']; TemplateId = $templateId; Name = $rd['displayName']; IsBuiltIn = [bool](Get-Prop $rd 'isBuiltIn')
        IsPrivileged = [bool]$isPriv; IsGlobalAdmin = $isGA; Actions = $actions; Score = $score
        Ignored = $rd['displayName'] -in $IgnoredRoleNames
    }
    $roles[$rd['id']] = $info
    if ($templateId -and -not $roles.ContainsKey($templateId)) { $roles[$templateId] = $info }
}
$roleList = @($roles.Values | Sort-Object Id -Unique)
Write-Host "  $($roleList.Count) role definitions."

$grantCache = @{}
function Get-RolesGranting {
    <# Returns the (non-ignored) roles that grant any of the required permissions. #>
    param([string[]]$Permissions)
    $key = ($Permissions | Sort-Object) -join '|'
    if ($grantCache.ContainsKey($key)) { return $grantCache[$key] }
    $result = @(foreach ($role in $roleList) {
        if ($role.Ignored) { continue }
        if ($role.IsGlobalAdmin) { $role; continue }
        $hit = $false
        foreach ($req in $Permissions) {
            foreach ($act in $role.Actions) { if (Test-ActionGranted $act $req) { $hit = $true; break } }
            if ($hit) { break }
        }
        if ($hit) { $role }
    }) | Sort-Object Score
    $grantCache[$key] = @($result)
    return @($result)
}

#endregion

#region Role timeline -----------------------------------------------------------

Write-Host 'Retrieving role assignments and PIM history...' -ForegroundColor Cyan
$rawWindows = [System.Collections.Generic.List[object]]::new()   # principalId-level windows
$eligible = [System.Collections.Generic.List[object]]::new()

function Add-RawWindow($PrincipalId, $RoleId, $Scope, $Start, $End, $Source) {
    $rawWindows.Add([pscustomobject]@{ PrincipalId = $PrincipalId; RoleId = $RoleId; Scope = $(if ($Scope) { $Scope } else { '/' }); Start = $Start; End = $End; Source = $Source })
}

function Get-PimErrorHint {
    param($ErrorRecord, [string]$Api)
    $msg = $ErrorRecord.Exception.Message
    $code = try { [int]$ErrorRecord.Exception.Response.StatusCode } catch { 0 }
    if (-not $code -and $msg -match '\b(40[0-9])\b') { $code = [int]$Matches[1] }
    if (-not $code -and $msg -match 'Forbidden') { $code = 403 }
    if (-not $code -and $msg -match 'BadRequest|Bad Request') { $code = 400 }
    $hint = switch ($code) {
        403 {
            if ($Api -eq 'history') {
                'Reading PIM activation history needs RoleAssignmentSchedule.ReadWrite.Directory or RoleManagement.ReadWrite.Directory (Microsoft Graph has no read-only permission for it). Re-run with -IncludeActivationHistoryPermission, or for app-only auth grant one of those application permissions.'
            } else {
                'Needs RoleManagement.Read.Directory, and when signed in as a user one of: Global Reader, Security Reader, Security Operator, Security Administrator or Privileged Role Administrator.'
            }
        }
        400 { 'The tenant may not be licensed for PIM (Entra ID P2 or ID Governance).' }
        default { '' }
    }
    return "$msg $hint".Trim()
}

$pimAvailable = $true      # current assignment / activation instances read OK
$historyAvailable = $true  # PIM request history read OK
try {
    foreach ($i in Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances') {
        $start = ConvertTo-UtcDate (Get-Prop $i 'startDateTime')
        $end   = ConvertTo-UtcDate (Get-Prop $i 'endDateTime')
        $src = if ((Get-Prop $i 'assignmentType') -eq 'Activated') { 'PIM activation' } elseif ($end) { 'Time-bound assignment' } else { 'Permanent assignment' }
        Add-RawWindow $i['principalId'] $i['roleDefinitionId'] (Get-Prop $i 'directoryScopeId') $start $end $src
    }
}
catch {
    $pimAvailable = $false
    Write-Warning "Could not read active role assignments from PIM: $(Get-PimErrorHint $_ 'instances')"
    Write-Warning 'Falling back to current role assignments, treated as active for the whole period.'
    $rawWindows.Clear()
    foreach ($a in Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments') {
        Add-RawWindow $a['principalId'] $a['roleDefinitionId'] (Get-Prop $a 'directoryScopeId') $null $null 'Assignment'
    }
}

try {
    $requests = @(Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleRequests')
    $deactivations = @($requests | Where-Object { $_['action'] -eq 'selfDeactivate' })
    foreach ($r in $requests) {
        $action = [string]$r['action']; $status = [string](Get-Prop $r 'status')
        $created = ConvertTo-UtcDate (Get-Prop $r 'createdDateTime')
        if ($action -eq 'selfActivate' -and $status -in $ValidRequestStatus) {
            $si = Get-Prop $r 'scheduleInfo'
            $start = ConvertTo-UtcDate (Get-Prop $si 'startDateTime'); if (-not $start) { $start = $created }
            $exp = Get-Prop $si 'expiration'
            $end = ConvertTo-UtcDate (Get-Prop $exp 'endDateTime')
            if (-not $end -and (Get-Prop $exp 'duration')) { $end = $start + [System.Xml.XmlConvert]::ToTimeSpan([string](Get-Prop $exp 'duration')) }
            # Cut short by a later self-deactivation of the same role
            foreach ($d in $deactivations) {
                $dt = ConvertTo-UtcDate (Get-Prop $d 'createdDateTime')
                if ($d['principalId'] -eq $r['principalId'] -and $d['roleDefinitionId'] -eq $r['roleDefinitionId'] -and $dt -gt $start -and (-not $end -or $dt -lt $end)) { $end = $dt }
            }
            if (-not $end -or $end -gt $periodStart) { Add-RawWindow $r['principalId'] $r['roleDefinitionId'] (Get-Prop $r 'directoryScopeId') $start $end 'PIM activation' }
        }
        elseif ($action -eq 'adminRemove' -and $status -in $ValidRequestStatus -and $created -gt $periodStart) {
            # Assignment removed during the period: it was active from (at least) the start of the period until removal
            $assigned = @($requests | Where-Object { $_['action'] -eq 'adminAssign' -and $_['principalId'] -eq $r['principalId'] -and $_['roleDefinitionId'] -eq $r['roleDefinitionId'] } |
                ForEach-Object { ConvertTo-UtcDate (Get-Prop $_ 'createdDateTime') } | Where-Object { $_ -lt $created } | Sort-Object -Descending)
            $start = if ($assigned.Count) { $assigned[0] } else { $null }
            Add-RawWindow $r['principalId'] $r['roleDefinitionId'] (Get-Prop $r 'directoryScopeId') $start $created 'Assignment (since removed)'
        }
    }
}
catch {
    $historyAvailable = $false
    Write-Warning "Could not read PIM activation history: $(Get-PimErrorHint $_ 'history')"
    Write-Warning 'Past activations will be rebuilt from the audit log instead.'
}

try {
    foreach ($e in Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances') {
        $eligible.Add([pscustomobject]@{ PrincipalId = $e['principalId']; RoleId = $e['roleDefinitionId']; Scope = (Get-Prop $e 'directoryScopeId')
            Start = (ConvertTo-UtcDate (Get-Prop $e 'startDateTime')); End = (ConvertTo-UtcDate (Get-Prop $e 'endDateTime')) })
    }
}
catch {
    Write-Warning "Could not read PIM eligible assignments: $(Get-PimErrorHint $_ 'eligibility')"
}

# Resolve principals; expand groups to their (current) members
$principalIds = @((Get-Values $rawWindows 'PrincipalId') + (Get-Values $eligible 'PrincipalId') | Where-Object { $_ } | Sort-Object -Unique)
$principals = @{}
for ($i = 0; $i -lt $principalIds.Count; $i += 1000) {
    $chunk = @($principalIds[$i..([math]::Min($i + 999, $principalIds.Count - 1))])
    $body = @{ ids = $chunk; types = @('user', 'group', 'servicePrincipal') } | ConvertTo-Json -Depth 3
    $resp = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/directoryObjects/getByIds' -Body $body -ContentType 'application/json' -OutputType Hashtable
    foreach ($o in $resp['value']) { $principals[[string]$o['id']] = $o }
}
$users = @{}   # userId -> @{ Upn; Name }
$windows = [System.Collections.Generic.List[object]]::new()
$groupMembers = @{}
foreach ($w in $rawWindows) {
    $p = $principals[[string]$w.PrincipalId]
    if (-not $p) { continue }
    switch (Get-Prop $p '@odata.type') {
        '#microsoft.graph.user' {
            $users[$p['id']] = @{ Upn = $p['userPrincipalName']; Name = $p['displayName'] }
            $windows.Add([pscustomobject]@{ UserId = $p['id']; RoleId = $w.RoleId; Scope = $w.Scope; Start = $w.Start; End = $w.End; Source = $w.Source })
        }
        '#microsoft.graph.group' {
            if (-not $groupMembers.ContainsKey($p['id'])) {
                $groupMembers[$p['id']] = @(Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/groups/$($p['id'])/transitiveMembers/microsoft.graph.user?`$select=id,userPrincipalName,displayName")
            }
            foreach ($m in $groupMembers[$p['id']]) {
                $users[$m['id']] = @{ Upn = $m['userPrincipalName']; Name = $m['displayName'] }
                $windows.Add([pscustomobject]@{ UserId = $m['id']; RoleId = $w.RoleId; Scope = $w.Scope; Start = $w.Start; End = $w.End; Source = "$($w.Source) via group $($p['displayName'])" })
            }
        }
    }
}

# Everyone to analyse: anyone with an active role window, plus anyone eligible for a role
# (their activations may only be visible in history / the audit log)
$candidateIds = [System.Collections.Generic.HashSet[string]]::new()
foreach ($w in $windows) { [void]$candidateIds.Add($w.UserId) }
foreach ($e in $eligible) {
    $p = $principals[[string]$e.PrincipalId]
    if (-not $p) { continue }
    if ((Get-Prop $p '@odata.type') -eq '#microsoft.graph.user') {
        $users[$p['id']] = @{ Upn = $p['userPrincipalName']; Name = $p['displayName'] }
        [void]$candidateIds.Add($p['id'])
    } elseif ((Get-Prop $p '@odata.type') -eq '#microsoft.graph.group') {
        if (-not $groupMembers.ContainsKey($p['id'])) {
            $groupMembers[$p['id']] = @(Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/groups/$($p['id'])/transitiveMembers/microsoft.graph.user?`$select=id,userPrincipalName,displayName")
        }
        foreach ($m in $groupMembers[$p['id']]) { $users[$m['id']] = @{ Upn = $m['userPrincipalName']; Name = $m['displayName'] }; [void]$candidateIds.Add($m['id']) }
    }
}
$candidates = @($candidateIds | Where-Object { -not $UserPrincipalName -or $users[$_].Upn -in $UserPrincipalName })

# Read each candidate's audit log once
$auditsByUser = @{}
$n = 0
foreach ($uid in $candidates) {
    $n++
    Write-Progress -Activity 'Reading audit logs' -Status "$n of $($candidates.Count): $($users[$uid].Upn)" -PercentComplete ($n / [math]::Max(1, $candidates.Count) * 100)
    $uri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=initiatedBy/user/id eq '$uid' and activityDateTime ge $(Format-Date $periodStart)&`$top=500"
    $auditsByUser[$uid] = @(Invoke-GraphPaged -Uri $uri)
}
Write-Progress -Activity 'Reading audit logs' -Completed

if (-not $historyAvailable) {
    # Rebuild PIM activations from the audit log: "Add member to role completed (PIM activation)",
    # ended early by "... (PIM deactivate)". Uses StartTime / ExpirationTime from the event's
    # additional details where present, otherwise assumes 8 hours (Entra's default maximum).
    $rolesByName = @{}; foreach ($r in $roleList) { $rolesByName[$r.Name] = $r }
    $rebuilt = 0
    foreach ($uid in $candidates) {
        $ev = @($auditsByUser[$uid] | Sort-Object { ConvertTo-UtcDate (Get-Prop $_ 'activityDateTime') })
        foreach ($a in $ev) {
            $act = [string](Get-Prop $a 'activityDisplayName')
            if ($act -notlike '*PIM activation*' -or $act -like '*expired*' -or $act -like '*requested*' -or (Get-Prop $a 'result') -eq 'failure') { continue }
            $roleTarget = @(Get-Prop $a 'targetResources') | Where-Object { (Get-Prop $_ 'type') -eq 'Role' } | Select-Object -First 1
            if (-not $roleTarget) { continue }
            $role = $roles[[string](Get-Prop $roleTarget 'id')]
            if (-not $role) { $role = $rolesByName[[string](Get-Prop $roleTarget 'displayName')] }
            if (-not $role) { continue }
            $details = @{}
            foreach ($kv in @(Get-Prop $a 'additionalDetails')) { if ($kv) { $details[[string](Get-Prop $kv 'key')] = Get-Prop $kv 'value' } }
            $start = ConvertTo-UtcDate $details['StartTime']; if (-not $start) { $start = ConvertTo-UtcDate (Get-Prop $a 'activityDateTime') }
            $end = ConvertTo-UtcDate $details['ExpirationTime']
            $src = 'PIM activation (from audit log)'
            if (-not $end) { $end = $start.AddHours(8); $src = 'PIM activation (from audit log, end assumed 8h)' }
            $deact = $ev | Where-Object {
                $d = ConvertTo-UtcDate (Get-Prop $_ 'activityDateTime')
                (Get-Prop $_ 'activityDisplayName') -like '*PIM deactivat*' -and $d -gt $start -and $d -lt $end -and
                (@(Get-Prop $_ 'targetResources') | Where-Object { (Get-Prop $_ 'type') -eq 'Role' -and ((Get-Prop $_ 'id') -eq $role.Id -or (Get-Prop $_ 'displayName') -eq $role.Name) })
            } | Select-Object -First 1
            if ($deact) { $end = ConvertTo-UtcDate (Get-Prop $deact 'activityDateTime') }
            $windows.Add([pscustomobject]@{ UserId = $uid; RoleId = $role.Id; Scope = '/'; Start = $start; End = $end; Source = $src })
            $rebuilt++
        }
    }
    Write-Host "  Rebuilt $rebuilt PIM activation(s) from the audit log."
}

# Merge overlapping windows for the same user, role, scope and kind of source
$merged = [System.Collections.Generic.List[object]]::new()
foreach ($g in ($windows | Group-Object UserId, RoleId, Scope, Source)) {
    $sorted = @($g.Group | Sort-Object { if ($_.Start) { $_.Start } else { [datetime]::MinValue } })
    $cur = $null
    foreach ($w in $sorted) {
        if ($cur -and ((-not $cur.End) -or (-not $w.Start) -or $w.Start -le $cur.End)) {
            if (-not $w.End -or ($cur.End -and $w.End -gt $cur.End)) { $cur.End = $w.End }
        } else {
            if ($cur) { $merged.Add($cur) }
            $cur = [pscustomobject]@{ UserId = $w.UserId; RoleId = $w.RoleId; Scope = $w.Scope; Start = $w.Start; End = $w.End; Source = $w.Source }
        }
    }
    if ($cur) { $merged.Add($cur) }
}
# Keep windows that overlap the period
$windows = @($merged | Where-Object { (-not $_.End -or $_.End -gt $periodStart) -and (-not $_.Start -or $_.Start -lt $now) })

$windows = @($windows | Where-Object { $_.UserId -in $candidates })
$adminIds = @(Get-Values $windows 'UserId' | Sort-Object -Unique)
Write-Host "  $($adminIds.Count) users held a directory role during the last $Days days ($($windows.Count) role periods)."

#endregion

#region Audit log & assessment ---------------------------------------------------

$objectCache = @{}
function Get-TargetObject {
    <# Cached lookup of a group / application / service principal with its current owners. #>
    param([string]$Type, [string]$Id)
    $key = "$Type|$Id"
    if ($objectCache.ContainsKey($key)) { return $objectCache[$key] }
    $obj = $null
    try {
        switch ($Type) {
            'Group' {
                $g = Invoke-MgGraphRequest -Method GET -OutputType Hashtable -Uri "https://graph.microsoft.com/v1.0/groups/$Id`?`$select=id,groupTypes,isAssignableToRole,securityEnabled&`$expand=owners(`$select=id)"
                $obj = @{ GroupTypes = @(Get-Prop $g 'groupTypes'); RoleAssignable = [bool](Get-Prop $g 'isAssignableToRole'); Owners = @(@(Get-Prop $g 'owners') | ForEach-Object { $_['id'] }) }
            }
            'Application' {
                $obj = @{ Owners = @(Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/applications/$Id/owners?`$select=id" | ForEach-Object { $_['id'] }) }
            }
            'ServicePrincipal' {
                $obj = @{ Owners = @(Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$Id/owners?`$select=id" | ForEach-Object { $_['id'] }) }
            }
        }
    } catch { $obj = $null }   # deleted or inaccessible
    $objectCache[$key] = $obj
    return $obj
}

function Find-Mapping {
    param([string]$Activity, [string]$Service)
    foreach ($m in $activityMap) {
        if ($Activity -like $m.Activity -and ($m.Service -in '', '*' -or $Service -like $m.Service)) { return $m }
    }
    return $null
}

$rows = [System.Collections.Generic.List[object]]::new()
$reportTime = Format-Date $now
$actionRecords = [System.Collections.Generic.List[object]]::new()
$unmatchedPerms = @{}

foreach ($uid in $adminIds) {
    $u = $users[$uid]
    $audits = @($auditsByUser[$uid])
    $userWindows = @($windows | Where-Object { $_.UserId -eq $uid })

    foreach ($a in $audits) {
        $when = ConvertTo-UtcDate (Get-Prop $a 'activityDateTime')
        $activity = [string](Get-Prop $a 'activityDisplayName')
        $service = [string](Get-Prop $a 'loggedByService')
        $targets = @(Get-Prop $a 'targetResources')
        $t0 = if ($targets.Count) { $targets[0] } else { $null }
        $targetName = if ($t0) { @((Get-Prop $t0 'displayName'), (Get-Prop $t0 'userPrincipalName')) | Where-Object { $_ } | Select-Object -First 1 } else { '' }
        $targetType = [string](Get-Prop $t0 'type')
        $targetId = [string](Get-Prop $t0 'id')

        $active = @($userWindows | Where-Object { (-not $_.Start -or $_.Start -le $when) -and (-not $_.End -or $_.End -gt $when) })
        $activeRoles = @($active | ForEach-Object { $roles[$_.RoleId] } | Where-Object { $_ } | Sort-Object Id -Unique | Sort-Object Score -Descending)

        $m = Find-Mapping $activity $service
        $assessment = $null; $detail = ''; $perms = @(); $covering = @(); $candidates = @(); $least = @()

        if (-not $m) { $assessment = 'Unmapped activity'; $detail = 'Not in the activity map; add it to LeastPrivilegeActivityMap.csv to assess it.' }
        elseif ($m.NoRoleWhen -eq 'Always') { $assessment = 'No role needed'; $detail = $m.Notes }
        else {
            $perms = @($m.Permissions -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            # No role needed: acting on yourself, as an owner, or user (not admin) consent
            switch -Wildcard ($m.NoRoleWhen) {
                'Self' { if ($targets | Where-Object { (Get-Prop $_ 'type') -eq 'User' -and (Get-Prop $_ 'id') -eq $uid }) { $assessment = 'No role needed'; $detail = 'Action on the user''s own account.' } }
                'Owner:*' {
                    $kind = @{ 'Owner:group' = 'Group'; 'Owner:application' = 'Application'; 'Owner:servicePrincipal' = 'ServicePrincipal' }[$m.NoRoleWhen]
                    $tgt = $targets | Where-Object { (Get-Prop $_ 'type') -eq $kind } | Select-Object -First 1
                    if ($tgt) {
                        $obj = Get-TargetObject $kind (Get-Prop $tgt 'id')
                        if ($obj -and $uid -in $obj.Owners) { $assessment = 'No role needed'; $detail = "User is an owner of the $($kind.ToLower()) (current ownership)." }
                    }
                }
                'UserConsent' {
                    $mp = @(Get-Prop $t0 'modifiedProperties')
                    if ($mp | Where-Object { (Get-Prop $_ 'displayName') -eq 'ConsentContext.IsAdminConsent' -and (Get-Prop $_ 'newValue') -match 'false' }) {
                        $assessment = 'No role needed'; $detail = 'User consent for themselves, not admin consent.'
                    }
                }
            }
            # Group actions: the permission depends on the kind of group
            if (-not $assessment -and $targetType -eq 'Group' -and ($perms | Where-Object { $_ -like 'microsoft.directory/groups/*' })) {
                $g = Get-TargetObject 'Group' $targetId
                $expanded = foreach ($p in $perms) {
                    if ($p -notlike 'microsoft.directory/groups/*') { $p; continue }
                    $rest = $p.Substring('microsoft.directory/groups/'.Length)
                    if ($g -and $g.RoleAssignable) {
                        'microsoft.directory/groupsAssignableToRoles/' + $(if ($rest -in 'create', 'delete', 'restore') { $rest } else { 'allProperties/update' })
                    } else {
                        $p
                        if (-not $g -or $g.GroupTypes -contains 'Unified') { "microsoft.directory/groups.unified/$rest" }
                        if (-not $g -or $g.GroupTypes -notcontains 'Unified') { "microsoft.directory/groups.security/$rest" }
                    }
                }
                $perms = @($expanded | Sort-Object -Unique)
                if ($g -and $g.RoleAssignable) { $detail = 'Role-assignable group: needs Privileged Role Administrator (or group owner).' }
            }
            if (-not $assessment) {
                $candidates = @(Get-RolesGranting $perms)
                if (-not $candidates.Count) {
                    $assessment = 'Mapping matches no role'; $detail = "No role in the tenant grants: $($perms -join ', ')"
                    $unmatchedPerms[$activity] = $perms -join ', '
                } else {
                    $preferred = @($m.PreferredRoles -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                    $least = @($candidates | Where-Object { $_.Name -in $preferred })
                    $candidateIds = Get-Values $candidates 'Id'
                    if (-not $least.Count) { $minScore = $candidates[0].Score; $least = @($candidates | Where-Object { $_.Score -eq $minScore }) }
                    $leastScore = ($least | Measure-Object Score -Maximum).Maximum
                    $covering = @($activeRoles | Where-Object { $_.Id -in $candidateIds } | Sort-Object Score)
                    if (-not $covering.Count) {
                        $assessment = 'Not covered by an active role'
                        if (-not $detail) { $detail = 'None of the user''s active roles grant this. They may be an owner, have had a role this report can''t see, or the role was removed.' }
                    } elseif ($covering[0].Score -le $leastScore) {
                        $assessment = 'Least privilege'
                    } else {
                        $assessment = 'Over-privileged'
                        $detail = "Used $($covering[0].Name); $((Get-Values $least 'Name' | Select-Object -Unique) -join ' or ') would be enough." + $(if ($m.Notes) { " Note: $($m.Notes)" } else { '' })
                    }
                }
            }
        }

        $record = [pscustomobject]@{
            UserId = $uid; When = $when; Activity = $activity; Assessment = $assessment
            CoveringIds = Get-Values $covering 'Id'; LowestCoveringId = $(if ($covering.Count) { $covering[0].Id } else { $null })
            LeastNames = @(Get-Values $least 'Name' | Select-Object -Unique)
        }
        $actionRecords.Add($record)

        $rows.Add([pscustomobject][ordered]@{
            RecordType = 'Action'; UserId = $uid; UserPrincipalName = $u.Upn; UserDisplayName = $u.Name
            ActivityDateTime = Format-Date $when; Activity = $activity; Category = Get-Prop $a 'category'; Service = $service
            Result = Get-Prop $a 'result'; TargetName = $targetName; TargetType = $targetType; TargetId = $targetId
            RequiredPermissions = $perms -join '; '
            Assessment = $assessment; AssessmentDetail = $detail
            ActiveRoles = (($active | ForEach-Object { $r = $roles[$_.RoleId]; if ($r) { "$($r.Name) [$($_.Source)$(if ($_.Scope -ne '/') { ", scope $($_.Scope)" })]" } }) -join '; ')
            HighestActiveRole = $(if ($activeRoles.Count) { $activeRoles[0].Name } else { '' })
            RoleUsed = $(if ($covering.Count) { $covering[0].Name } else { '' })
            CoveringRoles = ((Get-Values $covering 'Name') -join '; ')
            LeastPrivilegedRoles = ((Get-Values $least 'Name' | Select-Object -Unique) -join '; ')
            CandidateRoles = (($candidates | Select-Object -First 12 | ForEach-Object { "$($_.Name)|$($_.Score)" }) -join '; ')
            RoleName = ''; RoleId = ''; RoleIsPrivileged = ''; AssignmentSource = ''; Scope = ''; WindowStart = ''; WindowEnd = ''
            ActionsInWindow = ''; ActionsCoveredByRole = ''; WindowVerdict = ''; SuggestedRoles = ''
            RoleIsBuiltIn = ''; PrivilegeScore = ''; PimDataAvailable = $pimAvailable; PimHistoryAvailable = $historyAvailable
            PeriodStartUtc = Format-Date $periodStart; ReportGeneratedUtc = $reportTime
        })
    }
}
Write-Host "  $($actionRecords.Count) audited actions by admins."

#endregion

#region Role window verdicts -----------------------------------------------------

$roleNeeded = @('Least privilege', 'Over-privileged')
foreach ($w in $windows) {
    $role = $roles[$w.RoleId]; if (-not $role) { continue }
    $u = $users[$w.UserId]
    $inWindow = @($actionRecords | Where-Object { $_.UserId -eq $w.UserId -and (-not $w.Start -or $_.When -ge $w.Start) -and (-not $w.End -or $_.When -lt $w.End) })
    $needing = @($inWindow | Where-Object { $_.Assessment -in $roleNeeded })
    $byRole = @($needing | Where-Object { $role.Id -in $_.CoveringIds })
    $usedAsLowest = @($byRole | Where-Object { $_.LowestCoveringId -eq $role.Id })
    $suggest = @()
    $verdict = if (-not $byRole.Count) { 'Not used' }
        elseif (-not $usedAsLowest.Count) { 'Not needed (another role covered these actions)' }
        elseif ($usedAsLowest | Where-Object { $_.Assessment -eq 'Least privilege' }) { 'Appropriate' }
        else { $suggest = @(Get-Values $usedAsLowest 'LeastNames' | Sort-Object -Unique); 'Over-privileged' }
    $rows.Add([pscustomobject][ordered]@{
        RecordType = 'RoleWindow'; UserId = $w.UserId; UserPrincipalName = $u.Upn; UserDisplayName = $u.Name
        ActivityDateTime = ''; Activity = ''; Category = ''; Service = ''; Result = ''; TargetName = ''; TargetType = ''; TargetId = ''
        RequiredPermissions = ''; Assessment = ''; AssessmentDetail = ''; ActiveRoles = ''; HighestActiveRole = ''; RoleUsed = ''
        CoveringRoles = ''; LeastPrivilegedRoles = ''; CandidateRoles = ''
        RoleName = $role.Name; RoleId = $role.Id; RoleIsPrivileged = $role.IsPrivileged; AssignmentSource = $w.Source; Scope = $w.Scope
        WindowStart = Format-Date $w.Start; WindowEnd = Format-Date $w.End
        ActionsInWindow = $inWindow.Count; ActionsCoveredByRole = $byRole.Count; WindowVerdict = $verdict; SuggestedRoles = $suggest -join '; '
        RoleIsBuiltIn = $role.IsBuiltIn; PrivilegeScore = $role.Score; PimDataAvailable = $pimAvailable; PimHistoryAvailable = $historyAvailable
        PeriodStartUtc = Format-Date $periodStart; ReportGeneratedUtc = $reportTime
    })
}
foreach ($e in $eligible) {
    $role = $roles[$e.RoleId]; $p = $principals[[string]$e.PrincipalId]
    if (-not $role -or -not $p) { continue }
    if ((Get-Prop $p '@odata.type') -ne '#microsoft.graph.user') { continue }
    if ($UserPrincipalName -and $p['userPrincipalName'] -notin $UserPrincipalName) { continue }
    $users[$p['id']] = @{ Upn = $p['userPrincipalName']; Name = $p['displayName'] }
    $rows.Add([pscustomobject][ordered]@{
        RecordType = 'RoleWindow'; UserId = $p['id']; UserPrincipalName = $p['userPrincipalName']; UserDisplayName = $p['displayName']
        ActivityDateTime = ''; Activity = ''; Category = ''; Service = ''; Result = ''; TargetName = ''; TargetType = ''; TargetId = ''
        RequiredPermissions = ''; Assessment = ''; AssessmentDetail = ''; ActiveRoles = ''; HighestActiveRole = ''; RoleUsed = ''
        CoveringRoles = ''; LeastPrivilegedRoles = ''; CandidateRoles = ''
        RoleName = $role.Name; RoleId = $role.Id; RoleIsPrivileged = $role.IsPrivileged; AssignmentSource = 'Eligible (PIM)'; Scope = $e.Scope
        WindowStart = Format-Date $e.Start; WindowEnd = Format-Date $e.End
        ActionsInWindow = ''; ActionsCoveredByRole = ''; WindowVerdict = 'Eligible'; SuggestedRoles = ''
        RoleIsBuiltIn = $role.IsBuiltIn; PrivilegeScore = $role.Score; PimDataAvailable = $pimAvailable; PimHistoryAvailable = $historyAvailable
        PeriodStartUtc = Format-Date $periodStart; ReportGeneratedUtc = $reportTime
    })
}
foreach ($role in ($roleList | Where-Object { -not $_.Ignored })) {
    $rows.Add([pscustomobject][ordered]@{
        RecordType = 'Role'; UserId = ''; UserPrincipalName = ''; UserDisplayName = ''
        ActivityDateTime = ''; Activity = ''; Category = ''; Service = ''; Result = ''; TargetName = ''; TargetType = ''; TargetId = ''
        RequiredPermissions = ''; Assessment = ''; AssessmentDetail = ''; ActiveRoles = ''; HighestActiveRole = ''; RoleUsed = ''
        CoveringRoles = ''; LeastPrivilegedRoles = ''; CandidateRoles = ''
        RoleName = $role.Name; RoleId = $role.Id; RoleIsPrivileged = $role.IsPrivileged; AssignmentSource = ''; Scope = ''
        WindowStart = ''; WindowEnd = ''; ActionsInWindow = ''; ActionsCoveredByRole = ''; WindowVerdict = ''; SuggestedRoles = ''
        RoleIsBuiltIn = $role.IsBuiltIn; PrivilegeScore = $role.Score; PimDataAvailable = $pimAvailable; PimHistoryAvailable = $historyAvailable
        PeriodStartUtc = Format-Date $periodStart; ReportGeneratedUtc = $reportTime
    })
}

if ($unmatchedPerms.Count) {
    Write-Warning "$($unmatchedPerms.Count) mapped activities matched no role in this tenant; check their Permissions in the map: $($unmatchedPerms.Keys -join ', ')"
}
$summary = $rows | Where-Object RecordType -eq 'Action' | Group-Object Assessment | Sort-Object Count -Descending
foreach ($s in $summary) { Write-Host ("  {0,-32} {1}" -f $s.Name, $s.Count) }

#endregion

if ($OutputPath) {
    $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host "Report exported to $((Resolve-Path $OutputPath).Path)" -ForegroundColor Green
} else {
    $rows
}
