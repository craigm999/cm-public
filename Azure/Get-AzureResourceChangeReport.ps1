<#
.SYNOPSIS
    Reports Azure resources created, changed or deleted across every subscription in a
    tenant, with who made each change.

.DESCRIPTION
    For each subscription in the tenant the script reads:

      * The Activity Log (Administrative events, up to 90 days): every successful
        write / delete (and optionally action) with the caller - a user's UPN, or a
        service principal / managed identity, resolved to its name.
      * The current resource inventory, with each resource's created and last-changed
        time (ARM $expand=createdTime,changedTime). Used to tell creates from updates,
        and to list resources with who created / last changed them.
      * Azure Resource Graph 'resourcechanges' (last 14 days): which properties changed
        and an explicit Create / Update / Delete type, matched to Activity Log events.

    Changes made as part of an ARM / Bicep deployment are linked to the deployment name
    through the Activity Log correlation ID.

    It also reviews Azure RBAC (unless -SkipRoleAssignments):

      * Subscription owners: Owner assignments made directly on each subscription (not
        inherited from a management group), with each owner's account status. A
        subscription is 'Orphaned' when it has direct owners but none of them is an
        enabled person (enabled user, or a group with at least one enabled member).
      * Over-privileged role assignments: privileged roles (Owner, Contributor, User Access
        Administrator, RBAC Administrator, custom roles with '*' or role-assignment write)
        checked against what the principal actually changed in the Activity Log period:
        unused, Owner where Contributor would do, subscription-wide where a few resource
        groups would do, held by disabled / deleted / guest accounts, and so on.

    Output is one CSV with four kinds of row (RecordType):
      Change          one row per resource change event
      Resource        one row per resource that exists now
      Subscription    one row per subscription, with direct owners and any access errors
      RoleAssignment  one row per Azure role assignment, with findings and a suggestion

    Load it into AzureChangeDashboard.html (same folder).

    REQUIREMENTS
      * Az.Accounts module (Install-Module Az.Accounts -Scope CurrentUser)
      * Reader on the subscriptions (Reader at a management group covers them all).
        Reading the Activity Log needs Microsoft.Insights/eventtypes/* (included in Reader).
      * To show service principal / managed identity names, the signed-in account needs
        to be able to read service principals in Entra ID (any member user can by default).
      * For the RBAC review: Reader includes Microsoft.Authorization/*/read. Account status
        of users, groups and service principals comes from Microsoft Graph (any member user
        can read these; an unattended identity needs Directory.Read.All).

.PARAMETER TenantId
    Tenant to report on. Defaults to the current Az context's tenant.

.PARAMETER Days
    How many days back to read the Activity Log (1-90). Default 30.

.PARAMETER SubscriptionId
    Only these subscriptions. Default: every enabled subscription in the tenant you can see.

.PARAMETER IncludeActions
    Also include POST actions (e.g. VM start/stop, listKeys). Excluded by default as they
    don't change the resource definition, but they can be security relevant.

.PARAMETER IncludeFailed
    Also include failed operations.

.PARAMETER CreatorTagName
    Tag that holds the creator, if your organisation stamps one (e.g. 'CreatedBy').
    Used for resources created before the Activity Log period. Default 'CreatedBy'.

.PARAMETER SkipResourceGraphChanges
    Don't query Resource Graph for property-level change details.

.PARAMETER SkipRoleAssignments
    Don't review role assignments / subscription owners.

.PARAMETER BroadScopeResourceGroupLimit
    A subscription-wide (or wider) Owner / Contributor whose changes touched this many
    resource groups or fewer is flagged to be scoped to those resource groups. Default 3.

.PARAMETER ManagedIdentityClientId
    Run unattended as this user-assigned managed identity (e.g. in Azure Functions), getting
    tokens straight from the platform's identity endpoint. Az.Accounts isn't loaded in this
    mode, which avoids assembly conflicts with Microsoft.Graph.Authentication in the same
    PowerShell host. -TenantId is required.

.PARAMETER OutputPath
    CSV to write.

.EXAMPLE
    Connect-AzAccount -TenantId contoso.onmicrosoft.com
    .\Get-AzureResourceChangeReport.ps1 -Days 30 -OutputPath .\azure-changes.csv

.EXAMPLE
    .\Get-AzureResourceChangeReport.ps1 -SubscriptionId 00000000-0000-0000-0000-000000000000 -Days 7 -IncludeActions -OutputPath .\changes.csv
#>
[CmdletBinding()]
param(
    [string]$TenantId,
    [ValidateRange(1, 90)][int]$Days = 30,
    [string[]]$SubscriptionId,
    [switch]$IncludeActions,
    [switch]$IncludeFailed,
    [string]$CreatorTagName = 'CreatedBy',
    [switch]$SkipResourceGraphChanges,
    [switch]$SkipRoleAssignments,
    [ValidateRange(1, 50)][int]$BroadScopeResourceGroupLimit = 3,
    [string]$ManagedIdentityClientId,
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Arm = 'https://management.azure.com'
$CreateMatchMinutes = 15   # an event this close to a resource's createdTime is its creation

#region Helpers ---------------------------------------------------------------

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
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }
    try {
        return [datetime]::Parse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal)
    } catch { return $null }
}

function Format-Date($d) { if ($d) { $d.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' } }

$script:MiTokens = @{}
function Get-ManagedIdentityToken {
    <# Token for a resource from the App Service / Functions identity endpoint, or IMDS on a VM. Cached until near expiry. #>
    param([string]$Resource)
    $cached = $script:MiTokens[$Resource]
    if ($cached -and $cached.Expires -gt [datetime]::UtcNow.AddMinutes(5)) { return $cached.Token }
    if ($env:IDENTITY_ENDPOINT -and $env:IDENTITY_HEADER) {
        $uri = "$($env:IDENTITY_ENDPOINT)?resource=$([uri]::EscapeDataString($Resource))&api-version=2019-08-01&client_id=$ManagedIdentityClientId"
        $r = Invoke-RestMethod -Uri $uri -Headers @{ 'X-IDENTITY-HEADER' = $env:IDENTITY_HEADER }
    } else {
        $uri = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=$([uri]::EscapeDataString($Resource))&client_id=$ManagedIdentityClientId"
        $r = Invoke-RestMethod -Uri $uri -Headers @{ Metadata = 'true' }
    }
    $expires = [DateTimeOffset]::FromUnixTimeSeconds([long]$r.expires_on).UtcDateTime
    $script:MiTokens[$Resource] = @{ Token = $r.access_token; Expires = $expires }
    return $r.access_token
}

function Invoke-ApiRequest {
    <#
        Sends an ARM or Graph request and returns an object shaped like Invoke-AzRestMethod's
        (StatusCode, Content, Headers). Uses the managed identity when -ManagedIdentityClientId
        is set, otherwise Invoke-AzRestMethod with the signed-in Az context.
    #>
    param([string]$Uri, [string]$Method = 'GET', [string]$Payload)
    if (-not $ManagedIdentityClientId) {
        $params = @{ Uri = $Uri; Method = $Method }
        if ($Payload) { $params.Payload = $Payload }
        return Invoke-AzRestMethod @params
    }
    $resource = if ($Uri -like 'https://graph.microsoft.com/*') { 'https://graph.microsoft.com' } else { 'https://management.azure.com/' }
    $headers = @{ Authorization = "Bearer $(Get-ManagedIdentityToken $resource)" }
    $p = @{ Uri = $Uri; Method = $Method; Headers = $headers; SkipHttpErrorCheck = $true; UseBasicParsing = $true }
    if ($Payload) { $p.Body = $Payload; $p.ContentType = 'application/json' }
    $r = Invoke-WebRequest @p
    $ra = $r.Headers['Retry-After']
    return [pscustomobject]@{ StatusCode = [int]$r.StatusCode; Content = [string]$r.Content; Headers = @{ RetryAfterSeconds = $(if ($ra) { [int](@($ra)[0]) } else { $null }) } }
}

function Invoke-Rest {
    <# ARM / Graph request with retries on throttling / transient errors. Returns parsed JSON or throws. #>
    param([string]$Uri, [string]$Method = 'GET', [string]$Payload)
    for ($attempt = 1; $attempt -le 6; $attempt++) {
        $r = Invoke-ApiRequest -Uri $Uri -Method $Method -Payload $Payload
        $code = [int]$r.StatusCode
        if ($code -ge 200 -and $code -lt 300) { return ($r.Content | ConvertFrom-Json) }
        if ($code -eq 429 -or $code -ge 500) {
            $wait = 10
            try {
                $ra = if ($r.Headers -is [System.Collections.IDictionary]) { $r.Headers['RetryAfterSeconds'] } else { $r.Headers.RetryAfter.Delta.TotalSeconds }
                if ($ra) { $wait = [math]::Ceiling($ra) }
            } catch { }
            Start-Sleep -Seconds ([math]::Min(60, $wait * $attempt))
            continue
        }
        $msg = try { ($r.Content | ConvertFrom-Json).error.message } catch { $r.Content }
        throw "HTTP $code from $Uri : $msg"
    }
    throw "Gave up after repeated throttling: $Uri"
}

function Invoke-RestPaged {
    param([string]$Uri)
    $next = $Uri
    while ($next) {
        $page = Invoke-Rest -Uri $next
        foreach ($v in @(Get-Prop $page 'value')) { if ($null -ne $v) { $v } }
        $next = Get-Prop $page 'nextLink'
    }
}

function Split-ResourceId {
    <# Returns subscription, resource group, provider type and name from an ARM resource ID. #>
    param([string]$Id)
    $parts = $Id.Trim('/') -split '/'
    $sub = ''; $rg = ''; $type = ''; $name = ''
    for ($i = 0; $i -lt $parts.Count - 1; $i++) {
        if ($parts[$i] -eq 'subscriptions') { $sub = $parts[$i + 1] }
        if ($parts[$i] -eq 'resourceGroups' -or $parts[$i] -eq 'resourcegroups') { $rg = $parts[$i + 1] }
    }
    $pi = [array]::LastIndexOf([string[]]($parts | ForEach-Object { $_.ToLowerInvariant() }), 'providers')
    if ($pi -ge 0 -and $pi + 1 -lt $parts.Count) {
        $ns = $parts[$pi + 1]
        $typeParts = @(); $nameParts = @()
        for ($j = $pi + 2; $j -lt $parts.Count; $j += 2) { $typeParts += $parts[$j]; if ($j + 1 -lt $parts.Count) { $nameParts += $parts[$j + 1] } }
        $type = (@($ns) + $typeParts) -join '/'
        $name = $nameParts -join '/'
    } elseif ($rg) {
        $type = 'Microsoft.Resources/resourceGroups'; $name = $rg
    } elseif ($sub) {
        $type = 'Microsoft.Resources/subscriptions'; $name = $sub
    }
    return @{ Subscription = $sub; ResourceGroup = $rg; Type = $type; Name = $name }
}

#endregion

#region Connect & subscriptions ---------------------------------------------------

if ($ManagedIdentityClientId) {
    if (-not $TenantId) { throw '-TenantId is required with -ManagedIdentityClientId.' }
    Write-Host "Using managed identity $ManagedIdentityClientId"
} else {
    if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
        throw 'Az.Accounts module not found. Install it with: Install-Module Az.Accounts -Scope CurrentUser'
    }
    Import-Module Az.Accounts
    $ctx = Get-AzContext
    if (-not $ctx -or ($TenantId -and $ctx.Tenant.Id -ne $TenantId)) {
        $p = @{}; if ($TenantId) { $p.TenantId = $TenantId }
        Connect-AzAccount @p | Out-Null
        $ctx = Get-AzContext
    }
    if (-not $TenantId) { $TenantId = $ctx.Tenant.Id }
}

$now = [datetime]::UtcNow
$start = $now.AddDays(-$Days)
$reportTime = Format-Date $now

Write-Host 'Retrieving subscriptions...' -ForegroundColor Cyan
$subs = @(Invoke-RestPaged -Uri "$Arm/subscriptions?api-version=2022-12-01" |
    Where-Object { (Get-Prop $_ 'tenantId') -eq $TenantId -and (Get-Prop $_ 'state') -in 'Enabled', 'PastDue', 'Warned' })
if ($SubscriptionId) { $subs = @($subs | Where-Object { $_.subscriptionId -in $SubscriptionId }) }
Write-Host "  $($subs.Count) subscriptions in tenant $TenantId."
$subNames = @{}; foreach ($s in $subs) { $subNames[$s.subscriptionId.ToLowerInvariant()] = $s.displayName }

#endregion

#region Inventory ------------------------------------------------------------------

$rows = [System.Collections.Generic.List[object]]::new()
$inventory = @{}      # lower(resourceId) -> resource info
$subStatus = @{}      # subscriptionId -> @{ Events; Resources; Errors }

foreach ($s in $subs) {
    $sid = $s.subscriptionId
    $subStatus[$sid] = @{ Events = 0; Resources = 0; Errors = [System.Collections.Generic.List[string]]::new() }
    Write-Host "Inventory: $($s.displayName)" -ForegroundColor Cyan
    try {
        foreach ($rg in Invoke-RestPaged -Uri "$Arm/subscriptions/$sid/resourcegroups?api-version=2021-04-01") {
            $inventory[$rg.id.ToLowerInvariant()] = [pscustomobject]@{ Id = $rg.id; Name = $rg.name; Type = 'Microsoft.Resources/resourceGroups'
                Location = $rg.location; Sub = $sid; Rg = $rg.name; Created = $null; Changed = $null; Tags = (Get-Prop $rg 'tags') }
        }
        foreach ($r in Invoke-RestPaged -Uri "$Arm/subscriptions/$sid/resources?api-version=2021-04-01&`$expand=createdTime,changedTime") {
            $parts = Split-ResourceId $r.id
            $inventory[$r.id.ToLowerInvariant()] = [pscustomobject]@{ Id = $r.id; Name = $r.name; Type = $r.type; Location = (Get-Prop $r 'location')
                Sub = $sid; Rg = $parts.ResourceGroup; Created = (ConvertTo-UtcDate (Get-Prop $r 'createdTime'))
                Changed = (ConvertTo-UtcDate (Get-Prop $r 'changedTime')); Tags = (Get-Prop $r 'tags') }
            $subStatus[$sid].Resources++
        }
    } catch {
        $subStatus[$sid].Errors.Add("Inventory: $($_.Exception.Message)")
        Write-Warning "  Could not read resources in $($s.displayName): $($_.Exception.Message)"
    }
}
Write-Host "  $($inventory.Count) resources and resource groups."

#endregion

#region Activity Log ---------------------------------------------------------------

$events = [System.Collections.Generic.List[object]]::new()
$select = 'eventTimestamp,caller,claims,authorization,operationName,resourceId,status,category,correlationId,httpRequest,subscriptionId,resourceGroupName,eventDataId,operationId'
foreach ($s in $subs) {
    $sid = $s.subscriptionId
    Write-Host "Activity Log: $($s.displayName)" -ForegroundColor Cyan
    # Read a day at a time - keeps each request small for busy subscriptions
    for ($dayStart = $start; $dayStart -lt $now; $dayStart = $dayStart.AddDays(1)) {
        $dayEnd = if ($dayStart.AddDays(1) -lt $now) { $dayStart.AddDays(1) } else { $now }
        $filter = "eventTimestamp ge '$(Format-Date $dayStart)' and eventTimestamp le '$(Format-Date $dayEnd)'"
        $uri = "$Arm/subscriptions/$sid/providers/Microsoft.Insights/eventtypes/management/values?api-version=2015-04-01&`$filter=$([uri]::EscapeDataString($filter))&`$select=$select"
        Write-Progress -Activity "Activity Log: $($s.displayName)" -Status (Format-Date $dayStart) -PercentComplete ((($dayStart - $start).TotalDays / $Days) * 100)
        try {
            foreach ($e in Invoke-RestPaged -Uri $uri) {
                if ((Get-Prop (Get-Prop $e 'category') 'value') -ne 'Administrative') { continue }
                $status = [string](Get-Prop (Get-Prop $e 'status') 'value')
                if (-not ($status -eq 'Succeeded' -or ($IncludeFailed -and $status -eq 'Failed'))) { continue }
                $action = [string](Get-Prop (Get-Prop $e 'authorization') 'action')
                if (-not $action) { $action = [string](Get-Prop (Get-Prop $e 'operationName') 'value') }
                $kind = if ($action -match '/delete$') { 'Delete' } elseif ($action -match '/write$') { 'Write' } elseif ($action -match '/action$') { 'Action' } else { 'Other' }
                if ($kind -eq 'Other' -or ($kind -eq 'Action' -and -not $IncludeActions)) { continue }
                $e | Add-Member -NotePropertyName '_kind' -NotePropertyValue $kind -Force
                $e | Add-Member -NotePropertyName '_action' -NotePropertyValue $action -Force
                $e | Add-Member -NotePropertyName '_status' -NotePropertyValue $status -Force
                $events.Add($e)
                $subStatus[$sid].Events++
            }
        } catch {
            $subStatus[$sid].Errors.Add("Activity Log $(Format-Date $dayStart): $($_.Exception.Message)")
            Write-Warning "  $($_.Exception.Message)"
            break
        }
    }
    Write-Progress -Activity "Activity Log: $($s.displayName)" -Completed
}
Write-Host "  $($events.Count) change events."

#endregion

#region Resource Graph change details ----------------------------------------------

$argChanges = @{}   # lower(resourceId) -> list of @{ Time; Type; Props; By }
if (-not $SkipResourceGraphChanges -and $subs.Count) {
    Write-Host 'Retrieving Resource Graph change details (last 14 days)...' -ForegroundColor Cyan
    $query = @"
resourcechanges
| extend ts = todatetime(properties.changeAttributes.timestamp), changeType = tostring(properties.changeType),
         targetId = tolower(tostring(properties.targetResourceId)), changedBy = tostring(properties.changeAttributes.changedBy),
         changes = properties.changes
| where ts > ago($([math]::Min($Days, 14))d)
| project ts, changeType, targetId, changedBy, changes
"@
    $subIds = @($subs | ForEach-Object { $_.subscriptionId })
    try {
        for ($i = 0; $i -lt $subIds.Count; $i += 1000) {
            $batch = @($subIds[$i..([math]::Min($i + 999, $subIds.Count - 1))])
            $skip = $null
            do {
                $body = @{ subscriptions = $batch; query = $query; options = @{ '$top' = 1000 } }
                if ($skip) { $body.options['$skipToken'] = $skip }
                $res = Invoke-Rest -Uri "$Arm/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01" -Method POST -Payload ($body | ConvertTo-Json -Depth 5)
                foreach ($c in @(Get-Prop $res 'data')) {
                    if ($null -eq $c) { continue }
                    $props = @()
                    $ch = Get-Prop $c 'changes'
                    if ($ch) { $props = @($ch.PSObject.Properties | ForEach-Object { $_.Name }) }
                    $key = [string]$c.targetId
                    if (-not $argChanges.ContainsKey($key)) { $argChanges[$key] = [System.Collections.Generic.List[object]]::new() }
                    $argChanges[$key].Add([pscustomobject]@{ Time = (ConvertTo-UtcDate $c.ts); Type = [string]$c.changeType; Props = $props; By = [string]$c.changedBy })
                }
                $skip = Get-Prop $res '$skipToken'
            } while ($skip)
        }
        Write-Host "  Change details for $($argChanges.Count) resources."
    } catch {
        Write-Warning "Resource Graph query failed, continuing without property-level details: $($_.Exception.Message)"
    }
}

#endregion

#region Callers ---------------------------------------------------------------------

$appNames = @{}
function Resolve-AppName {
    param([string]$AppId)
    if ($appNames.ContainsKey($AppId)) { return $appNames[$AppId] }
    $name = $null
    try {
        $r = Invoke-ApiRequest -Uri "https://graph.microsoft.com/v1.0/servicePrincipals(appId='$AppId')?`$select=displayName,servicePrincipalType" -Method GET
        if ([int]$r.StatusCode -eq 200) { $j = $r.Content | ConvertFrom-Json; $name = $j.displayName }
    } catch { }
    $appNames[$AppId] = $name
    return $name
}

function Get-Caller {
    <# Works out who made the change: name, identifier and type. #>
    param($Evt)
    $caller = [string](Get-Prop $Evt 'caller')
    $claims = Get-Prop $Evt 'claims'
    $idtyp = [string](Get-Prop $claims 'idtyp')
    $miResource = [string](Get-Prop $claims 'xms_mirid')
    $appid = [string](Get-Prop $claims 'appid')
    if (-not $caller -and $appid) { $caller = $appid }
    if ($miResource) {
        return @{ Id = $caller; Name = ($miResource -split '/')[-1]; Type = 'Managed identity'; App = '' }
    }
    if ($caller -match '@') {
        $name = [string](Get-Prop $claims 'name')
        $via = if ($appid) { Resolve-AppName $appid } else { $null }
        return @{ Id = $caller; Name = $(if ($name) { $name } else { $caller }); Type = 'User'; App = $(if ($via) { $via } else { '' }) }
    }
    if ($idtyp -eq 'app' -or $caller -match '^[0-9a-fA-F-]{36}$') {
        $lookup = if ($appid) { $appid } else { $caller }
        $name = Resolve-AppName $lookup
        return @{ Id = $caller; Name = $(if ($name) { $name } else { $caller }); Type = 'Service principal'; App = '' }
    }
    return @{ Id = $caller; Name = $(if ($caller) { $caller } else { 'Unknown' }); Type = $(if ($caller) { 'Other' } else { 'Unknown' }); App = '' }
}

#endregion

#region Build change rows -----------------------------------------------------------

Write-Host 'Analysing changes...' -ForegroundColor Cyan
# Deployment names by correlation ID
$deployments = @{}
foreach ($e in $events) {
    if ($e._action -like 'Microsoft.Resources/deployments/write') {
        $deployments[[string](Get-Prop $e 'correlationId')] = ([string](Get-Prop $e 'resourceId') -split '/')[-1]
    }
}

# Keep one event per operation (the activity log can repeat a Succeeded event)
$seen = @{}
$changes = [System.Collections.Generic.List[object]]::new()
foreach ($e in ($events | Sort-Object { ConvertTo-UtcDate (Get-Prop $_ 'eventTimestamp') })) {
    $rid = [string](Get-Prop $e 'resourceId')
    if (-not $rid) { continue }
    $corr = [string](Get-Prop $e 'correlationId')
    $key = "$corr|$($rid.ToLowerInvariant())|$($e._action)|$($e._status)"
    if ($seen.ContainsKey($key)) { continue }
    $seen[$key] = $true
    $when = ConvertTo-UtcDate (Get-Prop $e 'eventTimestamp')
    $lid = $rid.ToLowerInvariant()
    $inv = $inventory[$lid]
    $parts = Split-ResourceId $rid

    # Create vs update
    $changeType = switch ($e._kind) { 'Delete' { 'Delete' } 'Action' { 'Action' } default { 'Update' } }
    $props = @()
    $argMatch = $null
    if ($argChanges.ContainsKey($lid)) {
        $argMatch = $argChanges[$lid] | Where-Object { $_.Time -and [math]::Abs(($_.Time - $when).TotalMinutes) -le 10 } |
            Sort-Object { [math]::Abs(($_.Time - $when).TotalSeconds) } | Select-Object -First 1
    }
    if ($e._kind -eq 'Write') {
        if ($argMatch -and $argMatch.Type -eq 'Create') { $changeType = 'Create' }
        elseif ($inv -and $inv.Created -and [math]::Abs(($inv.Created - $when).TotalMinutes) -le $CreateMatchMinutes) { $changeType = 'Create' }
        elseif (-not $inv) { $changeType = 'Create or update' }   # resource no longer exists - can't tell
    }
    if ($argMatch) { $props = @($argMatch.Props) }
    if ($e._action -like 'Microsoft.Resources/deployments/*') { $changeType = 'Deployment' }

    $c = Get-Caller $e
    $c.Oid = [string](Get-Prop (Get-Prop $e 'claims') 'http://schemas.microsoft.com/identity/claims/objectidentifier')
    $c.AppId = [string](Get-Prop (Get-Prop $e 'claims') 'appid')
    $changes.Add([pscustomobject]@{
        When = $when; Id = $rid; LId = $lid; Sub = $(if ($parts.Subscription) { $parts.Subscription } else { [string](Get-Prop $e 'subscriptionId') })
        Rg = $(if ($parts.ResourceGroup) { $parts.ResourceGroup } else { [string](Get-Prop $e 'resourceGroupName') })
        Type = $(if ($inv) { $inv.Type } else { $parts.Type }); Name = $(if ($inv) { $inv.Name } else { $parts.Name })
        Operation = $e._action; OperationName = [string](Get-Prop (Get-Prop $e 'operationName') 'localizedValue')
        ChangeType = $changeType; Status = $e._status; Caller = $c; Ip = [string](Get-Prop (Get-Prop $e 'httpRequest') 'clientIpAddress')
        Correlation = $corr; Deployment = $(if ($deployments.ContainsKey($corr) -and $changeType -ne 'Deployment') { $deployments[$corr] } else { '' })
        Props = $props
    })
}

$empty = [ordered]@{
    RecordType = ''; EventTime = ''; SubscriptionId = ''; SubscriptionName = ''; ResourceGroup = ''; ResourceName = ''; ResourceType = ''
    ResourceId = ''; Location = ''; ChangeType = ''; Operation = ''; OperationName = ''; Status = ''; Caller = ''; CallerName = ''; CallerType = ''
    CallerApp = ''; ClientIp = ''; Deployment = ''; CorrelationId = ''; ChangedProperties = ''; ResourceExists = ''
    CreatedTime = ''; CreatedBy = ''; CreatedBySource = ''; LastChangedTime = ''; LastChangedBy = ''; ChangesInPeriod = ''
    Events = ''; Resources = ''; Errors = ''
    DirectOwners = ''; DirectOwnerCount = ''; ValidDirectOwnerCount = ''; OwnershipStatus = ''; InheritedOwners = ''
    AssignmentId = ''; Scope = ''; ScopeType = ''; RoleName = ''; RoleType = ''; RoleIsPrivileged = ''; PrincipalId = ''; PrincipalName = ''
    PrincipalType = ''; PrincipalUpn = ''; PrincipalStatus = ''; ChangesInScope = ''; AuthorizationChanges = ''; ResourceGroupsChanged = ''
    ProvidersTouched = ''; LastChangeInScope = ''; Findings = ''; Severity = ''; Suggestion = ''
    PeriodStartUtc = (Format-Date $start); ReportGeneratedUtc = $reportTime
}
function New-Row([hashtable]$Values) { $r = [ordered]@{}; foreach ($k in $empty.Keys) { $r[$k] = $empty[$k] }; foreach ($k in $Values.Keys) { $r[$k] = $Values[$k] }; [pscustomobject]$r }

foreach ($c in $changes) {
    $rows.Add((New-Row @{
        RecordType = 'Change'; EventTime = (Format-Date $c.When); SubscriptionId = $c.Sub; SubscriptionName = $subNames[$c.Sub.ToLowerInvariant()]
        ResourceGroup = $c.Rg; ResourceName = $c.Name; ResourceType = $c.Type; ResourceId = $c.Id
        Location = $(if ($inventory[$c.LId]) { $inventory[$c.LId].Location } else { '' })
        ChangeType = $c.ChangeType; Operation = $c.Operation; OperationName = $c.OperationName; Status = $c.Status
        Caller = $c.Caller.Id; CallerName = $c.Caller.Name; CallerType = $c.Caller.Type; CallerApp = $c.Caller.App; ClientIp = $c.Ip
        Deployment = $c.Deployment; CorrelationId = $c.Correlation; ChangedProperties = ($c.Props -join '; ')
        ResourceExists = [bool]$inventory[$c.LId]
    }))
}

# Resource rows: who created / last changed each resource
$byResource = @{}
foreach ($c in $changes) { if (-not $byResource.ContainsKey($c.LId)) { $byResource[$c.LId] = [System.Collections.Generic.List[object]]::new() }; $byResource[$c.LId].Add($c) }
foreach ($key in $inventory.Keys) {
    $inv = $inventory[$key]
    $list = @(if ($byResource.ContainsKey($key)) { $byResource[$key] | Where-Object { $_.ChangeType -notin 'Action', 'Deployment' } })
    $create = $list | Where-Object { $_.ChangeType -eq 'Create' } | Select-Object -First 1
    $last = $list | Select-Object -Last 1
    $createdBy = ''; $createdSrc = ''
    if ($create) { $createdBy = $create.Caller.Name; $createdSrc = 'Activity Log' }
    elseif ($CreatorTagName -and $inv.Tags -and (Get-Prop $inv.Tags $CreatorTagName)) { $createdBy = [string](Get-Prop $inv.Tags $CreatorTagName); $createdSrc = "Tag '$CreatorTagName'" }
    elseif ($inv.Created -and $inv.Created -lt $start) { $createdSrc = 'Before report period' }
    $rows.Add((New-Row @{
        RecordType = 'Resource'; SubscriptionId = $inv.Sub; SubscriptionName = $subNames[$inv.Sub.ToLowerInvariant()]; ResourceGroup = $inv.Rg
        ResourceName = $inv.Name; ResourceType = $inv.Type; ResourceId = $inv.Id; Location = $inv.Location; ResourceExists = $true
        CreatedTime = (Format-Date $inv.Created); CreatedBy = $createdBy; CreatedBySource = $createdSrc
        LastChangedTime = $(if ($last) { Format-Date $last.When } else { Format-Date $inv.Changed })
        LastChangedBy = $(if ($last) { $last.Caller.Name } else { '' }); ChangesInPeriod = $list.Count
    }))
}

#region Role assignments & subscription owners ---------------------------------------

$assignments = [ordered]@{}   # lower(assignmentId) -> raw assignment
$roleDefs = @{}               # lower(role GUID) -> role info
$rbacRead = @{}               # subscriptionId -> $true when assignments were read
$seenIn = @{}                 # lower(assignmentId) -> subscriptions it applies to (for inherited ones)
$PrivilegedBuiltIn = @{
    '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' = 'Owner'
    'b24988ac-6180-42a0-ab88-20f7382dd24c' = 'Contributor'
    '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9' = 'User Access Administrator'
    'f58310d9-a9f6-439a-9e8d-f62e7b41a168' = 'Role Based Access Control Administrator'
}
$OwnerRoleId = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'

function Add-RoleDefinition($Def) {
    $guid = ([string]$Def.id -split '/')[-1].ToLowerInvariant()
    $pr = Get-Prop $Def 'properties'
    $actions = @(); $notActions = @()
    foreach ($perm in @(Get-Prop $pr 'permissions')) {
        if ($null -eq $perm) { continue }
        $actions += @(Get-Prop $perm 'actions') | Where-Object { $_ }
        $notActions += @(Get-Prop $perm 'notActions') | Where-Object { $_ }
    }
    $grants = { param($op) [bool](@($actions | Where-Object { $op -like $_ }).Count) -and -not @($notActions | Where-Object { $op -like $_ }).Count }
    $all = '*' -in $actions
    $rbac = & $grants 'Microsoft.Authorization/roleAssignments/write'
    $type = [string](Get-Prop $pr 'type')
    $roleDefs[$guid] = [pscustomobject]@{
        Id = $guid; Name = [string](Get-Prop $pr 'roleName'); Type = $(if ($type -eq 'CustomRole') { 'Custom' } else { 'Built-in' })
        AllActions = $all; GrantsRbac = $rbac
        Privileged = ($PrivilegedBuiltIn.ContainsKey($guid) -or $all -or $rbac)
    }
}

function Get-ScopeType([string]$Scope) {
    if ($Scope -eq '/') { return 'Root' }
    if ($Scope -match '^/providers/Microsoft\.Management/managementGroups/[^/]+$') { return 'Management group' }
    if ($Scope -match '^/subscriptions/[^/]+$') { return 'Subscription' }
    if ($Scope -match '^/subscriptions/[^/]+/resourceGroups/[^/]+$') { return 'Resource group' }
    return 'Resource'
}

if (-not $SkipRoleAssignments) {
    foreach ($s in $subs) {
        $sid = $s.subscriptionId
        Write-Host "Role assignments: $($s.displayName)" -ForegroundColor Cyan
        try {
            foreach ($d in Invoke-RestPaged -Uri "$Arm/subscriptions/$sid/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01") {
                $g = ([string]$d.id -split '/')[-1].ToLowerInvariant()
                if (-not $roleDefs.ContainsKey($g)) { Add-RoleDefinition $d }
            }
            # No filter: assignments at, above (management group / root) and below the subscription
            foreach ($a in Invoke-RestPaged -Uri "$Arm/subscriptions/$sid/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01") {
                $lid = ([string]$a.id).ToLowerInvariant()
                $assignments[$lid] = $a
                if (-not $seenIn.ContainsKey($lid)) { $seenIn[$lid] = [System.Collections.Generic.HashSet[string]]::new() }
                [void]$seenIn[$lid].Add($sid.ToLowerInvariant())
            }
            $rbacRead[$sid] = $true
        } catch {
            $subStatus[$sid].Errors.Add("Role assignments: $($_.Exception.Message)")
            Write-Warning "  Could not read role assignments in $($s.displayName): $($_.Exception.Message)"
        }
    }
    # Role definitions not listed at subscription scope (e.g. custom roles defined higher up)
    foreach ($a in $assignments.Values) {
        $rdId = [string](Get-Prop (Get-Prop $a 'properties') 'roleDefinitionId')
        $g = ($rdId -split '/')[-1].ToLowerInvariant()
        if ($roleDefs.ContainsKey($g)) { continue }
        try { Add-RoleDefinition (Invoke-Rest -Uri "$Arm$rdId`?api-version=2022-04-01") }
        catch { $roleDefs[$g] = [pscustomobject]@{ Id = $g; Name = "Unknown role ($g)"; Type = 'Unknown'; AllActions = $false; GrantsRbac = $false; Privileged = $false } }
    }
    Write-Host "  $($assignments.Count) role assignments."

    # --- Principals (Microsoft Graph, 20 per batch) ---
    $principals = @{}   # principalId -> @{ Name; Upn; Type; Status; Enabled; Guest; AppId; Members }
    $wanted = @{}
    foreach ($a in $assignments.Values) {
        $pr = Get-Prop $a 'properties'
        $wanted[[string](Get-Prop $pr 'principalId')] = [string](Get-Prop $pr 'principalType')
    }
    $ids = @($wanted.Keys)
    if ($ids.Count) { Write-Host "Resolving $($ids.Count) principals..." -ForegroundColor Cyan }
    $graphOk = $true
    for ($i = 0; $i -lt $ids.Count -and $graphOk; $i += 20) {
        $pending = @($ids[$i..([math]::Min($i + 19, $ids.Count - 1))])
        for ($attempt = 1; $pending.Count -and $attempt -le 5; $attempt++) {
            $reqs = foreach ($id in $pending) {
                $url = switch ($wanted[$id]) {
                    'User' { "/users/$id`?`$select=id,displayName,userPrincipalName,accountEnabled,userType" }
                    'Group' { "/groups/$id`?`$select=id,displayName" }
                    'ServicePrincipal' { "/servicePrincipals/$id`?`$select=id,displayName,appId,accountEnabled,servicePrincipalType" }
                    default { "/directoryObjects/$id" }
                }
                @{ id = $id; method = 'GET'; url = $url }
            }
            try {
                $resp = Invoke-Rest -Uri 'https://graph.microsoft.com/v1.0/$batch' -Method POST -Payload (@{ requests = @($reqs) } | ConvertTo-Json -Depth 4)
            } catch {
                Write-Warning "Could not resolve principals in Microsoft Graph, account status will be 'Unknown': $($_.Exception.Message)"
                $graphOk = $false; break
            }
            $retry = @(); $wait = 0
            foreach ($r in @(Get-Prop $resp 'responses')) {
                if ($null -eq $r) { continue }
                $id = [string](Get-Prop $r 'id'); $code = [int](Get-Prop $r 'status'); $b = Get-Prop $r 'body'
                $ptype = $wanted[$id]
                if ($code -eq 200) {
                    $enabled = Get-Prop $b 'accountEnabled'
                    $odt = [string](Get-Prop $b '@odata.type')
                    if ($ptype -notin 'User', 'Group', 'ServicePrincipal' -and $odt) { $ptype = ($odt -replace '^#microsoft\.graph\.', '') }
                    $spType = [string](Get-Prop $b 'servicePrincipalType')
                    $principals[$id] = @{
                        Name = [string](Get-Prop $b 'displayName'); Upn = [string](Get-Prop $b 'userPrincipalName'); AppId = [string](Get-Prop $b 'appId')
                        Type = $(if ($ptype -eq 'ServicePrincipal' -and $spType -eq 'ManagedIdentity') { 'Managed identity' } elseif ($ptype -eq 'ServicePrincipal') { 'Service principal' } else { $ptype })
                        Enabled = $(if ($null -eq $enabled) { $true } else { [bool]$enabled })
                        Guest = ([string](Get-Prop $b 'userType') -eq 'Guest')
                        Status = $(if ($null -ne $enabled -and -not $enabled) { 'Disabled' } else { 'Enabled' }); Members = $null
                    }
                }
                elseif ($code -eq 404) { $principals[$id] = @{ Name = ''; Upn = ''; AppId = ''; Type = $ptype; Enabled = $false; Guest = $false; Status = 'Deleted'; Members = $null } }
                elseif ($code -eq 429 -or $code -ge 500) {
                    $retry += $id
                    $ra = Get-Prop (Get-Prop $r 'headers') 'Retry-After'
                    $wait = [math]::Max($wait, $(if ($ra) { [int]$ra } else { 5 }))
                }
                else { Write-Verbose "Principal ${id}: HTTP $code" }
            }
            $pending = $retry
            if ($pending.Count -and $wait) { Start-Sleep -Seconds $wait }
        }
    }

    # Members of groups that hold privileged roles: owners need a real person behind them,
    # and members' changes count as use of the group's role.
    function Get-GroupMembers([string]$GroupId) {
        $p = $principals[$GroupId]
        if (-not $p -or $p.Status -ne 'Enabled') { return @() }
        if ($null -eq $p.Members) {
            $list = [System.Collections.Generic.List[object]]::new()
            try {
                $next = "https://graph.microsoft.com/v1.0/groups/$GroupId/transitiveMembers?`$select=id,displayName,userPrincipalName,accountEnabled,appId&`$top=999"
                for ($page = 0; $next -and $page -lt 20; $page++) {
                    $res = Invoke-Rest -Uri $next
                    foreach ($m in @(Get-Prop $res 'value')) {
                        if ($null -eq $m) { continue }
                        $odt = [string](Get-Prop $m '@odata.type')
                        if ($odt -and $odt -notin '#microsoft.graph.user', '#microsoft.graph.servicePrincipal') { continue }
                        $en = Get-Prop $m 'accountEnabled'
                        $list.Add(@{ Id = [string](Get-Prop $m 'id'); Upn = [string](Get-Prop $m 'userPrincipalName'); AppId = [string](Get-Prop $m 'appId')
                            IsUser = ($odt -ne '#microsoft.graph.servicePrincipal'); Enabled = ($null -eq $en -or [bool]$en) })
                    }
                    $next = Get-Prop $res '@odata.nextLink'
                }
                $p.Members = $list.ToArray()
            } catch {
                Write-Verbose "Members of group ${GroupId}: $($_.Exception.Message)"
                $p.Members = @()
                $p.MembersUnknown = $true
            }
        }
        return @($p.Members)
    }

    # --- Index changes by who made them ---
    $changesBy = @{}
    for ($ci = 0; $ci -lt $changes.Count; $ci++) {
        $c = $changes[$ci]
        if ($c.Status -ne 'Succeeded') { continue }
        foreach ($k in @($c.Caller.Oid, $c.Caller.Id, $c.Caller.AppId) | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique) {
            if (-not $changesBy.ContainsKey($k)) { $changesBy[$k] = [System.Collections.Generic.List[int]]::new() }
            $changesBy[$k].Add($ci)
        }
    }
    function Get-ChangesBy([string[]]$Keys) {
        $set = [System.Collections.Generic.HashSet[int]]::new()
        foreach ($k in $Keys) {
            if (-not $k) { continue }
            $l = $changesBy[$k.ToLowerInvariant()]
            if ($l) { foreach ($x in $l) { [void]$set.Add($x) } }
        }
        return $set
    }
    $sevRank = @{ None = 0; Low = 1; Medium = 2; High = 3 }

    # --- Assess each assignment ---
    $assessed = [System.Collections.Generic.List[object]]::new()
    foreach ($a in $assignments.Values) {
        $pr = Get-Prop $a 'properties'
        $scope = [string](Get-Prop $pr 'scope')
        $scopeType = Get-ScopeType $scope
        $role = $roleDefs[([string](Get-Prop $pr 'roleDefinitionId') -split '/')[-1].ToLowerInvariant()]
        $pid_ = [string](Get-Prop $pr 'principalId')
        $p = $principals[$pid_]
        if (-not $p) { $p = @{ Name = ''; Upn = ''; AppId = ''; Type = $wanted[$pid_]; Enabled = $true; Guest = $false; Status = 'Unknown'; Members = $null } }
        if ($p.Type -eq 'ServicePrincipal') { $p.Type = 'Service principal' }
        $isGroup = $p.Type -eq 'Group'
        $members = @(if ($isGroup -and ($role.Privileged -or $role.Id -eq $OwnerRoleId)) { Get-GroupMembers $pid_ })

        # Changes the principal (or, for a group, its members) made within the assignment's scope
        $keys = if ($isGroup) { @($members | ForEach-Object { $_.Id; $_.Upn; $_.AppId }) } else { @($pid_, $p.Upn, $p.AppId) }
        $idx = Get-ChangesBy $keys
        $lscope = $scope.ToLowerInvariant().TrimEnd('/')
        $inScope = @(foreach ($x in $idx) {
            $c = $changes[$x]
            if (($scopeType -in 'Root', 'Management group' -and $seenIn[([string]$a.id).ToLowerInvariant()].Contains($c.Sub.ToLowerInvariant())) -or
                $c.LId -eq $lscope -or $c.LId.StartsWith("$lscope/")) { $c }
        })
        $authChanges = @($inScope | Where-Object { $_.Operation -like 'Microsoft.Authorization/*' })
        $rgsChanged = @($inScope | Where-Object { $_.Rg } | ForEach-Object { "$($subNames[$_.Sub.ToLowerInvariant()])/$($_.Rg)" } | Sort-Object -Unique)
        $rgNames = @($inScope | Where-Object { $_.Rg } | ForEach-Object { $_.Rg } | Sort-Object -Unique)
        $subLevel = @($inScope | Where-Object { -not $_.Rg })
        $providers = @($inScope | ForEach-Object { ($_.Operation -split '/')[0] } | Sort-Object -Unique)
        $lastChange = $inScope | Sort-Object When -Descending | Select-Object -First 1

        $findings = [System.Collections.Generic.List[string]]::new(); $suggest = [System.Collections.Generic.List[string]]::new()
        $box = @{ Sev = 'None' }
        $flag = { param($sv, $f, $sg) $findings.Add($f); if ($sg) { $suggest.Add($sg) }; if ($sevRank[$sv] -gt $sevRank[$box.Sev]) { $box.Sev = $sv } }
        $broad = $scopeType -in 'Root', 'Management group', 'Subscription'
        $isOwnerLike = $role.Id -in '8e3af657-a8ff-443c-a75c-2fe8c4bcb635', '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9', 'f58310d9-a9f6-439a-9e8d-f62e7b41a168' -or ($role.Type -eq 'Custom' -and ($role.AllActions -or $role.GrantsRbac))
        # Can't judge use when the Activity Log couldn't be read for the subscription(s) in scope
        $scopeSubs = @(if ($scope -match '^/subscriptions/([^/]+)') { $Matches[1] } else { $subs | Where-Object { $seenIn[([string]$a.id).ToLowerInvariant()].Contains($_.subscriptionId.ToLowerInvariant()) } | ForEach-Object { $_.subscriptionId } })
        $logMissing = @($scopeSubs | Where-Object { -not $subStatus.ContainsKey($_) -or @($subStatus[$_].Errors | Where-Object { $_ -like 'Activity Log*' }).Count })
        $activityKnown = -not ($isGroup -and (-not $members.Count)) -and $logMissing.Count -lt $scopeSubs.Count

        if ($p.Status -eq 'Deleted') {
            & $flag $(if ($role.Privileged) { 'High' } else { 'Medium' }) 'Principal deleted' 'Remove the assignment: the identity no longer exists'
        }
        elseif ($p.Status -eq 'Disabled') {
            & $flag $(if ($role.Privileged) { 'High' } else { 'Medium' }) "Disabled $($p.Type.ToLowerInvariant()) holds the role" 'Remove the assignment: re-enabling the account would restore the access'
        }
        else {
            if ($p.Guest -and $role.Privileged) { & $flag 'High' 'Guest user with a privileged role' 'Use a member account, or a narrower role' }
            if ($role.Type -eq 'Custom' -and $role.AllActions) { & $flag $(if ($broad) { 'High' } else { 'Medium' }) "Custom role grants all actions ('*')" 'Replace with a role listing only the actions needed' }
            if ($isOwnerLike -and $p.Type -eq 'User' -and $broad) { & $flag 'Medium' "$($role.Name) assigned directly to a user at $($scopeType.ToLowerInvariant()) scope" 'Assign through a group and make it PIM-eligible rather than standing access' }
            if ($scopeType -in 'Root', 'Management group' -and $role.Privileged) { & $flag 'Low' "Privileged role at $($scopeType.ToLowerInvariant()) scope (inherited by every subscription below)" 'Assign at the subscriptions / resource groups that need it' }
            if ($role.Privileged -and $activityKnown -and $p.Status -eq 'Enabled') {
                if (-not $inScope.Count -and -not $logMissing.Count) {
                    & $flag 'Medium' "No changes made in scope in the last $Days days" "Remove, or make PIM-eligible; if it's used for data-plane or read access, a Reader / data role will do"
                }
                else {
                    if ($isOwnerLike -and -not $authChanges.Count) {
                        & $flag 'Medium' "$($role.Name) but no access-control (Microsoft.Authorization) changes made" 'Contributor (or a narrower role) covers the changes made'
                    }
                    if ($broad -and ($role.Id -in '8e3af657-a8ff-443c-a75c-2fe8c4bcb635', 'b24988ac-6180-42a0-ab88-20f7382dd24c' -or $role.AllActions) -and -not $subLevel.Count -and $rgNames.Count -le $BroadScopeResourceGroupLimit) {
                        & $flag 'Low' "$($scopeType)-wide role but changes only touched $($rgNames.Count) resource group(s)" "Scope to resource group(s): $($rgNames -join ', ')"
                    }
                }
            }
        }
        $sev = $box.Sev
        $sub = if ($scope -match '^/subscriptions/([^/]+)') { $Matches[1] } else { '' }
        $assessed.Add([pscustomobject]@{
            Id = [string]$a.id; Scope = $scope; ScopeType = $scopeType; Sub = $sub; Role = $role; PrincipalId = $pid_; P = $p; Members = $members
            InScope = $inScope.Count; Auth = $authChanges.Count; Rgs = $rgsChanged; Providers = $providers; Last = $(if ($lastChange) { $lastChange.When } else { $null })
            Findings = $findings; Suggest = $suggest; Severity = $sev; Created = (ConvertTo-UtcDate (Get-Prop $pr 'createdOn'))
            Rg = $(if ($scope -match '/resourceGroups/([^/]+)') { $Matches[1] } else { '' })
        })
    }
    $flagged = @($assessed | Where-Object { $_.Severity -ne 'None' })
    Write-Host "  $($flagged.Count) of $($assessed.Count) role assignments flagged as over-privileged or stale."
}

# Display name of a principal for the owner lists
function Get-PrincipalLabel($x) {
    $n = if ($x.P.Name) { $x.P.Name } elseif ($x.P.Upn) { $x.P.Upn } else { $x.PrincipalId }
    $t = if ($x.P.Type) { $x.P.Type } else { 'Unknown' }
    "$n ($t, $($x.P.Status))"
}

foreach ($s in $subs) {
    $st = $subStatus[$s.subscriptionId]
    $own = @{}
    if (-not $SkipRoleAssignments -and $rbacRead.ContainsKey($s.subscriptionId)) {
        $lsub = "/subscriptions/$($s.subscriptionId)".ToLowerInvariant()
        $owners = @($assessed | Where-Object { $_.Role.Id -eq $OwnerRoleId -and $_.Scope.ToLowerInvariant().TrimEnd('/') -eq $lsub })
        $inherited = @($assessed | Where-Object { $_.Role.Id -eq $OwnerRoleId -and $_.ScopeType -in 'Root', 'Management group' -and $seenIn[$_.Id.ToLowerInvariant()].Contains($s.subscriptionId.ToLowerInvariant()) })
        # A valid owner is an enabled person: an enabled user, or a group with an enabled user in it
        $valid = @($owners | Where-Object {
            ($_.P.Type -eq 'User' -and $_.P.Status -eq 'Enabled') -or
            ($_.P.Type -eq 'Group' -and $_.P.Status -eq 'Enabled' -and @($_.Members | Where-Object { $_.IsUser -and $_.Enabled }).Count)
        })
        $status = if (-not $owners.Count) { 'No direct owner' }
                  elseif (-not $valid.Count) { 'Orphaned' }
                  elseif (@($owners | Where-Object { $_.P.Status -in 'Disabled', 'Deleted' }).Count) { 'Has disabled owner(s)' }
                  else { 'OK' }
        $own = @{
            DirectOwners = (@($owners | ForEach-Object { Get-PrincipalLabel $_ }) -join '; '); DirectOwnerCount = $owners.Count
            ValidDirectOwnerCount = $valid.Count; OwnershipStatus = $status
            InheritedOwners = (@($inherited | ForEach-Object { "$(Get-PrincipalLabel $_) at $($_.Scope)" }) -join '; ')
        }
    }
    $rows.Add((New-Row (@{ RecordType = 'Subscription'; SubscriptionId = $s.subscriptionId; SubscriptionName = $s.displayName
        Events = $st.Events; Resources = $st.Resources; Errors = ($st.Errors -join ' | ') } + $own)))
}

if (-not $SkipRoleAssignments) {
    foreach ($x in $assessed) {
        $rows.Add((New-Row @{
            RecordType = 'RoleAssignment'; SubscriptionId = $x.Sub; SubscriptionName = $(if ($x.Sub) { $subNames[$x.Sub.ToLowerInvariant()] } else { '' })
            ResourceGroup = $x.Rg; ResourceId = $(if ($x.ScopeType -eq 'Resource') { $x.Scope } else { '' })
            ResourceName = $(if ($x.ScopeType -eq 'Resource') { ($x.Scope -split '/')[-1] } else { '' })
            AssignmentId = $x.Id; Scope = $x.Scope; ScopeType = $x.ScopeType; RoleName = $x.Role.Name; RoleType = $x.Role.Type; RoleIsPrivileged = $x.Role.Privileged
            PrincipalId = $x.PrincipalId; PrincipalName = $x.P.Name; PrincipalType = $x.P.Type; PrincipalUpn = $x.P.Upn; PrincipalStatus = $x.P.Status
            ChangesInScope = $x.InScope; AuthorizationChanges = $x.Auth; ResourceGroupsChanged = ($x.Rgs -join '; '); ProvidersTouched = ($x.Providers -join '; ')
            LastChangeInScope = (Format-Date $x.Last); Findings = ($x.Findings -join '; '); Severity = $x.Severity; Suggestion = ($x.Suggest -join '; ')
            CreatedTime = (Format-Date $x.Created)
        }))
    }
}

#endregion

$summary = $changes | Group-Object ChangeType | Sort-Object Count -Descending
foreach ($g in $summary) { Write-Host ("  {0,-18} {1}" -f $g.Name, $g.Count) }

#endregion

if ($OutputPath) {
    $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host "Report exported to $((Resolve-Path $OutputPath).Path)" -ForegroundColor Green
} else {
    $rows | Where-Object RecordType -eq 'Change'
}
