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

    Output is one CSV with three kinds of row (RecordType):
      Change        one row per resource change event
      Resource      one row per resource that exists now
      Subscription  one row per subscription, with any access errors

    Load it into AzureChangeDashboard.html (same folder).

    REQUIREMENTS
      * Az.Accounts module (Install-Module Az.Accounts -Scope CurrentUser)
      * Reader on the subscriptions (Reader at a management group covers them all).
        Reading the Activity Log needs Microsoft.Insights/eventtypes/* (included in Reader).
      * To show service principal / managed identity names, the signed-in account needs
        to be able to read service principals in Entra ID (any member user can by default).

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
    Events = ''; Resources = ''; Errors = ''; PeriodStartUtc = (Format-Date $start); ReportGeneratedUtc = $reportTime
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

foreach ($s in $subs) {
    $st = $subStatus[$s.subscriptionId]
    $rows.Add((New-Row @{ RecordType = 'Subscription'; SubscriptionId = $s.subscriptionId; SubscriptionName = $s.displayName
        Events = $st.Events; Resources = $st.Resources; Errors = ($st.Errors -join ' | ') }))
}

$summary = $changes | Group-Object ChangeType | Sort-Object Count -Descending
foreach ($g in $summary) { Write-Host ("  {0,-18} {1}" -f $g.Name, $g.Count) }

#endregion

if ($OutputPath) {
    $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host "Report exported to $((Resolve-Path $OutputPath).Path)" -ForegroundColor Green
} else {
    $rows | Where-Object RecordType -eq 'Change'
}
