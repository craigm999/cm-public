<#
.SYNOPSIS
    Reports App Registrations and Enterprise Applications (service principals) in an
    Entra ID (Azure AD) tenant with their last sign-in date and assigned owner(s).

.DESCRIPTION
    Uses Microsoft Graph to collect:
      * App registrations       (GET /v1.0/applications, owners expanded)
      * Enterprise applications (GET /v1.0/servicePrincipals, owners expanded)
      * Sign-in activity        (GET /beta/reports/servicePrincipalSignInActivities)

    The sign-in activity report records the most recent sign-in for every app across
    all sign-in methods:
      * Delegated (user) sign-ins where the app was the client
      * Delegated (user) sign-ins where the app was the resource
      * App-only (client credentials) sign-ins where the app was the client
      * App-only (client credentials) sign-ins where the app was the resource
    "LastSignIn" in the output is the most recent of all of these, and
    "LastSignInType" tells you which method it was.

    Sign-in activity is keyed by appId, so an app registration is reported with the
    sign-in activity of its service principal in this tenant.

    Each owner's account status is also checked (via Graph JSON batching) so that
    apps whose owners are disabled can be identified (DisabledOwnerCount,
    DisabledOwners and AllOwnersDisabled columns).

    When exported to CSV, dates are written as ISO 8601 UTC. The CSV can be loaded
    into AppSignInDashboard.html (in the same folder) to visualise it.

    REQUIREMENTS
      * Microsoft.Graph.Authentication module
          Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
      * Delegated (or application) permissions:
          Application.Read.All, Directory.Read.All, AuditLog.Read.All
      * Entra ID P1 or P2 licence (needed for the sign-in activity report)
      * A role that can read sign-in reports, e.g. Reports Reader, Security Reader
        or Global Reader.

.PARAMETER TenantId
    Tenant ID or domain to connect to. Optional when already connected.

.PARAMETER Type
    What to report on: All (default), AppRegistrations or EnterpriseApps.

.PARAMETER IncludeMicrosoftApps
    Include Microsoft first-party service principals (owned by the Microsoft
    services tenant). These are excluded by default as there are usually hundreds.

.PARAMETER IncludeManagedIdentities
    Include managed identity service principals. Excluded by default.

.PARAMETER ExcludeCopilotStudio
    Leave out apps created by Microsoft Copilot Studio (formerly Power Virtual Agents).
    Without this switch they are included and marked in the IsCopilotStudio and
    CopilotStudioSignal columns, so they can also be filtered in the dashboard.

    Detection follows Microsoft's guidance: Copilot Studio stamps tags on the service
    principals it creates (AgentCreatedBy:CopilotStudio, power-virtual-agents-<agentId>,
    AIAgentBuilder). Display names containing "Power Virtual Agents" or "Copilot Studio"
    are also matched. An app registration is marked when its service principal is, so
    use -Type All (the default) for the most complete detection.

.PARAMETER OutputPath
    Optional path to export the results to CSV.

.EXAMPLE
    .\Get-EntraAppSignInReport.ps1 -TenantId contoso.onmicrosoft.com -OutputPath .\apps.csv

.EXAMPLE
    # Apps not signed in to for 90+ days (or never)
    .\Get-EntraAppSignInReport.ps1 |
        Where-Object { $null -eq $_.LastSignIn -or $_.DaysSinceLastSignIn -ge 90 } |
        Format-Table ObjectType, DisplayName, LastSignIn, Owners

.EXAMPLE
    # Leave out Copilot Studio / Power Virtual Agents apps
    .\Get-EntraAppSignInReport.ps1 -ExcludeCopilotStudio -OutputPath .\apps.csv

.EXAMPLE
    # App-only connection with a certificate
    Connect-MgGraph -TenantId <tenant> -ClientId <appId> -CertificateThumbprint <thumb>
    .\Get-EntraAppSignInReport.ps1 -OutputPath .\apps.csv
#>
[CmdletBinding()]
param(
    [string]$TenantId,

    [ValidateSet('All', 'AppRegistrations', 'EnterpriseApps')]
    [string]$Type = 'All',

    [switch]$IncludeMicrosoftApps,

    [switch]$IncludeManagedIdentities,

    [switch]$ExcludeCopilotStudio,

    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Tenant that owns Microsoft first-party applications
$MicrosoftTenantIds = @(
    'f8cdef31-a31e-4b4a-93e4-5f571e91255a', # Microsoft Services
    '72f988bf-86f1-41af-91ab-2d7cd011db47'  # Microsoft corporate
)

# Signals that an app was created by Copilot Studio / Power Virtual Agents
$CopilotStudioTagPatterns = @(
    '^AgentCreatedBy:CopilotStudio$',
    '^power-virtual-agents-',
    '^AIAgentBuilder$'
)
$CopilotStudioNamePatterns = @('Power Virtual Agents', 'Copilot Studio')

#region Helpers ---------------------------------------------------------------

function Get-CopilotStudioSignal {
    <# Returns what identifies the object as a Copilot Studio / PVA app, or $null. #>
    param($Object)
    foreach ($tag in @(Get-Prop $Object 'tags' | Where-Object { $_ })) {
        foreach ($pattern in $CopilotStudioTagPatterns) {
            if ($tag -match $pattern) { return "Tag: $tag" }
        }
    }
    $name = [string](Get-Prop $Object 'displayName')
    foreach ($pattern in $CopilotStudioNamePatterns) {
        if ($name -like "*$pattern*") { return "Name contains '$pattern'" }
    }
    return $null
}

function Invoke-GraphPaged {
    <# Follows @odata.nextLink and emits every item in 'value'. #>
    param(
        [Parameter(Mandatory)][string]$Uri,
        [hashtable]$Headers = @{}
    )
    $next = $Uri
    while ($next) {
        $response = Invoke-MgGraphRequest -Method GET -Uri $next -Headers $Headers -OutputType Hashtable
        if ($response.ContainsKey('value')) {
            foreach ($item in $response['value']) { $item }
        }
        $next = if ($response.ContainsKey('@odata.nextLink')) { $response['@odata.nextLink'] } else { $null }
    }
}

function Get-Prop {
    <# Safe hashtable lookup (StrictMode friendly). #>
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

function ConvertTo-UtcDate {
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    try {
        return [datetime]::Parse(
            [string]$Value,
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor
            [System.Globalization.DateTimeStyles]::AssumeUniversal)
    }
    catch { return $null }
}

function Format-Owner {
    <# Returns a friendly label for an owner directory object (user or service principal). #>
    param($Owner)
    $odataType = Get-Prop $Owner '@odata.type'
    $name      = Get-Prop $Owner 'displayName'
    switch ($odataType) {
        '#microsoft.graph.user' {
            $upn = Get-Prop $Owner 'userPrincipalName'
            $label = if ($upn) { "$name <$upn>" } else { "$name" }
        }
        '#microsoft.graph.servicePrincipal' { $label = "$name (service principal)" }
        default { $label = if ($name) { "$name" } else { [string](Get-Prop $Owner 'id') } }
    }
    $id = [string](Get-Prop $Owner 'id')
    if ($script:OwnerEnabled -and $script:OwnerEnabled.ContainsKey($id) -and -not $script:OwnerEnabled[$id]) {
        $label += ' [disabled]'
    }
    return $label
}

function Get-Owners {
    <#
        Returns owners for an object. Uses the expanded owners where possible, but
        $expand is capped at 20 items, so fetch the full list when we hit that cap.
    #>
    param($Object, [ValidateSet('applications', 'servicePrincipals')][string]$Collection)
    $owners = @(Get-Prop $Object 'owners' | Where-Object { $_ })
    if ($owners.Count -ge 20) {
        $owners = @(Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/$Collection/$($Object['id'])/owners?`$top=999")
    }
    return , $owners
}

function Get-SignInSummary {
    <# Works out the most recent sign-in across all methods for an appId. #>
    param([string]$AppId)

    $result = [ordered]@{
        LastSignIn                    = $null
        LastSignInType                = $null
        LastDelegatedClientSignIn     = $null
        LastDelegatedResourceSignIn   = $null
        LastAppOnlyClientSignIn       = $null
        LastAppOnlyResourceSignIn     = $null
    }
    if (-not $script:SignInLookup -or -not $AppId -or -not $script:SignInLookup.ContainsKey($AppId)) {
        return $result
    }
    $activity = $script:SignInLookup[$AppId]

    $map = [ordered]@{
        LastDelegatedClientSignIn   = @{ Prop = 'delegatedClientSignInActivity';                  Label = 'Delegated (client)' }
        LastDelegatedResourceSignIn = @{ Prop = 'delegatedResourceSignInActivity';                Label = 'Delegated (resource)' }
        LastAppOnlyClientSignIn     = @{ Prop = 'applicationAuthenticationClientSignInActivity';  Label = 'App-only (client)' }
        LastAppOnlyResourceSignIn   = @{ Prop = 'applicationAuthenticationResourceSignInActivity'; Label = 'App-only (resource)' }
    }

    foreach ($key in $map.Keys) {
        $date = ConvertTo-UtcDate (Get-Prop (Get-Prop $activity $map[$key].Prop) 'lastSignInDateTime')
        $result[$key] = $date
        if ($date -and (-not $result.LastSignIn -or $date -gt $result.LastSignIn)) {
            $result.LastSignIn     = $date
            $result.LastSignInType = $map[$key].Label
        }
    }

    # Overall value reported by Graph (covers anything not broken out above)
    $overall = ConvertTo-UtcDate (Get-Prop (Get-Prop $activity 'lastSignInActivity') 'lastSignInDateTime')
    if ($overall -and (-not $result.LastSignIn -or $overall -gt $result.LastSignIn)) {
        $result.LastSignIn     = $overall
        $result.LastSignInType = 'Any'
    }
    return $result
}

#endregion

#region Connect ---------------------------------------------------------------

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    throw "Microsoft.Graph.Authentication module not found. Install it with: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser"
}
Import-Module Microsoft.Graph.Authentication

$requiredScopes = @('Application.Read.All', 'Directory.Read.All', 'AuditLog.Read.All')
$context = Get-MgContext
if (-not $context -or ($TenantId -and $context.TenantId -ne $TenantId)) {
    $connectParams = @{ Scopes = $requiredScopes; NoWelcome = $true }
    if ($TenantId) { $connectParams.TenantId = $TenantId }
    Connect-MgGraph @connectParams
    $context = Get-MgContext
}
Write-Verbose "Connected to tenant $($context.TenantId) as $($context.Account)$($context.AppName)"

#endregion

#region Sign-in activity ------------------------------------------------------

Write-Host 'Retrieving service principal sign-in activity...' -ForegroundColor Cyan
$script:SignInLookup = @{}
$signInDataAvailable = $true
try {
    foreach ($a in Invoke-GraphPaged -Uri 'https://graph.microsoft.com/beta/reports/servicePrincipalSignInActivities') {
        $appId = Get-Prop $a 'appId'
        if ($appId) { $script:SignInLookup[$appId] = $a }
    }
    Write-Host "  $($script:SignInLookup.Count) sign-in activity records found."
}
catch {
    $signInDataAvailable = $false
    Write-Warning ("Could not read sign-in activity (requires AuditLog.Read.All, a reports reader role " +
                   "and an Entra ID P1/P2 licence). Sign-in columns will be empty. Error: $($_.Exception.Message)")
}

#endregion

$pending = [System.Collections.Generic.List[object]]::new()
$results = [System.Collections.Generic.List[object]]::new()
$now = [datetime]::UtcNow
$script:OwnerEnabled = @{}

function Resolve-OwnerAccountStatus {
    <#
        Looks up accountEnabled for every distinct owner (users and service principals)
        using Graph JSON batching (20 requests per batch). Results go in $script:OwnerEnabled.
    #>
    param([object[]]$OwnerObjects)

    $todo = @{}
    foreach ($o in $OwnerObjects) {
        $id = [string](Get-Prop $o 'id')
        if (-not $id -or $todo.ContainsKey($id) -or $script:OwnerEnabled.ContainsKey($id)) { continue }
        $enabled = Get-Prop $o 'accountEnabled'
        if ($null -ne $enabled) { $script:OwnerEnabled[$id] = [bool]$enabled; continue }
        $collection = switch (Get-Prop $o '@odata.type') {
            '#microsoft.graph.user'             { 'users' }
            '#microsoft.graph.servicePrincipal' { 'servicePrincipals' }
            default                             { $null }
        }
        if ($collection) { $todo[$id] = $collection }
    }
    if ($todo.Count -eq 0) { return }

    Write-Host "Checking account status of $($todo.Count) owner(s)..." -ForegroundColor Cyan
    $ids = @($todo.Keys)
    for ($i = 0; $i -lt $ids.Count; $i += 20) {
        $chunk = $ids[$i..([math]::Min($i + 19, $ids.Count - 1))]
        $attempt = 0
        while ($chunk.Count -gt 0 -and $attempt -lt 5) {
            $attempt++
            $requests = @(foreach ($id in $chunk) {
                @{ id = $id; method = 'GET'; url = "/$($todo[$id])/$($id)?`$select=id,accountEnabled" }
            })
            $body = @{ requests = $requests } | ConvertTo-Json -Depth 5
            $resp = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/$batch' `
                        -Body $body -ContentType 'application/json' -OutputType Hashtable
            $retry = @()
            $wait = 0
            foreach ($r in $resp['responses']) {
                $status = [int]$r['status']
                if ($status -eq 200) {
                    $script:OwnerEnabled[[string]$r['id']] = [bool](Get-Prop $r['body'] 'accountEnabled')
                }
                elseif ($status -eq 429 -or $status -ge 500) {
                    $retry += [string]$r['id']
                    $ra = Get-Prop (Get-Prop $r 'headers') 'Retry-After'
                    $wait = [math]::Max($wait, $(if ($ra) { [int]$ra } else { 5 }))
                }
                else {
                    Write-Verbose "Owner $($r['id']) status lookup returned HTTP $status"
                }
            }
            $chunk = $retry
            if ($chunk.Count -gt 0) { Start-Sleep -Seconds $wait }
        }
    }
}

function New-ResultRow {
    param(
        [string]$ObjectType, $Object, [string]$AppId, [object[]]$Owners, [System.Collections.IDictionary]$Extra
    )
    $signIn = Get-SignInSummary -AppId $AppId
    $disabledOwners = @($Owners | Where-Object { $script:OwnerEnabled[[string](Get-Prop $_ 'id')] -eq $false })
    $enabledOwners  = @($Owners | Where-Object { $script:OwnerEnabled[[string](Get-Prop $_ 'id')] -eq $true })
    $row = [ordered]@{
        ObjectType          = $ObjectType
        DisplayName         = Get-Prop $Object 'displayName'
        AppId               = $AppId
        ObjectId            = Get-Prop $Object 'id'
        CreatedDateTime     = ConvertTo-UtcDate (Get-Prop $Object 'createdDateTime')
        LastSignIn          = $signIn.LastSignIn
        LastSignInType      = $signIn.LastSignInType
        DaysSinceLastSignIn = if ($signIn.LastSignIn) { [int][math]::Floor(($now - $signIn.LastSignIn).TotalDays) } else { $null }
        OwnerCount          = $Owners.Count
        Owners              = ($Owners | ForEach-Object { Format-Owner $_ }) -join '; '
        EnabledOwnerCount   = $enabledOwners.Count
        DisabledOwnerCount  = $disabledOwners.Count
        DisabledOwners      = ($disabledOwners | ForEach-Object { Format-Owner $_ }) -join '; '
        AllOwnersDisabled   = ($Owners.Count -gt 0 -and $disabledOwners.Count -eq $Owners.Count)
    }
    foreach ($k in $Extra.Keys) { $row[$k] = $Extra[$k] }
    $row.LastDelegatedClientSignIn   = $signIn.LastDelegatedClientSignIn
    $row.LastDelegatedResourceSignIn = $signIn.LastDelegatedResourceSignIn
    $row.LastAppOnlyClientSignIn     = $signIn.LastAppOnlyClientSignIn
    $row.LastAppOnlyResourceSignIn   = $signIn.LastAppOnlyResourceSignIn
    $row.SignInDataAvailable         = $signInDataAvailable
    [pscustomobject]$row
}

#region App registrations -----------------------------------------------------

if ($Type -in 'All', 'AppRegistrations') {
    Write-Host 'Retrieving app registrations...' -ForegroundColor Cyan
    $select = 'id,appId,displayName,createdDateTime,signInAudience,publisherDomain,tags'
    $uri = "https://graph.microsoft.com/v1.0/applications?`$select=$select&`$expand=owners&`$top=100"
    $count = 0
    foreach ($app in Invoke-GraphPaged -Uri $uri) {
        $count++
        Write-Progress -Activity 'App registrations' -Status "$count - $(Get-Prop $app 'displayName')"
        $owners = Get-Owners -Object $app -Collection 'applications'
        $pending.Add(@{ ObjectType = 'AppRegistration'; Object = $app; AppId = (Get-Prop $app 'appId'); Owners = $owners; Extra = ([ordered]@{
            ServicePrincipalType = $null
            AccountEnabled       = $null
            SignInAudience       = Get-Prop $app 'signInAudience'
            PublisherTenantId    = $context.TenantId
        }) })
    }
    Write-Progress -Activity 'App registrations' -Completed
    Write-Host "  $count app registrations found."
}

#endregion

#region Enterprise applications ----------------------------------------------

if ($Type -in 'All', 'EnterpriseApps') {
    Write-Host 'Retrieving enterprise applications (service principals)...' -ForegroundColor Cyan
    $select = 'id,appId,displayName,createdDateTime,servicePrincipalType,accountEnabled,appOwnerOrganizationId,signInAudience,tags'
    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$select=$select&`$expand=owners&`$top=100"
    $count = 0
    $skipped = 0
    foreach ($sp in Invoke-GraphPaged -Uri $uri) {
        $spType   = Get-Prop $sp 'servicePrincipalType'
        $ownerOrg = [string](Get-Prop $sp 'appOwnerOrganizationId')

        if (-not $IncludeManagedIdentities -and $spType -eq 'ManagedIdentity') { $skipped++; continue }
        if (-not $IncludeMicrosoftApps -and $ownerOrg -in $MicrosoftTenantIds) { $skipped++; continue }

        $count++
        Write-Progress -Activity 'Enterprise applications' -Status "$count - $(Get-Prop $sp 'displayName')"
        $owners = Get-Owners -Object $sp -Collection 'servicePrincipals'
        $pending.Add(@{ ObjectType = 'EnterpriseApp'; Object = $sp; AppId = (Get-Prop $sp 'appId'); Owners = $owners; Extra = ([ordered]@{
            ServicePrincipalType = $spType
            AccountEnabled       = Get-Prop $sp 'accountEnabled'
            SignInAudience       = Get-Prop $sp 'signInAudience'
            PublisherTenantId    = $ownerOrg
        }) })
    }
    Write-Progress -Activity 'Enterprise applications' -Completed
    Write-Host "  $count enterprise applications found ($skipped excluded - use -IncludeMicrosoftApps / -IncludeManagedIdentities to include)."
}

#endregion

#region Owner account status and output ----------------------------------------

# Copilot Studio / PVA detection. Tags usually sit on the service principal, so an
# app registration inherits the flag from its service principal (and vice versa).
$copilotByAppId = @{}
foreach ($p in $pending) {
    $p.CopilotSignal = Get-CopilotStudioSignal $p.Object
    if ($p.CopilotSignal -and $p.AppId -and -not $copilotByAppId.ContainsKey($p.AppId)) {
        $copilotByAppId[$p.AppId] = "$($p.CopilotSignal) (on $(if ($p.ObjectType -eq 'EnterpriseApp') { 'enterprise app' } else { 'app registration' }))"
    }
}
$copilotCount = 0
$keep = [System.Collections.Generic.List[object]]::new()
foreach ($p in $pending) {
    $signal = if ($p.CopilotSignal) { $p.CopilotSignal } elseif ($p.AppId -and $copilotByAppId.ContainsKey($p.AppId)) { $copilotByAppId[$p.AppId] } else { $null }
    if ($signal) { $copilotCount++ }
    if ($signal -and $ExcludeCopilotStudio) { continue }
    $p.Extra.Tags                = (@(Get-Prop $p.Object 'tags' | Where-Object { $_ }) -join '; ')
    $p.Extra.IsCopilotStudio     = [bool]$signal
    $p.Extra.CopilotStudioSignal = $signal
    $keep.Add($p)
}
$pending = $keep
if ($copilotCount) {
    $verb = if ($ExcludeCopilotStudio) { 'excluded' } else { 'found (marked in IsCopilotStudio; use -ExcludeCopilotStudio to leave them out)' }
    Write-Host "  $copilotCount Copilot Studio / Power Virtual Agents object(s) $verb."
}

Resolve-OwnerAccountStatus -OwnerObjects @($pending | ForEach-Object { $_.Owners })

foreach ($p in $pending) {
    $results.Add((New-ResultRow -ObjectType $p.ObjectType -Object $p.Object -AppId $p.AppId -Owners $p.Owners -Extra $p.Extra))
}

$results = $results | Sort-Object ObjectType, DisplayName

if ($OutputPath) {
    # Write dates as ISO 8601 UTC so the CSV is unambiguous whatever the locale
    # (the dashboard in this folder relies on that).
    $reportTime = $now.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $results | ForEach-Object {
        $copy = [ordered]@{}
        foreach ($prop in $_.PSObject.Properties) {
            $copy[$prop.Name] = if ($prop.Value -is [datetime]) { $prop.Value.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $prop.Value }
        }
        $copy.ReportGeneratedUtc = $reportTime
        [pscustomobject]$copy
    } | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host "Report exported to $((Resolve-Path $OutputPath).Path)" -ForegroundColor Green
}

$results

#endregion
