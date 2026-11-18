<#
.SYNOPSIS
    Reports the internet-facing (public) exposure of Azure resources across subscriptions or a
    management group, with a risk rating and the action to take for each finding.

.DESCRIPTION
    Reads the resources with Azure Resource Graph (one query across every subscription in
    scope), plus a few management-plane calls for details Resource Graph doesn't hold. Nothing
    is changed and no data-plane access is needed: Reader on the scope is enough.

    What it looks at:

      Public IPs        every public IP and what it's attached to (VM NIC, load balancer,
                        application gateway, firewall, Bastion, VPN / ExpressRoute gateway,
                        NAT gateway, or nothing).
      VMs / NICs        for a NIC with a public IP: which ports are reachable from any internet
                        address, working through the NIC and subnet NSGs in priority order
                        (including the default rules, and that a Basic public IP with no NSG is
                        open while a Standard one is closed by default).
      NSG rules         inbound rules allowing the internet to management, database, file-
                        sharing or container ports, or to every port.
      Load balancers    public frontends and the ports their rules and inbound NAT rules publish.
      App gateways      public listeners: WAF missing / in detection mode, HTTP listeners that
                        don't redirect to HTTPS, old TLS policies.
      Azure Firewall    DNAT rules (classic rules and Firewall Policy) publishing internal ports.
      Front Door / CDN  endpoints without a WAF policy.
      PaaS services     public network access and firewall settings: storage (incl. anonymous
                        blob containers), SQL, PostgreSQL / MySQL flexible server firewall rules,
                        Cosmos DB, Key Vault, App Service / Functions, container registries, AKS
                        API servers, Redis, Azure AI services, API Management, and any other
                        resource with public network access enabled.
      Routing           route tables sending the default route (0.0.0.0/0) straight to the
                        internet, and subnets relying on default outbound access.

    Each finding has a severity (Critical, High, Medium, Low, Info), what is exposed, to whom
    (any internet address, specific ranges, all Azure services), the evidence (rule names) and a
    recommendation.

    Output is one CSV with two kinds of row (RecordType):
      Finding        one row per finding (InternetReachable: whether the resource can be
                     reached from the internet, as opposed to a hygiene / outbound finding)
      Subscription   one row per subscription: resources checked, public / private, errors

    Load it into PublicExposureDashboard.html (same folder).

    REQUIREMENTS
      * Az.Accounts module (Install-Module Az.Accounts -Scope CurrentUser), or a managed identity.
      * Reader on the subscriptions or management group. (It includes reading SQL / PostgreSQL /
        MySQL firewall rules, blob container settings, App Service configuration and Firewall
        Policy rules.)

.PARAMETER TenantId
    Tenant to report on. Defaults to the current Az context's tenant.

.PARAMETER SubscriptionId
    Only these subscriptions.

.PARAMETER ManagementGroupId
    Only subscriptions under this management group (its ID, e.g. mg-landingzones).

.PARAMETER SkipAppServiceConfig
    Don't read each App Service / Function App's access restrictions (one call per app).

.PARAMETER SkipDetailChecks
    Don't make any of the per-resource calls (database firewall rules, blob containers, App
    Service config, Firewall Policy DNAT rules, Front Door security policies). Faster, less detail.

.PARAMETER ManagedIdentityClientId
    Run unattended as this user-assigned managed identity (e.g. in Azure Functions). -TenantId
    is required.

.PARAMETER OutputPath
    CSV to write.

.EXAMPLE
    Connect-AzAccount -TenantId contoso.onmicrosoft.com
    .\Get-AzurePublicExposureReport.ps1 -OutputPath .\exposure.csv

.EXAMPLE
    .\Get-AzurePublicExposureReport.ps1 -ManagementGroupId mg-landingzones -OutputPath .\exposure.csv
#>
[CmdletBinding()]
param(
    [string]$TenantId,
    [string[]]$SubscriptionId,
    [string]$ManagementGroupId,
    [switch]$SkipAppServiceConfig,
    [switch]$SkipDetailChecks,
    [string]$ManagedIdentityClientId,
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Arm = 'https://management.azure.com'

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

function Get-Path {
    <# Nested property by dotted path (null-safe). #>
    param($Object, [string]$Path)
    $o = $Object
    foreach ($p in $Path -split '\.') { if ($null -eq $o) { return $null }; $o = Get-Prop $o $p }
    return $o
}
function Get-List($Object, [string]$Path) { @(Get-Path $Object $Path | Where-Object { $null -ne $_ }) }
function Get-Lid([string]$Id) { if ($Id) { $Id.ToLowerInvariant() } else { '' } }
function Get-NameFromId([string]$Id) { if ($Id) { ($Id.TrimEnd('/') -split '/')[-1] } else { '' } }
function Get-SubscriptionFromLid([string]$Lid) { if ($Lid -match '^/subscriptions/([^/]+)') { $Matches[1] } else { '' } }

#endregion

#region Classification --------------------------------------------------------------

# Ports worth knowing about when they're reachable from the internet
$Ports = [ordered]@{
    22 = 'SSH'; 3389 = 'RDP'; 5985 = 'WinRM'; 5986 = 'WinRM (TLS)'; 23 = 'Telnet'
    1433 = 'SQL Server'; 3306 = 'MySQL'; 5432 = 'PostgreSQL'; 1521 = 'Oracle'; 27017 = 'MongoDB'; 6379 = 'Redis'; 9200 = 'Elasticsearch'; 11211 = 'Memcached'
    21 = 'FTP'; 445 = 'SMB'; 135 = 'RPC'; 139 = 'NetBIOS'
    2375 = 'Docker API'; 2376 = 'Docker API (TLS)'; 10250 = 'Kubelet'; 6443 = 'Kubernetes API'
    80 = 'HTTP'; 8080 = 'HTTP (alt)'; 443 = 'HTTPS'
}
$PortNames = @{}; foreach ($e in $Ports.GetEnumerator()) { $PortNames[[int]$e.Key] = $e.Value }   # hashtable: an ordered dictionary's [int] means position
$PortClass = @{}
foreach ($p in 22, 3389, 5985, 5986, 23) { $PortClass[$p] = 'management' }
foreach ($p in 1433, 3306, 5432, 1521, 27017, 6379, 9200, 11211) { $PortClass[$p] = 'database' }
foreach ($p in 21, 445, 135, 139) { $PortClass[$p] = 'file / RPC' }
foreach ($p in 2375, 2376, 10250, 6443) { $PortClass[$p] = 'container' }
foreach ($p in 80, 8080) { $PortClass[$p] = 'web (unencrypted)' }
$PortClass[443] = 'web'
$AnyPortProbe = 40000   # stands for "any other port": open only if an allow-all-ports rule wins

$SevRank = @{ Critical = 4; High = 3; Medium = 2; Low = 1; Info = 0 }
function Get-MaxSeverity([string[]]$Severities) { ($Severities | Sort-Object { $SevRank[$_] } -Descending | Select-Object -First 1) }

function Get-PortSeverity([int]$Port, [string]$Scope) {
    <# Severity of one port being reachable. Scope: any (any internet address) or restricted. #>
    $class = $PortClass[$Port]
    if ($Port -eq $AnyPortProbe) { if ($Scope -eq 'any') { return 'Critical' } else { return 'Low' } }
    if ($Scope -eq 'any') {
        switch ($class) {
            { $_ -in 'management', 'database', 'file / RPC', 'container' } { return 'Critical' }
            'web (unencrypted)' { return 'Medium' }
            'web' { return 'Info' }
            default { return 'Medium' }   # all ports / unknown port
        }
    }
    switch ($class) {
        { $_ -in 'management', 'database', 'file / RPC', 'container' } { return 'Low' }
        default { return 'Info' }
    }
}

function Get-PortAdvice([int[]]$PortList) {
    $classes = @($PortList | ForEach-Object { if ($_ -eq $AnyPortProbe) { 'all' } else { $PortClass[$_] } } | Sort-Object -Unique)
    $a = @()
    if ('all' -in $classes) { $a += 'Replace the rule allowing all ports with rules for only the ports the service needs.' }
    if ('management' -in $classes) { $a += 'Close management ports (SSH / RDP / WinRM) to the internet: use Azure Bastion, Just-in-time VM access or a VPN.' }
    if ('database' -in $classes) { $a += 'Never publish database / cache ports: reach them over private networking (private endpoint, VPN, peering).' }
    if ('file / RPC' -in $classes) { $a += 'Block SMB / RPC / NetBIOS / FTP from the internet.' }
    if ('container' -in $classes) { $a += 'Block Docker / kubelet / Kubernetes API ports from the internet.' }
    if ('web (unencrypted)' -in $classes) { $a += 'Serve web traffic over HTTPS only (or redirect HTTP), ideally behind a WAF (Application Gateway / Front Door).' }
    if (-not $a.Count) { $a += 'Check the exposure is intended; put internet-facing web workloads behind a WAF.' }
    return ($a -join ' ')
}

function Format-PortList([int[]]$PortList) {
    (@($PortList | Sort-Object -Unique | ForEach-Object { if ($_ -eq $AnyPortProbe) { 'all ports' } elseif ($PortNames.ContainsKey([int]$_)) { "$_ ($($PortNames[[int]$_]))" } else { "$_" } }) -join ', ')
}

function Test-InternetSource([string]$Prefix) {
    <# A source that means "any internet address". #>
    return ($Prefix -in '*', 'Internet', '0.0.0.0/0', '0.0.0.0', 'Any', '::/0')
}
function Test-PrivateSource([string]$Prefix) {
    if ($Prefix -in 'VirtualNetwork', 'AzureLoadBalancer', 'GatewayManager') { return $true }
    return ($Prefix -match '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.)')
}

function Test-PortInRanges([int]$Port, [string[]]$Ranges) {
    foreach ($r in $Ranges) {
        if (-not $r) { continue }
        if ($r -eq '*') { return $true }
        if ($r -match '^(\d+)-(\d+)$') { if ($Port -ge [int]$Matches[1] -and $Port -le [int]$Matches[2]) { return $true }; continue }
        if ($r -match '^\d+$' -and [int]$r -eq $Port) { return $true }
    }
    return $false
}

function Get-RulePorts($Rule) {
    $p = Get-Prop $Rule 'properties'
    @(@(Get-Prop $p 'destinationPortRange') + @(Get-List $p 'destinationPortRanges') | Where-Object { $_ })
}
function Get-RuleSources($Rule) {
    $p = Get-Prop $Rule 'properties'
    @(@(Get-Prop $p 'sourceAddressPrefix') + @(Get-List $p 'sourceAddressPrefixes') | Where-Object { $_ })
}

function Get-NsgRules($Nsg) {
    @(@(Get-List $Nsg 'properties.securityRules') + @(Get-List $Nsg 'properties.defaultSecurityRules') |
        Where-Object { (Get-Path $_ 'properties.direction') -eq 'Inbound' -and (Get-Path $_ 'properties.protocol') -in '*', 'Tcp', 'Udp', 'Any' } |
        Sort-Object { [int](Get-Path $_ 'properties.priority') })
}

function Get-NsgDecision($Nsg, [int]$Port) {
    <#
        What the NSG does with traffic from an arbitrary internet address to $Port: the first
        inbound rule (by priority) whose source covers any internet address and whose ports
        include $Port decides. Returns @{ Allow; Rule }.
    #>
    foreach ($r in (Get-NsgRules $Nsg)) {
        if (-not (Test-PortInRanges $Port (Get-RulePorts $r))) { continue }
        if (-not @(Get-RuleSources $r | Where-Object { Test-InternetSource $_ }).Count) { continue }
        return @{ Allow = ((Get-Path $r 'properties.access') -eq 'Allow'); Rule = "$(Get-NameFromId $Nsg.id)/$($r.name)" }
    }
    return @{ Allow = $false; Rule = "$(Get-NameFromId $Nsg.id)/(default deny)" }
}

function Get-NsgRestrictedAllows($Nsg, [int]$Port) {
    <# Allow rules for $Port from specific public sources (not any-internet, not private ranges). #>
    @(foreach ($r in (Get-NsgRules $Nsg)) {
        if ((Get-Path $r 'properties.access') -ne 'Allow') { continue }
        if (-not (Test-PortInRanges $Port (Get-RulePorts $r))) { continue }
        $src = @(Get-RuleSources $r)
        if (@($src | Where-Object { Test-InternetSource $_ }).Count) { continue }
        $public = @($src | Where-Object { -not (Test-PrivateSource $_) })
        if ($public.Count) { "$(Get-NameFromId $Nsg.id)/$($r.name) from $($public -join ', ')" }
    })
}

#endregion

#region Connect & scope ---------------------------------------------------------------

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
$reportTime = Format-Date ([datetime]::UtcNow)

function Invoke-Arg {
    <# Resource Graph query across the subscriptions in scope, all pages. #>
    param([string]$Query, [string[]]$Subscriptions, [string]$ManagementGroup)
    $out = [System.Collections.Generic.List[object]]::new()
    $batches = [System.Collections.Generic.List[object]]::new()
    if ($ManagementGroup) { $batches.Add(@()) }
    else { for ($i = 0; $i -lt $Subscriptions.Count; $i += 1000) { $batches.Add(@($Subscriptions[$i..([math]::Min($i + 999, $Subscriptions.Count - 1))])) } }
    foreach ($batch in $batches) {
        $skip = $null
        do {
            $body = @{ query = $Query; options = @{ '$top' = 1000; resultFormat = 'objectArray' } }
            if ($ManagementGroup) { $body.managementGroups = @($ManagementGroup) } else { $body.subscriptions = @($batch) }
            if ($skip) { $body.options['$skipToken'] = $skip }
            $res = Invoke-Rest -Uri "$Arm/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01" -Method POST -Payload ($body | ConvertTo-Json -Depth 6)
            foreach ($r in @(Get-Prop $res 'data')) { if ($null -ne $r) { $out.Add($r) } }
            $skip = Get-Prop $res '$skipToken'
        } while ($skip)
    }
    return , $out.ToArray()
}

Write-Host 'Retrieving subscriptions...' -ForegroundColor Cyan
$subs = @(Invoke-RestPaged -Uri "$Arm/subscriptions?api-version=2022-12-01" |
    Where-Object { (Get-Prop $_ 'tenantId') -eq $TenantId -and (Get-Prop $_ 'state') -in 'Enabled', 'PastDue', 'Warned' })
if ($ManagementGroupId) {
    $inMg = @(Invoke-Arg -Query "resourcecontainers | where type =~ 'microsoft.resources/subscriptions' | project subscriptionId" -ManagementGroup $ManagementGroupId |
        ForEach-Object { [string]$_.subscriptionId })
    $subs = @($subs | Where-Object { $_.subscriptionId -in $inMg })
}
if ($SubscriptionId) { $subs = @($subs | Where-Object { $_.subscriptionId -in $SubscriptionId }) }
if (-not $subs.Count) { throw 'No subscriptions in scope (check -SubscriptionId / -ManagementGroupId and Reader access).' }
$subIds = @($subs | ForEach-Object { $_.subscriptionId })
$subNames = @{}; foreach ($s in $subs) { $subNames[$s.subscriptionId.ToLowerInvariant()] = $s.displayName }
$subStats = @{}; foreach ($s in $subIds) { $subStats[$s.ToLowerInvariant()] = @{ Checked = 0; Public = 0; Private = 0; Errors = [System.Collections.Generic.List[string]]::new() } }
Write-Host "  $($subs.Count) subscription(s)$(if ($ManagementGroupId) { " under $ManagementGroupId" })."

#endregion

#region Inventory -----------------------------------------------------------------------

$networkTypes = @('microsoft.network/publicipaddresses', 'microsoft.network/networkinterfaces', 'microsoft.network/networksecuritygroups',
    'microsoft.network/loadbalancers', 'microsoft.network/applicationgateways', 'microsoft.network/azurefirewalls', 'microsoft.network/bastionhosts',
    'microsoft.network/virtualnetworkgateways', 'microsoft.network/natgateways', 'microsoft.network/routetables', 'microsoft.network/virtualnetworks',
    'microsoft.network/frontdoors', 'microsoft.cdn/profiles', 'microsoft.network/applicationgatewaywebapplicationfirewallpolicies',
    'microsoft.network/frontdoorwebapplicationfirewallpolicies')
Write-Host 'Reading network resources (Resource Graph)...' -ForegroundColor Cyan
$q = "resources | where type in~ ('$($networkTypes -join "','")') | project id, name, type, kind, location, resourceGroup, subscriptionId, sku, properties"
$net = Invoke-Arg -Query $q -Subscriptions $subIds
Write-Host "  $($net.Count) network resources."

$paasTypes = @('microsoft.storage/storageaccounts', 'microsoft.sql/servers', 'microsoft.dbforpostgresql/flexibleservers', 'microsoft.dbformysql/flexibleservers',
    'microsoft.documentdb/databaseaccounts', 'microsoft.keyvault/vaults', 'microsoft.web/sites', 'microsoft.containerregistry/registries',
    'microsoft.containerservice/managedclusters', 'microsoft.cache/redis', 'microsoft.cognitiveservices/accounts', 'microsoft.apimanagement/service')
Write-Host 'Reading PaaS resources (Resource Graph)...' -ForegroundColor Cyan
$q = "resources | where type in~ ('$($paasTypes -join "','")') or isnotempty(properties.publicNetworkAccess) | where type !in~ ('$($networkTypes -join "','")') | project id, name, type, kind, location, resourceGroup, subscriptionId, sku, properties"
$paas = Invoke-Arg -Query $q -Subscriptions $subIds
Write-Host "  $($paas.Count) PaaS resources."

$byId = @{}
foreach ($r in @($net) + @($paas)) { $byId[(Get-Lid $r.id)] = $r }
$ofType = { param($t) @($net | Where-Object { $_.type -eq $t }) }

# Subnets (from VNets): NSG, route table, NAT gateway, default outbound access, workloads
$subnets = @{}
foreach ($v in (& $ofType 'microsoft.network/virtualnetworks')) {
    foreach ($sn in (Get-List $v 'properties.subnets')) {
        $subnets[(Get-Lid $sn.id)] = @{
            Id = $sn.id; Name = $sn.name; Vnet = $v.name; Sub = $v.subscriptionId; Rg = $v.resourceGroup; Location = $v.location
            Nsg = Get-Lid (Get-Path $sn 'properties.networkSecurityGroup.id'); RouteTable = Get-Lid (Get-Path $sn 'properties.routeTable.id')
            NatGateway = Get-Lid (Get-Path $sn 'properties.natGateway.id'); DefaultOutbound = Get-Path $sn 'properties.defaultOutboundAccess'
            IpConfigs = @(Get-List $sn 'properties.ipConfigurations').Count
        }
    }
}

#endregion

#region Findings --------------------------------------------------------------------------

$findings = [System.Collections.Generic.List[object]]::new()
$publicResources = @{}   # lower id -> $true for resources reachable from the internet
function Add-Finding {
    param($Resource, [string]$Severity, [string]$Category, [string]$Finding, [string]$Recommendation,
        [string]$Exposure = '', [string]$PublicIp = '', [string]$PortsText = '', [string]$Source = '', [string]$AttachedTo = '', [string]$Evidence = '', [switch]$NotPublic)
    $id = [string]$Resource.id
    $sub = [string](Get-Prop $Resource 'subscriptionId')
    if (-not $NotPublic) { $publicResources[(Get-Lid $id)] = $true }
    $findings.Add([pscustomobject][ordered]@{
        RecordType = 'Finding'; Severity = $Severity; Category = $Category
        ResourceName = [string]$Resource.name; ResourceType = [string]$Resource.type; ResourceGroup = [string](Get-Prop $Resource 'resourceGroup')
        SubscriptionId = $sub; SubscriptionName = $subNames[$sub.ToLowerInvariant()]; Location = [string](Get-Prop $Resource 'location'); ResourceId = $id
        Exposure = $Exposure; PublicIp = $PublicIp; Ports = $PortsText; Source = $Source; AttachedTo = $AttachedTo; InternetReachable = (-not $NotPublic)
        Finding = $Finding; Recommendation = $Recommendation; Evidence = $Evidence
        ResourcesChecked = ''; PublicResources = ''; PrivateResources = ''; Errors = ''; Scope = ''; ReportGeneratedUtc = $reportTime
    })
}
function Get-SubResource([string]$Id) {
    <# A synthetic resource object for a sub-resource or a resource that isn't in the inventory. #>
    $p = Split-ResourceId $Id
    [pscustomobject]@{ id = $Id; name = $p.Name; type = $p.Type.ToLowerInvariant(); resourceGroup = $p.ResourceGroup; subscriptionId = $p.Subscription; location = '' }
}

# --- Public IPs and what they're attached to -----------------------------------------------
Write-Host 'Assessing public IPs and network paths...' -ForegroundColor Cyan
$pipInfo = @{}   # lower pip id -> @{ Ip; Sku; Resource }
foreach ($pip in (& $ofType 'microsoft.network/publicipaddresses')) {
    $ip = [string](Get-Path $pip 'properties.ipAddress')
    $pipInfo[(Get-Lid $pip.id)] = @{ Ip = $(if ($ip) { $ip } else { '(dynamic, not allocated)' }); Sku = [string](Get-Path $pip 'sku.name'); Resource = $pip }
    $cfg = [string](Get-Path $pip 'properties.ipConfiguration.id')
    $natGw = [string](Get-Path $pip 'properties.natGateway.id')
    $kind = if ($natGw) { 'NAT gateway' } elseif (-not $cfg) { '' } else {
        switch -Regex ($cfg) {
            '/networkInterfaces/' { 'VM network interface' }
            '/loadBalancers/' { 'Load balancer' }
            '/applicationGateways/' { 'Application gateway' }
            '/azureFirewalls/' { 'Azure Firewall' }
            '/bastionHosts/' { 'Azure Bastion' }
            '/virtualNetworkGateways/' { 'VPN / ExpressRoute gateway' }
            default { (Split-ResourceId $cfg).Type }
        }
    }
    $owner = if ($natGw) { Get-NameFromId $natGw } elseif ($cfg) { ($cfg -split '/')[8] } else { '' }
    if (-not $kind) {
        Add-Finding $pip 'Low' 'Public IP' 'Public IP not attached to anything.' 'Delete it if it isn''t needed (it costs money and could be attached to something by mistake).' `
            -Exposure 'Not in use' -PublicIp $pipInfo[(Get-Lid $pip.id)].Ip -NotPublic
        continue
    }
    $info = switch ($kind) {
        'NAT gateway' { 'Outbound only (NAT gateway): not reachable inbound.' }
        'Azure Bastion' { 'Azure Bastion: the recommended way to reach VMs; exposes only HTTPS.' }
        'VPN / ExpressRoute gateway' { 'VPN / ExpressRoute gateway: expected to be public.' }
        default { $null }
    }
    if ($info) {
        Add-Finding $pip 'Info' 'Public IP' $info 'No action.' -Exposure $kind -PublicIp $pipInfo[(Get-Lid $pip.id)].Ip -AttachedTo $owner -NotPublic:($kind -eq 'NAT gateway')
    }
}

# --- VMs: NIC with a public IP, through NIC + subnet NSGs ------------------------------
$nsgs = @{}; foreach ($n in (& $ofType 'microsoft.network/networksecuritygroups')) { $nsgs[(Get-Lid $n.id)] = $n }
$nsgReported = @{}   # NSGs whose open rules are already covered by a VM finding
foreach ($nic in (& $ofType 'microsoft.network/networkinterfaces')) {
    $vmId = [string](Get-Path $nic 'properties.virtualMachine.id')
    $nicNsg = $nsgs[(Get-Lid (Get-Path $nic 'properties.networkSecurityGroup.id'))]
    foreach ($ipc in (Get-List $nic 'properties.ipConfigurations')) {
        $pipId = Get-Lid (Get-Path $ipc 'properties.publicIPAddress.id')
        if (-not $pipId) { continue }
        $pi = $pipInfo[$pipId]
        $sn = $subnets[(Get-Lid (Get-Path $ipc 'properties.subnet.id'))]
        $snNsg = if ($sn -and $sn.Nsg) { $nsgs[$sn.Nsg] } else { $null }
        $layers = @(@($snNsg, $nicNsg) | Where-Object { $_ })
        $sku = if ($pi) { $pi.Sku } else { '' }
        $ip = if ($pi) { $pi.Ip } else { '' }
        $target = if ($vmId) { Get-SubResource $vmId } else { $nic }
        $open = @(); $evidence = @(); $restricted = @(); $restrictedEv = @()
        foreach ($port in @($Ports.Keys) + $AnyPortProbe) {
            if (-not $layers.Count) {
                if ($sku -eq 'Basic') { $open += $port; $evidence += 'no NSG on the NIC or subnet (Basic public IP: open by default)' }
                continue
            }
            $decisions = @($layers | ForEach-Object { Get-NsgDecision $_ $port })
            if (-not @($decisions | Where-Object { -not $_.Allow }).Count) { $open += $port; $evidence += @($decisions | ForEach-Object Rule) }
            elseif ($PortClass[$port] -in 'management', 'database', 'file / RPC', 'container') {
                $r = @($layers | ForEach-Object { Get-NsgRestrictedAllows $_ $port })
                if ($r.Count) { $restricted += $port; $restrictedEv += $r }
            }
        }
        foreach ($l in $layers) { $nsgReported[(Get-Lid $l.id)] = $true }
        $attached = "$(if ($vmId) { "VM $(Get-NameFromId $vmId)" } else { "NIC $($nic.name)" }) ($sku public IP)"
        $evText = (@($(if ($open.Count -or -not $restricted.Count) { $evidence } else { $restrictedEv }) | Sort-Object -Unique) -join '; ')
        if ($open -contains $AnyPortProbe) {
            Add-Finding $target 'Critical' 'Virtual machine' 'All ports are reachable from any internet address.' (Get-PortAdvice @($AnyPortProbe)) `
                -Exposure "Internet -> all ports on $ip" -PublicIp $ip -PortsText 'all ports' -Source 'Any internet address' -AttachedTo $attached -Evidence $evText
        } elseif ($open.Count) {
            $sev = Get-MaxSeverity @($open | ForEach-Object { Get-PortSeverity $_ 'any' })
            $names = Format-PortList $open
            Add-Finding $target $sev 'Virtual machine' "Reachable from any internet address on $names." (Get-PortAdvice $open) `
                -Exposure "Internet -> $names on $ip" -PublicIp $ip -PortsText (($open | Sort-Object) -join ',') -Source 'Any internet address' -AttachedTo $attached -Evidence $evText
        } elseif ($restricted.Count) {
            Add-Finding $target 'Low' 'Virtual machine' "Sensitive ports open to specific public addresses only: $(Format-PortList $restricted)." 'Check the source ranges are still needed and as narrow as possible; prefer Azure Bastion or Just-in-time access.' `
                -Exposure "Restricted ranges -> $(Format-PortList $restricted) on $ip" -PublicIp $ip -PortsText (($restricted | Sort-Object) -join ',') -Source 'Specific public ranges' -AttachedTo $attached -Evidence $evText
        } else {
            Add-Finding $target 'Info' 'Virtual machine' "Has a public IP, but the NSGs block inbound internet traffic$(if (-not $layers.Count) { ' (Standard public IP: closed by default)' })." 'Remove the public IP if the VM doesn''t need it; use Bastion for admin access.' `
                -Exposure "Public IP $ip (no inbound ports open)" -PublicIp $ip -AttachedTo $attached -Evidence $evText
        }
    }
}

# --- NSG rules that open sensitive ports to the internet (not already covered above) ------
foreach ($nsg in $nsgs.Values) {
    if ($nsgReported.ContainsKey((Get-Lid $nsg.id))) { continue }
    $assoc = @(Get-List $nsg 'properties.subnets') + @(Get-List $nsg 'properties.networkInterfaces')
    $open = @(foreach ($port in @($Ports.Keys) + $AnyPortProbe) {
        if ($PortClass[$port] -notin 'management', 'database', 'file / RPC', 'container' -and $port -ne $AnyPortProbe) { continue }
        $d = Get-NsgDecision $nsg $port
        if ($d.Allow) { @{ Port = $port; Rule = $d.Rule } }
    })
    if (-not $open.Count) { continue }
    $portList = @($open | ForEach-Object { $_.Port })
    $sev = if ($assoc.Count) { 'Medium' } else { 'Low' }
    Add-Finding $nsg $sev 'Network rule' "Allows any internet address to $(Format-PortList $portList)$(if (-not $assoc.Count) { ' (NSG not attached to anything)' } else { ' (no public IP leads to it directly today, but a load balancer, NAT rule or a public IP added later would)' })." `
        (Get-PortAdvice $portList) -Exposure "Rule allows Internet -> $(Format-PortList $portList)" -PortsText (($portList | Sort-Object) -join ',') -Source 'Any internet address' `
        -AttachedTo ((@($assoc | ForEach-Object { Get-NameFromId $_.id }) | Select-Object -First 5) -join ', ') -Evidence ((@($open | ForEach-Object Rule) | Sort-Object -Unique) -join '; ') -NotPublic
}

# --- Load balancers --------------------------------------------------------------------
foreach ($lb in (& $ofType 'microsoft.network/loadbalancers')) {
    $fe = @{}
    foreach ($f in (Get-List $lb 'properties.frontendIPConfigurations')) {
        $pid_ = Get-Lid (Get-Path $f 'properties.publicIPAddress.id')
        if ($pid_) { $fe[(Get-Lid $f.id)] = $(if ($pipInfo[$pid_]) { $pipInfo[$pid_].Ip } else { Get-NameFromId $pid_ }) }
    }
    if (-not $fe.Count) { continue }
    $published = @(); $evidence = @()
    foreach ($rule in @(Get-List $lb 'properties.loadBalancingRules') + @(Get-List $lb 'properties.inboundNatRules')) {
        $f = Get-Lid (Get-Path $rule 'properties.frontendIPConfiguration.id')
        if (-not $fe.ContainsKey($f)) { continue }
        $ports = @()
        if ($null -ne (Get-Path $rule 'properties.frontendPort') -and [int](Get-Path $rule 'properties.frontendPort') -ne 0) { $ports += [int](Get-Path $rule 'properties.frontendPort') }
        if ((Get-Path $rule 'properties.backendPort')) { $bp = [int](Get-Path $rule 'properties.backendPort'); if ($bp -and $bp -notin $ports -and $PortClass.ContainsKey($bp)) { $ports += $bp } }
        if ([int](Get-Path $rule 'properties.frontendPort') -eq 0 -and $rule.id -match '/loadBalancingRules/') { $ports += $AnyPortProbe }   # HA ports
        foreach ($p in $ports) { $published += $p; $evidence += "$($rule.name) -> $(if ($p -eq $AnyPortProbe) { 'all ports' } else { $p }) on $($fe[$f])" }
    }
    $ips = (@($fe.Values) | Sort-Object -Unique) -join ', '
    if (-not $published.Count) {
        Add-Finding $lb 'Info' 'Load balancer' 'Public frontend with no rules publishing ports.' 'Remove the public frontend if it isn''t needed.' -Exposure "Public IP $ips" -PublicIp $ips
        continue
    }
    $published = @($published | Sort-Object -Unique)
    $sevs = @($published | ForEach-Object { $s = Get-PortSeverity $_ 'any'; if ($s -eq 'Critical') { 'High' } else { $s } })   # backend NSGs still apply (Standard LB)
    $sev = Get-MaxSeverity $sevs
    Add-Finding $lb $sev 'Load balancer' "Publishes $(Format-PortList $published) to the internet." "$(Get-PortAdvice $published) Backends still need an NSG allowing the traffic (Standard SKU), so check those NSGs too." `
        -Exposure "Internet -> $(Format-PortList $published) on $ips" -PublicIp $ips -PortsText ($published -join ',') -Source 'Any internet address (subject to backend NSGs)' -Evidence (($evidence | Sort-Object -Unique) -join '; ')
}

# --- Application gateways -------------------------------------------------------------
$wafPolicies = @{}; foreach ($w in (& $ofType 'microsoft.network/applicationgatewaywebapplicationfirewallpolicies')) { $wafPolicies[(Get-Lid $w.id)] = $w }
foreach ($agw in (& $ofType 'microsoft.network/applicationgateways')) {
    $pubFe = @(Get-List $agw 'properties.frontendIPConfigurations' | Where-Object { Get-Path $_ 'properties.publicIPAddress.id' })
    if (-not $pubFe.Count) { continue }
    $ips = (@($pubFe | ForEach-Object { $p = $pipInfo[(Get-Lid (Get-Path $_ 'properties.publicIPAddress.id'))]; if ($p) { $p.Ip } }) | Where-Object { $_ }) -join ', '
    $feIds = @($pubFe | ForEach-Object { Get-Lid $_.id })
    $listeners = @(Get-List $agw 'properties.httpListeners' | Where-Object { (Get-Lid (Get-Path $_ 'properties.frontendIPConfiguration.id')) -in $feIds })
    $tier = [string](Get-Path $agw 'sku.tier')
    $policy = $wafPolicies[(Get-Lid (Get-Path $agw 'properties.firewallPolicy.id'))]
    $wafOn = $false; $wafMode = ''
    if ($policy) { $wafOn = (Get-Path $policy 'properties.policySettings.state') -eq 'Enabled'; $wafMode = [string](Get-Path $policy 'properties.policySettings.mode') }
    elseif ((Get-Path $agw 'properties.webApplicationFirewallConfiguration.enabled')) { $wafOn = $true; $wafMode = [string](Get-Path $agw 'properties.webApplicationFirewallConfiguration.firewallMode') }
    $issues = @()
    if ($tier -notlike 'WAF*' -or -not $wafOn) { $issues += @{ Sev = 'High'; Text = 'No web application firewall (WAF) in front of the public listeners.'; Fix = 'Use the WAF_v2 tier with a WAF policy in Prevention mode.' } }
    elseif ($wafMode -ne 'Prevention') { $issues += @{ Sev = 'Medium'; Text = 'WAF is in Detection mode: attacks are logged, not blocked.'; Fix = 'Switch the WAF policy to Prevention mode once false positives are tuned.' } }
    $redirectListeners = @(Get-List $agw 'properties.requestRoutingRules' | Where-Object { Get-Path $_ 'properties.redirectConfiguration.id' } | ForEach-Object { Get-Lid (Get-Path $_ 'properties.httpListener.id') })
    $http = @($listeners | Where-Object { (Get-Path $_ 'properties.protocol') -eq 'Http' -and (Get-Lid $_.id) -notin $redirectListeners })
    if ($http.Count) { $issues += @{ Sev = 'Medium'; Text = "HTTP listener(s) serving content unencrypted: $(($http | ForEach-Object name) -join ', ')."; Fix = 'Redirect HTTP to HTTPS (or remove the HTTP listener).' } }
    $ssl = Get-Path $agw 'properties.sslPolicy'
    $sslName = [string](Get-Path $ssl 'policyName'); $minTls = [string](Get-Path $ssl 'minProtocolVersion')
    if ($sslName -in 'AppGwSslPolicy20150501', 'AppGwSslPolicy20170401' -or $minTls -in 'TLSv1_0', 'TLSv1_1') { $issues += @{ Sev = 'Medium'; Text = "TLS policy allows old protocol versions ($(if ($sslName) { $sslName } else { "minimum $minTls" }))."; Fix = 'Use AppGwSslPolicy20220101 (TLS 1.2+) or newer.' } }
    elseif (-not $ssl -and @($listeners | Where-Object { (Get-Path $_ 'properties.protocol') -eq 'Https' }).Count) { $issues += @{ Sev = 'Low'; Text = 'No TLS policy set: older gateways default to a policy that allows TLS 1.0 / 1.1.'; Fix = 'Set the TLS policy to AppGwSslPolicy20220101 or newer.' } }
    $exposure = "Internet -> $($listeners.Count) listener(s) on $ips"
    if (-not $issues.Count) {
        Add-Finding $agw 'Info' 'Application gateway' "Public listeners behind a WAF in Prevention mode, HTTPS only." 'No action.' -Exposure $exposure -PublicIp $ips -Source 'Any internet address'
    }
    foreach ($i in $issues) { Add-Finding $agw $i.Sev 'Application gateway' $i.Text $i.Fix -Exposure $exposure -PublicIp $ips -Source 'Any internet address' -Evidence "tier $tier; WAF $(if ($wafOn) { $wafMode } else { 'off' })" }
}

# --- Azure Firewall DNAT ----------------------------------------------------------------
function Add-DnatFinding($Fw, [object[]]$Rules, [string]$Where) {
    $any = @(); $restricted = @(); $ev = @()
    foreach ($r in $Rules) {
        $src = @(@(Get-Prop $r 'sourceAddresses') + @(Get-Path $r 'properties.sourceAddresses') | Where-Object { $_ })
        $dst = @(@(Get-Prop $r 'destinationPorts') + @(Get-Path $r 'properties.destinationPorts') | Where-Object { $_ })
        $tp = [string]$(if (Get-Prop $r 'translatedPort') { Get-Prop $r 'translatedPort' } else { Get-Path $r 'properties.translatedPort' })
        $ports = @(@($dst) + @($tp) | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ } | Sort-Object -Unique)
        if ($dst -contains '*') { $ports += $AnyPortProbe }
        $isAny = [bool]@($src | Where-Object { Test-InternetSource $_ }).Count
        foreach ($p in $ports) { if ($isAny) { $any += $p } else { $restricted += $p } }
        $ev += "$($r.name): $($dst -join ',') -> $(Get-Prop $r 'translatedAddress')$(Get-Path $r 'properties.translatedAddress'):$tp from $(($src | Select-Object -First 3) -join ',')"
    }
    if (-not ($any.Count + $restricted.Count)) { return }
    $ports = @($any + $restricted | Sort-Object -Unique)
    $sev = if ($any.Count) { Get-MaxSeverity @($any | ForEach-Object { Get-PortSeverity $_ 'any' }) } else { Get-MaxSeverity @($restricted | ForEach-Object { Get-PortSeverity $_ 'restricted' }) }
    Add-Finding $Fw $sev 'Firewall DNAT' "DNAT rules ($Where) publish internal $(Format-PortList $ports) to $(if ($any.Count) { 'any internet address' } else { 'specific source ranges' })." (Get-PortAdvice $ports) `
        -Exposure "Internet -> $(Format-PortList $ports) via firewall" -PortsText ($ports -join ',') -Source $(if ($any.Count) { 'Any internet address' } else { 'Specific public ranges' }) -Evidence (($ev | Select-Object -First 10) -join '; ')
}
foreach ($fw in (& $ofType 'microsoft.network/azurefirewalls')) {
    $classic = @(Get-List $fw 'properties.natRuleCollections' | ForEach-Object { Get-List $_ 'properties.rules' })
    if ($classic.Count) { Add-DnatFinding $fw $classic 'classic rules' }
    $policyId = [string](Get-Path $fw 'properties.firewallPolicy.id')
    if ($policyId -and -not $SkipDetailChecks) {
        try {
            $rules = @(Invoke-RestPaged -Uri "$Arm$policyId/ruleCollectionGroups?api-version=2024-05-01" | ForEach-Object { Get-List $_ 'properties.ruleCollections' } |
                Where-Object { (Get-Prop $_ 'ruleCollectionType') -eq 'FirewallPolicyNatRuleCollection' } | ForEach-Object { Get-List $_ 'rules' })
            if ($rules.Count) { Add-DnatFinding $fw $rules "policy $(Get-NameFromId $policyId)" }
        } catch { $subStats[$fw.subscriptionId.ToLowerInvariant()].Errors.Add("Firewall policy $(Get-NameFromId $policyId): $($_.Exception.Message)") }
    }
}

# --- Front Door / CDN -------------------------------------------------------------------
foreach ($fd in (& $ofType 'microsoft.network/frontdoors')) {
    $noWaf = @(Get-List $fd 'properties.frontendEndpoints' | Where-Object { -not (Get-Path $_ 'properties.webApplicationFirewallPolicyLink.id') })
    if ($noWaf.Count) { Add-Finding $fd 'Medium' 'Front Door' "Endpoint(s) without a WAF policy: $(($noWaf | ForEach-Object { Get-Path $_ 'properties.hostName' }) -join ', ')." 'Attach a Front Door WAF policy in Prevention mode. (Front Door classic is being retired: plan the move to Front Door Standard / Premium.)' -Exposure 'Public Front Door endpoints' -Source 'Any internet address' }
    else { Add-Finding $fd 'Info' 'Front Door' 'All endpoints have a WAF policy.' 'Front Door classic is being retired: plan the move to Front Door Standard / Premium.' -Exposure 'Public Front Door endpoints' -Source 'Any internet address' }
}
foreach ($cdn in (& $ofType 'microsoft.cdn/profiles')) {
    $sku = [string](Get-Path $cdn 'sku.name')
    if ($sku -notlike '*AzureFrontDoor*') { Add-Finding $cdn 'Info' 'Front Door' "CDN profile ($sku): content is public by design." 'Make sure only content meant to be public is served.' -Exposure 'Public CDN endpoints' -Source 'Any internet address'; continue }
    if ($SkipDetailChecks) { continue }
    try {
        $sp = @(Invoke-RestPaged -Uri "$Arm$($cdn.id)/securityPolicies?api-version=2024-02-01")
        if (-not $sp.Count) { Add-Finding $cdn 'Medium' 'Front Door' "Front Door ($sku) has no security policy, so no WAF in front of its endpoints." 'Add a security policy with a WAF policy in Prevention mode (Premium adds managed rule sets).' -Exposure 'Public Front Door endpoints' -Source 'Any internet address' }
        else { Add-Finding $cdn 'Info' 'Front Door' "Front Door ($sku) with $($sp.Count) security polic$(if ($sp.Count -eq 1) { 'y' } else { 'ies' }) (WAF)." 'Check the WAF policies are in Prevention mode.' -Exposure 'Public Front Door endpoints' -Source 'Any internet address' }
    } catch { $subStats[$cdn.subscriptionId.ToLowerInvariant()].Errors.Add("Front Door $($cdn.name): $($_.Exception.Message)") }
}

# --- Routing ------------------------------------------------------------------------------
foreach ($rt in (& $ofType 'microsoft.network/routetables')) {
    $attached = @(Get-List $rt 'properties.subnets')
    foreach ($route in (Get-List $rt 'properties.routes')) {
        if ((Get-Path $route 'properties.nextHopType') -ne 'Internet') { continue }
        $prefix = [string](Get-Path $route 'properties.addressPrefix')
        $len = if ($prefix -match '/(\d+)$') { [int]$Matches[1] } else { 32 }
        if ($prefix -ne '0.0.0.0/0' -and $len -gt 8) { continue }
        Add-Finding $rt $(if ($prefix -eq '0.0.0.0/0' -and $attached.Count) { 'Medium' } else { 'Low' }) 'Routing' `
            "Route $($route.name) sends $prefix straight to the internet$(if ($attached.Count) { " for $($attached.Count) subnet(s)" } else { ' (route table not attached)' }), bypassing any firewall." `
            'Send internet-bound traffic through Azure Firewall / your NVA (next hop VirtualAppliance), or a NAT gateway for controlled outbound IPs.' `
            -Exposure "Outbound $prefix -> Internet" -AttachedTo ((@($attached | ForEach-Object { Get-NameFromId $_.id }) | Select-Object -First 5) -join ', ') -NotPublic
    }
}
$routeTables = @{}; foreach ($rt in (& $ofType 'microsoft.network/routetables')) { $routeTables[(Get-Lid $rt.id)] = $rt }
foreach ($sn in $subnets.Values) {
    if ($sn.Name -in 'GatewaySubnet', 'AzureFirewallSubnet', 'AzureFirewallManagementSubnet', 'AzureBastionSubnet', 'RouteServerSubnet') { continue }
    if (-not $sn.IpConfigs -or $sn.NatGateway -or $sn.DefaultOutbound -eq $false) { continue }
    $rt = $routeTables[$sn.RouteTable]
    $viaAppliance = $rt -and @(Get-List $rt 'properties.routes' | Where-Object { (Get-Path $_ 'properties.addressPrefix') -eq '0.0.0.0/0' -and (Get-Path $_ 'properties.nextHopType') -in 'VirtualAppliance', 'VirtualNetworkGateway' }).Count
    if ($viaAppliance) { continue }
    $res = [pscustomobject]@{ id = $sn.Id; name = "$($sn.Vnet)/$($sn.Name)"; type = 'microsoft.network/virtualnetworks/subnets'; resourceGroup = $sn.Rg; subscriptionId = $sn.Sub; location = $sn.Location }
    Add-Finding $res 'Low' 'Routing' 'Workloads in this subnet reach the internet through default outbound access (an implicit, shared Microsoft IP).' `
        'Give the subnet explicit outbound: a NAT gateway, or a 0.0.0.0/0 route to your firewall; then make it a private subnet (default outbound access off). Default outbound access is off by default for new VNets from 2026.' `
        -Exposure 'Outbound via default outbound access' -NotPublic
}

# --- PaaS ---------------------------------------------------------------------------------
Write-Host 'Assessing PaaS services...' -ForegroundColor Cyan
function Get-DbFirewallFindings($Res, [object[]]$Rules, [string]$What) {
    <# Classifies database firewall rules: any address, all Azure services, broad ranges, specific. #>
    $all = @(); $azure = @(); $broad = @(); $specific = @()
    foreach ($r in $Rules) {
        $s = [string](Get-Path $r 'properties.startIpAddress'); $e = [string](Get-Path $r 'properties.endIpAddress')
        $label = "$($r.name) ($s - $e)"
        if ($s -eq '0.0.0.0' -and $e -eq '255.255.255.255') { $all += $label; continue }
        if ($s -eq '0.0.0.0' -and $e -eq '0.0.0.0') { $azure += $label; continue }
        try {
            $a = [System.Net.IPAddress]::Parse($s).GetAddressBytes(); [array]::Reverse($a); $b = [System.Net.IPAddress]::Parse($e).GetAddressBytes(); [array]::Reverse($b)
            $size = [BitConverter]::ToUInt32($b, 0) - [BitConverter]::ToUInt32($a, 0) + 1
            if ($size -gt 65536) { $broad += $label } else { $specific += $label }
        } catch { $specific += $label }
    }
    if ($all.Count) { Add-Finding $Res 'Critical' 'Database' "$What firewall allows every internet address." 'Delete the 0.0.0.0 - 255.255.255.255 rule; use private endpoints, or allow only the specific addresses that need access.' -Exposure "$What open to the internet" -Source 'Any internet address' -Evidence ($all -join '; ') }
    if ($broad.Count) { Add-Finding $Res 'High' 'Database' "$What firewall allows large address ranges (more than a /16)." 'Narrow the ranges to the addresses that need access, or use private endpoints.' -Exposure "$What open to broad ranges" -Source 'Broad public ranges' -Evidence ($broad -join '; ') }
    if ($azure.Count) { Add-Finding $Res 'Medium' 'Database' "$What allows all Azure services (any customer's Azure resources, not just yours)." 'Turn off "Allow Azure services and resources to access this server"; use private endpoints or VNet rules for your own services.' -Exposure "$What open to all of Azure" -Source 'All Azure services' -Evidence ($azure -join '; ') }
    if ($specific.Count -and -not ($all.Count + $broad.Count)) { Add-Finding $Res 'Low' 'Database' "$What public endpoint allows $($specific.Count) specific address range(s)." 'Prefer private endpoints and disable public network access; otherwise keep the list short and reviewed.' -Exposure "$What restricted to $($specific.Count) range(s)" -Source 'Specific public ranges' -Evidence (($specific | Select-Object -First 10) -join '; ') }
    if (-not ($all.Count + $broad.Count + $azure.Count + $specific.Count)) { Add-Finding $Res 'Info' 'Database' "$What has public network access enabled but no firewall rules, so it's closed to the internet." 'Disable public network access to make that explicit.' -Exposure 'Public endpoint, no firewall rules' -NotPublic }
}
function Test-PublicAccess($Res, [string]$Path = 'properties.publicNetworkAccess') {
    $v = [string](Get-Path $Res $Path)
    return ($v -notin 'Disabled', 'SecuredByPerimeter')
}

foreach ($r in $paas) {
    $sub = $r.subscriptionId.ToLowerInvariant()
    if ($subStats.ContainsKey($sub)) { $subStats[$sub].Checked++ }
    $type = ([string]$r.type).ToLowerInvariant()
    $pe = @(Get-List $r 'properties.privateEndpointConnections').Count
    $peNote = if ($pe) { " It has $pe private endpoint(s): disable public network access if nothing needs it." } else { '' }
    try {
        switch ($type) {
            'microsoft.storage/storageaccounts' {
                $open = (Test-PublicAccess $r) -and (Get-Path $r 'properties.networkAcls.defaultAction') -ne 'Deny'
                if ($open) { Add-Finding $r 'Medium' 'Storage' "Accepts connections from all networks.$peNote" 'Set the firewall default action to Deny and allow only the networks / services that need it, or use private endpoints.' -Exposure 'Storage endpoints open to all networks' -Source 'Any internet address' }
                elseif (Test-PublicAccess $r) { Add-Finding $r 'Info' 'Storage' "Public endpoint restricted by the storage firewall ($(@(Get-List $r 'properties.networkAcls.ipRules').Count) IP rule(s), $(@(Get-List $r 'properties.networkAcls.virtualNetworkRules').Count) VNet rule(s))." 'No action; prefer private endpoints.' -Exposure 'Restricted public endpoint' -Source 'Specific networks' -NotPublic }
                if ((Get-Path $r 'properties.allowBlobPublicAccess') -eq $true -and (Test-PublicAccess $r)) {
                    $anon = @()
                    if (-not $SkipDetailChecks) { $anon = @(Invoke-RestPaged -Uri "$Arm$($r.id)/blobServices/default/containers?api-version=2023-05-01" | Where-Object { (Get-Path $_ 'properties.publicAccess') -in 'Blob', 'Container' } | ForEach-Object { "$($_.name) ($(Get-Path $_ 'properties.publicAccess'))" }) }
                    if ($anon.Count) { Add-Finding $r $(if ($open) { 'Critical' } else { 'High' }) 'Storage' "Anonymous (no sign-in) read access on container(s): $(($anon | Select-Object -First 5) -join ', ')$(if ($anon.Count -gt 5) { ' ...' })." 'Set the containers to private and turn off "Allow blob anonymous access" on the account, unless the content is meant to be public (then use a CDN / Front Door).' -Exposure 'Anonymous blob access' -Source 'Anyone' -Evidence ($anon -join '; ') }
                    else { Add-Finding $r 'Low' 'Storage' "Anonymous blob access is allowed on the account$(if ($SkipDetailChecks) { ' (containers not checked)' } else { ' (no container uses it today)' })." 'Turn off "Allow blob anonymous access".' -Exposure 'Anonymous access allowed' -NotPublic }
                }
                if ((Get-Path $r 'properties.minimumTlsVersion') -in 'TLS1_0', 'TLS1_1') { Add-Finding $r 'Low' 'Storage' "Minimum TLS version is $(Get-Path $r 'properties.minimumTlsVersion')." 'Set the minimum TLS version to 1.2.' -NotPublic }
            }
            'microsoft.sql/servers' {
                if (-not (Test-PublicAccess $r)) { break }
                $rules = if ($SkipDetailChecks) { @() } else { @(Invoke-RestPaged -Uri "$Arm$($r.id)/firewallRules?api-version=2021-11-01") }
                if ($SkipDetailChecks) { Add-Finding $r 'Medium' 'Database' "SQL server has public network access enabled (firewall rules not checked).$peNote" 'Disable public network access and use private endpoints.' -Exposure 'Public SQL endpoint' }
                else { Get-DbFirewallFindings $r $rules 'SQL server' }
                if ((Get-Path $r 'properties.minimalTlsVersion') -in '1.0', '1.1') { Add-Finding $r 'Low' 'Database' "Minimum TLS version is $(Get-Path $r 'properties.minimalTlsVersion')." 'Set the minimum TLS version to 1.2.' -NotPublic }
            }
            { $_ -in 'microsoft.dbforpostgresql/flexibleservers', 'microsoft.dbformysql/flexibleservers' } {
                if (-not (Test-PublicAccess $r 'properties.network.publicNetworkAccess')) { break }
                $what = if ($type -like '*postgres*') { 'PostgreSQL server' } else { 'MySQL server' }
                $api = if ($type -like '*postgres*') { '2022-12-01' } else { '2023-06-30' }
                if ($SkipDetailChecks) { Add-Finding $r 'Medium' 'Database' "$what has public access enabled (firewall rules not checked)." 'Use private access (VNet integration) or private endpoints.' -Exposure "Public $what endpoint" }
                else { Get-DbFirewallFindings $r @(Invoke-RestPaged -Uri "$Arm$($r.id)/firewallRules?api-version=$api") $what }
            }
            'microsoft.documentdb/databaseaccounts' {
                if (-not (Test-PublicAccess $r)) { break }
                $ipRules = @(Get-List $r 'properties.ipRules' | ForEach-Object { [string](Get-Prop $_ 'ipAddressOrRange') })
                $vnetFilter = (Get-Path $r 'properties.isVirtualNetworkFilterEnabled') -eq $true
                if (-not $ipRules.Count -and -not $vnetFilter) { Add-Finding $r 'High' 'Database' "Cosmos DB accepts connections from all networks.$peNote" 'Restrict to selected networks (IP rules / VNet rules) or use private endpoints and disable public access.' -Exposure 'Cosmos DB open to all networks' -Source 'Any internet address' }
                elseif ($ipRules -contains '0.0.0.0') { Add-Finding $r 'Medium' 'Database' 'Cosmos DB accepts connections from all Azure datacenters (0.0.0.0 rule).' 'Remove "Accept connections from within public Azure datacenters"; use private endpoints / VNet rules.' -Exposure 'Cosmos DB open to all of Azure' -Source 'All Azure services' }
                else { Add-Finding $r 'Low' 'Database' "Cosmos DB public endpoint restricted to $($ipRules.Count) IP range(s)$(if ($vnetFilter) { ' and VNet rules' })." 'Prefer private endpoints and disable public access.' -Exposure 'Restricted public endpoint' -Source 'Specific networks' -Evidence ($ipRules -join ', ') }
            }
            'microsoft.keyvault/vaults' {
                if (-not (Test-PublicAccess $r)) { break }
                if ((Get-Path $r 'properties.networkAcls.defaultAction') -ne 'Deny') { Add-Finding $r 'Medium' 'Key Vault' "Key Vault accepts connections from all networks.$peNote" 'Set the firewall to allow only selected networks (or trusted Microsoft services), or use private endpoints.' -Exposure 'Key Vault open to all networks' -Source 'Any internet address' }
                else { Add-Finding $r 'Info' 'Key Vault' 'Public endpoint restricted by the Key Vault firewall.' 'No action; prefer private endpoints.' -Exposure 'Restricted public endpoint' -NotPublic }
            }
            'microsoft.web/sites' {
                if (-not (Test-PublicAccess $r)) { break }
                $kindText = if ([string]$r.kind -like '*functionapp*') { 'Function App' } elseif ([string]$r.kind -like '*workflowapp*') { 'Logic App' } else { 'Web app' }
                $issues = @()
                if ((Get-Path $r 'properties.httpsOnly') -ne $true) { $issues += @{ Sev = 'Medium'; Text = "$kindText accepts plain HTTP (HTTPS only is off)."; Fix = 'Turn on HTTPS only.' } }
                $restricted = $false; $cfgText = ''
                if (-not $SkipAppServiceConfig -and -not $SkipDetailChecks) {
                    $cfg = Get-Prop (Invoke-Rest -Uri "$Arm$($r.id)/config/web?api-version=2024-04-01") 'properties'
                    $rules = @(Get-List $cfg 'ipSecurityRestrictions' | Where-Object { (Get-Prop $_ 'ipAddress') -ne 'Any' -or (Get-Prop $_ 'action') -ne 'Allow' })
                    $restricted = $rules.Count -gt 0 -or (Get-Prop $cfg 'ipSecurityRestrictionsDefaultAction') -eq 'Deny'
                    $cfgText = "$($rules.Count) access restriction(s)"
                    if ((Get-Prop $cfg 'remoteDebuggingEnabled') -eq $true) { $issues += @{ Sev = 'High'; Text = "Remote debugging is on."; Fix = 'Turn remote debugging off.' } }
                    if ((Get-Prop $cfg 'ftpsState') -eq 'AllAllowed') { $issues += @{ Sev = 'Medium'; Text = 'FTP (unencrypted) deployment is allowed.'; Fix = 'Set FTP state to Disabled (or FTPS only).' } }
                    if ((Get-Prop $cfg 'minTlsVersion') -in '1.0', '1.1') { $issues += @{ Sev = 'Low'; Text = "Minimum TLS version is $(Get-Prop $cfg 'minTlsVersion')."; Fix = 'Set the minimum TLS version to 1.2.' } }
                }
                $exp = if ($restricted) { "Public endpoint with access restrictions ($cfgText)" } else { 'Public endpoint open to the internet' }
                Add-Finding $r 'Info' 'App Service' "$kindText is reachable from $(if ($restricted) { 'the addresses its access restrictions allow' } else { 'any internet address' })$(if ($SkipAppServiceConfig -or $SkipDetailChecks) { ' (access restrictions not checked)' }).$peNote" `
                    $(if ($restricted) { 'No action.' } else { 'If it isn''t meant to be public, add access restrictions or a private endpoint; if it is, consider Front Door / Application Gateway with a WAF in front.' }) -Exposure $exp -Source $(if ($restricted) { 'Specific networks' } else { 'Any internet address' })
                foreach ($i in $issues) { Add-Finding $r $i.Sev 'App Service' $i.Text $i.Fix -Exposure $exp }
            }
            'microsoft.containerregistry/registries' {
                if ((Get-Path $r 'properties.anonymousPullEnabled') -eq $true) { Add-Finding $r 'High' 'Container' 'Anyone can pull images without signing in (anonymous pull).' 'Turn off anonymous pull unless the images are meant to be public.' -Exposure 'Anonymous image pull' -Source 'Anyone' }
                if (-not (Test-PublicAccess $r)) { break }
                if ((Get-Path $r 'properties.networkRuleSet.defaultAction') -ne 'Deny') { Add-Finding $r 'Medium' 'Container' "Container registry accepts connections from all networks.$peNote" 'Restrict with the registry firewall (Premium) or private endpoints.' -Exposure 'Registry open to all networks' -Source 'Any internet address' }
                if ((Get-Path $r 'properties.adminUserEnabled') -eq $true) { Add-Finding $r 'Medium' 'Container' 'The admin user (a shared username and password) is enabled.' 'Disable the admin user; use Entra ID identities / tokens.' -Exposure 'Shared admin credentials' }
            }
            'microsoft.containerservice/managedclusters' {
                $private = (Get-Path $r 'properties.apiServerAccessProfile.enablePrivateCluster') -eq $true
                $ranges = @(Get-List $r 'properties.apiServerAccessProfile.authorizedIPRanges')
                if ($private) { break }
                if (-not $ranges.Count) { Add-Finding $r 'High' 'Kubernetes' 'The Kubernetes API server is reachable from any internet address.' 'Set authorized IP ranges, or make it a private cluster (or use API server VNet integration).' -Exposure 'Public Kubernetes API server' -Source 'Any internet address' }
                else { Add-Finding $r 'Low' 'Kubernetes' "The Kubernetes API server is public but limited to $($ranges.Count) authorized IP range(s)." 'Consider a private cluster.' -Exposure 'Restricted public API server' -Source 'Specific public ranges' -Evidence ($ranges -join ', ') }
            }
            'microsoft.cache/redis' {
                if ((Get-Path $r 'properties.enableNonSslPort') -eq $true) { Add-Finding $r 'High' 'Database' 'Redis accepts unencrypted connections (non-TLS port 6379).' 'Turn off the non-TLS port.' -Exposure 'Redis non-TLS port' -PortsText '6379' }
                if (Test-PublicAccess $r) { Add-Finding $r 'Medium' 'Database' "Redis has public network access enabled.$peNote" 'Use private endpoints and disable public network access (or restrict with Redis firewall rules).' -Exposure 'Public Redis endpoint' }
            }
            'microsoft.cognitiveservices/accounts' {
                if (-not (Test-PublicAccess $r)) { break }
                if ((Get-Path $r 'properties.networkAcls.defaultAction') -ne 'Deny') { Add-Finding $r 'Medium' 'AI services' "Azure AI service ($($r.kind)) accepts connections from all networks.$peNote" 'Restrict to selected networks or private endpoints.' -Exposure 'AI service open to all networks' -Source 'Any internet address' }
                if ((Get-Path $r 'properties.disableLocalAuth') -ne $true) { Add-Finding $r 'Low' 'AI services' 'API keys are allowed (local authentication on).' 'Disable local auth and use Entra ID.' -NotPublic }
            }
            'microsoft.apimanagement/service' {
                $vnetType = [string](Get-Path $r 'properties.virtualNetworkType')
                if ($vnetType -eq 'Internal' -or -not (Test-PublicAccess $r)) { break }
                Add-Finding $r 'Info' 'API Management' "API Management gateway is public (virtual network type: $(if ($vnetType) { $vnetType } else { 'None' }))." 'Public by design: make sure each API requires authentication; consider Application Gateway / Front Door with a WAF in front.' -Exposure 'Public API gateway' -Source 'Any internet address'
            }
            default {
                if (-not (Test-PublicAccess $r)) { break }
                $acl = [string](Get-Path $r 'properties.networkAcls.defaultAction')
                if (-not $acl) { $acl = [string](Get-Path $r 'properties.networkRuleSet.defaultAction') }
                if ($acl -eq 'Deny') { break }
                if ([string](Get-Path $r 'properties.publicNetworkAccess') -eq '') { break }   # property present but empty: unknown
                Add-Finding $r 'Low' 'Other PaaS' "Public network access is enabled ($($r.type)).$peNote" 'If it doesn''t need to be reachable from the internet, disable public network access or restrict it with the service''s firewall / private endpoints.' -Exposure 'Public endpoint' -Source 'Any internet address (unless the service has other restrictions)'
            }
        }
    } catch {
        $subStats[$sub].Errors.Add("$($r.name): $($_.Exception.Message)")
        Write-Warning "  $($r.name): $($_.Exception.Message)"
    }
}
foreach ($r in $net) {
    $sub = $r.subscriptionId.ToLowerInvariant()
    if ($subStats.ContainsKey($sub) -and $r.type -in 'microsoft.network/publicipaddresses', 'microsoft.network/loadbalancers', 'microsoft.network/applicationgateways', 'microsoft.network/azurefirewalls', 'microsoft.network/frontdoors', 'microsoft.cdn/profiles') { $subStats[$sub].Checked++ }
}

#endregion

#region Output --------------------------------------------------------------------------

foreach ($k in $publicResources.Keys) {
    $s = Get-SubscriptionFromLid $k
    if ($subStats.ContainsKey($s)) { $subStats[$s].Public++ }
}
$rows = [System.Collections.Generic.List[object]]::new()
foreach ($f in ($findings | Sort-Object { -$SevRank[$_.Severity] }, Category, ResourceName)) { $rows.Add($f) }
$scopeText = if ($ManagementGroupId) { "Management group $ManagementGroupId" } elseif ($SubscriptionId) { "$($subs.Count) selected subscription(s)" } else { "All $($subs.Count) subscription(s) in the tenant" }
foreach ($s in $subs) {
    $st = $subStats[$s.subscriptionId.ToLowerInvariant()]
    $rows.Add([pscustomobject][ordered]@{
        RecordType = 'Subscription'; Severity = ''; Category = ''; ResourceName = ''; ResourceType = ''; ResourceGroup = ''
        SubscriptionId = $s.subscriptionId; SubscriptionName = $s.displayName; Location = ''; ResourceId = "/subscriptions/$($s.subscriptionId)"
        Exposure = ''; PublicIp = ''; Ports = ''; Source = ''; AttachedTo = ''; InternetReachable = ''; Finding = ''; Recommendation = ''; Evidence = ''
        ResourcesChecked = $st.Checked; PublicResources = $st.Public; PrivateResources = [math]::Max(0, $st.Checked - $st.Public); Errors = ($st.Errors -join ' | ')
        Scope = $scopeText; ReportGeneratedUtc = $reportTime
    })
}

$summary = $findings | Group-Object Severity | Sort-Object { -$SevRank[$_.Name] }
Write-Host 'Findings:' -ForegroundColor Cyan
foreach ($g in $summary) { Write-Host ("  {0,-9} {1}" -f $g.Name, $g.Count) }

if ($OutputPath) {
    $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host "Report exported to $((Resolve-Path $OutputPath).Path)" -ForegroundColor Green
} else {
    $rows | Where-Object RecordType -eq 'Finding'
}

#endregion
