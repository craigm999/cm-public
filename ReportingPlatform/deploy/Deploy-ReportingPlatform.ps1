<#
.SYNOPSIS
    Deploys (or updates) the Identity & Azure reporting platform: asks about your environment,
    checks your permissions, then deploys the infrastructure (Bicep), the sign-in app, the
    managed identity's permissions and the Function App code.

.DESCRIPTION
    Run it from PowerShell 7.4+ with the Azure CLI installed. It:

      1. Signs you in with the Azure CLI (one sign-in covers Azure, Bicep and Microsoft Graph).
      2. Asks about the target environment, discovering what's already there: subscription,
         VNet and subnets, private DNS zones, resource group, app registration, reader group,
         Log Analytics workspace, and how the Azure report should be scoped.
         Answers are saved to a settings file (no secrets in it), so later runs can update the
         platform without questions (-NonInteractive), and an admin can pick up the steps you
         don't have rights for (Grant-ReportingAccess.ps1).
      3. Checks everything before changing anything: your Azure and Entra permissions for each
         step, resource providers, region support, names, subnets and DNS. Steps you can't do
         are listed with the exact command for someone who can.
      4. Shows what will change (Bicep what-if) and asks you to confirm.
      5. Deploys: integration subnet, sign-in app registration, Bicep template, Graph and Azure
         read permissions for the managed identity, and the code.

    Re-running is safe: every step is idempotent.

.PARAMETER SettingsPath
    Where answers are saved / read. Default: settings.json next to this script.

.PARAMETER NonInteractive
    Use the saved settings as they are: no questions (for re-deployments and pipelines).

.PARAMETER CodeOnly
    Only build and deploy the Function App code (uses the saved settings).

.PARAMETER SkipCode
    Deploy everything except the code.

.PARAMETER PackagePath
    Deploy this already-built package instead of building one.

.PARAMETER GraphModuleVersion
    Microsoft.Graph.Authentication version bundled into the package.

.PARAMETER Force
    Carry on even if pre-flight checks report something missing.

.PARAMETER WhatIf
    Ask the questions and run the checks and the Bicep what-if, but change nothing.

.EXAMPLE
    ./Deploy-ReportingPlatform.ps1

.EXAMPLE
    ./Deploy-ReportingPlatform.ps1 -WhatIf

.EXAMPLE
    ./Deploy-ReportingPlatform.ps1 -SettingsPath ./settings.prd.json -NonInteractive
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$SettingsPath = (Join-Path $PSScriptRoot 'settings.json'),
    [switch]$NonInteractive,
    [switch]$CodeOnly,
    [switch]$SkipCode,
    [string]$PackagePath,
    [string]$GraphModuleVersion = '2.25.0',
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'ReportingDeploy.psm1') -Force

$Preview = [bool]$WhatIfPreference
$WhatIfPreference = $false   # the module's own calls aren't previewed one by one; steps are gated below
$platformRoot = Split-Path -Parent $PSScriptRoot
$Arm = 'https://management.azure.com'
$template = Join-Path $PSScriptRoot 'main.bicep'
$FlexProviders = @('Microsoft.Web', 'Microsoft.App', 'Microsoft.Storage', 'Microsoft.Network', 'Microsoft.ManagedIdentity', 'Microsoft.Insights', 'Microsoft.OperationalInsights')
$DnsZoneNames = [ordered]@{ blob = 'privatelink.blob.core.windows.net'; queue = 'privatelink.queue.core.windows.net'; table = 'privatelink.table.core.windows.net'; sites = 'privatelink.azurewebsites.net' }
$DefaultSchedules = [ordered]@{ leastPrivilege = '0 0 2 * * *'; azureChanges = '0 30 2 * * *'; appSignIns = '0 0 4 * * 1'; conditionalAccess = '0 30 4 * * 1'; authMethods = '0 0 3 * * *' }
$ScheduleNames = @{ leastPrivilege = 'Least privilege'; azureChanges = 'Azure changes'; appSignIns = 'Applications'; conditionalAccess = 'Conditional Access'; authMethods = 'Authentication methods' }
$OutboundFqdns = @('login.microsoftonline.com', 'graph.microsoft.com', 'management.azure.com', '<region>.in.applicationinsights.azure.com (see the connection string)', '<region>.livediagnostics.monitor.azure.com')
$Interactive = -not $NonInteractive -and -not $CodeOnly

#region Settings ------------------------------------------------------------------------

function New-DefaultSettings {
    [ordered]@{
        version         = 1
        tenantId        = ''
        subscriptionId  = ''
        namePrefix      = 'idrpt'
        environmentName = 'prd'
        names           = [ordered]@{}
        tags            = [ordered]@{}
        resourceGroup   = [ordered]@{ name = ''; create = $false }
        location        = ''
        storageSku      = ''
        network         = [ordered]@{
            vnetId                  = ''
            privateEndpointSubnetId = ''
            integrationSubnet       = [ordered]@{ mode = ''; id = ''; name = ''; addressPrefix = ''; nsgId = ''; routeTableId = '' }
            dnsMode                 = 'zones'     # zones | policy | manual
            privateDnsZoneIds       = [ordered]@{ blob = ''; queue = ''; table = ''; sites = '' }
            outboundViaFirewall     = $false
        }
        signIn          = [ordered]@{ mode = 'create'; clientId = ''; displayName = 'Identity & Azure Reports'; readerGroupId = ''; readerGroupName = ''; createReaderGroup = $false }
        permissions     = [ordered]@{ grantGraph = $true; azureReaderScope = 'tenantRoot'; managementGroupId = ''; subscriptionIds = @(); includeUserAuthenticationMethodRead = $false }
        monitoring      = [ordered]@{ logAnalyticsWorkspaceId = '' }
        schedules       = [ordered]@{}
        codeDeployment  = 'direct'               # direct | temporaryAccess | skip
        deployed        = [ordered]@{}           # filled in after a deployment
    }
}

function Merge-Settings($Defaults, $Saved) {
    if ($null -eq $Saved) { return $Defaults }
    foreach ($k in @($Saved.Keys)) {
        if ($Defaults.Contains($k) -and $Defaults[$k] -is [System.Collections.IDictionary] -and $Saved[$k] -is [System.Collections.IDictionary] -and $k -notin 'names', 'tags', 'schedules', 'deployed') {
            $Defaults[$k] = Merge-Settings $Defaults[$k] $Saved[$k]
        } else { $Defaults[$k] = $Saved[$k] }
    }
    return $Defaults
}

function Save-Settings($S) {
    $S | ConvertTo-Json -Depth 10 | Set-Content -Path $SettingsPath -Encoding utf8NoBOM
}

function Get-Names($S) {
    $base = "$($S.namePrefix)-$($S.environmentName)"; $compact = "$($S.namePrefix)$($S.environmentName)"
    $n = [ordered]@{
        functionApp = "func-$base-reports"; plan = "asp-$base-reports"; identity = "id-$base-reports"
        hostStorage = "st$($compact)rptfn".Substring(0, [math]::Min(24, "st$($compact)rptfn".Length))
        reportsStorage = "st$($compact)rptdata".Substring(0, [math]::Min(24, "st$($compact)rptdata".Length))
        appInsights = "appi-$base-reports"; logAnalytics = "log-$base-reports"
    }
    foreach ($k in @($S.names.Keys)) { if ($S.names[$k]) { $n[$k] = $S.names[$k] } }
    return $n
}

#endregion

#region Questions -----------------------------------------------------------------------

function Read-Subscription($S) {
    $subs = @(Invoke-AzCli @('account', 'list') | Where-Object { $_.tenantId -eq $S.tenantId -and $_.state -eq 'Enabled' } | Sort-Object name)
    if (-not $subs.Count) { throw "No enabled subscriptions in tenant $($S.tenantId) for this account." }
    $default = if ($S.subscriptionId) { $S.subscriptionId } else { (@($subs | Where-Object isDefault) + $subs)[0].id }
    $S.subscriptionId = Read-Choice 'Which subscription should the platform be deployed to?' @($subs | ForEach-Object { @{ Label = $_.name; Value = $_.id; Detail = $_.id } }) $default
}

function Read-Naming($S) {
    $S.namePrefix = Read-Text 'Short name prefix for the resources (2-10 lowercase letters / digits)' $S.namePrefix { param($v) if ($v -notmatch '^[a-z0-9]{2,10}$') { 'Use 2-10 lowercase letters or digits.' } } -Help 'Used in every resource name, e.g. func-<prefix>-<env>-reports.'
    $S.environmentName = Read-Text 'Environment name (2-5 lowercase letters / digits)' $S.environmentName { param($v) if ($v -notmatch '^[a-z0-9]{2,5}$') { 'Use 2-5 lowercase letters or digits.' } }
    $n = Get-Names $S
    Write-Note "Function App $($n.functionApp), storage $($n.hostStorage) + $($n.reportsStorage), identity $($n.identity)."
}

function Read-Network($S) {
    $net = $S.network
    Write-Section 'Network'
    Write-Note 'Everything is private: the portal and storage are only reachable through private endpoints in your VNet.'
    $vnets = @(Invoke-AzCli @('network', 'vnet', 'list') | Sort-Object name)
    $opts = @($vnets | ForEach-Object { @{ Label = "$($_.name)"; Value = $_.id; Detail = "$($_.resourceGroup), $($_.location), $(@($_.addressSpace.addressPrefixes) -join ' ')" } })
    if ($net.vnetId -and -not ($vnets | Where-Object { $_.id -eq $net.vnetId })) { $opts += @{ Label = "$(Get-ResourceName $net.vnetId) (saved)"; Value = $net.vnetId; Detail = 'another subscription' } }
    $opts += @{ Label = 'A VNet in another subscription (enter its resource ID)'; Value = '__other' }
    $choice = Read-Choice 'Which existing virtual network should the platform join?' $opts $(if ($net.vnetId) { $net.vnetId } else { $null }) -Help 'The Function App is created in the same region as the VNet (VNet integration needs this).'
    if ($choice -eq '__other') {
        $choice = Read-Text 'VNet resource ID' '' { param($v) if ($v -notmatch '^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.Network/virtualNetworks/[^/]+$') { 'Expected /subscriptions/.../resourceGroups/.../providers/Microsoft.Network/virtualNetworks/<name>' } }
    }
    $net.vnetId = $choice
    $vnet = Invoke-AzCli @('network', 'vnet', 'show', '--ids', $net.vnetId)
    $S.location = $vnet.location
    $vnetPrefixes = @($vnet.addressSpace.addressPrefixes)
    $subnets = @($vnet.subnets)
    $used = @($subnets | ForEach-Object { if (Get-Prop $_ 'addressPrefix') { $_.addressPrefix } else { @(Get-Prop $_ 'addressPrefixes') } } | Where-Object { $_ })
    $special = 'GatewaySubnet', 'AzureFirewallSubnet', 'AzureFirewallManagementSubnet', 'AzureBastionSubnet', 'RouteServerSubnet'
    $info = {
        param($sn)
        $prefix = if (Get-Prop $sn 'addressPrefix') { $sn.addressPrefix } else { @(Get-Prop $sn 'addressPrefixes')[0] }
        $r = ConvertTo-IpRange $prefix
        $inUse = @(Get-Prop $sn 'ipConfigurations' | Where-Object { $_ }).Count
        $free = if ($r) { [int]$r.Size - 5 - $inUse } else { -1 }
        @{ Prefix = $prefix; InUse = $inUse; Free = $free; Delegations = @(Get-Prop $sn 'delegations' | ForEach-Object { Get-Prop $_ 'serviceName' } | Where-Object { $_ }); Size = $(if ($r) { [int]$r.Size } else { 0 }) }
    }

    # Private endpoint subnet
    $peCandidates = @($subnets | Where-Object { $_.name -notin $special -and -not (& $info $_).Delegations.Count })
    if (-not $peCandidates.Count) { throw "VNet $($vnet.name) has no subnet without a delegation for the private endpoints. Create one (a /28 is enough) and run again." }
    $net.privateEndpointSubnetId = Read-Choice 'Which subnet should the 5 private endpoints go in?' @($peCandidates | ForEach-Object {
            $i = & $info $_; @{ Label = $_.name; Value = $_.id; Detail = "$($i.Prefix), $($i.Free) free IPs$(if ($i.Free -lt 5) { ' - NOT ENOUGH' })" } }) $(if ($net.privateEndpointSubnetId) { $net.privateEndpointSubnetId } else { $null }) -Help 'Usually your shared private endpoint subnet. Needs 5 free addresses.'
    $peSubnet = $subnets | Where-Object { $_.id -eq $net.privateEndpointSubnetId }

    # Integration subnet
    $int = $net.integrationSubnet
    $ready = @($subnets | Where-Object { (& $info $_).Delegations -contains 'Microsoft.App/environments' })
    $empty = @($subnets | Where-Object { $i = & $info $_; $_.name -notin $special -and -not $i.Delegations.Count -and $i.InUse -eq 0 -and $i.Size -ge 32 -and $_.id -ne $net.privateEndpointSubnetId -and -not @(Get-Prop $_ 'privateEndpoints' | Where-Object { $_ }).Count })
    $opts = @()
    $opts += @($ready | ForEach-Object { $i = & $info $_; @{ Label = "$($_.name) (already delegated to Microsoft.App/environments)"; Value = "existing|$($_.id)"; Detail = $i.Prefix } })
    $opts += @($empty | ForEach-Object { $i = & $info $_; @{ Label = "$($_.name) (empty: delegate it to Microsoft.App/environments)"; Value = "delegate|$($_.id)"; Detail = $i.Prefix } })
    $suggested = Find-FreeSubnetRange -VnetPrefixes $vnetPrefixes -UsedPrefixes $used -PrefixLength 27
    $opts += @{ Label = 'Create a new subnet'; Value = 'create|'; Detail = $(if ($suggested) { "first free /27: $suggested" } else { 'no free /27 found in the address space' }) }
    $def = if ($int.mode -eq 'create') { 'create|' } elseif ($int.mode) { "$($int.mode)|$($int.id)" } elseif ($ready.Count) { "existing|$($ready[0].id)" } else { 'create|' }
    $pick = Read-Choice 'Which subnet should the Function App use for outbound traffic (VNet integration)?' $opts $def -Help "It must be delegated to Microsoft.App/environments, /27 or larger, with nothing else in it`n(other Flex Consumption apps can share it). Private endpoints can't go in it."
    $parts = $pick -split '\|', 2; $int.mode = $parts[0]; $int.id = $parts[1]
    if ($int.mode -eq 'create') {
        $int.name = Read-Text 'Name for the new subnet' $(if ($int.name) { $int.name } else { "snet-$($S.namePrefix)-$($S.environmentName)-reports-func" }) { param($v) if ($v -in @($subnets | ForEach-Object name)) { "A subnet called $v already exists." } }
        $int.addressPrefix = Read-Text 'Address range for it (/27 or larger)' $(if ($int.addressPrefix) { $int.addressPrefix } else { $suggested }) { param($v) Test-SubnetPrefix $v $vnetPrefixes $used }
        $nsg = Get-Prop (Get-Prop $peSubnet 'networkSecurityGroup') 'id'; $rt = Get-Prop (Get-Prop $peSubnet 'routeTable') 'id'
        $int.nsgId = ''; $int.routeTableId = ''
        if ($nsg -or $rt) {
            $what = @(if ($nsg) { "NSG $(Get-ResourceName $nsg)" }; if ($rt) { "route table $(Get-ResourceName $rt)" }) -join ' and '
            if (Read-YesNo "Attach the same $what as $($peSubnet.name) to the new subnet?" $true -Help 'Usually yes where outbound traffic must go through a firewall, or policy requires an NSG on every subnet.') {
                $int.nsgId = "$nsg"; $int.routeTableId = "$rt"
            }
        }
        $int.id = "$($net.vnetId)/subnets/$($int.name)"
    }

    # Private DNS
    $net.dnsMode = Read-Choice 'How are DNS records for private endpoints created in your environment?' @(
        @{ Label = 'In private DNS zones (privatelink.*) - pick them next'; Value = 'zones'; Detail = 'found automatically across your subscriptions' }
        @{ Label = 'Automatically by Azure Policy'; Value = 'policy'; Detail = 'typical in a hub-and-spoke landing zone' }
        @{ Label = 'Other DNS - I will create the records myself'; Value = 'manual'; Detail = 'you get the list of names and IPs at the end' }
    ) $net.dnsMode
    foreach ($k in @($DnsZoneNames.Keys)) { if ($net.dnsMode -ne 'zones') { $net.privateDnsZoneIds[$k] = '' } }
    if ($net.dnsMode -eq 'zones') {
        $q = "resources | where type =~ 'microsoft.network/privatednszones' and name in~ ('$($DnsZoneNames.Values -join "','")') | project id, name, subscriptionId, resourceGroup"
        $zones = @((Invoke-AzRest -Method POST -Url "$Arm/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01" -Body @{ query = $q; options = @{ resultFormat = 'objectArray' } } -AllowFailure).data | Where-Object { $_ })
        $lq = "resources | where type =~ 'microsoft.network/privatednszones/virtualnetworklinks' and tostring(properties.virtualNetwork.id) =~ '$($net.vnetId)' | project id"
        $links = @((Invoke-AzRest -Method POST -Url "$Arm/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01" -Body @{ query = $lq; options = @{ resultFormat = 'objectArray' } } -AllowFailure).data | Where-Object { $_ } | ForEach-Object { ($_.id -split '/virtualNetworkLinks/')[0].ToLowerInvariant() })
        foreach ($k in @($DnsZoneNames.Keys)) {
            $zn = $DnsZoneNames[$k]
            $found = @($zones | Where-Object { $_.name -eq $zn })
            $opts = @($found | ForEach-Object { @{ Label = "$zn in $($_.resourceGroup)"; Value = $_.id; Detail = $(if ($_.id.ToLowerInvariant() -in $links) { 'linked to the VNet' } else { 'NOT linked to the VNet' }) } })
            $opts += @{ Label = "Don't register a record for $k"; Value = '' ; Detail = 'Policy or your DNS team creates it' }
            $opts += @{ Label = 'Enter a zone resource ID'; Value = '__other' }
            $def = if ($net.privateDnsZoneIds[$k]) { $net.privateDnsZoneIds[$k] } elseif (@($found | Where-Object { $_.id.ToLowerInvariant() -in $links }).Count) { @($found | Where-Object { $_.id.ToLowerInvariant() -in $links })[0].id } elseif ($found.Count) { $found[0].id } else { '' }
            $v = Read-Choice "Private DNS zone for $k ($zn)?" $opts $def
            if ($v -eq '__other') { $v = Read-Text "Resource ID of $zn" '' { param($x) if ($x -notmatch "/providers/Microsoft\.Network/privateDnsZones/$([regex]::Escape($zn))$") { "Expected a resource ID ending in /privateDnsZones/$zn" } } }
            $net.privateDnsZoneIds[$k] = $v
        }
    }
    $net.outboundViaFirewall = Read-YesNo 'Does outbound internet traffic from this VNet go through a firewall or proxy (forced tunnelling)?' ([bool]$net.outboundViaFirewall) -Help "If yes, you'll get the list of addresses the Function App needs to reach (Graph, ARM, sign-in, App Insights)."
}

function Read-ResourceGroup($S) {
    Write-Section 'Resource group'
    $rgs = @(Invoke-AzCli @('group', 'list') | Sort-Object name)
    $opts = @($rgs | ForEach-Object { @{ Label = $_.name; Value = $_.name; Detail = $_.location } })
    $opts += @{ Label = 'Create a new resource group'; Value = '__new' }
    $def = if ($S.resourceGroup.name -and -not $S.resourceGroup.create) { $S.resourceGroup.name } elseif ($S.resourceGroup.create) { '__new' } else { $null }
    $choice = Read-Choice 'Which resource group should the platform go in?' $opts $def -Help "Resources are created in the VNet's region ($($S.location)) whatever the group's region. A new Flex Consumption app can fail in a group that already holds other App Service plans: if so, use a dedicated group."
    if ($choice -eq '__new') {
        $S.resourceGroup.name = Read-Text 'Name for the new resource group' $(if ($S.resourceGroup.create -and $S.resourceGroup.name) { $S.resourceGroup.name } else { "rg-$($S.namePrefix)-$($S.environmentName)-reports" }) { param($v) if ($v -in @($rgs | ForEach-Object name)) { "$v already exists - pick it from the list instead." } elseif ($v -notmatch '^[-\w\._\(\)]{1,90}$') { 'Invalid resource group name.' } }
        $S.resourceGroup.create = $true
    } else { $S.resourceGroup.name = $choice; $S.resourceGroup.create = $false }
}

function Read-SignIn($S) {
    $si = $S.signIn
    Write-Section 'Portal sign-in'
    $si.mode = Read-Choice 'Do you already have an app registration for the portal sign-in?' @(
        @{ Label = "No - create one ('$($si.displayName)')"; Value = 'create'; Detail = 'needs Cloud Application Administrator or Application Administrator' }
        @{ Label = 'Yes - use an existing one (I have its client ID)'; Value = 'existing'; Detail = 'e.g. created for you by an admin' }
    ) $si.mode
    if ($si.mode -eq 'existing') {
        $si.clientId = Read-Text 'Client (application) ID of the app registration' $si.clientId { param($v)
            if ($v -notmatch '^[0-9a-fA-F-]{36}$') { return 'Enter the GUID shown as Application (client) ID.' }
            if (-not (Get-SignInApp $v)) { return "No app registration with client ID $v in this tenant." } }
    } else {
        $si.displayName = Read-Text 'Display name for the new app registration' $si.displayName
    }
    while ($true) {
        $q = Read-Text 'Which security group should be able to open the portal? (name or object ID)' $(if ($si.readerGroupName) { $si.readerGroupName } else { $si.readerGroupId }) -Help 'Only members of this group can sign in (the enterprise app requires assignment).'
        $found = @(Find-Group $q)
        if ($found.Count -eq 1 -and ($found[0].displayName -eq $q -or $found[0].id -eq $q)) { $si.readerGroupId = $found[0].id; $si.readerGroupName = $found[0].displayName; $si.createReaderGroup = $false; break }
        if ($found.Count) {
            $opts = @($found | ForEach-Object { @{ Label = $_.displayName; Value = $_.id; Detail = $_.id } }) + @{ Label = 'None of these - search again'; Value = '' }
            $id = Read-Choice "Groups matching '$q':" $opts
            if ($id) { $g = $found | Where-Object { $_.id -eq $id }; $si.readerGroupId = $g.id; $si.readerGroupName = $g.displayName; $si.createReaderGroup = $false; break }
            continue
        }
        if ($q -notmatch '^[0-9a-fA-F-]{36}$' -and (Read-YesNo "No group called '$q'. Create it as a security group?" $true -Help 'Needs Groups Administrator or User Administrator, unless your tenant lets users create security groups.')) {
            $si.readerGroupId = ''; $si.readerGroupName = $q; $si.createReaderGroup = $true; break
        }
    }
}

function Read-ReportAccess($S, $MyRoles) {
    $p = $S.permissions
    Write-Section 'What the reports can read'
    Write-Note 'The reports run as a user-assigned managed identity with read-only access.'
    $canGrant = Test-HasEntraRole $MyRoles 'GlobalAdministrator', 'PrivilegedRoleAdministrator'
    $p.grantGraph = Read-YesNo 'Grant the managed identity its Microsoft Graph read permissions as part of this deployment?' $(if ($null -ne $p.grantGraph -and -not $canGrant) { $false } else { [bool]$p.grantGraph }) -Help @"
Application permissions: $($GraphReadPermissions -join ', ').
Needs Privileged Role Administrator (or Global Administrator) - $(if ($canGrant) { 'you have it (active).' } else { "you don't have it active, so answer n to get a command for an admin." })
"@
    $mgs = @(Invoke-AzCli @('account', 'management-group', 'list') -AllowFailure | Where-Object { $_ })
    $opts = @(
        @{ Label = 'Tenant root management group (every subscription)'; Value = 'tenantRoot'; Detail = 'recommended; needs Owner / User Access Administrator at the root' }
    )
    if ($mgs.Count) { $opts += @{ Label = 'A specific management group'; Value = 'managementGroup' } }
    $opts += @{ Label = 'Specific subscriptions'; Value = 'subscriptions' }
    $opts += @{ Label = "Don't grant it now (I'll give it Reader myself)"; Value = 'none' }
    $p.azureReaderScope = Read-Choice 'Which subscriptions should the Azure changes report cover? (the identity gets Reader there)' $opts $p.azureReaderScope
    if ($p.azureReaderScope -eq 'managementGroup') {
        $p.managementGroupId = Read-Choice 'Which management group?' @($mgs | Sort-Object displayName | ForEach-Object { @{ Label = $_.displayName; Value = $_.name; Detail = $_.name } }) $p.managementGroupId
    }
    if ($p.azureReaderScope -eq 'subscriptions') {
        $subs = @(Invoke-AzCli @('account', 'list') | Where-Object { $_.tenantId -eq $S.tenantId -and $_.state -eq 'Enabled' } | Sort-Object name)
        $p.subscriptionIds = @(Read-MultiChoice 'Which subscriptions?' @($subs | ForEach-Object { @{ Label = $_.name; Value = $_.id; Detail = $_.id } }) @($p.subscriptionIds))
    }
}

function Read-Monitoring($S) {
    Write-Section 'Monitoring and schedules'
    $ws = @(Invoke-AzCli @('monitor', 'log-analytics', 'workspace', 'list') -AllowFailure | Where-Object { $_ } | Sort-Object name)
    $opts = @(@{ Label = 'Create a new Log Analytics workspace'; Value = '' }) + @($ws | ForEach-Object { @{ Label = $_.name; Value = $_.id; Detail = "$($_.resourceGroup), $($_.location)" } })
    $S.monitoring.logAnalyticsWorkspaceId = Read-Choice 'Where should the Function App logs (Application Insights) go?' $opts $S.monitoring.logAnalyticsWorkspaceId
    $keep = Read-YesNo "Keep the default report schedules? (UTC: least privilege 02:00, Azure changes 02:30, auth methods 03:00 daily; apps 04:00 and Conditional Access 04:30 on Mondays)" (-not $S.schedules.Count)
    if ($keep) { $S.schedules = [ordered]@{} } else {
        foreach ($k in @($DefaultSchedules.Keys)) {
            $S.schedules[$k] = Read-Text "Schedule for $($ScheduleNames[$k]) (NCRONTAB, UTC: second minute hour day month weekday)" $(if ($S.schedules[$k]) { $S.schedules[$k] } else { $DefaultSchedules[$k] }) { param($v) if (@($v -split '\s+').Count -ne 6) { 'Six fields, e.g. 0 0 2 * * * for daily at 02:00.' } }
        }
    }
    $tagText = Read-Text 'Tags for the resources (key=value; key=value), or Enter for none' (@($S.tags.Keys | ForEach-Object { "$_=$($S.tags[$_])" }) -join '; ') { param($v) if (@($v -split ';' | Where-Object { $_.Trim() -and $_ -notmatch '^\s*[^=]+=.*$' }).Count) { 'Use key=value pairs separated by ;' } } -AllowEmpty
    $S.tags = [ordered]@{}; foreach ($pair in @($tagText -split ';' | Where-Object { $_.Trim() })) { $k, $v = $pair -split '=', 2; $S.tags[$k.Trim()] = $v.Trim() }
}

function Read-CodeDeployment($S) {
    Write-Section 'Code deployment'
    $S.codeDeployment = Read-Choice 'Can this machine reach the private network (VPN, ExpressRoute, or a jump box in or peered to the VNet)?' @(
        @{ Label = 'Yes - deploy the code over the private network'; Value = 'direct'; Detail = 'recommended' }
        @{ Label = "No - open the deployment endpoint to this machine's public IP only, while the upload runs"; Value = 'temporaryAccess'; Detail = 'closed again straight after (the portal itself stays private)' }
        @{ Label = "No - skip the code; I'll run the code step later from a machine on the network"; Value = 'skip' }
    ) $S.codeDeployment -Help 'The code is uploaded to the Function App''s deployment (SCM) endpoint, which only has a private endpoint.'
}

#endregion

#region Pre-flight ----------------------------------------------------------------------

function Invoke-Preflight($S, $MyRoles, [bool]$IsUser) {
    Reset-Checks
    $n = Get-Names $S
    $sub = "/subscriptions/$($S.subscriptionId)"
    $rgScope = "$sub/resourceGroups/$($S.resourceGroup.name)"
    $net = $S.network

    # --- Tools & platform
    $ver = Invoke-AzCli @('version') -AllowFailure
    $cli = [version]('0.0.0' + ''); if ($ver) { [void][version]::TryParse([string](Get-Prop $ver 'azure-cli'), [ref]$cli) }
    if ($cli -ge [version]'2.60.0') { Add-Check 'Tools' 'Azure CLI 2.60+' 'OK' "$cli" } else { Add-Check 'Tools' 'Azure CLI 2.60+' 'Missing' "found $cli" 'az upgrade' }
    $flex = @(Invoke-AzCli @('functionapp', 'list-flexconsumption-locations') -AllowFailure | ForEach-Object { ([string]$_.name -replace '\s', '').ToLowerInvariant() })
    if (-not $flex.Count) { Add-Check 'Platform' "Flex Consumption in $($S.location)" 'Warning' "couldn't list supported regions" }
    elseif ($S.location.ToLowerInvariant() -in $flex) { Add-Check 'Platform' "Flex Consumption in $($S.location)" 'OK' }
    else { Add-Check 'Platform' "Flex Consumption in $($S.location)" 'Missing' 'region not supported' 'Use a VNet in a supported region (az functionapp list-flexconsumption-locations)' }

    $script:ProvidersToRegister = @()
    foreach ($p in $FlexProviders) {
        $st = Get-Prop (Invoke-AzCli @('provider', 'show', '-n', $p, '--query', '{s:registrationState}') -AllowFailure) 's'
        if ($st -eq 'Registered') { continue }
        $t = Test-AzPermission -Scope $sub -Actions "$p/register/action"
        if ($t.Known -and -not $t.Missing.Count) { Add-Check 'Platform' "Resource provider $p" 'OK' "$st - will be registered"; $script:ProvidersToRegister += $p }
        else { Add-Check 'Platform' "Resource provider $p" 'Missing' "$st" "A subscription Contributor/Owner runs: az provider register -n $p --subscription $($S.subscriptionId)" }
    }

    # --- Names
    $existingApp = Invoke-AzRest -Url "$Arm$rgScope/providers/Microsoft.Web/sites/$($n.functionApp)?api-version=2024-04-01" -AllowFailure
    if (-not $existingApp) {
        $na = Invoke-AzRest -Method POST -Url "$Arm$sub/providers/Microsoft.Web/checknameavailability?api-version=2024-04-01" -Body @{ name = $n.functionApp; type = 'Microsoft.Web/sites' } -AllowFailure
        if ($na -and -not $na.nameAvailable) { Add-Check 'Names' "Function App name $($n.functionApp)" 'Missing' "$($na.message)" 'Change the prefix / environment name, or set names.functionApp in the settings file' }
        else { Add-Check 'Names' "Function App name $($n.functionApp)" 'OK' }
    } else { Add-Check 'Names' "Function App $($n.functionApp)" 'OK' 'exists - will be updated' }
    foreach ($k in 'hostStorage', 'reportsStorage') {
        $mine = Invoke-AzRest -Url "$Arm$rgScope/providers/Microsoft.Storage/storageAccounts/$($n[$k])?api-version=2023-05-01" -AllowFailure
        if ($mine) { Add-Check 'Names' "Storage account $($n[$k])" 'OK' 'exists - will be updated'; continue }
        $na = Invoke-AzCli @('storage', 'account', 'check-name', '--name', $n[$k]) -AllowFailure
        if ($na -and -not $na.nameAvailable) { Add-Check 'Names' "Storage account $($n[$k])" 'Missing' "$($na.reason): $($na.message)" "Set names.$k in $SettingsPath to a unique name (3-24 lowercase letters/digits), or change the prefix" }
        else { Add-Check 'Names' "Storage account $($n[$k])" 'OK' }
    }

    # --- Azure permissions
    $deployActions = @('Microsoft.Resources/deployments/write', 'Microsoft.Web/serverfarms/write', 'Microsoft.Web/sites/write', 'Microsoft.Storage/storageAccounts/write',
        'Microsoft.ManagedIdentity/userAssignedIdentities/write', 'Microsoft.ManagedIdentity/userAssignedIdentities/assign/action', 'Microsoft.Insights/components/write',
        'Microsoft.Network/privateEndpoints/write', 'Microsoft.Authorization/roleAssignments/write')
    if (-not $S.monitoring.logAnalyticsWorkspaceId) { $deployActions += 'Microsoft.OperationalInsights/workspaces/write' }
    if ($S.resourceGroup.create) {
        Add-PermissionCheck 'Azure' "Create resource group $($S.resourceGroup.name)" $sub @('Microsoft.Resources/subscriptions/resourceGroups/write') 'Contributor on the subscription, or ask for the group to be created for you' | Out-Null
        Add-PermissionCheck 'Azure' 'Deploy into the new resource group' $sub $deployActions 'Owner on the subscription (or Contributor + Role Based Access Control Administrator)' | Out-Null
    } else {
        Add-PermissionCheck 'Azure' "Deploy into $($S.resourceGroup.name)" $rgScope $deployActions 'Owner on the resource group, or Contributor + Role Based Access Control Administrator (the template assigns storage / monitoring roles to the identity)' | Out-Null
    }
    Add-PermissionCheck 'Azure' "Private endpoints in subnet $(Get-ResourceName $net.privateEndpointSubnetId)" $net.privateEndpointSubnetId @('Microsoft.Network/virtualNetworks/subnets/join/action') 'Network Contributor on the VNet or subnet' | Out-Null
    switch ($net.integrationSubnet.mode) {
        'existing' { Add-PermissionCheck 'Azure' "VNet integration with $(Get-ResourceName $net.integrationSubnet.id)" $net.integrationSubnet.id @('Microsoft.Network/virtualNetworks/subnets/join/action') 'Network Contributor on the VNet or subnet' | Out-Null }
        'delegate' { Add-PermissionCheck 'Azure' "Delegate subnet $(Get-ResourceName $net.integrationSubnet.id)" $net.integrationSubnet.id @('Microsoft.Network/virtualNetworks/subnets/write', 'Microsoft.Network/virtualNetworks/subnets/join/action') 'Network Contributor on the VNet' | Out-Null }
        'create' {
            Add-PermissionCheck 'Azure' "Create subnet $($net.integrationSubnet.name)" $net.vnetId @('Microsoft.Network/virtualNetworks/subnets/write', 'Microsoft.Network/virtualNetworks/subnets/join/action') 'Network Contributor on the VNet' | Out-Null
            if ($net.integrationSubnet.nsgId) { Add-PermissionCheck 'Azure' 'Attach the NSG' $net.integrationSubnet.nsgId @('Microsoft.Network/networkSecurityGroups/join/action') 'Network Contributor on the NSG' | Out-Null }
            if ($net.integrationSubnet.routeTableId) { Add-PermissionCheck 'Azure' 'Attach the route table' $net.integrationSubnet.routeTableId @('Microsoft.Network/routeTables/join/action') 'Network Contributor on the route table' | Out-Null }
        }
    }
    foreach ($k in @($DnsZoneNames.Keys)) {
        $z = $net.privateDnsZoneIds[$k]
        if ($z) { Add-PermissionCheck 'Azure' "Register records in $($DnsZoneNames[$k])" $z @('Microsoft.Network/privateDnsZones/join/action') 'Private DNS Zone Contributor on the zone (or leave the zone out if Policy creates records)' | Out-Null }
    }
    if ($S.monitoring.logAnalyticsWorkspaceId) { Add-PermissionCheck 'Azure' "Use workspace $(Get-ResourceName $S.monitoring.logAnalyticsWorkspaceId)" $S.monitoring.logAnalyticsWorkspaceId @('Microsoft.OperationalInsights/workspaces/read') 'Reader (or Log Analytics Contributor) on the workspace' | Out-Null }
    foreach ($scope in (Get-ReaderScopes $S)) {
        $t = Test-AzPermission -Scope $scope -Actions 'Microsoft.Authorization/roleAssignments/write'
        if ($t.Known -and -not $t.Missing.Count) { Add-Check 'Azure' "Grant Reader at $scope" 'OK' }
        elseif (-not $t.Known) { Add-Check 'Azure' "Grant Reader at $scope" 'Warning' "couldn't check your rights there - will try, and hand it over if it fails" }
        else { Add-Check 'Azure' "Grant Reader at $scope" 'Deferred' 'not allowed' 'Owner / User Access Administrator there runs Grant-ReportingAccess.ps1 -Stage Permissions (printed at the end)' }
    }

    # --- Network sanity
    $vnet = Invoke-AzCli @('network', 'vnet', 'show', '--ids', $net.vnetId) -AllowFailure
    if ($vnet) {
        $pe = @($vnet.subnets | Where-Object { $_.id -eq $net.privateEndpointSubnetId }) | Select-Object -First 1
    }
    if ($vnet -and -not $pe) { Add-Check 'Network' 'Private endpoint subnet' 'Missing' "$(Get-ResourceName $net.privateEndpointSubnetId) not found in the VNet" 'Run again and pick the subnet' }
    elseif ($vnet) {
        $r = ConvertTo-IpRange $(if (Get-Prop $pe 'addressPrefix') { $pe.addressPrefix } else { @($pe.addressPrefixes)[0] })
        $free = if ($r) { [int]$r.Size - 5 - @(Get-Prop $pe 'ipConfigurations' | Where-Object { $_ }).Count } else { 99 }
        $peMine = @(Get-Prop $pe 'privateEndpoints' | Where-Object { $_ -and (Get-Prop $_ 'id') -like "*/pe-$($S.namePrefix)-$($S.environmentName)-reports-*" }).Count
        if ($free + $peMine -ge 5) { Add-Check 'Network' 'Free addresses for 5 private endpoints' 'OK' "$free free" } else { Add-Check 'Network' 'Free addresses for 5 private endpoints' 'Missing' "$free free" 'Use a larger or emptier subnet' }
    }
    if ($net.dnsMode -eq 'zones' -and -not @($net.privateDnsZoneIds.Values | Where-Object { $_ }).Count) { Add-Check 'Network' 'Private DNS' 'Warning' 'no zones selected - names will not resolve unless something else creates the records' }
    if ($net.outboundViaFirewall) { Add-Check 'Network' 'Outbound through a firewall' 'Warning' "allow HTTPS from the integration subnet to: $($OutboundFqdns -join ', ')" }

    # --- Entra
    if (-not $IsUser) {
        Add-Check 'Entra ID' 'Directory roles' 'Warning' "signed in as a service principal: the app registration and Graph permission steps need it to hold the equivalent Graph application permissions"
    } else {
        $appRoles = 'GlobalAdministrator', 'ApplicationAdministrator', 'CloudApplicationAdministrator'
        if ($S.signIn.mode -eq 'create') {
            if (Test-HasEntraRole $MyRoles $appRoles) { Add-Check 'Entra ID' 'Create the sign-in app registration' 'OK' }
            else { Add-Check 'Entra ID' 'Create the sign-in app registration' 'Missing' 'needs Cloud Application Administrator or Application Administrator (activate it in PIM first)' "Or have an admin run Grant-ReportingAccess.ps1 -Stage SignInApp -SettingsPath $SettingsPath, then re-run this and choose 'existing'" }
        } else {
            if (Test-HasEntraRole $MyRoles $appRoles) { Add-Check 'Entra ID' 'Update the sign-in app registration' 'OK' }
            else { Add-Check 'Entra ID' 'Update the sign-in app registration' 'Warning' "works only if you own the app registration and its enterprise app" "Or have an admin run Grant-ReportingAccess.ps1 -Stage SignInApp -SettingsPath $SettingsPath" }
        }
        if ($S.signIn.createReaderGroup) {
            if (Test-HasEntraRole $MyRoles 'GlobalAdministrator', 'GroupsAdministrator', 'UserAdministrator') { Add-Check 'Entra ID' "Create group $($S.signIn.readerGroupName)" 'OK' }
            else { Add-Check 'Entra ID' "Create group $($S.signIn.readerGroupName)" 'Warning' 'works only if your tenant lets users create security groups' 'Groups Administrator, or create the group yourself and re-run' }
        }
        if ($S.permissions.grantGraph) {
            if (Test-HasEntraRole $MyRoles 'GlobalAdministrator', 'PrivilegedRoleAdministrator') { Add-Check 'Entra ID' 'Grant Graph read permissions to the identity' 'OK' }
            else { Add-Check 'Entra ID' 'Grant Graph read permissions to the identity' 'Deferred' 'needs Privileged Role Administrator' 'A Privileged Role Administrator runs Grant-ReportingAccess.ps1 -Stage Permissions (printed at the end)' }
        } else { Add-Check 'Entra ID' 'Grant Graph read permissions to the identity' 'Deferred' 'you chose to leave it for an admin' }
    }
    return $existingApp
}

#endregion

#region Steps -----------------------------------------------------------------------------

function Invoke-BicepDeployment($S, [string]$IntegrationSubnetId, [string]$ClientId, [switch]$WhatIfOnly) {
    $params = [ordered]@{
        location = $S.location; namePrefix = $S.namePrefix; environmentName = $S.environmentName; names = $S.names; tags = $S.tags
        privateEndpointSubnetId = $S.network.privateEndpointSubnetId; integrationSubnetId = $IntegrationSubnetId
        privateDnsZoneIds = [ordered]@{}; easyAuthClientId = $ClientId; reportTenantId = $S.tenantId; schedules = $S.schedules
        storageSku = $S.storageSku; logAnalyticsWorkspaceId = $S.monitoring.logAnalyticsWorkspaceId
    }
    foreach ($k in @($S.network.privateDnsZoneIds.Keys)) { if ($S.network.privateDnsZoneIds[$k]) { $params.privateDnsZoneIds[$k] = $S.network.privateDnsZoneIds[$k] } }
    $file = [System.IO.Path]::GetTempFileName() + '.json'
    $doc = [ordered]@{ '$schema' = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#'; contentVersion = '1.0.0.0'; parameters = [ordered]@{} }
    foreach ($k in $params.Keys) { $doc.parameters[$k] = @{ value = $params[$k] } }
    $doc | ConvertTo-Json -Depth 10 | Set-Content -Path $file -Encoding utf8NoBOM
    $name = "reporting-platform-$((Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss'))"
    $common = @('-g', $S.resourceGroup.name, '-f', $template, '-p', "@$file")
    try {
        Write-Step 'Previewing changes (Bicep what-if)...'
        $wi = Invoke-AzCli (@('deployment', 'group', 'what-if') + $common + @('--no-pretty-print', '--result-format', 'ResourceIdOnly'))
        $changes = @($wi.changes | Where-Object { $_ })
        foreach ($g in ($changes | Group-Object changeType | Sort-Object Name)) {
            Write-Note ("{0,-9} {1}" -f $g.Name, (@($g.Group | ForEach-Object { Get-ResourceName $_.resourceId }) -join ', '))
        }
        if ($WhatIfOnly) { return $null }
        if ($Interactive -and -not (Read-YesNo 'Apply these changes?' $true)) { throw 'Stopped before deploying.' }
        Write-Step "Deploying $name (a few minutes)..."
        $d = Invoke-AzCli (@('deployment', 'group', 'create', '-n', $name) + $common)
        $o = $d.properties.outputs
        $out = @{}; foreach ($p in $o.PSObject.Properties) { $out[$p.Name] = $p.Value.value }
        Write-Done "Deployed $($out.functionAppName) ($($out.functionAppHostName))."
        return $out
    } finally { Remove-Item $file -Force -ErrorAction SilentlyContinue }
}

function Get-UploadHint([string]$Mode, [string]$ErrorText) {
    $hints = @()
    if ($ErrorText -match 'Microsoft\.Web/sites/publish|AuthorizationFailed') { $hints += 'You need the publish permission on the Function App: Website Contributor, Contributor or Owner.' }
    if ($ErrorText -match 'Ip Forbidden|ip restriction|Access Denied') {
        $hints += $(if ($Mode -eq 'temporaryAccess') { 'The deployment endpoint saw a different IP address from the one allowed (proxy / VPN split tunnel?). Re-run -CodeOnly and enter the address Azure sees, or deploy from a machine on the network.' }
                    else { "The deployment endpoint was reached over its public address. Check $($S.network.privateDnsZoneIds.sites) / your DNS resolves the scm host name to the private endpoint IP from this machine." })
    }
    $hints += 'If it still fails: Function App > Deployment Center > Logs shows whether the package couldn''t be written to storage (the app''s identity needs Storage Blob Data Owner on the host storage account, and blob/queue/table must resolve to private IPs from the VNet).'
    ($hints | ForEach-Object { "  - $_" }) -join "`n"
}

function Test-PrivateDnsReady($S, [string]$ResourceGroup) {
    <#
        The app reaches its storage (where the code package goes) and the deployment endpoint
        through the private endpoints, so their names must resolve privately first.
        zones:  records are created with the private endpoints - nothing to wait for.
        policy: waits (up to 20 minutes) for Azure Policy to add the DNS zone groups.
        manual: shows the records and asks whether they've been created.
        Returns $true when it's safe to upload.
    #>
    $prefix = "pe-$($S.namePrefix)-$($S.environmentName)-reports-"
    $needed = @('host-blob', 'host-queue', 'host-table', 'function')
    switch ($S.network.dnsMode) {
        'zones' { return $true }
        'policy' {
            Write-Step 'Waiting for Azure Policy to register the private endpoints in DNS...'
            $deadline = [datetime]::UtcNow.AddMinutes(20)
            while ($true) {
                $pending = @($needed | Where-Object {
                    $groups = Invoke-AzRest -Url "$Arm/subscriptions/$($S.subscriptionId)/resourceGroups/$ResourceGroup/providers/Microsoft.Network/privateEndpoints/$prefix$_/privateDnsZoneGroups?api-version=2024-05-01" -AllowFailure
                    -not @(Get-Prop $groups 'value' | Where-Object { $_ }).Count })
                if (-not $pending.Count) { Write-Done 'DNS records registered.'; return $true }
                if ([datetime]::UtcNow -gt $deadline) {
                    Write-Attention "No DNS registration yet for: $($pending -join ', '). Check the DNS policy assignment (it usually runs within a few minutes)."
                    return $false
                }
                Write-Note "Still waiting for: $($pending -join ', ')"
                Start-Sleep -Seconds 30
            }
        }
        'manual' {
            Write-Attention 'These DNS records must exist (and resolve from the VNet and from this machine) before the code can be uploaded:'
            foreach ($pe in @(Invoke-AzCli @('network', 'private-endpoint', 'list', '-g', $ResourceGroup) | Where-Object { $_.name -like "$prefix*" })) {
                foreach ($c in @($pe.customDnsConfigs)) { Write-Host "    $($c.fqdn) -> $(@($c.ipAddresses) -join ', ')" }
            }
            if ($CodeOnly) { return $true }   # run -CodeOnly once the records exist
            if (-not $Interactive) { return $false }
            return (Read-YesNo 'Have these records been created?' $false -Help "If not, answer n and run ./Deploy-ReportingPlatform.ps1 -CodeOnly once they have.")
        }
    }
    return $true
}

function Publish-Code($S, [string]$FunctionAppId) {
    $rg = Get-ResourceGroupFromId $FunctionAppId; $app = Get-ResourceName $FunctionAppId
    $zip = $PackagePath
    if (-not $zip) {
        Write-Step 'Building the code package...'
        $zip = Join-Path ([System.IO.Path]::GetTempPath()) "reporting-app-$([guid]::NewGuid()).zip"
        & (Join-Path $platformRoot 'build/Build-FunctionPackage.ps1') -OutputPath $zip -GraphModuleVersion $GraphModuleVersion | Out-Host
    }
    $hosts = Get-ScmHost $FunctionAppId
    $mode = $S.codeDeployment
    if ($mode -ne 'skip' -and -not (Test-PrivateDnsReady $S $rg)) {
        if (-not $PackagePath -and (Test-Path $zip)) { Remove-Item $zip -Force }
        Write-Attention 'Code not uploaded yet: DNS for the private endpoints is not in place.'
        return $false
    }
    $opened = $false
    try {
        if ($mode -eq 'direct') {
            $t = Test-TcpReachable $hosts.Scm
            if (-not $t.Reachable -or -not $t.Private) {
                Write-Attention "$($hosts.Scm) $(if ($t.Addresses) { "resolves to $($t.Addresses -join ', ')" } else { "doesn't resolve" }) and isn't reachable privately from here."
                if (-not $Interactive) { throw "Can't reach the deployment endpoint over the private network. Run from a machine on the network, or set codeDeployment to temporaryAccess in $SettingsPath." }
                $mode = Read-Choice 'How do you want to continue?' @(
                    @{ Label = "Open the deployment endpoint to this machine's public IP while uploading"; Value = 'temporaryAccess' }
                    @{ Label = 'Skip the code for now'; Value = 'skip' }) 'temporaryAccess'
            }
        }
        if ($mode -eq 'skip') { return $false }
        if ($mode -eq 'temporaryAccess') {
            $detected = try { [string](Invoke-RestMethod -Uri 'https://api.ipify.org' -TimeoutSec 8) } catch { '' }
            $ip = if ($Interactive) { Read-Text "This machine's public IP address, as Azure sees it (detected via api.ipify.org)" $detected { param($v) if ($v -notmatch '^\d+\.\d+\.\d+\.\d+$') { 'Enter an IPv4 address.' } } } else { $detected }
            if (-not $ip) { throw "Couldn't detect this machine's public IP address." }
            Write-Step "Opening the deployment endpoint to $ip only..."
            Set-TemporaryDeployAccess -FunctionAppId $FunctionAppId -IpAddress $ip
            $opened = $true
            Start-Sleep -Seconds 30
        }
        # The package is written to the app's storage by the app's managed identity. On a first
        # deployment its storage roles were assigned moments ago and can take ~10 minutes to
        # apply, so a 403 is retried for a while before giving up.
        for ($attempt = 1; ; $attempt++) {
            Write-Step "Uploading the package to $app$(if ($attempt -gt 1) { " (attempt $attempt)" })..."
            Invoke-AzCli @('functionapp', 'deployment', 'source', 'config-zip', '-g', $rg, '-n', $app, '--src', $zip) -AllowFailure | Out-Null
            if (-not (Get-AzLastError)) { break }
            $err = Get-AzLastError
            $retryable = $err -match '403|Forbidden|AuthorizationPermissionMismatch|AuthorizationFailure|not authorized' -and $err -notmatch 'Ip Forbidden|Microsoft\.Web/sites/publish'
            if (-not $retryable -or $attempt -ge 6) {
                throw "Code upload failed: $err`n$(Get-UploadHint $mode $err)"
            }
            Write-Attention 'Got 403 - usually the new storage roles of the app''s identity still taking effect. Retrying in 2 minutes...'
            Start-Sleep -Seconds 120
        }
        $expected = @(Get-ChildItem (Join-Path $platformRoot 'app') -Directory | Where-Object { Test-Path (Join-Path $_.FullName 'function.json') } | ForEach-Object Name)
        for ($i = 0; $i -lt 6; $i++) {
            $names = @(Invoke-AzCli @('functionapp', 'function', 'list', '-g', $rg, '-n', $app) -AllowFailure | ForEach-Object { ($_.name -split '/')[-1] })
            $missing = @($expected | Where-Object { $_ -notin $names })
            if (-not $missing.Count) { Write-Done "Code deployed: $($names -join ', ')."; return $true }
            Start-Sleep -Seconds 10
        }
        Write-Attention "Deployed, but these functions aren't listed yet: $($missing -join ', '). Check the Function App in the portal in a few minutes."
        return $true
    } finally {
        if ($opened) { Write-Step 'Closing the deployment endpoint again...'; Set-TemporaryDeployAccess -FunctionAppId $FunctionAppId -Close; Write-Done 'Public access disabled.' }
        if (-not $PackagePath -and $zip -and (Test-Path $zip)) { Remove-Item $zip -Force }
    }
}

#endregion

# =====================================================================================
#  Main
# =====================================================================================

Write-Host ''
Write-Host 'Identity & Azure reporting platform - deployment' -ForegroundColor Cyan
if ($Preview) { Write-Attention 'Preview (-WhatIf): nothing will be changed.' }

# --- Tools
if ($PSVersionTable.PSVersion -lt [version]'7.4') { throw "PowerShell 7.4 or later is needed (this is $($PSVersionTable.PSVersion)). Install from https://aka.ms/powershell" }
if (-not (Get-Command az -ErrorAction SilentlyContinue)) { throw 'The Azure CLI (az) is needed: https://aka.ms/installazurecli' }

# --- Settings
$saved = $null
if (Test-Path $SettingsPath) { $saved = ConvertTo-Hashtable (Get-Content -Raw $SettingsPath | ConvertFrom-Json) }
$S = Merge-Settings (New-DefaultSettings) $saved
$askQuestions = $Interactive
if (-not $Interactive -and -not $saved) { throw "No settings at $SettingsPath. Run interactively first (without -NonInteractive / -CodeOnly)." }
if ($Interactive -and $saved) {
    $how = Read-Choice "Found saved answers in $SettingsPath." @(
        @{ Label = 'Review them (Enter keeps each saved answer)'; Value = 'review' }
        @{ Label = 'Use them as they are'; Value = 'use' }
        @{ Label = 'Start again'; Value = 'new' }) 'review'
    if ($how -eq 'use') { $askQuestions = $false }
    if ($how -eq 'new') { $S = New-DefaultSettings }
}

# --- Sign in
Write-Section 'Sign-in'
$account = Invoke-AzCli @('account', 'show') -AllowFailure
if ($askQuestions) {
    $current = if ($account) { $account.tenantId } else { '' }
    $S.tenantId = Read-Text 'Tenant ID (or primary domain) to deploy to' $(if ($S.tenantId) { $S.tenantId } else { $current }) -Help $(if ($account) { "Signed in to the Azure CLI as $($account.user.name) in tenant $($account.tenantId)." } else { 'Not signed in to the Azure CLI yet.' })
}
if (-not $account -or ($S.tenantId -and $account.tenantId -ne $S.tenantId -and $account.tenantDefaultDomain -ne $S.tenantId)) {
    if (-not $Interactive) { throw "Sign in first: az login --tenant $($S.tenantId)" }
    Write-Step "Signing in to $($S.tenantId) (a browser window or device code prompt follows)..."
    & az login --tenant $S.tenantId --only-show-errors -o none
    if ($LASTEXITCODE) { throw 'az login failed.' }
    $account = Invoke-AzCli @('account', 'show')
}
$S.tenantId = $account.tenantId
$isUser = $account.user.type -eq 'user'
Write-Done "Signed in as $($account.user.name) to tenant $($S.tenantId)."
$myRoles = @(if ($isUser) { Get-MyEntraRoles })
if ($isUser) {
    $names = @($EntraRoles.Keys | Where-Object { $EntraRoles[$_] -in $myRoles })
    Write-Note "Active Entra roles: $(if ($names) { $names -join ', ' } else { 'none' }) (PIM-eligible roles must be activated first to count)."
}

# --- Questions
if ($askQuestions) {
    Write-Section 'Subscription and names'
    Read-Subscription $S
    Invoke-AzCli @('account', 'set', '--subscription', $S.subscriptionId) | Out-Null
    Read-Naming $S
    Read-Network $S
    Read-ResourceGroup $S
    Read-SignIn $S
    Read-ReportAccess $S $myRoles
    Read-Monitoring $S
    Read-CodeDeployment $S
} else {
    Invoke-AzCli @('account', 'set', '--subscription', $S.subscriptionId) | Out-Null
}
if (-not $S.storageSku) {
    $loc = @((Invoke-AzRest -Url "$Arm/subscriptions/$($S.subscriptionId)/locations?api-version=2022-12-01").value | Where-Object { $_.name -eq $S.location })[0]
    $S.storageSku = if (@(Get-Prop $loc 'availabilityZoneMappings' | Where-Object { $_ }).Count) { 'Standard_ZRS' } else { 'Standard_LRS' }
}
foreach ($required in 'subscriptionId', 'location', 'namePrefix') { if (-not $S[$required]) { throw "Setting '$required' is missing in $SettingsPath." } }
if (-not $Preview) { Save-Settings $S; Write-Note "Answers saved to $SettingsPath (no secrets, but it holds your tenant, subscription and resource IDs: keep it private)." }

$names = Get-Names $S
$rgScope = "/subscriptions/$($S.subscriptionId)/resourceGroups/$($S.resourceGroup.name)"
$functionAppId = "$rgScope/providers/Microsoft.Web/sites/$($names.functionApp)"

# --- Code only
if ($CodeOnly) {
    Write-Section 'Code deployment'
    if (-not (Invoke-AzRest -Url "$Arm$functionAppId`?api-version=2024-04-01" -AllowFailure)) { throw "$($names.functionApp) doesn't exist yet. Run a full deployment first." }
    if ($Preview) { Write-Note "Would build and deploy the code to $($names.functionApp)."; return }
    $S.codeDeployment = if ($S.codeDeployment -eq 'skip') { 'direct' } else { $S.codeDeployment }
    if (Publish-Code $S $functionAppId) { $S.deployed.codeDeployedUtc = (Get-Date).ToUniversalTime().ToString('o'); Save-Settings $S }
    return
}

# --- Pre-flight
Write-Section 'Pre-flight checks'
$existingApp = Invoke-Preflight $S $myRoles $isUser
Show-Checks
$checks = Get-Checks
$blockers = @($checks | Where-Object Status -eq 'Missing')
$deferred = @($checks | Where-Object Status -eq 'Deferred')
if ($blockers.Count -and -not $Force) {
    Write-Host ''
    Write-Host "$($blockers.Count) check(s) failed. Fix them (see 'fix:' above) and run again, or use -Force to try anyway." -ForegroundColor Red
    return
}

# --- Summary & confirm
Write-Section 'Plan'
$plan = [ordered]@{
    'Tenant / subscription' = "$($S.tenantId) / $($S.subscriptionId)"
    'Resource group'        = "$($S.resourceGroup.name)$(if ($S.resourceGroup.create) { ' (new)' }) - resources in $($S.location)"
    'Function App'          = "$($names.functionApp) (Flex Consumption, PowerShell 7.4)"
    'Storage'               = "$($names.hostStorage), $($names.reportsStorage) ($($S.storageSku))"
    'Private endpoints'     = "5 in $(Get-ResourceName $S.network.privateEndpointSubnetId)"
    'Integration subnet'    = "$(Get-ResourceName $S.network.integrationSubnet.id) ($($S.network.integrationSubnet.mode))"
    'Private DNS'           = $(switch ($S.network.dnsMode) { 'zones' { (@($S.network.privateDnsZoneIds.Keys | Where-Object { $S.network.privateDnsZoneIds[$_] }) -join ', ') + ' zones' } 'policy' { 'by Azure Policy' } default { 'manual (records listed at the end)' } })
    'Sign-in'               = "$(if ($S.signIn.mode -eq 'create') { "new app registration '$($S.signIn.displayName)'" } else { "app registration $($S.signIn.clientId)" }); group '$($S.signIn.readerGroupName)'$(if ($S.signIn.createReaderGroup) { ' (new)' })"
    'Graph permissions'     = $(if ($S.permissions.grantGraph -and -not ($deferred | Where-Object Check -like 'Grant Graph*')) { 'granted now' } else { 'left for an admin' })
    'Azure Reader'          = $(if (@(Get-ReaderScopes $S).Count) { @(Get-ReaderScopes $S) -join ', ' } else { 'not granted' })
    'Logs'                  = $(if ($S.monitoring.logAnalyticsWorkspaceId) { Get-ResourceName $S.monitoring.logAnalyticsWorkspaceId } else { "new workspace $($names.logAnalytics)" })
    'Code'                  = $(if ($SkipCode) { 'skipped (-SkipCode)' } else { @{ direct = 'over the private network'; temporaryAccess = 'through a temporary, IP-restricted opening'; skip = 'skipped' }[$S.codeDeployment] })
}
foreach ($k in $plan.Keys) { Write-Host ("  {0,-22} {1}" -f $k, $plan[$k]) }
if ($Interactive -and -not $Preview -and -not (Read-YesNo 'Go ahead?' $true)) { Write-Host 'Stopped. Your answers are saved; run again to continue.'; return }

# =====================================================================================
#  Deploy
# =====================================================================================
$handoffs = [System.Collections.Generic.List[string]]::new()

Write-Section 'Deploying'
if ($Preview) {
    Write-Note "Would: register providers ($($script:ProvidersToRegister -join ', ')), $(if ($S.resourceGroup.create) { 'create the resource group, ' })prepare the integration subnet ($($S.network.integrationSubnet.mode)), $(if ($S.signIn.createReaderGroup) { 'create the reader group, ' })set up the sign-in app, deploy the template, grant permissions and deploy the code."
    if (-not $S.resourceGroup.create -and $S.signIn.clientId -and $S.network.integrationSubnet.mode -eq 'existing') {
        Invoke-BicepDeployment $S $S.network.integrationSubnet.id $S.signIn.clientId -WhatIfOnly | Out-Null
    } else { Write-Note 'Bicep what-if runs once the resource group, subnet and app registration exist.' }
    return
}

foreach ($p in $script:ProvidersToRegister) { Write-Step "Registering $p..."; Invoke-AzCli @('provider', 'register', '-n', $p, '--wait') | Out-Null; Write-Done "$p registered." }

if ($S.resourceGroup.create) {
    Write-Step "Creating resource group $($S.resourceGroup.name)..."
    $tagArgs = @(foreach ($k in $S.tags.Keys) { "$k=$($S.tags[$k])" })
    Invoke-AzCli (@('group', 'create', '-n', $S.resourceGroup.name, '-l', $S.location) + $(if ($tagArgs) { @('--tags') + $tagArgs } else { @() })) | Out-Null
    $S.resourceGroup.create = $false; Save-Settings $S
    Write-Done 'Created.'
}

Write-Step 'Integration subnet...'
$integrationSubnetId = Set-IntegrationSubnet -Integration $S.network.integrationSubnet -VnetId $S.network.vnetId
if ($S.network.integrationSubnet.mode -ne 'existing') { $S.network.integrationSubnet.mode = 'existing'; $S.network.integrationSubnet.id = $integrationSubnetId; Save-Settings $S }

if ($S.signIn.createReaderGroup) {
    Write-Step "Creating security group $($S.signIn.readerGroupName)..."
    $g = New-SecurityGroup $S.signIn.readerGroupName 'People who can open the Identity & Azure reporting portal.'
    $S.signIn.readerGroupId = $g.id; $S.signIn.createReaderGroup = $false; Save-Settings $S
    Write-Done "Created ($($g.id)). Add the people who should see the reports to it."
}

Write-Step 'Sign-in app registration...'
$hostNames = @(if ($existingApp) { $existingApp.properties.defaultHostName } else { "$($names.functionApp).azurewebsites.net" })
try {
    $signIn = Set-SignInApp -ClientId $S.signIn.clientId -DisplayName $S.signIn.displayName -HostNames $hostNames -ReaderGroupId $S.signIn.readerGroupId
    $S.signIn.clientId = $signIn.ClientId; $S.signIn.mode = 'existing'; Save-Settings $S
} catch {
    if (-not $S.signIn.clientId) { throw "Couldn't create the sign-in app registration: $($_.Exception.Message)" }
    Write-Attention "Couldn't update the app registration ($($_.Exception.Message)). Continuing with $($S.signIn.clientId)."
    $handoffs.Add("Cloud Application Administrator: ./Grant-ReportingAccess.ps1 -Stage SignInApp -SettingsPath '$SettingsPath'")
}

$out = Invoke-BicepDeployment $S $integrationSubnetId $S.signIn.clientId
$S.deployed = [ordered]@{
    functionAppId = $out.functionAppId; functionAppHostName = $out.functionAppHostName
    managedIdentityPrincipalId = $out.managedIdentityPrincipalId; managedIdentityClientId = $out.managedIdentityClientId
    deployedUtc = (Get-Date).ToUniversalTime().ToString('o')
}
Save-Settings $S

if ($out.functionAppHostName -notin $hostNames) {
    Write-Step "The app's address is $($out.functionAppHostName); updating the sign-in redirect URI..."
    try { Set-SignInApp -ClientId $S.signIn.clientId -DisplayName $S.signIn.displayName -HostNames @($out.functionAppHostName) -ReaderGroupId $S.signIn.readerGroupId | Out-Null }
    catch { $handoffs.Add("Cloud Application Administrator: ./Grant-ReportingAccess.ps1 -Stage SignInApp -SettingsPath '$SettingsPath'  (redirect URI for $($out.functionAppHostName))") }
}

Write-Section 'Permissions for the managed identity'
$graphDeferred = -not $S.permissions.grantGraph -or [bool]($deferred | Where-Object Check -like 'Grant Graph*')
if (-not $graphDeferred) {
    try { Grant-GraphReadPermissions -PrincipalId $out.managedIdentityPrincipalId -IncludeUserAuthenticationMethodRead:([bool]$S.permissions.includeUserAuthenticationMethodRead) }
    catch { Write-Attention "Graph permissions failed: $($_.Exception.Message)"; $graphDeferred = $true }
}
if ($graphDeferred) { $handoffs.Add("Privileged Role Administrator: ./Grant-ReportingAccess.ps1 -Stage Permissions -GraphOnly -SettingsPath '$SettingsPath'") }
$readerDeferred = $false
foreach ($scope in (Get-ReaderScopes $S)) {
    if ($deferred | Where-Object Check -eq "Grant Reader at $scope") { $readerDeferred = $true; continue }
    try { Grant-AzureReader -PrincipalId $out.managedIdentityPrincipalId -Scope $scope } catch { Write-Attention $_.Exception.Message; $readerDeferred = $true }
}
if ($readerDeferred) { $handoffs.Add("Owner / User Access Administrator at $((Get-ReaderScopes $S) -join ', '): ./Grant-ReportingAccess.ps1 -Stage Permissions -AzureOnly -SettingsPath '$SettingsPath'") }

$codeDone = $false
if (-not $SkipCode) {
    Write-Section 'Code'
    $codeDone = Publish-Code $S $out.functionAppId
    if ($codeDone) { $S.deployed.codeDeployedUtc = (Get-Date).ToUniversalTime().ToString('o'); Save-Settings $S }
}
if (-not $codeDone) { $handoffs.Add("From a machine on the private network: ./Deploy-ReportingPlatform.ps1 -CodeOnly -SettingsPath '$SettingsPath'") }

# --- Done
Write-Section 'Done'
Write-Host "  Portal:   https://$($out.functionAppHostName)  (from the corporate network / VPN, as a member of '$($S.signIn.readerGroupName)')"
Write-Host "  Settings: $SettingsPath  (re-run with -NonInteractive to update)"
if ($S.network.dnsMode -eq 'manual') {
    Write-Host '  Create these DNS records (A records, privatelink zones or your DNS servers):' -ForegroundColor Yellow
    foreach ($pe in @(Invoke-AzCli @('network', 'private-endpoint', 'list', '-g', $S.resourceGroup.name) | Where-Object { $_.name -like "pe-$($S.namePrefix)-$($S.environmentName)-reports-*" })) {
        foreach ($c in @($pe.customDnsConfigs)) { Write-Host "    $($c.fqdn) -> $(@($c.ipAddresses) -join ', ')" }
    }
}
if ($S.network.outboundViaFirewall) { Write-Host "  Allow outbound HTTPS from $(Get-ResourceName $integrationSubnetId) to: $($OutboundFqdns -join ', ')" -ForegroundColor Yellow }
if ($handoffs.Count) {
    Write-Host '  Still to do (by someone with the rights shown):' -ForegroundColor Yellow
    $handoffs | ForEach-Object { Write-Host "    - $_" }
    Write-Host '    Reports that need these permissions fail (and say so on their tab) until then.' -ForegroundColor DarkGray
}
Write-Host '  Reports first run on their schedules (UTC); each tab shows "not run yet" until then.' -ForegroundColor DarkGray
