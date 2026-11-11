# Shared functions for Deploy-ReportingPlatform.ps1 and Grant-ReportingAccess.ps1.
# Everything Azure / Entra goes through the Azure CLI (az), so one 'az login' covers ARM,
# Bicep and Microsoft Graph, and there are no PowerShell module version conflicts.

Set-StrictMode -Version Latest

$script:GraphAppId = '00000003-0000-0000-c000-000000000000'
$script:PortalAppTag = 'identity-azure-reporting-portal'
$script:SignInScopes = @('openid', 'profile', 'email', 'User.Read')
$script:GraphReadPermissions = @('Directory.Read.All', 'AuditLog.Read.All', 'Application.Read.All', 'Policy.Read.All', 'RoleManagement.Read.Directory')
$script:ReaderRoleId = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'
$script:Arm = 'https://management.azure.com'
$script:Graph = 'https://graph.microsoft.com/v1.0'

# Entra role template IDs
$script:EntraRoles = @{
    GlobalAdministrator            = '62e90394-69f5-4237-9190-012177145e10'
    PrivilegedRoleAdministrator    = 'e8611ab8-c189-46e8-94e1-60213ab1f814'
    ApplicationAdministrator       = '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'
    CloudApplicationAdministrator  = '158c047a-c907-4556-b7ef-446551a6b5f7'
    GroupsAdministrator            = 'fdd7a751-b60b-444a-984c-02652fe8fa1c'
    UserAdministrator              = 'fe930be7-5e62-47db-91af-98c3a49a38b1'
}

#region Output ---------------------------------------------------------------------------

function Write-Section([string]$Text) { Write-Host ''; Write-Host "== $Text $('=' * [math]::Max(3, 70 - $Text.Length))" -ForegroundColor Cyan }
function Write-Step([string]$Text) { Write-Host "-> $Text" -ForegroundColor White }
function Write-Done([string]$Text) { Write-Host "   $Text" -ForegroundColor Green }
function Write-Note([string]$Text) { Write-Host "   $Text" -ForegroundColor DarkGray }
function Write-Attention([string]$Text) { Write-Host "   $Text" -ForegroundColor Yellow }

#endregion

#region Utilities -----------------------------------------------------------------------

function Get-Prop {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] }; return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function ConvertTo-Hashtable {
    <# Saved settings come back from JSON as PSCustomObjects; work with hashtables. #>
    param($InputObject)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) { $h = [ordered]@{}; foreach ($k in $InputObject.Keys) { $h[$k] = ConvertTo-Hashtable $InputObject[$k] }; return $h }
    if ($InputObject -is [pscustomobject]) { $h = [ordered]@{}; foreach ($p in $InputObject.PSObject.Properties) { $h[$p.Name] = ConvertTo-Hashtable $p.Value }; return $h }
    if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) { return , @($InputObject | ForEach-Object { ConvertTo-Hashtable $_ }) }
    return $InputObject
}

function Get-ResourceName([string]$Id) { if ($Id) { ($Id.TrimEnd('/') -split '/')[-1] } else { '' } }
function Get-ResourceGroupFromId([string]$Id) { if ($Id -match '/resourceGroups/([^/]+)') { $Matches[1] } else { '' } }
function Get-SubscriptionFromId([string]$Id) { if ($Id -match '^/subscriptions/([^/]+)') { $Matches[1] } else { '' } }

function ConvertTo-IpRange([string]$Cidr) {
    <# IPv4 CIDR -> @{ Start; End } as uint32, or $null for IPv6. #>
    if ($Cidr -notmatch '^(\d+\.\d+\.\d+\.\d+)/(\d+)$') { return $null }
    $b = ([System.Net.IPAddress]::Parse($Matches[1])).GetAddressBytes(); [array]::Reverse($b)
    $ip = [BitConverter]::ToUInt32($b, 0); $bits = [int]$Matches[2]
    $size = [uint32]([math]::Pow(2, 32 - $bits))
    $start = [uint32]($ip - ($ip % $size))
    return @{ Start = $start; End = [uint32]($start + $size - 1); Size = $size }
}

function ConvertTo-IpString([uint32]$Value) { $b = [BitConverter]::GetBytes($Value); [array]::Reverse($b); ([System.Net.IPAddress]::new($b)).ToString() }

function Find-FreeSubnetRange {
    <# First free block of the given size (e.g. 27) in the VNet's IPv4 address space, or $null. #>
    param([string[]]$VnetPrefixes, [string[]]$UsedPrefixes, [int]$PrefixLength = 27)
    $used = @($UsedPrefixes | ForEach-Object { ConvertTo-IpRange $_ } | Where-Object { $_ })
    $size = [uint32]([math]::Pow(2, 32 - $PrefixLength))
    foreach ($vp in $VnetPrefixes) {
        $r = ConvertTo-IpRange $vp
        if (-not $r -or $r.Size -lt $size) { continue }
        for ([uint64]$s = $r.Start; $s + $size - 1 -le $r.End; $s += $size) {
            $e = $s + $size - 1
            if (-not @($used | Where-Object { $s -le $_.End -and $e -ge $_.Start }).Count) { return "$(ConvertTo-IpString ([uint32]$s))/$PrefixLength" }
        }
    }
    return $null
}

function Test-SubnetPrefix {
    <# '' when the prefix is a valid /27-or-larger range inside the VNet and free; otherwise the reason. #>
    param([string]$Prefix, [string[]]$VnetPrefixes, [string[]]$UsedPrefixes)
    $r = ConvertTo-IpRange $Prefix
    if (-not $r) { return 'Enter an IPv4 range like 10.20.4.0/27.' }
    if ($r.Size -lt 32) { return 'Use /27 or larger.' }
    if ($Prefix -notmatch "^$([regex]::Escape((ConvertTo-IpString $r.Start)))/") { return "Not aligned; did you mean $(ConvertTo-IpString $r.Start)/$(($Prefix -split '/')[1])?" }
    $inside = @($VnetPrefixes | ForEach-Object { ConvertTo-IpRange $_ } | Where-Object { $_ -and $r.Start -ge $_.Start -and $r.End -le $_.End })
    if (-not $inside.Count) { return "Outside the VNet's address space ($($VnetPrefixes -join ', '))." }
    foreach ($u in $UsedPrefixes) { $ur = ConvertTo-IpRange $u; if ($ur -and $r.Start -le $ur.End -and $r.End -ge $ur.Start) { return "Overlaps existing subnet range $u." } }
    return ''
}

#endregion

#region Azure CLI ------------------------------------------------------------------------

$script:AzLastError = ''
$script:AzInvoker = $null

function Get-AzInvoker {
    <#
        How to start the Azure CLI. On Windows 'az' is a batch file (az.cmd), so its arguments go
        through cmd.exe, which treats ( ) & | < > as its own syntax - Graph URLs such as
        servicePrincipals(appId='...')?$select=... or ...&$top=... then fail with "... was
        unexpected at this time". So on Windows the CLI's own Python is started directly (what
        az.cmd does), or, if it can't be found, cmd.exe is given every argument in quotes.
    #>
    if ($null -ne $script:AzInvoker) { return $script:AzInvoker }
    $inv = @{ Mode = 'direct' }
    $c = Get-Command az -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($IsWindows -and $c -and $c.CommandType -eq 'Application' -and $c.Source -match '\.(cmd|bat)$') {
        $py = [System.IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $c.Source) '..\python.exe'))
        $inv = if (Test-Path -LiteralPath $py) { @{ Mode = 'python'; Exe = $py } } else { @{ Mode = 'cmd'; Exe = $c.Source } }
    }
    $script:AzInvoker = $inv
    return $inv
}

function Format-CmdLine([string]$Exe, [string[]]$Arguments) {
    <# cmd.exe /s /c line with every argument quoted, so cmd treats ( ) & | < > literally. #>
    $quoted = @($Exe) + $Arguments | ForEach-Object { '"' + ($_ -replace '"', '""') + '"' }
    return '"' + ($quoted -join ' ') + '"'
}

function Invoke-AzCli {
    <#
        Runs az with JSON output and returns the parsed result. Throws on failure unless
        -AllowFailure, in which case it returns $null and the error is in $script:AzLastError.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory, Position = 0)][string[]]$Arguments, [switch]$AllowFailure)
    $script:AzLastError = ''
    $errFile = [System.IO.Path]::GetTempFileName()
    try {
        $all = @($Arguments) + @('--only-show-errors', '-o', 'json')
        $inv = Get-AzInvoker
        $out = switch ($inv.Mode) {
            'python' { $env:AZ_INSTALLER = 'MSI'; & $inv.Exe -IBm azure.cli @all 2> $errFile }
            'cmd' { & $env:ComSpec /d /s /c (Format-CmdLine $inv.Exe $all) 2> $errFile }
            default { & az @all 2> $errFile }
        }
        $code = $LASTEXITCODE
        $err = [string](Get-Content -Raw $errFile -ErrorAction SilentlyContinue)
    } finally { Remove-Item $errFile -Force -ErrorAction SilentlyContinue }
    if ($code -ne 0) {
        $script:AzLastError = $err.Trim()
        if ($AllowFailure) { return $null }
        $what = ($Arguments | Where-Object { $_ -notlike '@*' } | Select-Object -First 4) -join ' '
        throw "az $what failed: $($script:AzLastError)"
    }
    $text = ($out | Out-String).Trim()
    if (-not $text) { return $null }
    return ($text | ConvertFrom-Json -Depth 64)
}

function Invoke-AzRest {
    <# ARM or Graph request through 'az rest' (az picks the token audience from the URL). #>
    [CmdletBinding()]
    param([string]$Method = 'GET', [Parameter(Mandatory)][string]$Url, $Body, [switch]$AllowFailure)
    $a = @('rest', '--method', $Method, '--url', $Url)
    $tmp = $null
    if ($null -ne $Body) {
        $tmp = [System.IO.Path]::GetTempFileName()
        ($Body | ConvertTo-Json -Depth 30 -Compress) | Set-Content -Path $tmp -Encoding utf8NoBOM
        $a += @('--body', "@$tmp", '--headers', 'Content-Type=application/json')
    }
    try { Invoke-AzCli $a -AllowFailure:$AllowFailure }
    finally { if ($tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue } }
}

function Get-AzLastError { $script:AzLastError }

function Get-AzErrorKind {
    <# Rough HTTP status of the last failed az rest call, from its error text. #>
    $e = $script:AzLastError
    if ($e -match 'Not Found|NotFound|ResourceNotFound|Request_ResourceNotFound|\b404\b') { return 'NotFound' }
    if ($e -match 'Forbidden|AuthorizationFailed|Authorization_RequestDenied|Insufficient privileges|\b403\b') { return 'Forbidden' }
    if ($e -match 'Conflict|already exists|RoleAssignmentExists|\b409\b') { return 'Conflict' }
    if ($e -match 'Bad Request|BadRequest|\b400\b') { return 'BadRequest' }
    return 'Other'
}

function Get-GraphAll([string]$Url) {
    $next = $Url
    while ($next) {
        $r = Invoke-AzRest -Url $next
        foreach ($v in @(Get-Prop $r 'value')) { if ($null -ne $v) { $v } }
        $next = Get-Prop $r '@odata.nextLink'
    }
}

function Wait-ArmProvisioning([string]$Id, [string]$ApiVersion, [int]$TimeoutSeconds = 300) {
    $deadline = [datetime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $r = Invoke-AzRest -Url "$script:Arm$Id`?api-version=$ApiVersion" -AllowFailure
        $state = Get-Prop (Get-Prop $r 'properties') 'provisioningState'
        if ($state -eq 'Succeeded') { return $r }
        if ($state -eq 'Failed') { throw "$Id failed to provision." }
        Start-Sleep -Seconds 5
    } while ([datetime]::UtcNow -lt $deadline)
    throw "Timed out waiting for $Id."
}

#endregion

#region Prompts --------------------------------------------------------------------------

function Read-Choice {
    <#
        Numbered menu. Options: @{ Label; Value; Detail }. Returns the chosen option's Value.
        -Default is the Value to preselect (falls back to the first option).
    #>
    param([string]$Question, [object[]]$Options, $Default, [string]$Help)
    Write-Host ''
    Write-Host $Question -ForegroundColor Cyan
    if ($Help) { $Help -split "`n" | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray } }
    $def = 0
    for ($i = 0; $i -lt $Options.Count; $i++) {
        if ($null -ne $Default -and "$($Options[$i].Value)" -eq "$Default") { $def = $i }
    }
    for ($i = 0; $i -lt $Options.Count; $i++) {
        $o = $Options[$i]
        Write-Host ("  {0,2}) {1}" -f ($i + 1), $o.Label) -NoNewline -ForegroundColor $(if ($i -eq $def) { 'White' } else { 'Gray' })
        if (Get-Prop $o 'Detail') { Write-Host "  $($o.Detail)" -ForegroundColor DarkGray } else { Write-Host '' }
    }
    while ($true) {
        $a = Read-Host "  Choose 1-$($Options.Count) [$($def + 1)]"
        if ([string]::IsNullOrWhiteSpace($a)) { return $Options[$def].Value }
        $n = 0
        if ([int]::TryParse($a.Trim(), [ref]$n) -and $n -ge 1 -and $n -le $Options.Count) { return $Options[$n - 1].Value }
        Write-Host '  Enter one of the numbers shown.' -ForegroundColor Yellow
    }
}

function Read-MultiChoice {
    <# Several numbers, comma separated. Returns the chosen Values. #>
    param([string]$Question, [object[]]$Options, [object[]]$Default = @(), [string]$Help)
    Write-Host ''
    Write-Host $Question -ForegroundColor Cyan
    if ($Help) { Write-Host "  $Help" -ForegroundColor DarkGray }
    $defIdx = @()
    for ($i = 0; $i -lt $Options.Count; $i++) {
        if ("$($Options[$i].Value)" -in @($Default | ForEach-Object { "$_" })) { $defIdx += ($i + 1) }
        Write-Host ("  {0,2}) {1}" -f ($i + 1), $Options[$i].Label) -NoNewline
        if (Get-Prop $Options[$i] 'Detail') { Write-Host "  $($Options[$i].Detail)" -ForegroundColor DarkGray } else { Write-Host '' }
    }
    while ($true) {
        $a = Read-Host "  Numbers separated by commas$(if ($defIdx) { " [$($defIdx -join ',')]" })"
        if ([string]::IsNullOrWhiteSpace($a) -and $defIdx) { return @($defIdx | ForEach-Object { $Options[$_ - 1].Value }) }
        $nums = @($a -split '[,\s]+' | Where-Object { $_ } | ForEach-Object { $n = 0; if ([int]::TryParse($_, [ref]$n)) { $n } else { -1 } })
        if ($nums.Count -and -not @($nums | Where-Object { $_ -lt 1 -or $_ -gt $Options.Count }).Count) { return @($nums | Sort-Object -Unique | ForEach-Object { $Options[$_ - 1].Value }) }
        Write-Host '  Enter one or more of the numbers shown, e.g. 1,3.' -ForegroundColor Yellow
    }
}

function Read-Text {
    <# Free text with a default and an optional validator returning '' (ok) or an error message. #>
    param([string]$Question, [string]$Default = '', [scriptblock]$Validate, [string]$Help, [switch]$AllowEmpty)
    Write-Host ''
    Write-Host $Question -ForegroundColor Cyan
    if ($Help) { $Help -split "`n" | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray } }
    while ($true) {
        $a = Read-Host "  $(if ($Default) { "[$Default]" } else { '>' })"
        if ([string]::IsNullOrWhiteSpace($a)) { $a = $Default }
        $a = "$a".Trim()
        if (-not $a -and -not $AllowEmpty) { Write-Host '  A value is needed.' -ForegroundColor Yellow; continue }
        if ($Validate -and $a) { $msg = & $Validate $a; if ($msg) { Write-Host "  $msg" -ForegroundColor Yellow; continue } }
        return $a
    }
}

function Read-YesNo([string]$Question, [bool]$Default = $true, [string]$Help) {
    Write-Host ''
    Write-Host $Question -ForegroundColor Cyan
    if ($Help) { $Help -split "`n" | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray } }
    while ($true) {
        $a = Read-Host "  $(if ($Default) { '[Y/n]' } else { '[y/N]' })"
        if ([string]::IsNullOrWhiteSpace($a)) { return $Default }
        if ($a -match '^(y|yes)$') { return $true }
        if ($a -match '^(n|no)$') { return $false }
        Write-Host '  Answer y or n.' -ForegroundColor Yellow
    }
}

#endregion

#region Pre-flight checks ----------------------------------------------------------------

$script:Checks = [System.Collections.Generic.List[object]]::new()

function Reset-Checks { $script:Checks.Clear() }
function Add-Check {
    param([string]$Area, [string]$Check, [ValidateSet('OK', 'Missing', 'Warning', 'Deferred')][string]$Status, [string]$Detail = '', [string]$Fix = '')
    $script:Checks.Add([pscustomobject]@{ Area = $Area; Check = $Check; Status = $Status; Detail = $Detail; Fix = $Fix })
}
function Get-Checks { , @($script:Checks) }

function Show-Checks {
    $colour = @{ OK = 'Green'; Missing = 'Red'; Warning = 'Yellow'; Deferred = 'Yellow' }
    foreach ($group in ($script:Checks | Group-Object Area)) {
        Write-Host "  $($group.Name)" -ForegroundColor White
        foreach ($c in $group.Group) {
            Write-Host ("    [{0,-8}] " -f $c.Status) -NoNewline -ForegroundColor $colour[$c.Status]
            Write-Host $c.Check -NoNewline
            if ($c.Detail) { Write-Host " - $($c.Detail)" -ForegroundColor DarkGray } else { Write-Host '' }
            if ($c.Fix -and $c.Status -ne 'OK') { Write-Host "               fix: $($c.Fix)" -ForegroundColor DarkYellow }
        }
    }
}

function Test-AzPermission {
    <#
        Which of -Actions the signed-in account is NOT allowed at -Scope, using the effective
        permissions API. Returns @{ Known; Missing }. Known = $false when the scope couldn't be
        checked (e.g. no read access at all, or the API isn't available at that scope).
        Note: role assignment conditions (ABAC) aren't evaluated.
    #>
    param([string]$Scope, [string[]]$Actions)
    $r = Invoke-AzRest -Url "$script:Arm$Scope/providers/Microsoft.Authorization/permissions?api-version=2022-04-01" -AllowFailure
    if ($null -eq $r) { return @{ Known = $false; Missing = @($Actions); Error = $script:AzLastError } }
    $perms = @(Get-Prop $r 'value')
    $missing = foreach ($a in $Actions) {
        $ok = $false
        foreach ($p in $perms) {
            if ($null -eq $p) { continue }
            if (@(Get-Prop $p 'actions') | Where-Object { $_ -and $a -like $_ }) {
                if (-not (@(Get-Prop $p 'notActions') | Where-Object { $_ -and $a -like $_ })) { $ok = $true; break }
            }
        }
        if (-not $ok) { $a }
    }
    return @{ Known = $true; Missing = @($missing) }
}

function Add-PermissionCheck {
    <# Runs Test-AzPermission and records the result. #>
    param([string]$Area, [string]$Check, [string]$Scope, [string[]]$Actions, [string]$Fix, [switch]$WarnOnly)
    $t = Test-AzPermission -Scope $Scope -Actions $Actions
    if (-not $t.Known) { Add-Check $Area $Check 'Warning' "couldn't check permissions at $Scope" $Fix; return $false }
    if ($t.Missing.Count) { Add-Check $Area $Check $(if ($WarnOnly) { 'Warning' } else { 'Missing' }) "not allowed: $($t.Missing -join ', ')" $Fix; return $false }
    Add-Check $Area $Check 'OK'
    return $true
}

function Get-MyEntraRoles {
    <# Template IDs of the signed-in user's ACTIVE directory roles (direct or through groups). #>
    $ids = @(Get-GraphAll "$script:Graph/me/transitiveMemberOf?`$select=id,displayName,roleTemplateId" |
        Where-Object { (Get-Prop $_ '@odata.type') -eq '#microsoft.graph.directoryRole' } | ForEach-Object { [string](Get-Prop $_ 'roleTemplateId') })
    return $ids
}

function Test-HasEntraRole([string[]]$MyRoles, [string[]]$RoleNames) {
    foreach ($n in $RoleNames) { if ($script:EntraRoles[$n] -in $MyRoles) { return $true } }
    return $false
}

#endregion

#region Entra ID -------------------------------------------------------------------------

function Get-GraphServicePrincipal {
    Invoke-AzRest -Url "$script:Graph/servicePrincipals(appId='$script:GraphAppId')?`$select=id,appRoles,oauth2PermissionScopes"
}

function Find-Group([string]$NameOrId) {
    if ($NameOrId -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
        $g = Invoke-AzRest -Url "$script:Graph/groups/$NameOrId`?`$select=id,displayName,securityEnabled" -AllowFailure
        return @($g | Where-Object { $_ })
    }
    $q = $NameOrId -replace "'", "''"
    $exact = @(Get-GraphAll "$script:Graph/groups?`$filter=displayName eq '$q'&`$select=id,displayName,securityEnabled")
    if ($exact.Count) { return $exact }
    return @((Invoke-AzRest -Url "$script:Graph/groups?`$filter=startswith(displayName,'$q')&`$select=id,displayName,securityEnabled&`$top=15").value)
}

function New-SecurityGroup([string]$DisplayName, [string]$Description) {
    $nick = (($DisplayName -replace '[^A-Za-z0-9]', '') + '').Substring(0, [math]::Min(40, ($DisplayName -replace '[^A-Za-z0-9]', '').Length))
    if (-not $nick) { $nick = 'reportreaders' }
    Invoke-AzRest -Method POST -Url "$script:Graph/groups" -Body @{
        displayName = $DisplayName; description = $Description; mailEnabled = $false; mailNickname = "$nick$(Get-Random -Maximum 9999)"; securityEnabled = $true
    }
}

function Get-SignInApp([string]$ClientId) {
    $r = Invoke-AzRest -Url "$script:Graph/applications?`$filter=appId eq '$ClientId'&`$select=id,appId,displayName,web,tags,identifierUris,signInAudience"
    return @($r.value) | Select-Object -First 1
}

function Set-SignInApp {
    <#
        Creates or updates the portal's sign-in app registration and enterprise app:
        single tenant, web redirect https://<host>/.auth/login/aad/callback, ID tokens, no
        secret, assignment required, reader group assigned, tenant-wide consent for sign-in
        scopes. Idempotent. Returns @{ ClientId; ObjectId; ServicePrincipalId }.
    #>
    param([string]$ClientId, [string]$DisplayName, [Parameter(Mandatory)][string[]]$HostNames, [Parameter(Mandatory)][string]$ReaderGroupId)
    $graphSp = Get-GraphServicePrincipal
    $scopeIds = foreach ($s in $script:SignInScopes) {
        $m = @($graphSp.oauth2PermissionScopes | Where-Object { $_.value -eq $s }) | Select-Object -First 1
        if (-not $m) { throw "Graph scope $s not found." }
        @{ id = $m.id; type = 'Scope' }
    }
    $redirects = @($HostNames | ForEach-Object { "https://$_/.auth/login/aad/callback" })
    $app = if ($ClientId) { Get-SignInApp $ClientId } else {
        @((Invoke-AzRest -Url "$script:Graph/applications?`$filter=displayName eq '$($DisplayName -replace "'", "''")'&`$select=id,appId,displayName,web,tags,identifierUris").value |
            Where-Object { @(Get-Prop $_ 'tags') -contains $script:PortalAppTag }) | Select-Object -First 1
    }
    $web = @{ logoutUrl = "https://$($HostNames[0])/.auth/logout"; implicitGrantSettings = @{ enableIdTokenIssuance = $true; enableAccessTokenIssuance = $false } }
    if (-not $app) {
        if ($ClientId) { throw "No app registration with client ID $ClientId." }
        $web.redirectUris = $redirects
        $app = Invoke-AzRest -Method POST -Url "$script:Graph/applications" -Body @{
            displayName = $DisplayName; signInAudience = 'AzureADMyOrg'; tags = @($script:PortalAppTag); web = $web
            requiredResourceAccess = @(@{ resourceAppId = $script:GraphAppId; resourceAccess = @($scopeIds) })
        }
        Invoke-AzRest -Method PATCH -Url "$script:Graph/applications/$($app.id)" -Body @{ identifierUris = @("api://$($app.appId)") } | Out-Null
        Write-Done "Created app registration '$DisplayName' ($($app.appId))."
    } else {
        $existingUris = @(Get-Prop (Get-Prop $app 'web') 'redirectUris')
        $web.redirectUris = @($existingUris + $redirects | Where-Object { $_ } | Select-Object -Unique)
        Invoke-AzRest -Method PATCH -Url "$script:Graph/applications/$($app.id)" -Body @{
            web = $web; requiredResourceAccess = @(@{ resourceAppId = $script:GraphAppId; resourceAccess = @($scopeIds) })
        } | Out-Null
        if (-not @(Get-Prop $app 'identifierUris' | Where-Object { $_ }).Count) {
            Invoke-AzRest -Method PATCH -Url "$script:Graph/applications/$($app.id)" -Body @{ identifierUris = @("api://$($app.appId)") } | Out-Null
        }
        Write-Done "Updated app registration '$($app.displayName)' ($($app.appId)): redirect URI, ID tokens, sign-in permissions."
    }

    # Enterprise app with assignment required
    $sp = @((Invoke-AzRest -Url "$script:Graph/servicePrincipals?`$filter=appId eq '$($app.appId)'&`$select=id,appRoleAssignmentRequired").value) | Select-Object -First 1
    if (-not $sp) {
        $sp = Invoke-AzRest -Method POST -Url "$script:Graph/servicePrincipals" -Body @{ appId = $app.appId; tags = @('WindowsAzureActiveDirectoryIntegratedApp') }
    }
    if (-not (Get-Prop $sp 'appRoleAssignmentRequired')) {
        Invoke-AzRest -Method PATCH -Url "$script:Graph/servicePrincipals/$($sp.id)" -Body @{ appRoleAssignmentRequired = $true } | Out-Null
        Write-Done 'Enterprise app now requires assignment (only assigned users / groups can sign in).'
    }

    # Reader group
    $assigned = @(Get-GraphAll "$script:Graph/servicePrincipals/$($sp.id)/appRoleAssignedTo" | Where-Object { $_.principalId -eq $ReaderGroupId })
    if (-not $assigned.Count) {
        Invoke-AzRest -Method POST -Url "$script:Graph/servicePrincipals/$($sp.id)/appRoleAssignedTo" -Body @{
            principalId = $ReaderGroupId; resourceId = $sp.id; appRoleId = '00000000-0000-0000-0000-000000000000'
        } | Out-Null
        Write-Done 'Reader group assigned to the enterprise app.'
    }

    # Tenant-wide consent for the sign-in scopes, so users aren't prompted
    $scopeString = $script:SignInScopes -join ' '
    $grant = @((Invoke-AzRest -Url "$script:Graph/oauth2PermissionGrants?`$filter=clientId eq '$($sp.id)' and consentType eq 'AllPrincipals' and resourceId eq '$($graphSp.id)'").value) | Select-Object -First 1
    if (-not $grant) {
        Invoke-AzRest -Method POST -Url "$script:Graph/oauth2PermissionGrants" -Body @{ clientId = $sp.id; consentType = 'AllPrincipals'; resourceId = $graphSp.id; scope = $scopeString } | Out-Null
        Write-Done "Consented to '$scopeString' for all users."
    } elseif (@($script:SignInScopes | Where-Object { $_ -notin ((Get-Prop $grant 'scope') -split ' ') }).Count) {
        Invoke-AzRest -Method PATCH -Url "$script:Graph/oauth2PermissionGrants/$($grant.id)" -Body @{ scope = $scopeString } | Out-Null
    }
    return @{ ClientId = $app.appId; ObjectId = $app.id; ServicePrincipalId = $sp.id }
}

function Grant-GraphReadPermissions {
    <#
        Grants the managed identity the reports' read-only Graph application permissions and
        warns about any write permissions it already has. Idempotent.
    #>
    param([Parameter(Mandatory)][string]$PrincipalId, [switch]$IncludeUserAuthenticationMethodRead)
    $wanted = @($script:GraphReadPermissions) + @(if ($IncludeUserAuthenticationMethodRead) { 'UserAuthenticationMethod.Read.All' })
    $mi = Invoke-AzRest -Url "$script:Graph/servicePrincipals/$PrincipalId`?`$select=id,displayName,servicePrincipalType"
    if ($mi.servicePrincipalType -ne 'ManagedIdentity') { throw "$PrincipalId is not a managed identity ($($mi.servicePrincipalType))." }
    $graphSp = Get-GraphServicePrincipal
    $current = @(Get-GraphAll "$script:Graph/servicePrincipals/$PrincipalId/appRoleAssignments" | Where-Object { $_.resourceId -eq $graphSp.id })
    foreach ($perm in $wanted) {
        $role = @($graphSp.appRoles | Where-Object { $_.value -eq $perm -and @($_.allowedMemberTypes) -contains 'Application' }) | Select-Object -First 1
        if (-not $role) { throw "Graph application permission $perm not found." }
        if ($current | Where-Object { $_.appRoleId -eq $role.id }) { Write-Note "$perm - already granted"; continue }
        Invoke-AzRest -Method POST -Url "$script:Graph/servicePrincipals/$PrincipalId/appRoleAssignments" -Body @{ principalId = $PrincipalId; resourceId = $graphSp.id; appRoleId = $role.id } | Out-Null
        Write-Done "$perm - granted"
    }
    $names = @{}; foreach ($r in $graphSp.appRoles) { $names[$r.id] = $r.value }
    foreach ($x in @($current | ForEach-Object { $names[$_.appRoleId] } | Where-Object { $_ -and $_ -notin $wanted })) {
        Write-Attention "The identity also has $x, which the reports don't need$(if ($x -match 'ReadWrite|Write|FullControl') { ' (write access!)' }). Consider removing it."
    }
}

#endregion

#region Azure ----------------------------------------------------------------------------

function Grant-AzureReader {
    <# Reader for the managed identity at a scope. Deterministic assignment name: re-runs are no-ops. #>
    param([Parameter(Mandatory)][string]$PrincipalId, [Parameter(Mandatory)][string]$Scope)
    $md5 = [System.Security.Cryptography.MD5]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$Scope|$PrincipalId|$script:ReaderRoleId".ToLowerInvariant()))
    $name = [guid]::new($md5).ToString()
    $body = @{ properties = @{ roleDefinitionId = "$Scope/providers/Microsoft.Authorization/roleDefinitions/$script:ReaderRoleId"; principalId = $PrincipalId; principalType = 'ServicePrincipal' } }
    $r = Invoke-AzRest -Method PUT -Url "$script:Arm$Scope/providers/Microsoft.Authorization/roleAssignments/$name`?api-version=2022-04-01" -Body $body -AllowFailure
    if ($null -ne $r) { Write-Done "Reader granted at $Scope"; return }
    if ((Get-AzErrorKind) -eq 'Conflict') { Write-Note "Reader already granted at $Scope"; return }
    throw "Reader assignment at $Scope failed: $($script:AzLastError)"
}

function Get-ReaderScopes([System.Collections.IDictionary]$Settings) {
    $p = $Settings.permissions
    switch ($p.azureReaderScope) {
        'tenantRoot' { @("/providers/Microsoft.Management/managementGroups/$($Settings.tenantId)") }
        'managementGroup' { @("/providers/Microsoft.Management/managementGroups/$($p.managementGroupId)") }
        'subscriptions' { @($p.subscriptionIds | ForEach-Object { "/subscriptions/$_" }) }
        default { @() }
    }
}

function Set-IntegrationSubnet {
    <#
        Makes sure the Function App's outbound integration subnet exists and is delegated to
        Microsoft.App/environments: creates it, or adds the delegation to an existing empty one.
        Returns the subnet resource ID.
    #>
    param([System.Collections.IDictionary]$Integration, [string]$VnetId)
    $api = '2024-05-01'
    $delegation = @{ name = 'flex-consumption'; properties = @{ serviceName = 'Microsoft.App/environments' } }
    switch ($Integration.mode) {
        'existing' { return $Integration.id }
        'delegate' {
            $s = Invoke-AzRest -Url "$script:Arm$($Integration.id)?api-version=$api"
            $props = ConvertTo-Hashtable $s.properties
            if (@($props.delegations | Where-Object { (Get-Prop (Get-Prop $_ 'properties') 'serviceName') -eq 'Microsoft.App/environments' }).Count) { return $Integration.id }
            $props.delegations = @($props.delegations) + $delegation | Where-Object { $_ }
            foreach ($ro in 'provisioningState', 'ipConfigurations', 'privateEndpoints', 'purpose', 'serviceAssociationLinks', 'resourceNavigationLinks') { if ($props.Contains($ro)) { $props.Remove($ro) } }
            Invoke-AzRest -Method PUT -Url "$script:Arm$($Integration.id)?api-version=$api" -Body @{ properties = $props } | Out-Null
            Wait-ArmProvisioning $Integration.id $api | Out-Null
            Write-Done "Delegated $(Get-ResourceName $Integration.id) to Microsoft.App/environments."
            return $Integration.id
        }
        'create' {
            $id = "$VnetId/subnets/$($Integration.name)"
            $props = @{ addressPrefix = $Integration.addressPrefix; delegations = @($delegation); privateEndpointNetworkPolicies = 'Disabled' }
            if ($Integration.nsgId) { $props.networkSecurityGroup = @{ id = $Integration.nsgId } }
            if ($Integration.routeTableId) { $props.routeTable = @{ id = $Integration.routeTableId } }
            $existing = Invoke-AzRest -Url "$script:Arm$id`?api-version=$api" -AllowFailure
            if ($existing) { Write-Note "Subnet $($Integration.name) already exists."; return $id }
            Invoke-AzRest -Method PUT -Url "$script:Arm$id`?api-version=$api" -Body @{ properties = $props } | Out-Null
            Wait-ArmProvisioning $id $api | Out-Null
            Write-Done "Created subnet $($Integration.name) ($($Integration.addressPrefix)), delegated to Microsoft.App/environments."
            return $id
        }
    }
    throw "Unknown integration subnet mode '$($Integration.mode)'."
}

function Get-ScmHost([string]$FunctionAppId) {
    $site = Invoke-AzRest -Url "$script:Arm$FunctionAppId`?api-version=2024-04-01"
    $scm = @($site.properties.hostNameSslStates | Where-Object { $_.hostType -eq 'Repository' } | ForEach-Object { $_.name }) | Select-Object -First 1
    return @{ Default = $site.properties.defaultHostName; Scm = $(if ($scm) { $scm } else { $site.properties.defaultHostName -replace '^([^.]+)\.', '$1.scm.' }) }
}

function Test-TcpReachable([string]$HostName, [int]$Port = 443, [int]$TimeoutMs = 4000) {
    <# @{ Reachable; Addresses; Private } for the host from this machine. #>
    $addrs = @()
    try { $addrs = @([System.Net.Dns]::GetHostAddresses($HostName) | ForEach-Object { $_.ToString() }) } catch { return @{ Reachable = $false; Addresses = @(); Private = $false } }
    $private = [bool](@($addrs | Where-Object { $_ -match '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)' }).Count)
    $client = [System.Net.Sockets.TcpClient]::new()
    try { $ok = $client.ConnectAsync($HostName, $Port).Wait($TimeoutMs) -and $client.Connected } catch { $ok = $false } finally { $client.Dispose() }
    return @{ Reachable = $ok; Addresses = $addrs; Private = $private }
}

function Set-TemporaryDeployAccess {
    <#
        Opens (or closes) public access to the deployment (SCM) endpoint for one IP address only;
        the app itself stays blocked. Used when deploying code from a machine that can't reach
        the private endpoint.
    #>
    param([string]$FunctionAppId, [string]$IpAddress, [switch]$Close)
    $siteConfig = if ($Close) {
        @{ scmIpSecurityRestrictions = @(); scmIpSecurityRestrictionsDefaultAction = 'Deny'; ipSecurityRestrictionsDefaultAction = 'Deny' }
    } else {
        @{ ipSecurityRestrictionsDefaultAction = 'Deny'; scmIpSecurityRestrictionsUseMain = $false; scmIpSecurityRestrictionsDefaultAction = 'Deny'
           scmIpSecurityRestrictions = @(@{ ipAddress = "$IpAddress/32"; action = 'Allow'; priority = 100; name = 'temporary-deployment' }) }
    }
    Invoke-AzRest -Method PATCH -Url "$script:Arm$FunctionAppId`?api-version=2024-04-01" -Body @{
        properties = @{ publicNetworkAccess = $(if ($Close) { 'Disabled' } else { 'Enabled' }); siteConfig = $siteConfig }
    } | Out-Null
}

#endregion

# Only when loaded as a module (Import-Module). If this file is run or dot-sourced directly
# (e.g. F5 in an editor with this file active), skip it rather than fail.
if ($ExecutionContext.SessionState.Module) {
    Export-ModuleMember -Function * -Variable GraphReadPermissions, EntraRoles, Arm, Graph
}
