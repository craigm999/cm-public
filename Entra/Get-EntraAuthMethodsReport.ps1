<#
.SYNOPSIS
    Reports each user's registered Entra authentication methods (user registration details),
    with account status, admin flag and the strongest method they have.

.DESCRIPTION
    Combines two Microsoft Graph sources:

      * /reports/authenticationMethods/userRegistrationDetails - methods registered, MFA /
        SSPR / passwordless registration and capability, default MFA method, admin flag.
      * /users - account enabled / disabled, user type, department, job title, created date,
        on-premises sync, and last successful sign-in (signInActivity).

    The registration details report doesn't cover disabled accounts, so disabled users are
    listed with RegistrationDataSource = 'Not available (disabled account)'. With
    -IncludeDisabledUserMethods their methods are read per user from
    /users/{id}/authentication/methods instead (needs UserAuthenticationMethod.Read.All).

    Each user gets a StrongestMethodTier:
      Phishing-resistant   FIDO2 security key, passkey, Windows Hello for Business,
                           macOS platform credential, certificate-based authentication
      Passwordless         Microsoft Authenticator passwordless phone sign-in
      App-based MFA        Authenticator push, software / hardware OATH codes, external MFA
      Phone (SMS / voice)  mobile, alternate mobile or office phone only
      No MFA method        nothing usable for MFA (e.g. only email / security questions)
      Unknown              no registration data available

    Load the CSV into AuthMethodsDashboard.html (same folder).

    REQUIREMENTS
      * Microsoft.Graph.Authentication module
      * Graph permissions: AuditLog.Read.All, Directory.Read.All (User.Read.All is enough for
        the user list). -IncludeDisabledUserMethods also needs UserAuthenticationMethod.Read.All.
      * When signed in as a user: Reports Reader, Security Reader, Security Administrator or
        Global Reader.
      * Entra ID P1 or P2 for the registration details report and sign-in activity.

.PARAMETER TenantId
    Tenant ID or domain to connect to. Optional when already connected.

.PARAMETER IncludeDisabledUserMethods
    Read disabled users' methods from the per-user authentication methods API
    (one request per disabled user, batched).

.PARAMETER OutputPath
    CSV to write.

.EXAMPLE
    .\Get-EntraAuthMethodsReport.ps1 -TenantId contoso.onmicrosoft.com -OutputPath .\auth-methods.csv

.EXAMPLE
    .\Get-EntraAuthMethodsReport.ps1 -IncludeDisabledUserMethods -OutputPath .\auth-methods.csv
#>
[CmdletBinding()]
param(
    [string]$TenantId,
    [switch]$IncludeDisabledUserMethods,
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Method name -> strength tier. Unrecognised future methods fall back to 'Other'.
$Tiers = [ordered]@{
    'Phishing-resistant'  = @('fido2SecurityKey', 'windowsHelloForBusiness', 'passKeyDeviceBound', 'passKeyDeviceBoundAuthenticator',
                              'passKeyDeviceBoundWindowsHello', 'passKeySynced', 'macOsSecureEnclaveKey', 'platformCredential',
                              'x509Certificate', 'certificateBasedAuthentication', 'x509CertificateMultiFactor')
    'Passwordless'        = @('microsoftAuthenticatorPasswordless')
    'App-based MFA'       = @('microsoftAuthenticatorPush', 'softwareOneTimePasscode', 'hardwareOneTimePasscode', 'externalAuthenticationMethod')
    'Phone (SMS / voice)' = @('mobilePhone', 'alternateMobilePhone', 'officePhone')
}
$TierOrder = @('Phishing-resistant', 'Passwordless', 'App-based MFA', 'Phone (SMS / voice)', 'No MFA method', 'Unknown')

#region Helpers ---------------------------------------------------------------

function Invoke-GraphPaged {
    param([Parameter(Mandatory)][string]$Uri, [hashtable]$Headers = @{})
    $next = $Uri
    while ($next) {
        $response = Invoke-MgGraphRequest -Method GET -Uri $next -Headers $Headers -OutputType Hashtable
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
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }
    try {
        return [datetime]::Parse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal)
    } catch { return $null }
}

function Format-Date($d) { if ($d) { $d.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' } }

function Get-StrongestTier {
    param([string[]]$Methods)
    foreach ($tier in $Tiers.Keys) {
        if ($Methods | Where-Object { $_ -in $Tiers[$tier] }) { return $tier }
    }
    return 'No MFA method'
}

function ConvertFrom-AuthMethod {
    <# Maps a /users/{id}/authentication/methods entry to the registration report's method names. #>
    param($Method)
    switch -Wildcard ([string](Get-Prop $Method '@odata.type')) {
        '*fido2AuthenticationMethod' { 'fido2SecurityKey' }
        '*windowsHelloForBusinessAuthenticationMethod' { 'windowsHelloForBusiness' }
        '*platformCredentialAuthenticationMethod' { 'macOsSecureEnclaveKey' }
        '*x509CertificateAuthenticationMethod' { 'x509Certificate' }
        '*microsoftAuthenticatorAuthenticationMethod' { 'microsoftAuthenticatorPush' }
        '*softwareOathAuthenticationMethod' { 'softwareOneTimePasscode' }
        '*hardwareOathAuthenticationMethod' { 'hardwareOneTimePasscode' }
        '*emailAuthenticationMethod' { 'email' }
        '*temporaryAccessPassAuthenticationMethod' { 'temporaryAccessPass' }
        '*phoneAuthenticationMethod' {
            switch ([string](Get-Prop $Method 'phoneType')) { 'alternateMobile' { 'alternateMobilePhone' } 'office' { 'officePhone' } default { 'mobilePhone' } }
        }
        '*passwordAuthenticationMethod' { }   # everyone has one; the registration report doesn't list it either
        default { ([string](Get-Prop $Method '@odata.type')) -replace '^#microsoft\.graph\.', '' -replace 'AuthenticationMethod$', '' }
    }
}

#endregion

#region Connect ---------------------------------------------------------------

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    throw "Microsoft.Graph.Authentication module not found. Install it with: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser"
}
Import-Module Microsoft.Graph.Authentication
$requiredScopes = @('AuditLog.Read.All', 'Directory.Read.All')
if ($IncludeDisabledUserMethods) { $requiredScopes += 'UserAuthenticationMethod.Read.All' }
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
}

#endregion

#region Collect -----------------------------------------------------------------

Write-Host 'Retrieving users...' -ForegroundColor Cyan
$select = 'id,userPrincipalName,displayName,accountEnabled,userType,department,jobTitle,createdDateTime,onPremisesSyncEnabled'
$signInAvailable = $true
try {
    $users = @(Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/users?`$select=$select,signInActivity&`$top=999")
} catch {
    $signInAvailable = $false
    Write-Warning "Sign-in activity unavailable ($($_.Exception.Message)); continuing without last sign-in dates. It needs AuditLog.Read.All and Entra ID P1/P2."
    $users = @(Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/users?`$select=$select&`$top=999")
}
Write-Host "  $($users.Count) users."

Write-Host 'Retrieving user registration details...' -ForegroundColor Cyan
$registration = @{}
foreach ($r in Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails') {
    $registration[[string]$r['id']] = $r
}
Write-Host "  $($registration.Count) registration records."

# Disabled users aren't in the registration report: optionally read their methods directly.
$directMethods = @{}
if ($IncludeDisabledUserMethods) {
    $disabledIds = @($users | Where-Object { -not (Get-Prop $_ 'accountEnabled') -and -not $registration.ContainsKey([string]$_['id']) } | ForEach-Object { [string]$_['id'] })
    Write-Host "Reading authentication methods for $($disabledIds.Count) disabled users..." -ForegroundColor Cyan
    for ($i = 0; $i -lt $disabledIds.Count; $i += 20) {
        $chunk = @($disabledIds[$i..([math]::Min($i + 19, $disabledIds.Count - 1))])
        $pending = $chunk
        for ($attempt = 1; $pending.Count -and $attempt -le 5; $attempt++) {
            $body = @{ requests = @($pending | ForEach-Object { @{ id = $_; method = 'GET'; url = "/users/$_/authentication/methods" } }) } | ConvertTo-Json -Depth 4
            $resp = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/$batch' -Body $body -ContentType 'application/json' -OutputType Hashtable
            $retry = @(); $wait = 0
            foreach ($r in $resp['responses']) {
                $status = [int]$r['status']
                if ($status -eq 200) { $directMethods[[string]$r['id']] = @(@(Get-Prop $r['body'] 'value') | ForEach-Object { ConvertFrom-AuthMethod $_ } | Where-Object { $_ } | Sort-Object -Unique) }
                elseif ($status -eq 429 -or $status -ge 500) {
                    $retry += [string]$r['id']
                    $ra = Get-Prop (Get-Prop $r 'headers') 'Retry-After'
                    $wait = [math]::Max($wait, $(if ($ra) { [int]$ra } else { 5 }))
                }
                else { Write-Verbose "Methods for $($r['id']): HTTP $status" }
            }
            $pending = $retry
            if ($pending.Count) { Start-Sleep -Seconds $wait }
        }
        Write-Progress -Activity 'Disabled users' -Status "$([math]::Min($i + 20, $disabledIds.Count)) of $($disabledIds.Count)" -PercentComplete ([math]::Min(100, ($i + 20) / [math]::Max(1, $disabledIds.Count) * 100))
    }
    Write-Progress -Activity 'Disabled users' -Completed
}

#endregion

#region Build rows ----------------------------------------------------------------

$reportTime = Format-Date ([datetime]::UtcNow)
$rows = foreach ($u in ($users | Sort-Object { [string]$_['displayName'] })) {
    $id = [string]$u['id']
    $enabled = [bool](Get-Prop $u 'accountEnabled')
    $reg = $registration[$id]
    $sia = Get-Prop $u 'signInActivity'
    $lastSuccess = ConvertTo-UtcDate (Get-Prop $sia 'lastSuccessfulSignInDateTime')
    if (-not $lastSuccess) {
        $lastSuccess = @((ConvertTo-UtcDate (Get-Prop $sia 'lastSignInDateTime')), (ConvertTo-UtcDate (Get-Prop $sia 'lastNonInteractiveSignInDateTime'))) |
            Where-Object { $_ } | Sort-Object -Descending | Select-Object -First 1
    }

    if ($reg) {
        $methods = @(@(Get-Prop $reg 'methodsRegistered') | Where-Object { $_ })
        $source = 'Registration report'
        $tier = Get-StrongestTier $methods
    } elseif ($directMethods.ContainsKey($id)) {
        $methods = @($directMethods[$id])
        $source = 'Authentication methods API'
        $tier = Get-StrongestTier $methods
    } else {
        $methods = @()
        $source = if (-not $enabled) { 'Not available (disabled account)' } else { 'Not available (not yet in report)' }
        $tier = 'Unknown'
    }
    $boolOrBlank = { param($v) if ($null -eq $v) { '' } else { [bool]$v } }

    [pscustomobject][ordered]@{
        UserId                      = $id
        UserPrincipalName           = Get-Prop $u 'userPrincipalName'
        DisplayName                 = Get-Prop $u 'displayName'
        UserType                    = Get-Prop $u 'userType'
        AccountEnabled              = $enabled
        IsAdmin                     = & $boolOrBlank (Get-Prop $reg 'isAdmin')
        Department                  = Get-Prop $u 'department'
        JobTitle                    = Get-Prop $u 'jobTitle'
        OnPremisesSynced            = [bool](Get-Prop $u 'onPremisesSyncEnabled')
        CreatedDateTime             = Format-Date (ConvertTo-UtcDate (Get-Prop $u 'createdDateTime'))
        LastSuccessfulSignIn        = Format-Date $lastSuccess
        StrongestMethodTier         = $tier
        MethodsRegistered           = ($methods -join '; ')
        MethodCount                 = $methods.Count
        IsMfaRegistered             = & $boolOrBlank (Get-Prop $reg 'isMfaRegistered')
        IsMfaCapable                = & $boolOrBlank (Get-Prop $reg 'isMfaCapable')
        IsPasswordlessCapable       = & $boolOrBlank (Get-Prop $reg 'isPasswordlessCapable')
        IsSsprRegistered            = & $boolOrBlank (Get-Prop $reg 'isSsprRegistered')
        IsSsprEnabled               = & $boolOrBlank (Get-Prop $reg 'isSsprEnabled')
        IsSsprCapable               = & $boolOrBlank (Get-Prop $reg 'isSsprCapable')
        DefaultMfaMethod            = Get-Prop $reg 'userPreferredMethodForSecondaryAuthentication'
        SystemPreferredEnabled      = & $boolOrBlank (Get-Prop $reg 'isSystemPreferredAuthenticationMethodEnabled')
        SystemPreferredMethods      = (@(Get-Prop $reg 'systemPreferredAuthenticationMethods') | Where-Object { $_ }) -join '; '
        RegistrationDataSource      = $source
        RegistrationLastUpdated     = Format-Date (ConvertTo-UtcDate (Get-Prop $reg 'lastUpdatedDateTime'))
        SignInActivityAvailable     = $signInAvailable
        ReportGeneratedUtc          = $reportTime
    }
}
$rows = @($rows)

foreach ($t in $TierOrder) {
    $n = @($rows | Where-Object { $_.StrongestMethodTier -eq $t }).Count
    if ($n) { Write-Host ("  {0,-22} {1}" -f $t, $n) }
}

#endregion

if ($OutputPath) {
    $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host "Report exported to $((Resolve-Path $OutputPath).Path)" -ForegroundColor Green
} else {
    $rows
}
