<#
    ReportPlatform - shared helpers for the reporting Function App.

    * Runs report scripts on a schedule as the app's user-assigned managed identity and
      stores the CSV output in the private reports storage account.
    * Serves stored reports to the dashboard (behind App Service authentication).

    Storage is reached with Entra tokens from the platform identity endpoint (no keys,
    no Az.Storage dependency). Blob layout in the reports container:

        latest/<id>.csv              most recent successful run
        history/<id>/<yyyy-MM-dd>.csv one per day (a re-run on the same day replaces it)
        status/<id>.json             last run: queued / running / succeeded / failed

    App settings used:
        AZURE_CLIENT_ID          client ID of the user-assigned managed identity
        REPORT_TENANT_ID         tenant to report on
        REPORTS_BLOB_ENDPOINT    e.g. https://stexample.blob.core.windows.net/
        REPORTS_CONTAINER        e.g. reports
        REPORTS_DEV_MODE         '1' only for local development: skips the sign-in check
#>

Set-StrictMode -Version Latest

$script:StorageApiVersion = '2023-11-03'
$script:Tokens = @{}

function Get-AppRoot {
    if ($env:AzureWebJobsScriptRoot) { return $env:AzureWebJobsScriptRoot }
    return (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

function Get-ReportRegistry {
    <# Returns the report definitions from reports.json. #>
    $path = Join-Path (Get-AppRoot) 'reports.json'
    return @((Get-Content -Raw -Path $path | ConvertFrom-Json).reports)
}

function Get-ReportDefinition {
    param([Parameter(Mandatory)][string]$Id)
    $def = Get-ReportRegistry | Where-Object { $_.id -eq $Id } | Select-Object -First 1
    if (-not $def) { throw "Unknown report '$Id'." }
    return $def
}

function Get-ManagedIdentityToken {
    <# Access token for a resource, as the app's user-assigned managed identity. Cached until near expiry. #>
    param([Parameter(Mandatory)][string]$Resource)
    $cached = $script:Tokens[$Resource]
    if ($cached -and $cached.Expires -gt [datetime]::UtcNow.AddMinutes(5)) { return $cached.Token }
    if (-not $env:IDENTITY_ENDPOINT -or -not $env:IDENTITY_HEADER) { throw 'No managed identity endpoint available (IDENTITY_ENDPOINT / IDENTITY_HEADER not set).' }
    $uri = "$($env:IDENTITY_ENDPOINT)?resource=$([uri]::EscapeDataString($Resource))&api-version=2019-08-01&client_id=$($env:AZURE_CLIENT_ID)"
    $r = Invoke-RestMethod -Uri $uri -Headers @{ 'X-IDENTITY-HEADER' = $env:IDENTITY_HEADER }
    $script:Tokens[$Resource] = @{ Token = $r.access_token; Expires = [DateTimeOffset]::FromUnixTimeSeconds([long]$r.expires_on).UtcDateTime }
    return $r.access_token
}

#region Blob storage ------------------------------------------------------------

function Get-BlobUri {
    param([string]$Path, [string]$Query)
    $base = $env:REPORTS_BLOB_ENDPOINT.TrimEnd('/')
    $container = $env:REPORTS_CONTAINER
    $escaped = (($Path -split '/') | ForEach-Object { [uri]::EscapeDataString($_) }) -join '/'
    $uri = if ($Path) { "$base/$container/$escaped" } else { "$base/$container" }
    if ($Query) { $uri += "?$Query" }
    return $uri
}

function Invoke-BlobRequest {
    param([string]$Method = 'GET', [string]$Path, [string]$Query, [hashtable]$Headers = @{}, [string]$InFile, [string]$Body, [string]$ContentType)
    $h = @{ Authorization = "Bearer $(Get-ManagedIdentityToken 'https://storage.azure.com/')"; 'x-ms-version' = $script:StorageApiVersion }
    foreach ($k in $Headers.Keys) { $h[$k] = $Headers[$k] }
    $p = @{ Uri = (Get-BlobUri -Path $Path -Query $Query); Method = $Method; Headers = $h; SkipHttpErrorCheck = $true; UseBasicParsing = $true }
    if ($InFile) { $p.InFile = $InFile }
    if ($PSBoundParameters.ContainsKey('Body')) { $p.Body = [System.Text.Encoding]::UTF8.GetBytes($Body) }
    if ($ContentType) { $p.ContentType = $ContentType }
    for ($attempt = 1; $attempt -le 4; $attempt++) {
        $r = Invoke-WebRequest @p
        if ([int]$r.StatusCode -lt 500 -and [int]$r.StatusCode -ne 429) { return $r }
        Start-Sleep -Seconds (2 * $attempt)
    }
    return $r
}

function Send-ReportBlob {
    <# Uploads a file (or text) as a block blob. #>
    param([Parameter(Mandatory)][string]$Path, [string]$File, [string]$Text, [string]$ContentType = 'text/csv; charset=utf-8')
    $req = @{ Method = 'PUT'; Path = $Path; Headers = @{ 'x-ms-blob-type' = 'BlockBlob'; 'x-ms-blob-content-type' = $ContentType }; ContentType = $ContentType }
    if ($File) { $req.InFile = $File } else { $req.Body = $Text }
    $r = Invoke-BlobRequest @req
    if ([int]$r.StatusCode -ne 201) { throw "Upload of '$Path' failed: HTTP $($r.StatusCode) $($r.Content)" }
}

function Get-ReportBlob {
    <# Returns @{ StatusCode; Content; LastModified } for a blob. #>
    param([Parameter(Mandatory)][string]$Path)
    $r = Invoke-BlobRequest -Method GET -Path $Path
    $content = $r.Content
    if ($content -is [byte[]]) { $content = [System.Text.Encoding]::UTF8.GetString($content) }
    $lm = $r.Headers['Last-Modified']
    return @{ StatusCode = [int]$r.StatusCode; Content = [string]$content; LastModified = $(if ($lm) { @($lm)[0] } else { $null }) }
}

function Get-ReportBlobList {
    <# Lists blob names under a prefix. #>
    param([Parameter(Mandatory)][string]$Prefix)
    $names = [System.Collections.Generic.List[string]]::new()
    $marker = $null
    do {
        $q = "restype=container&comp=list&prefix=$([uri]::EscapeDataString($Prefix))&maxresults=5000"
        if ($marker) { $q += "&marker=$([uri]::EscapeDataString($marker))" }
        $r = Invoke-BlobRequest -Method GET -Query $q
        if ([int]$r.StatusCode -ne 200) { throw "Listing '$Prefix' failed: HTTP $($r.StatusCode)" }
        $text = $r.Content; if ($text -is [byte[]]) { $text = [System.Text.Encoding]::UTF8.GetString($text) }
        [xml]$xml = $text.TrimStart([char]0xFEFF)
        foreach ($n in $xml.SelectNodes('/EnumerationResults/Blobs/Blob/Name')) { $names.Add([string]$n.InnerText) }
        $m = $xml.SelectSingleNode('/EnumerationResults/NextMarker')
        $marker = if ($m) { [string]$m.InnerText } else { $null }
    } while ($marker)
    return $names.ToArray()
}

#endregion

#region Scheduled runs ----------------------------------------------------------

$script:RunTimeoutHours = 2   # host.json functionTimeout: a 'running' status older than this is stale

function Get-StatusValue($Status, [string]$Name) {
    if ($null -eq $Status) { return $null }
    $p = $Status.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Get-ReportStatus {
    <# The report's status/<id>.json, or $null. #>
    param([Parameter(Mandatory)][string]$Id)
    $blob = Get-ReportBlob -Path "status/$Id.json"
    if ($blob.StatusCode -ne 200) { return $null }
    try { return ($blob.Content | ConvertFrom-Json) } catch { return $null }
}

function Test-ReportBusy {
    <# True while a run is queued or in progress (ignoring stale entries from runs that were cut off). #>
    param($Status)
    $result = [string](Get-StatusValue $Status 'result')
    if ($result -notin 'queued', 'running') { return $false }
    $since = [string](Get-StatusValue $Status $(if ($result -eq 'queued') { 'requested' } else { 'started' }))
    $t = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    if (-not [datetime]::TryParse($since, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$t)) { return $false }
    return ([datetime]::UtcNow - $t).TotalHours -lt $script:RunTimeoutHours
}

function Set-ReportQueued {
    <# Marks a report as queued for an on-demand run. Keeps the last run's details under 'previous'. #>
    param([Parameter(Mandatory)][string]$Id, [string]$RequestedBy, $Current)
    $prev = $Current
    if ($prev -and (Get-StatusValue $prev 'result') -in 'queued', 'running') { $prev = Get-StatusValue $prev 'previous' }
    $status = [ordered]@{ id = $Id; result = 'queued'; trigger = 'manual'; requested = [datetime]::UtcNow.ToString('o'); requestedBy = $RequestedBy; previous = $prev }
    Send-ReportBlob -Path "status/$Id.json" -Text ($status | ConvertTo-Json -Depth 6) -ContentType 'application/json'
    return $status
}

function Invoke-ScheduledReport {
    <#
        Runs a registered report script as the managed identity and stores the result.
        Writes status/<id>.json when it starts ('running') and when it ends, whether it succeeds
        or fails; a failure keeps the previous latest/<id>.csv in place. Skips the run if
        another run of the same report is already in progress.
    #>
    param([Parameter(Mandatory)][string]$Id, [ValidateSet('schedule', 'manual')][string]$Trigger = 'schedule', [string]$RequestedBy)
    $ProgressPreference = 'SilentlyContinue'
    $def = Get-ReportDefinition -Id $Id
    $current = try { Get-ReportStatus -Id $Id } catch { $null }
    if ((Get-StatusValue $current 'result') -eq 'running' -and (Test-ReportBusy $current)) {
        Write-Warning "[$Id] Already running since $(Get-StatusValue $current 'started'); skipping this $Trigger run."
        return
    }
    $started = [datetime]::UtcNow
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) "$Id-$([guid]::NewGuid()).csv"
    $warnings = @()
    $previous = if ((Get-StatusValue $current 'result') -in 'queued', 'running') { Get-StatusValue $current 'previous' } else { $current }
    $status = [ordered]@{ id = $Id; trigger = $Trigger; requestedBy = $(if ($RequestedBy) { $RequestedBy } else { $null }); started = $started.ToString('o'); finished = $null; result = 'running'
        durationSeconds = $null; rows = $null; bytes = $null; warnings = @(); error = $null; previous = $previous }
    try { Send-ReportBlob -Path "status/$Id.json" -Text ($status | ConvertTo-Json -Depth 6) -ContentType 'application/json' }
    catch { Write-Warning "[$Id] Couldn't write run status: $($_.Exception.Message)" }
    $status.Remove('previous')
    try {
        $script = Join-Path (Get-AppRoot) (Join-Path 'scripts' $def.script)
        $params = @{}
        if ($def.parameters) { foreach ($p in $def.parameters.PSObject.Properties) { $params[$p.Name] = $p.Value } }
        $params.OutputPath = $tmp
        switch ($def.auth) {
            'graph' {
                Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
                Connect-MgGraph -Identity -ClientId $env:AZURE_CLIENT_ID -NoWelcome -ErrorAction Stop | Out-Null
            }
            'managedIdentityParameter' {
                $params.ManagedIdentityClientId = $env:AZURE_CLIENT_ID
                $params.TenantId = $env:REPORT_TENANT_ID
            }
            default { throw "Unknown auth type '$($def.auth)' for report '$Id'." }
        }
        Write-Host "[$Id] Running $($def.script)"
        & $script @params -WarningVariable +warnings
        if (-not (Test-Path $tmp)) { throw 'The report script did not produce an output file.' }

        $date = $started.ToString('yyyy-MM-dd')
        Send-ReportBlob -Path "history/$Id/$date.csv" -File $tmp
        Send-ReportBlob -Path "latest/$Id.csv" -File $tmp
        $status.rows = [math]::Max(0, ([System.IO.File]::ReadLines($tmp) | Measure-Object).Count - 1)
        $status.bytes = (Get-Item $tmp).Length
        $status.result = 'succeeded'
    }
    catch {
        $status.result = 'failed'
        $status.error = $_.Exception.Message
        throw
    }
    finally {
        $status.finished = [datetime]::UtcNow.ToString('o')
        $status.durationSeconds = [math]::Round(([datetime]::UtcNow - $started).TotalSeconds)
        $status.warnings = @($warnings | ForEach-Object { [string]$_ } | Select-Object -First 20)
        try { Send-ReportBlob -Path "status/$Id.json" -Text ($status | ConvertTo-Json -Depth 4) -ContentType 'application/json' }
        catch { Write-Warning "[$Id] Couldn't write run status: $($_.Exception.Message)" }
        Remove-Item $tmp -ErrorAction SilentlyContinue
        Write-Host "[$Id] $($status.result) in $($status.durationSeconds)s"
    }
}

#endregion

#region HTTP helpers -------------------------------------------------------------

function Get-HeaderValue {
    param($Headers, [string]$Name)
    if (-not $Headers) { return $null }
    foreach ($k in $Headers.Keys) { if ($k -ieq $Name) { return $Headers[$k] } }
    return $null
}

function Get-RequestPrincipal {
    <#
        The signed-in user, from the headers App Service authentication adds after sign-in.
        Returns $null when there is no authenticated Entra principal. Requests can only carry
        these headers via the platform: App Service authentication strips them from incoming
        requests.
    #>
    param($Request)
    if ($env:REPORTS_DEV_MODE -eq '1') { return @{ Name = 'developer (dev mode)'; Id = 'dev' } }
    $idp = Get-HeaderValue $Request.Headers 'x-ms-client-principal-idp'
    $name = Get-HeaderValue $Request.Headers 'x-ms-client-principal-name'
    $id = Get-HeaderValue $Request.Headers 'x-ms-client-principal-id'
    if (-not $id -or $idp -ne 'aad') { return $null }
    return @{ Name = $name; Id = $id }
}

function New-HttpResponse {
    param([int]$StatusCode = 200, $Body = '', [string]$ContentType = 'application/json; charset=utf-8', [hashtable]$Headers = @{})
    # The content type goes in the ContentType property, not a header: the PowerShell worker only
    # recognises a lower-case 'content-type' header, otherwise it adds its own (text/plain for a
    # string body) and the browser shows the page source.
    $h = @{
        'Cache-Control'          = 'no-store'
        'X-Content-Type-Options' = 'nosniff'
        'Referrer-Policy'        = 'no-referrer'
    }
    foreach ($k in $Headers.Keys) { if ($k -ne 'Content-Type') { $h[$k] = $Headers[$k] } }
    return [HttpResponseContext]@{ StatusCode = $StatusCode; Headers = $h; ContentType = $ContentType; Body = $Body }
}

#endregion

Export-ModuleMember -Function Get-AppRoot, Get-ReportRegistry, Get-ReportDefinition, Get-ManagedIdentityToken,
    Send-ReportBlob, Get-ReportBlob, Get-ReportBlobList, Invoke-ScheduledReport, Get-RequestPrincipal, New-HttpResponse, Get-HeaderValue,
    Get-ReportStatus, Test-ReportBusy, Set-ReportQueued
