<#
    Report data API. Authentication is enforced by App Service authentication;
    authLevel is anonymous so the platform sign-in is the only gate, and every request is
    checked again here for an authenticated Entra principal.

      GET /api/reports                            reports with their last-run status
      GET /api/reports/{id}/latest                latest CSV
      GET /api/reports/{id}/history               dates with a stored run
      GET /api/reports/{id}/history/{yyyy-MM-dd}  CSV from that day
      POST /api/reports/{id}/run                  queue an on-demand run (needs header X-Requested-With)
#>
using namespace System.Net
param($Request, $TriggerMetadata)

Import-Module ReportPlatform

function Send([int]$Code, $Body, [string]$Type = 'application/json; charset=utf-8', [hashtable]$Headers = @{}) {
    Push-OutputBinding -Name Response -Value (New-HttpResponse -StatusCode $Code -Body $Body -ContentType $Type -Headers $Headers)
}

$principal = Get-RequestPrincipal $Request
if (-not $principal) { Send 401 (@{ error = 'Sign-in required.' } | ConvertTo-Json); return }

$id = [string]$Request.Params.id
$action = [string]$Request.Params.action
$date = [string]$Request.Params.date

try {
    $registry = Get-ReportRegistry
    $method = ([string]$Request.Method).ToUpperInvariant()

    if ($method -eq 'POST') {
        if (-not $id -or $action -ne 'run' -or $date) { Send 404 (@{ error = 'Unknown action.' } | ConvertTo-Json); return }
        # Only the portal's own script sends this header; a cross-site form post can't (CSRF protection).
        if (-not (Get-HeaderValue $Request.Headers 'X-Requested-With')) { Send 403 (@{ error = 'Missing X-Requested-With header.' } | ConvertTo-Json); return }
        if (-not ($registry | Where-Object { $_.id -eq $id })) { Send 404 (@{ error = 'Unknown report.' } | ConvertTo-Json); return }
        $current = Get-ReportStatus -Id $id
        if (Test-ReportBusy $current) { Send 409 (@{ error = 'This report is already queued or running.'; status = $current } | ConvertTo-Json -Depth 6); return }
        $queued = Set-ReportQueued -Id $id -RequestedBy $principal.Name -Current $current
        Push-OutputBinding -Name RunRequest -Value (@{ id = $id; requestedBy = $principal.Name; requested = $queued.requested } | ConvertTo-Json -Compress)
        Write-Host "[$id] Run requested by $($principal.Name)"
        Send 202 (@{ queued = $true; status = $queued } | ConvertTo-Json -Depth 6)
        return
    }
    if ($method -and $method -ne 'GET') { Send 405 (@{ error = 'Method not allowed.' } | ConvertTo-Json); return }

    if (-not $id) {
        $reports = foreach ($r in $registry) {
            $status = $null
            $blob = Get-ReportBlob -Path "status/$($r.id).json"
            if ($blob.StatusCode -eq 200) { $status = $blob.Content | ConvertFrom-Json }
            [ordered]@{
                id = $r.id; title = $r.title; description = $r.description
                dashboard = "reports/$($r.id).html"; status = $status
            }
        }
        Send 200 (@{ user = $principal.Name; reports = @($reports) } | ConvertTo-Json -Depth 6)
        return
    }

    if (-not ($registry | Where-Object { $_.id -eq $id })) { Send 404 (@{ error = 'Unknown report.' } | ConvertTo-Json); return }

    $csvHeaders = @{ 'Content-Disposition' = "inline; filename=`"$id.csv`"" }
    switch ($action) {
        'latest' {
            $blob = Get-ReportBlob -Path "latest/$id.csv"
            if ($blob.StatusCode -eq 404) { Send 404 (@{ error = 'This report has not run yet.' } | ConvertTo-Json); return }
            if ($blob.StatusCode -ne 200) { throw "Storage returned HTTP $($blob.StatusCode)." }
            if ($blob.LastModified) { $csvHeaders['Last-Modified'] = $blob.LastModified }
            Send 200 $blob.Content 'text/csv; charset=utf-8' $csvHeaders
        }
        'history' {
            if (-not $date) {
                $dates = @(Get-ReportBlobList -Prefix "history/$id/" | ForEach-Object { ($_ -split '/')[-1] -replace '\.csv$', '' } |
                    Where-Object { $_ -match '^\d{4}-\d{2}-\d{2}$' } | Sort-Object -Descending)
                Send 200 (ConvertTo-Json -InputObject @{ id = $id; dates = $dates } -Depth 3)
                return
            }
            if ($date -notmatch '^\d{4}-\d{2}-\d{2}$') { Send 400 (@{ error = 'Date must be yyyy-MM-dd.' } | ConvertTo-Json); return }
            $blob = Get-ReportBlob -Path "history/$id/$date.csv"
            if ($blob.StatusCode -eq 404) { Send 404 (@{ error = 'No run stored for that date.' } | ConvertTo-Json); return }
            if ($blob.StatusCode -ne 200) { throw "Storage returned HTTP $($blob.StatusCode)." }
            $csvHeaders['Content-Disposition'] = "inline; filename=`"$id-$date.csv`""
            Send 200 $blob.Content 'text/csv; charset=utf-8' $csvHeaders
        }
        default { Send 404 (@{ error = 'Unknown action.' } | ConvertTo-Json) }
    }
}
catch {
    Write-Warning "API error: $($_.Exception.Message)"
    Send 500 (@{ error = 'The report could not be retrieved. See the function logs for details.' } | ConvertTo-Json)
}
