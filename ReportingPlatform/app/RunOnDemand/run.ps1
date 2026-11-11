# On-demand run of a report, queued from the portal's "Run now" button (POST /api/reports/{id}/run).
# Runs in the background, so it isn't limited by the HTTP request timeout.
param($QueueItem, $TriggerMetadata)
Import-Module ReportPlatform

$msg = if ($QueueItem -is [string]) { $QueueItem | ConvertFrom-Json -AsHashtable } else { $QueueItem }
$id = [string]$msg['id']
if (-not (Get-ReportRegistry | Where-Object { $_.id -eq $id })) { Write-Warning "Ignoring run request for unknown report '$id'."; return }
Write-Host "[$id] On-demand run requested by $($msg['requestedBy'])"
try { Invoke-ScheduledReport -Id $id -Trigger manual -RequestedBy ([string]$msg['requestedBy']) }
catch {
    # The failure is recorded in the report's status; don't let the queue retry a failed report.
    Write-Warning "[$id] On-demand run failed: $($_.Exception.Message)"
}
