# Scheduled run of the 'azure-changes' report. Schedule (UTC, NCRONTAB): app setting SCHEDULE_AZURE_CHANGES.
param($Timer)
Import-Module ReportPlatform
Invoke-ScheduledReport -Id 'azure-changes'
