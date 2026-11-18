# Scheduled run of the 'public-exposure' report. Schedule (UTC, NCRONTAB): app setting SCHEDULE_PUBLIC_EXPOSURE.
param($Timer)
Import-Module ReportPlatform
Invoke-ScheduledReport -Id 'public-exposure'
