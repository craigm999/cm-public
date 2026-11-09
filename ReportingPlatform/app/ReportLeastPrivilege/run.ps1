# Scheduled run of the 'least-privilege' report. Schedule (UTC, NCRONTAB): app setting SCHEDULE_LEAST_PRIVILEGE.
param($Timer)
Import-Module ReportPlatform
Invoke-ScheduledReport -Id 'least-privilege'
