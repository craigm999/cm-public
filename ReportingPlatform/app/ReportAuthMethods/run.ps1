# Scheduled run of the 'auth-methods' report. Schedule (UTC, NCRONTAB): app setting SCHEDULE_AUTH_METHODS.
param($Timer)
Import-Module ReportPlatform
Invoke-ScheduledReport -Id 'auth-methods'
