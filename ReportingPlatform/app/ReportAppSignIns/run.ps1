# Scheduled run of the 'app-signins' report. Schedule (UTC, NCRONTAB): app setting SCHEDULE_APP_SIGNINS.
param($Timer)
Import-Module ReportPlatform
Invoke-ScheduledReport -Id 'app-signins'
