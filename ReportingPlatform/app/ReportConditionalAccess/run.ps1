# Scheduled run of the 'conditional-access' report. Schedule (UTC, NCRONTAB): app setting SCHEDULE_CONDITIONAL_ACCESS.
param($Timer)
Import-Module ReportPlatform
Invoke-ScheduledReport -Id 'conditional-access'
