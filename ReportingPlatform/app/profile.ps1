# Runs on each PowerShell worker cold start. Keep it light: Flex Consumption allows 30 seconds
# for app start-up, so modules are imported by the functions that need them, not here.
$ProgressPreference = 'SilentlyContinue'
