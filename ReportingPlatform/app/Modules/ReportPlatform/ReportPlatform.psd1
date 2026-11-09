@{
    RootModule        = 'ReportPlatform.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = '7d6b1f0e-3c1a-4c55-9a5e-2f1b8c4d7e90'
    Author            = 'Reporting platform'
    Description       = 'Shared helpers for the Entra / Azure reporting Function App.'
    PowerShellVersion = '7.4'
    FunctionsToExport = @('Get-AppRoot', 'Get-ReportRegistry', 'Get-ReportDefinition', 'Get-ManagedIdentityToken', 'Send-ReportBlob',
                          'Get-ReportBlob', 'Get-ReportBlobList', 'Invoke-ScheduledReport', 'Get-RequestPrincipal', 'New-HttpResponse', 'Get-HeaderValue')
}
