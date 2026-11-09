<#
.SYNOPSIS
    Builds the Function App deployment package (zip) for the reporting platform.

.DESCRIPTION
    Assembles ReportingPlatform/app with:
      * each registered report's script folder (*.ps1, *.csv) under scripts/
      * each report's dashboard as www/reports/<id>.html
      * Microsoft.Graph.Authentication saved into Modules/ (Flex Consumption doesn't
        support managed dependencies, so modules ship with the app)
    and zips the result. The report scripts and dashboards stay where they are in the repo
    (Entra/, Azure/), so they can still be run and opened locally.

    Checks that every report in reports.json has a timer function and a dashboard.

.PARAMETER OutputPath
    Zip file to create.

.PARAMETER GraphModuleVersion
    Version of Microsoft.Graph.Authentication to bundle. Pin this so builds are repeatable.

.PARAMETER ModuleRepository
    PowerShell repository to download modules from (default PSGallery). Point this at an
    internal feed if the build agent has no internet access.

.PARAMETER SkipModuleDownload
    Don't download modules (for local testing of the package layout).

.EXAMPLE
    ./Build-FunctionPackage.ps1 -OutputPath ./out/reporting-app.zip -GraphModuleVersion 2.25.0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutputPath,
    [string]$GraphModuleVersion = '2.25.0',
    [string]$ModuleRepository = 'PSGallery',
    [switch]$SkipModuleDownload
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$platformRoot = Split-Path -Parent $PSScriptRoot
$repoRoot = Split-Path -Parent $platformRoot
$appSource = Join-Path $platformRoot 'app'
$staging = Join-Path ([System.IO.Path]::GetTempPath()) "reporting-app-$([guid]::NewGuid())"

Write-Host "Staging in $staging"
Copy-Item -Path $appSource -Destination $staging -Recurse
New-Item -ItemType Directory -Force -Path (Join-Path $staging 'scripts'), (Join-Path $staging 'www/reports') | Out-Null

$registry = (Get-Content -Raw (Join-Path $appSource 'reports.json') | ConvertFrom-Json).reports
$timerIds = @(Get-ChildItem -Path $appSource -Filter run.ps1 -Recurse | ForEach-Object {
    if ((Get-Content -Raw $_.FullName) -match "Invoke-ScheduledReport\s+-Id\s+'([^']+)'") { $Matches[1] }
})
$problems = @()
$copiedFolders = @{}
foreach ($r in $registry) {
    if ($r.id -notmatch '^[a-z0-9-]+$') { $problems += "Report id '$($r.id)' must be lowercase letters, digits and hyphens." }
    $script = Join-Path $repoRoot $r.script
    $dashboard = Join-Path $repoRoot $r.dashboard
    if (-not (Test-Path $script)) { $problems += "[$($r.id)] script not found: $($r.script)"; continue }
    if (-not (Test-Path $dashboard)) { $problems += "[$($r.id)] dashboard not found: $($r.dashboard)"; continue }
    if ($r.id -notin $timerIds) { $problems += "[$($r.id)] has no timer function (a run.ps1 calling Invoke-ScheduledReport -Id '$($r.id)')." }
    if ((Get-Content -Raw $dashboard) -notmatch 'URLSearchParams\(location\.search\)') { $problems += "[$($r.id)] dashboard doesn't support ?src= loading (see existing dashboards)." }

    $folder = Split-Path -Parent $r.script
    if (-not $copiedFolders.ContainsKey($folder)) {
        $dest = Join-Path $staging (Join-Path 'scripts' $folder)
        New-Item -ItemType Directory -Force -Path $dest | Out-Null
        Get-ChildItem -Path (Join-Path $repoRoot $folder) -File | Where-Object { $_.Extension -in '.ps1', '.csv', '.psm1', '.psd1' } |
            Copy-Item -Destination $dest
        $copiedFolders[$folder] = $true
    }
    Copy-Item $dashboard (Join-Path $staging "www/reports/$($r.id).html")
    Write-Host "  [$($r.id)] $($r.script) + $($r.dashboard)"
}
if ($problems) { $problems | ForEach-Object { Write-Error $_ -ErrorAction Continue }; throw "Package validation failed ($($problems.Count) problem(s))." }

if (-not $SkipModuleDownload) {
    Write-Host "Saving Microsoft.Graph.Authentication $GraphModuleVersion from $ModuleRepository"
    Save-Module -Name Microsoft.Graph.Authentication -RequiredVersion $GraphModuleVersion -Repository $ModuleRepository -Path (Join-Path $staging 'Modules') -Force
}

$outDir = Split-Path -Parent ([System.IO.Path]::GetFullPath($OutputPath))
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
if (Test-Path $OutputPath) { Remove-Item $OutputPath -Force }
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($staging, [System.IO.Path]::GetFullPath($OutputPath))
Remove-Item -Recurse -Force $staging
Write-Host "Package written to $OutputPath ($([math]::Round((Get-Item $OutputPath).Length / 1MB, 1)) MB)" -ForegroundColor Green
