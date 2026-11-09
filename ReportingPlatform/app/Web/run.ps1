<#
    Serves the portal (www/index.html) and the report dashboards (www/reports/*.html).
    Only files under www/ with an allowed extension are served.
#>
using namespace System.Net
param($Request, $TriggerMetadata)

Import-Module ReportPlatform

$types = @{
    '.html' = 'text/html; charset=utf-8'; '.js' = 'text/javascript; charset=utf-8'; '.css' = 'text/css; charset=utf-8'
    '.json' = 'application/json; charset=utf-8'; '.svg' = 'image/svg+xml'; '.txt' = 'text/plain; charset=utf-8'
}
$security = @{
    'Content-Security-Policy' = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-src 'self'; frame-ancestors 'self'; base-uri 'none'; form-action 'self'; object-src 'none'"
    'X-Frame-Options' = 'SAMEORIGIN'
    'Strict-Transport-Security' = 'max-age=31536000'
    'Permissions-Policy' = 'camera=(), microphone=(), geolocation=()'
}

if (-not (Get-RequestPrincipal $Request)) {
    Push-OutputBinding -Name Response -Value (New-HttpResponse -StatusCode 401 -Body 'Sign-in required.' -ContentType 'text/plain; charset=utf-8' -Headers $security)
    return
}

$path = [string]$Request.Params.path
if ([string]::IsNullOrWhiteSpace($path)) { $path = 'index.html' }
$www = [System.IO.Path]::GetFullPath((Join-Path (Get-AppRoot) 'www'))
$full = [System.IO.Path]::GetFullPath((Join-Path $www $path))
$ext = [System.IO.Path]::GetExtension($full).ToLowerInvariant()

if (-not $full.StartsWith($www + [System.IO.Path]::DirectorySeparatorChar) -or -not $types.ContainsKey($ext) -or -not (Test-Path -LiteralPath $full -PathType Leaf)) {
    Push-OutputBinding -Name Response -Value (New-HttpResponse -StatusCode 404 -Body 'Not found.' -ContentType 'text/plain; charset=utf-8' -Headers $security)
    return
}

$headers = $security.Clone()
$headers['Cache-Control'] = 'no-cache'
Push-OutputBinding -Name Response -Value (New-HttpResponse -StatusCode 200 -Body ([System.IO.File]::ReadAllText($full)) -ContentType $types[$ext] -Headers $headers)
