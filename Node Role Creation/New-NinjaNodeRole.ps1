<#
.SYNOPSIS
    Creates custom NinjaOne node roles via the internal /swb/s6/noderole endpoint -
    parameter-driven selection of which roles to create.

.DESCRIPTION
    Authenticates with an existing browser session cookie (sessionKey) and sends a POST to
    https://<region>.ninjarmm.com/swb/s6/noderole for each selected role.

    The -Roles parameter controls what gets created. Pass a group keyword (e.g. 'server-all')
    or select individual roles by short key (e.g. datev,sql).

    The role catalog and group keywords live in ..\Shared\NinjaRoleCatalog.ps1 (shared with
    New-NinjaChildPolicy.ps1 so role and policy naming never drift). Run with -Roles ? or an
    unknown key to see the list of valid values.

    The sessionKey is a short-lived session cookie from a logged-in browser session. Once it
    expires you get 401/403 back - sign in again in the browser and pass the current cookie value.

.PARAMETER Roles
    One or more roles to create. Accepts group keywords (server-all, workstation-all, testlab)
    and/or individual short keys (comma-separated), e.g. -Roles server-all,testworkstation,testserver

.PARAMETER SessionKey
    The sessionKey cookie value from the logged-in NinjaOne browser session.
    If omitted, the script reads the NINJA_SESSION_KEY environment variable.
    The key is intentionally NOT stored in the script (secret).

.PARAMETER Region
    The NinjaOne instance subdomain (e.g. 'eu', 'app', 'us2'). Default: eu.

.PARAMETER WhatIf
    Shows what would be sent without actually performing the POST.

.EXAMPLE
    .\New-NinjaNodeRole.ps1 -Roles server-all
    Creates all five Windows Server roles.

.EXAMPLE
    .\New-NinjaNodeRole.ps1 -Roles datev,sql
    Creates only "Windows Server - DATEV" and "Windows Server - SQL Server".

.EXAMPLE
    .\New-NinjaNodeRole.ps1 -Roles server-all -WhatIf
    Dry run: shows the planned requests but sends nothing.

.EXAMPLE
    $env:NINJA_SESSION_KEY = "<sessionKey-from-browser>"
    .\New-NinjaNodeRole.ps1 -Roles sql,terminal
    Set the session key via the environment variable, then create selected roles.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string[]] $Roles,

    [Parameter()]
    [string] $SessionKey = $env:NINJA_SESSION_KEY,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $Region = "eu"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($SessionKey)) {
    throw "No session key. Set `$env:NINJA_SESSION_KEY or pass -SessionKey '<value>'."
}

# --- Shared role catalog ------------------------------------------------------
# Defines $RoleCatalog, $RoleGroups, $CategoryMeta and Resolve-NinjaRoleSelection.
# Path built without literal separators so it works on Windows and macOS/Linux alike.
$catalogPath = Join-Path (Join-Path (Split-Path -Parent $PSScriptRoot) "Shared") "NinjaRoleCatalog.ps1"
if (-not (Test-Path $catalogPath)) {
    throw "Shared catalog not found at '$catalogPath'. Expected a 'Shared/NinjaRoleCatalog.ps1' next to this script's folder."
}
. $catalogPath

# --- Resolve role selection ---------------------------------------------------
$selected = Resolve-NinjaRoleSelection -Roles $Roles

# --- Prepare HTTP client ------------------------------------------------------
$baseUrl   = "https://$Region.ninjarmm.com"
$uri       = "$baseUrl/swb/s6/noderole"
$userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36"

# Use .NET HttpClient directly instead of Invoke-WebRequest: the create POST responds with a
# redirect to an http:// URL. AllowAutoRedirect=$false returns the 3xx status cleanly (no
# exception like Invoke-WebRequest in PS 7.4+), and the session cookie is never sent over
# unencrypted http.
try { Add-Type -AssemblyName System.Net.Http -ErrorAction Stop } catch { }
$handler = [System.Net.Http.HttpClientHandler]::new()
$handler.AllowAutoRedirect = $false
$client = [System.Net.Http.HttpClient]::new($handler)

$headers = [ordered]@{
    "accept"           = "*/*"
    "accept-language"  = "en-US,en;q=0.9,de-DE;q=0.8,de;q=0.7,fr;q=0.6"
    "origin"           = $baseUrl
    "referer"          = "$baseUrl/"
    "sec-ch-ua"        = '"Google Chrome";v="155", "Chromium";v="155", "Not(A:Brand";v="24"'
    "sec-ch-ua-mobile" = "?0"
    "sec-fetch-dest"   = "empty"
    "sec-fetch-mode"   = "cors"
    "sec-fetch-site"   = "same-origin"
    "user-agent"       = $userAgent
    "cookie"           = "sessionKey=$SessionKey"
}

Write-Host "Target: $uri"
Write-Host ("Selected roles ({0}): {1}" -f $selected.Count, (($selected.Values | ForEach-Object { $_.name }) -join ", "))
Write-Host ""

# --- Create roles -------------------------------------------------------------
$created = 0
$failed  = 0

foreach ($role in $selected.Values) {
    $payload = [ordered]@{
        nodeClass        = $role.nodeClass
        custom           = $true
        nodeRoleParentId = $role.nodeRoleParentId
        name             = $role.name
        chassisType      = "UNKNOWN"
        description      = ""
    }
    $body = $payload | ConvertTo-Json -Compress

    if (-not $PSCmdlet.ShouldProcess($role.name, "POST $uri")) {
        Write-Host "[WhatIf] $($role.name)  ->  $body"
        continue
    }

    $req  = $null
    $resp = $null
    try {
        $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Post, $uri)
        $req.Content = [System.Net.Http.StringContent]::new($body, [System.Text.Encoding]::UTF8, "application/json")
        foreach ($h in $headers.GetEnumerator()) {
            [void]$req.Headers.TryAddWithoutValidation($h.Key, [string]$h.Value)
        }

        $resp = $client.SendAsync($req).GetAwaiter().GetResult()
        $code = [int]$resp.StatusCode

        if ($code -lt 400) {
            # 2xx = created directly, 3xx = created + Location redirect (which we do not follow)
            Write-Host ("[OK {0}] {1}" -f $code, $role.name) -ForegroundColor Green
            $created++
        }
        else {
            $respBody = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            Write-Host ("[ERROR {0}] {1} - {2}" -f $code, $role.name, $respBody) -ForegroundColor Red
            $failed++
        }
    }
    catch {
        Write-Host ("[ERROR] {0} - {1}" -f $role.name, $_.Exception.Message) -ForegroundColor Red
        $failed++
    }
    finally {
        if ($resp) { $resp.Dispose() }
        if ($req)  { $req.Dispose() }
    }
}

Write-Host ""
Write-Host ("Done. Created: {0}, Failed: {1}" -f $created, $failed)
if ($failed -gt 0) { exit 1 }
