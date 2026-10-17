<#
.SYNOPSIS
    Creates custom NinjaOne node roles via the internal /swb/s6/noderole endpoint -
    parameter-driven selection of which roles to create.

.DESCRIPTION
    Authenticates with an existing browser session cookie (sessionKey) and sends a POST to
    https://<region>.ninjarmm.com/swb/s6/noderole for each selected role.

    The -Roles parameter controls what gets created. Pass a group keyword (e.g. 'server-all')
    or select individual roles by short key (e.g. datev,sql).

    Windows Server roles (under parent WINDOWS_SERVER, nodeRoleParentId = 1):
        datev            Windows Server - DATEV
        sql              Windows Server - SQL Server
        terminal         Windows Server - Terminal Server
        application      Windows Server - Application Server
        file             Windows Server - File Server
        testserver       Windows Server - Test Server

    Windows Workstation roles (under parent WINDOWS_WORKSTATION, nodeRoleParentId = 2):
        homeoffice       Workstation - Home Office
        vip              Workstation - VIP
        testworkstation  Workstation - Test Workstation

    Group keywords:
        server-all       -> datev, sql, terminal, application, file
        workstation-all  -> homeoffice, vip
        testlab          -> testserver, testworkstation

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

# Catalog of all known roles. Key = short key for -Roles.
# nodeRoleParentId is the id of the built-in parent role this custom role hangs under:
#   1 = WINDOWS_SERVER, 2 = WINDOWS_WORKSTATION (confirmed via GET /swb/s6/noderole/list).
$RoleCatalog = [ordered]@{
    # Windows Server roles (under built-in WINDOWS_SERVER, id 1)
    datev           = @{ name = "Windows Server - DATEV";             nodeClass = "WINDOWS_SERVER";      nodeRoleParentId = 1 }
    sql             = @{ name = "Windows Server - SQL Server";        nodeClass = "WINDOWS_SERVER";      nodeRoleParentId = 1 }
    terminal        = @{ name = "Windows Server - Terminal Server";   nodeClass = "WINDOWS_SERVER";      nodeRoleParentId = 1 }
    application     = @{ name = "Windows Server - Application Server"; nodeClass = "WINDOWS_SERVER";      nodeRoleParentId = 1 }
    file            = @{ name = "Windows Server - File Server";        nodeClass = "WINDOWS_SERVER";      nodeRoleParentId = 1 }
    testserver      = @{ name = "Windows Server - Test Server";        nodeClass = "WINDOWS_SERVER";      nodeRoleParentId = 1 }

    # Windows Workstation roles (under built-in WINDOWS_WORKSTATION, id 2)
    homeoffice      = @{ name = "Workstation - Home Office";           nodeClass = "WINDOWS_WORKSTATION"; nodeRoleParentId = 2 }
    vip             = @{ name = "Workstation - VIP";                   nodeClass = "WINDOWS_WORKSTATION"; nodeRoleParentId = 2 }
    testworkstation = @{ name = "Workstation - Test Workstation";      nodeClass = "WINDOWS_WORKSTATION"; nodeRoleParentId = 2 }

    # --- Coming later: macOS and Linux roles ----------------------------------
    # No role names decided yet. The parent ids are already known from
    # GET /swb/s6/noderole/list, so adding a role later is a one-liner - uncomment
    # and rename. Pattern: a custom role's nodeRoleParentId = id of its built-in parent.
    #   <key> = @{ name = "Linux Server - NGINX"; nodeClass = "LINUX_SERVER";      nodeRoleParentId = 21 }
    #   <key> = @{ name = "Linux - Kiosk";        nodeClass = "LINUX_WORKSTATION"; nodeRoleParentId = 3  }
    #   <key> = @{ name = "Mac - Design";         nodeClass = "MAC";               nodeRoleParentId = 4  }
    #   <key> = @{ name = "Mac Server - CI";      nodeClass = "MAC_SERVER";        nodeRoleParentId = 22 }
}

# Group keywords that expand to multiple roles.
$RoleGroups = @{
    "server-all"      = @("datev", "sql", "terminal", "application", "file")
    "workstation-all" = @("homeoffice", "vip")
    "testlab"         = @("testserver", "testworkstation")
    # Coming later, once macOS / Linux roles exist:
    # "mac-all"       = @(...)
    # "linux-all"     = @(...)
}

# --- Resolve role selection ---------------------------------------------------
$selected = [System.Collections.Specialized.OrderedDictionary]::new()
foreach ($token in $Roles) {
    $key = $token.Trim().ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($key)) { continue }

    if ($RoleGroups.ContainsKey($key)) {
        foreach ($member in $RoleGroups[$key]) {
            if (-not $selected.Contains($member)) { $selected.Add($member, $RoleCatalog[$member]) }
        }
    }
    elseif ($RoleCatalog.Contains($key)) {
        if (-not $selected.Contains($key)) { $selected.Add($key, $RoleCatalog[$key]) }
    }
    else {
        $valid = (@($RoleGroups.Keys) + @($RoleCatalog.Keys)) -join ", "
        throw "Unknown role '$token'. Valid values: $valid"
    }
}

if ($selected.Count -eq 0) {
    throw "No roles selected."
}

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
