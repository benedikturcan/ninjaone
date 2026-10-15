<#
.SYNOPSIS
    Erstellt benutzerdefinierte NinjaOne Node-Rollen (node roles) ueber den internen
    /swb/s6/noderole Endpunkt - gesteuert ueber Parameter, welche Rollen angelegt werden.

.DESCRIPTION
    Das Skript authentifiziert sich mit einem bestehenden Browser-Session-Cookie (sessionKey)
    und sendet fuer jede ausgewaehlte Rolle einen POST an https://<region>.ninjarmm.com/swb/s6/noderole.

    Welche Rollen angelegt werden, bestimmt der Parameter -Roles. Du kannst entweder das
    Sammel-Keyword 'server-all' angeben (legt alle Windows-Server-Rollen an) oder einzelne
    Rollen selektiv per Kurzschluessel waehlen (z.B. datev,sql).

    Verfuegbare Windows-Server-Rollen (alle unter Parent WINDOWS_SERVER, nodeRoleParentId = 1):
        datev         Windows Server - DATEV
        sql           Windows Server - SQL Server
        terminal      Windows Server - Terminal Server
        application   Windows Server - Application Server
        file          Windows Server - File Server

    Der sessionKey ist ein kurzlebiges Session-Cookie aus einer angemeldeten Browser-Sitzung.
    Laeuft er ab, bekommst du 401/403 zurueck - dann im Browser neu anmelden und den aktuellen
    Cookie-Wert uebergeben.

.PARAMETER Roles
    Eine oder mehrere Rollen, die angelegt werden sollen. Akzeptiert:
        server-all                          -> alle Windows-Server-Rollen
        datev, sql, terminal, application, file  -> einzelne Rollen (kommagetrennt)

.PARAMETER SessionKey
    Der sessionKey Cookie-Wert aus der angemeldeten NinjaOne Browser-Sitzung.
    Wird kein Wert uebergeben, liest das Skript die Umgebungsvariable NINJA_SESSION_KEY.
    Der Schluessel wird bewusst NICHT im Skript hinterlegt (Secret).

.PARAMETER Region
    Die NinjaOne Instanz-Subdomain (z.B. 'eu', 'app', 'us2'). Default: eu.

.PARAMETER WhatIf
    Zeigt nur an, was gesendet wuerde, ohne den POST tatsaechlich auszufuehren.

.EXAMPLE
    .\New-NinjaNodeRole.ps1 -Roles server-all
    Legt alle fuenf Windows-Server-Rollen an.

.EXAMPLE
    .\New-NinjaNodeRole.ps1 -Roles datev,sql
    Legt nur "Windows Server - DATEV" und "Windows Server - SQL Server" an.

.EXAMPLE
    .\New-NinjaNodeRole.ps1 -Roles server-all -WhatIf
    Trockenlauf: zeigt die geplanten Requests, sendet aber nichts.

.EXAMPLE
    $env:NINJA_SESSION_KEY = "<sessionKey-aus-dem-browser>"
    .\New-NinjaNodeRole.ps1 -Roles sql,terminal
    Session-Key ueber die Umgebungsvariable setzen, dann selektiv Rollen anlegen.
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
    throw "Kein Session-Key. Setze `$env:NINJA_SESSION_KEY oder uebergib -SessionKey '<wert>'."
}

# Katalog aller bekannten Rollen. Key = Kurzschluessel fuer -Roles.
$RoleCatalog = [ordered]@{
    datev       = @{ name = "Windows Server - DATEV";              nodeClass = "WINDOWS_SERVER"; nodeRoleParentId = 1 }
    sql         = @{ name = "Windows Server - SQL Server";         nodeClass = "WINDOWS_SERVER"; nodeRoleParentId = 1 }
    terminal    = @{ name = "Windows Server - Terminal Server";    nodeClass = "WINDOWS_SERVER"; nodeRoleParentId = 1 }
    application = @{ name = "Windows Server - Application Server";  nodeClass = "WINDOWS_SERVER"; nodeRoleParentId = 1 }
    file        = @{ name = "Windows Server - File Server";        nodeClass = "WINDOWS_SERVER"; nodeRoleParentId = 1 }
}

# Sammel-Keywords, die auf mehrere Rollen expandieren.
$RoleGroups = @{
    "server-all" = @("datev", "sql", "terminal", "application", "file")
}

# --- Rollen-Auswahl aufloesen -------------------------------------------------
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
        throw "Unbekannte Rolle '$token'. Gueltige Werte: $valid"
    }
}

if ($selected.Count -eq 0) {
    throw "Keine Rollen ausgewaehlt."
}

# --- HTTP-Session vorbereiten -------------------------------------------------
$baseUrl = "https://$Region.ninjarmm.com"
$uri     = "$baseUrl/swb/s6/noderole"

$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$session.UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36"
$session.Cookies.Add((New-Object System.Net.Cookie("sessionKey", $SessionKey, "/", "$Region.ninjarmm.com")))

$headers = @{
    "accept"           = "*/*"
    "accept-language"  = "en-US,en;q=0.9,de-DE;q=0.8,de;q=0.7,fr;q=0.6"
    "origin"           = $baseUrl
    "referer"          = "$baseUrl/"
    "sec-ch-ua"        = '"Google Chrome";v="155", "Chromium";v="155", "Not(A:Brand";v="24"'
    "sec-ch-ua-mobile" = "?0"
    "sec-fetch-dest"   = "empty"
    "sec-fetch-mode"   = "cors"
    "sec-fetch-site"   = "same-origin"
}

Write-Host "Ziel: $uri"
Write-Host ("Ausgewaehlte Rollen ({0}): {1}" -f $selected.Count, (($selected.Values | ForEach-Object { $_.name }) -join ", "))
Write-Host ""

# --- Rollen anlegen -----------------------------------------------------------
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

    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri $uri -Method POST `
            -WebSession $session -Headers $headers -ContentType "application/json" -Body $body

        Write-Host ("[OK {0}] {1}" -f $response.StatusCode, $role.name) -ForegroundColor Green
        $created++
    }
    catch {
        $status = $null
        if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
        Write-Host ("[FEHLER {0}] {1} - {2}" -f $status, $role.name, $_.Exception.Message) -ForegroundColor Red
        $failed++
    }
}

Write-Host ""
Write-Host ("Fertig. Erstellt: {0}, Fehlgeschlagen: {1}" -f $created, $failed)
if ($failed -gt 0) { exit 1 }
