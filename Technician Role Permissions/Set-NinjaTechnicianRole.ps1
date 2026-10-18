<#
.SYNOPSIS
    Sets the permission set of a NinjaOne technician role in one run - ships a least-privilege
    "1st Level Support" permission profile and applies it with a single PUT.

.DESCRIPTION
    Talks to the internal /swb/s6/user-roles/{id} endpoint the web UI uses, authenticated with a
    short-lived browser session cookie (sessionKey). The technician role permission model is a
    flat list of grants - each entry is { entityId, entityType, name, allowed }. An access level
    like "View, run" is NOT a single enum value; it decomposes into one entry per capability
    (a "View" entry AND a "Run" entry). Multi-selects (remote tools, remote access apps) are one
    entry each (e.g. RemoteTools.TaskManager.Access).

    The role is saved with PUT /swb/s6/user-roles/{id} and the ENTIRE permission list is replaced
    on every save (there is no partial PATCH). So the script first GETs the role to preserve its
    name / type / description / members, then PUTs those back together with the desired permission
    set. Role-type default grants (e.g. "View and add public comments") are implied by the role
    type and are intentionally NOT stored, so they do not appear in the list.

    The built-in $Profiles catalog holds the "1st Level Support" permission set captured from the
    web UI. Adjust that catalog (or add another named profile) to change what gets applied - no
    other code changes needed.

    Idempotent and -WhatIf-safe: if the role already carries exactly the desired grants the PUT is
    skipped, and -WhatIf prints the add/remove diff without sending anything.

    The sessionKey is a short-lived session cookie from a logged-in browser session. Once it
    expires you get 401/403 back - sign in again in the browser and pass the current value.

.PARAMETER RoleId
    The numeric id of an EXISTING technician role to configure. Default: 8 (the "1st Level
    Support" role). Find it in the role editor URL: #/editor/role/<id>/permissions/...
    Use this to update a role you already know by id.

.PARAMETER RoleName
    Target a technician role BY NAME. The script lists the technician roles and, if a role with
    this exact name exists, updates it; if none exists, it CREATES a new technician role with
    this name (POST) and then applies the profile. Use this to create-or-update in one run.

.PARAMETER Description
    Description for a role created via -RoleName (ignored when updating an existing role).
    Default: empty.

.PARAMETER ProfileName
    Which permission profile from the built-in catalog to apply. Default: "1st-level-support".

.PARAMETER SessionKey
    The sessionKey cookie value from the logged-in NinjaOne browser session.
    If omitted, the script reads the NINJA_SESSION_KEY environment variable.
    The key is intentionally NOT stored in the script (secret).

.PARAMETER Region
    The NinjaOne instance subdomain (e.g. 'eu', 'app', 'us2'). Default: eu.

.PARAMETER WhatIf
    Shows the add/remove diff without sending the PUT.

.EXAMPLE
    $env:NINJA_SESSION_KEY = "<sessionKey-from-browser>"
    .\Set-NinjaTechnicianRole.ps1
    Applies the "1st Level Support" permission profile to role id 8.

.EXAMPLE
    .\Set-NinjaTechnicianRole.ps1 -RoleId 8 -WhatIf
    Dry run: shows which grants would be added / removed, sends nothing.

.EXAMPLE
    .\Set-NinjaTechnicianRole.ps1 -RoleId 12 -SessionKey "<value>" -Region app
    Applies the profile to role id 12 on a different instance with a one-off session key.

.EXAMPLE
    .\Set-NinjaTechnicianRole.ps1 -RoleName "1st Level Support" -Description "L1 helpdesk"
    Creates a technician role named "1st Level Support" (if it does not exist yet) and applies
    the profile - or updates it in place if a role with that name already exists.
#>

[CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = "ById")]
param(
    [Parameter(Position = 0, ParameterSetName = "ById")]
    [int] $RoleId = 8,

    [Parameter(Mandatory, ParameterSetName = "ByName")]
    [ValidateNotNullOrEmpty()]
    [string] $RoleName,

    [Parameter(ParameterSetName = "ByName")]
    [string] $Description = "",

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $ProfileName = "1st-level-support",

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

# =============================================================================
# Permission profiles (single source of truth for what each role should carry)
# =============================================================================
# Each grant is "<ENTITY_TYPE>|<name>". On save every grant becomes the object
#   { entityId = 0, entityType = <type>, name = <name>, allowed = $true }
# An access level maps to one grant per capability it includes, e.g.
#   "View, run"  -> NODE|View  +  NODE|Run
# A multi-select option is one grant, e.g. a single allowed remote tool:
#   NODE|RemoteTools.TaskManager.Access
#
# The "1st-level-support" set below is a least-privilege 1st Level Support profile:
#   - Devices:    view + run, core remote troubleshooting tools, screen-sharing apps
#   - Org/Policy: read-only (see structure and which policy applies, no edits)
#   - Scripts:    view + run approved automations (no create/delete)
#   - Ticketing:  create/view/update tickets, comments history, relations, mobile
#                 (NO administrative actions: boards, triggers, SLAs stay with L2/admins)
#   - Docs:       read knowledge base, org documentation and templates
#   - ITAM:       read software licenses and asset fields
#   - System:     use the mobile app, view contacts, view & schedule reports
$Profiles = [ordered]@{
    "1st-level-support" = @(
        # --- Devices (entityType NODE) ---------------------------------------
        "NODE|View"                                 # Default Access: View
        "NODE|Run"                                  # Default Access: run
        "NODE|RemoteTools.TaskManager.Access"       # Remote Tools: Task Manager
        "NODE|RemoteTools.FileExplorer.Access"      # Remote Tools: File Explorer
        "NODE|RemoteTools.CommandLine.Access"       # Remote Tools: Command Line
        "NODE|RemoteTools.ServicesManager.Access"   # Remote Tools: Services Manager
        "NODE|RemoteAccess.Splashtop.Access"        # Remote Access: Splashtop
        "NODE|RemoteAccess.NinjaConnect.Access"     # Remote Access: NinjaOne Remote

        # --- Organizations (read-only) ---------------------------------------
        "ORGANIZATION|View"

        # --- Policies (read-only) --------------------------------------------
        "POLICY|View"

        # --- Automation Library / Script categories (view + run) -------------
        "SCRIPT_CATEGORY|View"
        "SCRIPT_CATEGORY|Run"

        # --- Ticketing -------------------------------------------------------
        "TICKETING|Ticket.View"
        "TICKETING|Ticket.Create"
        "TICKETING|Ticket.Update"
        "TICKETING|Ticketing.Comment.Change.History.View"
        "TICKETING|Ticketing.Relationship.View"
        "TICKETING|Ticketing.Relationship.Manage"
        "TICKETING|Ticketing.Mobile.Access"

        # --- Documentation (read-only) ---------------------------------------
        "DOCUMENTATION|Global.KB.Management.View"
        "DOCUMENTATION|Management.View"
        "DOCUMENTATION|Template.View"

        # --- IT Asset Management (read-only) ---------------------------------
        "ITAM|Itam.SoftwareLicense.View"
        "ITAM|Itam.CoreAssetAttribute.View"

        # --- System ----------------------------------------------------------
        "SYSTEM|MobileApp.Access"
        "SYSTEM|Contact.View"
        "SYSTEM|Reports.ViewSchedule"
    )
}

if (-not $Profiles.Contains($ProfileName)) {
    $valid = ($Profiles.Keys) -join ", "
    throw "Unknown profile '$ProfileName'. Valid values: $valid"
}
$desiredTokens = @($Profiles[$ProfileName])

# Turn "ENTITY|name" tokens into the API permission objects and a lookup set.
$desiredPermissions = foreach ($t in $desiredTokens) {
    $parts = $t.Split("|", 2)
    [ordered]@{ entityId = 0; entityType = $parts[0]; name = $parts[1]; allowed = $true }
}
$desiredSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($t in $desiredTokens) { [void]$desiredSet.Add($t) }

# =============================================================================
# HTTP client
# =============================================================================
$baseUrl       = "https://$Region.ninjarmm.com"
$rolesEndpoint = "$baseUrl/swb/s6/user-roles"
$userAgent     = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36"

# .NET HttpClient with AllowAutoRedirect=$false keeps the session cookie off any http:// redirect
# hop and returns 3xx cleanly (no PS 7.4+ insecure-redirect exception).
try { Add-Type -AssemblyName System.Net.Http -ErrorAction Stop } catch { }
$handler = [System.Net.Http.HttpClientHandler]::new()
$handler.AllowAutoRedirect = $false
$client = [System.Net.Http.HttpClient]::new($handler)

$headers = [ordered]@{
    "accept"           = "application/json, text/plain, */*"
    "accept-language"  = "en-US,en;q=0.9,de-DE;q=0.8,de;q=0.7,fr;q=0.6"
    "content-type"     = "application/json"
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

# Sends one request via HttpClient. Returns @{ Code; Body }.
function Invoke-NinjaApi {
    param(
        [Parameter(Mandatory)] [string] $Method,
        [Parameter(Mandatory)] [string] $Uri,
        [string] $Body
    )
    $req  = $null
    $resp = $null
    try {
        $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::new($Method), $Uri)
        if (-not [string]::IsNullOrEmpty($Body)) {
            $req.Content = [System.Net.Http.StringContent]::new($Body, [System.Text.Encoding]::UTF8, "application/json")
        }
        foreach ($h in $headers.GetEnumerator()) {
            if ($h.Key -eq "content-type") { continue }  # set on the StringContent above
            [void]$req.Headers.TryAddWithoutValidation($h.Key, [string]$h.Value)
        }
        $resp = $client.SendAsync($req).GetAwaiter().GetResult()
        $text = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        return [pscustomobject]@{ Code = [int]$resp.StatusCode; Body = $text }
    }
    finally {
        if ($resp) { $resp.Dispose() }
        if ($req)  { $req.Dispose() }
    }
}

Write-Host "Target: $baseUrl"
Write-Host ("Profile: {0} ({1} grants)" -f $ProfileName, $desiredTokens.Count)
Write-Host ""

# =============================================================================
# Resolve the target role: existing (by id, or found by name) vs. create (by name)
# =============================================================================
# $isCreate drives whether we POST a new role first; $role carries the envelope
# (name/type/description/members) and $currentSet the grants we are diffing against.
$isCreate   = $false
$role       = $null
$currentSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

if ($PSCmdlet.ParameterSetName -eq "ByName") {
    # List technician roles and look for an exact (case-insensitive) name match.
    $listUri  = "$rolesEndpoint`?roleType=TECHNICIAN"
    $listResp = Invoke-NinjaApi -Method "GET" -Uri $listUri
    if ($listResp.Code -ge 400) {
        throw "Could not list technician roles (HTTP $($listResp.Code)). Session key expired? Response: $($listResp.Body)"
    }
    $techRoles   = @($listResp.Body | ConvertFrom-Json)
    $nameMatches = @($techRoles | Where-Object { $_.type -eq "TECHNICIAN" -and $_.name -eq $RoleName })
    if ($nameMatches.Count -gt 1) {
        $ids = ($nameMatches | ForEach-Object { $_.id }) -join ", "
        throw "Found $($nameMatches.Count) technician roles named '$RoleName' (ids: $ids). Target one by -RoleId instead."
    }
    if ($nameMatches.Count -eq 1) {
        $RoleId = [int]$nameMatches[0].id
        Write-Host ("Found existing technician role '{0}' (id {1}) - will update it." -f $RoleName, $RoleId)
    }
    else {
        $isCreate = $true
        Write-Host ("No technician role named '{0}' yet - will create it (POST)." -f $RoleName)
    }
}

if ($isCreate) {
    # Fresh role: no current grants, empty member list, envelope built from the parameters.
    $role = [pscustomobject]@{
        name        = $RoleName
        type        = "TECHNICIAN"
        description = $Description
        members     = @()
    }
}
else {
    # Load the existing role to preserve name/type/description/members and to diff.
    $roleUri = "$rolesEndpoint/$RoleId"
    $getResp = Invoke-NinjaApi -Method "GET" -Uri $roleUri
    if ($getResp.Code -ge 400) {
        throw "Could not load role $RoleId (HTTP $($getResp.Code)). Session key expired or wrong id? Response: $($getResp.Body)"
    }
    $role = $getResp.Body | ConvertFrom-Json

    if ($role.type -ne "TECHNICIAN") {
        throw "Role $RoleId is type '$($role.type)', not TECHNICIAN. Refusing to touch it."
    }

    Write-Host ("Role: '{0}' (id {1}, type {2}, members: {3})" -f $role.name, $RoleId, $role.type, @($role.members).Count)

    # Current grants as an "ENTITY|name" set (only the allowed ones).
    foreach ($p in @($role.permissions)) {
        if ($p.allowed) { [void]$currentSet.Add(("{0}|{1}" -f $p.entityType, $p.name)) }
    }
}

# Diff current -> desired.
$toAdd    = @($desiredTokens | Where-Object { -not $currentSet.Contains($_) } | Sort-Object)
$toRemove = @($currentSet    | Where-Object { -not $desiredSet.Contains($_) } | Sort-Object)

Write-Host ""
Write-Host "== Permission diff =="
if ($toAdd.Count -eq 0 -and $toRemove.Count -eq 0) {
    Write-Host ("[OK] Role already carries exactly the '{0}' profile ({1} grants) - nothing to do." -f $ProfileName, $desiredTokens.Count) -ForegroundColor Green
    Write-Host ""
    Write-Host "Done. Added: 0, Removed: 0 (no change)."
    return
}
if ($toAdd.Count -gt 0) {
    Write-Host ("Grants to ADD ({0}):" -f $toAdd.Count) -ForegroundColor Green
    foreach ($g in $toAdd) { Write-Host ("  + {0}" -f $g) -ForegroundColor Green }
}
if ($toRemove.Count -gt 0) {
    Write-Host ("Grants to REMOVE ({0}):" -f $toRemove.Count) -ForegroundColor Yellow
    foreach ($g in $toRemove) { Write-Host ("  - {0}" -f $g) -ForegroundColor Yellow }
}
Write-Host ""

# =============================================================================
# Apply: (create the role first if needed) then PUT the full role with the grants
# =============================================================================
# Save is a full replace: the PUT carries the entire role envelope (name/type/description/
# members) and the desired permission set. members are round-tripped untouched so we never
# deassign anyone. A create is two steps: POST an empty role to mint the id, then PUT the grants
# (POSTing permissions inline is not a verified contract, so we keep the two calls separate).
$action = if ($isCreate) {
    "CREATE technician role '{0}' then PUT {1} grants" -f $role.name, $desiredTokens.Count
} else {
    "PUT {0} grants (add {1}, remove {2})" -f $desiredTokens.Count, $toAdd.Count, $toRemove.Count
}

if ($PSCmdlet.ShouldProcess($role.name, $action)) {
    if ($isCreate) {
        # Mint the role with an empty permission list; the body of the response is the new id.
        $createBody = [ordered]@{
            name              = $role.name
            type              = $role.type
            description       = $role.description
            permissions       = @()
            members           = @()
            globalPermissions = @()
        } | ConvertTo-Json -Depth 10 -Compress

        $cr = Invoke-NinjaApi -Method "POST" -Uri $rolesEndpoint -Body $createBody
        if ($cr.Code -ge 400) {
            Write-Host ("[ERROR {0}] Create (POST) failed - {1}" -f $cr.Code, $cr.Body) -ForegroundColor Red
            exit 1
        }
        $newId = ($cr.Body).Trim().Trim('"')
        if ($newId -notmatch '^\d+$') {
            throw "Create succeeded (HTTP $($cr.Code)) but the response was not a role id: '$($cr.Body)'."
        }
        $RoleId = [int]$newId
        Write-Host ("[OK {0}] Created technician role '{1}' (id {2})." -f $cr.Code, $role.name, $RoleId) -ForegroundColor Green
    }

    $roleUri = "$rolesEndpoint/$RoleId"
    $payload = [ordered]@{
        name              = $role.name
        type              = $role.type
        description       = $role.description
        permissions       = @($desiredPermissions)
        members           = @($role.members)
        globalPermissions = @()
    }
    $body = $payload | ConvertTo-Json -Depth 10 -Compress

    $r = Invoke-NinjaApi -Method "PUT" -Uri $roleUri -Body $body
    if ($r.Code -lt 400) {
        $verb = if ($isCreate) { "Created and applied" } else { "Applied" }
        Write-Host ("[OK {0}] {1} '{2}' profile to role '{3}' (id {4})." -f $r.Code, $verb, $ProfileName, $role.name, $RoleId) -ForegroundColor Green
        Write-Host ""
        Write-Host ("Done. Added: {0}, Removed: {1}, Total grants now: {2}." -f `
            $toAdd.Count, $toRemove.Count, $desiredTokens.Count)
    }
    else {
        Write-Host ("[ERROR {0}] PUT failed - {1}" -f $r.Code, $r.Body) -ForegroundColor Red
        exit 1
    }
}
else {
    if ($isCreate) {
        Write-Host ("[WhatIf] would CREATE technician role '{0}' then PUT {1} grants." -f $role.name, $desiredTokens.Count)
    }
    else {
        Write-Host ("[WhatIf] would PUT {0} grants to role '{1}' (add {2}, remove {3})." -f `
            $desiredTokens.Count, $role.name, $toAdd.Count, $toRemove.Count)
    }
}
