<#
.SYNOPSIS
    One-shot NinjaOne tenant initial setup: creates the custom node roles AND the matching
    policy hierarchy (default-policy naming convention + child policies) in a single run.

.DESCRIPTION
    Talks to the internal /swb/s6/* endpoints the web UI uses, authenticated with a short-lived
    browser session cookie (sessionKey). One -Roles selection drives everything. The script runs
    in three passes:

      Pass 1 - Node roles (only when -Roles is given)
          Creates one custom node role per selected role.
          POST /swb/s6/noderole

      Pass 2 - Default policy naming convention (ALWAYS, regardless of -Roles)
          Renames every built-in default policy to the numbering convention so the whole
          hierarchy stays consistent even for categories without roles:
              Windows Workstation Policy  ->  0.0 Windows Workstation Policy
              Windows Server Policy       ->  1.0 Windows Server Policy
              Mac / Mac Server / Linux / Linux Server -> 2.0 / 3.0 / 4.0 / 5.0 ...
          PATCH /swb/s6/policy/{id}  { name, description, enabled }

      Pass 3 - Child policies (only when -Roles is given)
          Creates one child policy per selected role, inheriting everything from that role's
          default (its parent). Numbering "{major}.{minor}", e.g.:
              1.1 Windows Server Policy - Terminal Server
              1.2 Windows Server Policy - SQL Server    ...
          POST /swb/s6/policy  { enabled, name, nodeClassDefault:false, nodeClass,
                                 description:null, parentPolicyId }

    A child policy links to its parent ONLY via parentPolicyId and inherits the parent's settings;
    it is not tied to the custom node role, so the policy passes do not depend on the role pass.

    Fully idempotent and -WhatIf-safe: existing node roles are skipped, defaults already carrying
    the convention name are left alone, and an already-existing child is skipped. Safe to re-run.

    The sessionKey is a short-lived session cookie from a logged-in browser session. Once it
    expires you get 401/403 back - sign in again in the browser and pass the current value.

.PARAMETER Roles
    Optional. One or more roles to create (node role + child policy). Group keywords
    (server-all, workstation-all, testlab) and/or individual short keys (comma-separated),
    e.g. -Roles server-all,testworkstation. Omit entirely to only enforce the default-policy
    naming convention (Pass 2) without creating any roles or child policies.

.PARAMETER SessionKey
    The sessionKey cookie value from the logged-in NinjaOne browser session.
    If omitted, the script reads the NINJA_SESSION_KEY environment variable.
    The key is intentionally NOT stored in the script (secret).

.PARAMETER Region
    The NinjaOne instance subdomain (e.g. 'eu', 'app', 'us2'). Default: eu.

.PARAMETER WhatIf
    Shows what would be created/renamed without sending anything.

.EXAMPLE
    $env:NINJA_SESSION_KEY = "<sessionKey-from-browser>"
    .\Initialize-NinjaTenant.ps1 -Roles server-all
    Creates the five Windows Server node roles, renames every default policy to the convention,
    and creates one child policy per server role (1.1 .. 1.5).

.EXAMPLE
    .\Initialize-NinjaTenant.ps1
    No roles: only renames every built-in default policy to the convention (0.0, 1.0, 2.0, ...).

.EXAMPLE
    .\Initialize-NinjaTenant.ps1 -Roles sql,terminal -WhatIf
    Dry run: shows the two node roles, the renames and the two child policies that would be made.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    # Optional: if omitted, only the default-policy naming convention (Pass 2) runs.
    [Parameter(Position = 0)]
    [string[]] $Roles = @(),

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
# Role catalog (single source of truth for roles, groups and policy naming)
# =============================================================================
# nodeRoleParentId is the id of the built-in parent role a custom role hangs under
# (confirmed via GET /swb/s6/noderole/list): 1 = WINDOWS_SERVER, 2 = WINDOWS_WORKSTATION.
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
    # No role names decided yet. Parent ids are already known from
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

# Per-category policy metadata:
#   major          - the major number in the policy naming convention ("{major}.0 ...")
#   policyBaseName - target base name of the default policy after renaming; also reused in
#                    child policy names ("{major}.{minor} {base} - {role}")
#   rolePrefix     - prefix stripped off a role's name to get the short label used in the
#                    child policy name ("Windows Server - Terminal Server" -> "Terminal Server")
$CategoryMeta = [ordered]@{
    WINDOWS_WORKSTATION = @{ major = 0; policyBaseName = "Windows Workstation Policy"; rolePrefix = "Workstation - " }
    WINDOWS_SERVER      = @{ major = 1; policyBaseName = "Windows Server Policy";      rolePrefix = "Windows Server - " }
    MAC                 = @{ major = 2; policyBaseName = "Mac Policy";                 rolePrefix = "Mac - " }
    MAC_SERVER          = @{ major = 3; policyBaseName = "Mac Server Policy";          rolePrefix = "Mac Server - " }
    LINUX_WORKSTATION   = @{ major = 4; policyBaseName = "Linux Policy";               rolePrefix = "Linux - " }
    LINUX_SERVER        = @{ major = 5; policyBaseName = "Linux Server Policy";        rolePrefix = "Linux Server - " }
}

# Resolve a -Roles selection into an ordered map of key -> catalog entry.
# Expands group keywords, deduplicates, preserves order, throws on unknown keys.
function Resolve-NinjaRoleSelection {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [string[]] $Roles)

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
    if ($selected.Count -eq 0) { throw "No roles selected." }
    return $selected
}

# --- Resolve role selection (optional) ----------------------------------------
$cleanRoles   = @($Roles | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
$hasSelection = $cleanRoles.Count -gt 0
$selected     = if ($hasSelection) { Resolve-NinjaRoleSelection -Roles $cleanRoles } else { $null }

# =============================================================================
# HTTP client
# =============================================================================
$baseUrl         = "https://$Region.ninjarmm.com"
$noderoleUri     = "$baseUrl/swb/s6/noderole"
$noderoleListUri = "$baseUrl/swb/s6/noderole/list?allRoles=true"
$policyUri       = "$baseUrl/swb/s6/policy"
$policyListUri   = "$baseUrl/swb/s6/policy/list"
$userAgent       = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36"

# .NET HttpClient with AllowAutoRedirect=$false: the create POSTs answer with a redirect to an
# http:// URL. Not following it returns the 3xx status cleanly (no PS 7.4+ insecure-redirect
# exception) and keeps the session cookie off the unencrypted hop.
try { Add-Type -AssemblyName System.Net.Http -ErrorAction Stop } catch { }
$handler = [System.Net.Http.HttpClientHandler]::new()
$handler.AllowAutoRedirect = $false
$client = [System.Net.Http.HttpClient]::new($handler)

$headers = [ordered]@{
    "accept"           = "application/json, text/plain, */*"
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
if ($hasSelection) {
    Write-Host ("Selected roles ({0}): {1}" -f $selected.Count, (($selected.Values | ForEach-Object { $_.name }) -join ", "))
}
else {
    Write-Host "No roles selected - enforcing the policy naming convention only."
}
Write-Host ""

# --- Counters & result lists --------------------------------------------------
$rolesCreated = 0
$renamed      = 0
$created      = 0
$skipped      = 0
$failed       = 0
$rolesCreatedNames = [System.Collections.Generic.List[string]]::new()  # created node roles
$renamedNames      = [System.Collections.Generic.List[string]]::new()  # renamed default policies
$createdNames      = [System.Collections.Generic.List[string]]::new()  # created child policies

# =============================================================================
# Pass 1: create custom node roles (only when -Roles is given)
# =============================================================================
if ($hasSelection) {
    Write-Host "== Node roles =="

    $roleListResp = Invoke-NinjaApi -Method "GET" -Uri $noderoleListUri
    if ($roleListResp.Code -ge 400) {
        throw "Could not load node role list (HTTP $($roleListResp.Code)). Session key expired? Response: $($roleListResp.Body)"
    }
    $existingRoles = @($roleListResp.Body | ConvertFrom-Json)

    foreach ($role in $selected.Values) {
        $exists = $existingRoles | Where-Object {
            $_.name -eq $role.name -and $_.nodeClass -eq $role.nodeClass
        } | Select-Object -First 1
        if ($exists) {
            Write-Host ("[SKIP] node role already exists: '{0}'" -f $role.name) -ForegroundColor Yellow
            $skipped++
            continue
        }

        $rolePayload = [ordered]@{
            nodeClass        = $role.nodeClass
            custom           = $true
            nodeRoleParentId = $role.nodeRoleParentId
            name             = $role.name
            chassisType      = "UNKNOWN"
            description      = ""
        } | ConvertTo-Json -Compress

        if ($PSCmdlet.ShouldProcess($role.name, "POST $noderoleUri")) {
            $r = Invoke-NinjaApi -Method "POST" -Uri $noderoleUri -Body $rolePayload
            if ($r.Code -lt 400) {
                Write-Host ("[OK {0}] node role {1}" -f $r.Code, $role.name) -ForegroundColor Green
                $rolesCreatedNames.Add($role.name)
                $rolesCreated++
            }
            else {
                Write-Host ("[ERROR {0}] node role {1} - {2}" -f $r.Code, $role.name, $r.Body) -ForegroundColor Red
                $failed++
            }
        }
        else {
            Write-Host ("[WhatIf] create node role '{0}'" -f $role.name)
        }
    }
    Write-Host ""
}

# =============================================================================
# Load current policies (needed for passes 2 and 3)
# =============================================================================
$policyListResp = Invoke-NinjaApi -Method "GET" -Uri $policyListUri
if ($policyListResp.Code -ge 400) {
    throw "Could not load policy list (HTTP $($policyListResp.Code)). Session key expired? Response: $($policyListResp.Body)"
}
$allPolicies = $policyListResp.Body | ConvertFrom-Json

# =============================================================================
# Pass 2: enforce the naming convention on ALL default policies (always)
# =============================================================================
Write-Host "== Default policy naming convention =="
foreach ($nodeClass in $CategoryMeta.Keys) {
    $meta = $CategoryMeta[$nodeClass]

    $default = $allPolicies | Where-Object { $_.nodeClass -eq $nodeClass -and $_.nodeClassDefault -eq $true } | Select-Object -First 1
    if (-not $default) {
        Write-Host ("[WARN] No default policy found for nodeClass '{0}' - skipping." -f $nodeClass) -ForegroundColor Yellow
        continue
    }

    $desiredDefaultName = "{0}.0 {1}" -f $meta.major, $meta.policyBaseName

    if ($default.name -eq $desiredDefaultName) {
        Write-Host ("[OK] already named '{0}'" -f $desiredDefaultName) -ForegroundColor DarkGray
        continue
    }

    $renameBody = [ordered]@{
        name        = $desiredDefaultName
        description = $default.description
        enabled     = $default.enabled
    } | ConvertTo-Json -Compress

    if ($PSCmdlet.ShouldProcess($default.name, "PATCH rename -> '$desiredDefaultName'")) {
        $r = Invoke-NinjaApi -Method "PATCH" -Uri ("{0}/{1}" -f $policyUri, $default.id) -Body $renameBody
        if ($r.Code -lt 400) {
            Write-Host ("[RENAMED {0}] '{1}' -> '{2}'" -f $r.Code, $default.name, $desiredDefaultName) -ForegroundColor Cyan
            $default.name = $desiredDefaultName   # keep in-memory copy current for pass 3
            $renamedNames.Add($desiredDefaultName)
            $renamed++
        }
        else {
            Write-Host ("[ERROR {0}] rename '{1}' - {2}" -f $r.Code, $default.name, $r.Body) -ForegroundColor Red
            $failed++
        }
    }
    else {
        Write-Host ("[WhatIf] rename '{0}' -> '{1}'" -f $default.name, $desiredDefaultName)
    }
}
Write-Host ""

# =============================================================================
# Pass 3: one child policy per selected role (only when -Roles is given)
# =============================================================================
if ($hasSelection) {
    Write-Host "== Child policies for selected roles =="
    foreach ($nodeClass in $CategoryMeta.Keys) {
        $rolesInClass = @($selected.Values | Where-Object { $_.nodeClass -eq $nodeClass })
        if ($rolesInClass.Count -eq 0) { continue }

        $meta = $CategoryMeta[$nodeClass]

        $default = $allPolicies | Where-Object { $_.nodeClass -eq $nodeClass -and $_.nodeClassDefault -eq $true } | Select-Object -First 1
        if (-not $default) {
            Write-Host ("[ERROR] No default policy found for nodeClass '{0}' - cannot create its child policies." -f $nodeClass) -ForegroundColor Red
            $failed += $rolesInClass.Count
            continue
        }

        # Existing children of this default (to dedupe and to continue the minor numbering).
        $children = @($allPolicies | Where-Object { $_.parentPolicyId -eq $default.id })

        $minorPattern = "^{0}\.(\d+)\s" -f $meta.major
        $maxMinor = 0
        foreach ($c in $children) {
            $m = [regex]::Match($c.name, $minorPattern)
            if ($m.Success) {
                $n = [int]$m.Groups[1].Value
                if ($n -gt $maxMinor) { $maxMinor = $n }
            }
        }
        $nextMinor = $maxMinor + 1

        foreach ($role in $rolesInClass) {
            $roleShort = $role.name
            if ($roleShort.StartsWith($meta.rolePrefix)) {
                $roleShort = $roleShort.Substring($meta.rolePrefix.Length)
            }
            $suffix = " - $roleShort"

            $existing = $children | Where-Object { $_.name.EndsWith($suffix, [System.StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 1
            if ($existing) {
                Write-Host ("[SKIP] child for '{0}' already exists: '{1}'" -f $roleShort, $existing.name) -ForegroundColor Yellow
                $skipped++
                continue
            }

            $childName = "{0}.{1} {2}{3}" -f $meta.major, $nextMinor, $meta.policyBaseName, $suffix
            $createBody = [ordered]@{
                enabled          = $true
                name             = $childName
                nodeClassDefault = $false
                nodeClass        = $nodeClass
                description      = $null
                parentPolicyId   = $default.id
            } | ConvertTo-Json -Compress

            if ($PSCmdlet.ShouldProcess($childName, "POST create child (parent $($default.id))")) {
                $r = Invoke-NinjaApi -Method "POST" -Uri $policyUri -Body $createBody
                if ($r.Code -lt 400) {
                    Write-Host ("[OK {0}] {1}" -f $r.Code, $childName) -ForegroundColor Green
                    $createdNames.Add($childName)
                    $created++
                    $nextMinor++
                }
                else {
                    Write-Host ("[ERROR {0}] {1} - {2}" -f $r.Code, $childName, $r.Body) -ForegroundColor Red
                    $failed++
                }
            }
            else {
                Write-Host ("[WhatIf] create '{0}'  (parent {1})" -f $childName, $default.id)
                $nextMinor++
            }
        }
    }
    Write-Host ""
}

# =============================================================================
# Summary
# =============================================================================
Write-Host "== Summary =="
if ($rolesCreatedNames.Count -gt 0) {
    Write-Host ("Created node roles ({0}):" -f $rolesCreatedNames.Count)
    foreach ($n in $rolesCreatedNames) { Write-Host ("  - {0}" -f $n) }
}
if ($renamedNames.Count -gt 0) {
    Write-Host ("Renamed default policies ({0}):" -f $renamedNames.Count)
    foreach ($n in $renamedNames) { Write-Host ("  - {0}" -f $n) }
}
if ($createdNames.Count -gt 0) {
    Write-Host ("Created child policies ({0}):" -f $createdNames.Count)
    foreach ($n in $createdNames) { Write-Host ("  - {0}" -f $n) }
}
if ($rolesCreatedNames.Count -eq 0 -and $renamedNames.Count -eq 0 -and $createdNames.Count -eq 0) {
    Write-Host "Nothing changed - everything already matched the convention."
}
Write-Host ""
Write-Host ("Done. Node roles: {0}, Renamed: {1}, Child policies: {2}, Skipped: {3}, Failed: {4}" -f `
    $rolesCreated, $renamed, $created, $skipped, $failed)
if ($failed -gt 0) { exit 1 }
