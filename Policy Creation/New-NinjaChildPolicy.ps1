<#
.SYNOPSIS
    Creates NinjaOne child policies for selected device roles via the internal /swb/s6/policy
    endpoint, and enforces the policy naming convention on the built-in default policies.

.DESCRIPTION
    Companion to New-NinjaNodeRole.ps1. The script runs in two passes:

      Pass 1 - Naming convention on ALL built-in default policies (always, regardless of
      -Roles, so the whole hierarchy stays consistent). Idempotent rename:
             Windows Workstation Policy  ->  0.0 Windows Workstation Policy
             Windows Server Policy       ->  1.0 Windows Server Policy
             Mac Policy / Mac Server / Linux Policy / Linux Server -> 2.0 / 3.0 / 4.0 / 5.0 ...
         Rename:  PATCH /swb/s6/policy/{id}  { name, description, enabled }

      Pass 2 - One child policy per selected role, inheriting everything from that role's
      default (its parent). Only runs for the roles you pass in -Roles:
             1.1 Windows Server Policy - Terminal Server
             1.2 Windows Server Policy - SQL Server    ...
         Create:  POST /swb/s6/policy  { enabled, name, nodeClassDefault:false, nodeClass,
                                         description:null, parentPolicyId }

    Pass the SAME -Roles selection you used to create the node roles. Omit -Roles entirely to
    run only Pass 1 (enforce the naming convention without creating any child policies).

    Numbering: the default policy is "{major}.0", child policies get "{major}.{minor}" with
    minor counting up per category. The major number and base name per category live in
    $CategoryMeta in the shared Shared/NinjaRoleCatalog.ps1.

    Idempotent: default policies already carrying the convention name are left alone, and a
    child whose role already exists under the parent is skipped. Safe to re-run.

    The sessionKey is a short-lived session cookie from a logged-in browser session. Once it
    expires you get 401/403 back - sign in again in the browser and pass the current value.

.PARAMETER Roles
    Optional. One or more roles to create child policies for. Same values as New-NinjaNodeRole.ps1:
    group keywords (server-all, workstation-all, testlab) and/or individual short keys
    (comma-separated), e.g. -Roles server-all,testworkstation. If omitted, only the default-policy
    naming convention (Pass 1) is applied.

.PARAMETER SessionKey
    The sessionKey cookie value from the logged-in NinjaOne browser session.
    If omitted, the script reads the NINJA_SESSION_KEY environment variable.

.PARAMETER Region
    The NinjaOne instance subdomain (e.g. 'eu', 'app', 'us2'). Default: eu.

.PARAMETER WhatIf
    Shows the planned renames and child-policy creates without sending anything.

.EXAMPLE
    .\New-NinjaChildPolicy.ps1 -Roles server-all
    Renames the Windows Server default to "1.0 Windows Server Policy" and creates one child
    policy per selected server role (1.1, 1.2, ...).

.EXAMPLE
    .\New-NinjaChildPolicy.ps1 -Roles terminal,sql -WhatIf
    Dry run: shows the rename + the two child policies that would be created.

.EXAMPLE
    .\New-NinjaChildPolicy.ps1
    No roles: only renames every built-in default policy to the naming convention
    (0.0, 1.0, 2.0, 3.0, 4.0, 5.0) and creates no child policies.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    # Optional: if omitted, the script still enforces the naming convention on ALL default
    # policies but creates no child policies.
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

# --- Shared role catalog ------------------------------------------------------
# Defines $RoleCatalog, $RoleGroups, $CategoryMeta and Resolve-NinjaRoleSelection.
# Path built without literal separators so it works on Windows and macOS/Linux alike.
$catalogPath = Join-Path (Join-Path (Split-Path -Parent $PSScriptRoot) "Shared") "NinjaRoleCatalog.ps1"
if (-not (Test-Path $catalogPath)) {
    throw "Shared catalog not found at '$catalogPath'. Expected a 'Shared/NinjaRoleCatalog.ps1' next to this script's folder."
}
. $catalogPath

# --- Resolve role selection (optional) ----------------------------------------
# $Roles may be empty: then we only enforce the naming convention on the defaults.
$cleanRoles = @($Roles | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
$hasSelection = $cleanRoles.Count -gt 0
$selected = if ($hasSelection) { Resolve-NinjaRoleSelection -Roles $cleanRoles } else { $null }

# --- Prepare HTTP client ------------------------------------------------------
$baseUrl    = "https://$Region.ninjarmm.com"
$policyUri  = "$baseUrl/swb/s6/policy"
$listUri    = "$baseUrl/swb/s6/policy/list"
$userAgent  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36"

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

# Sends one request via HttpClient. Returns @{ Code; Body }. Cookie never travels over http
# because redirects are not followed (AllowAutoRedirect = $false).
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

Write-Host "Target: $policyUri"
if ($hasSelection) {
    Write-Host ("Selected roles ({0}): {1}" -f $selected.Count, (($selected.Values | ForEach-Object { $_.name }) -join ", "))
}
else {
    Write-Host "No roles selected - enforcing naming convention on default policies only."
}
Write-Host ""

# --- Load current policies ----------------------------------------------------
$listResp = Invoke-NinjaApi -Method "GET" -Uri $listUri
if ($listResp.Code -ge 400) {
    throw "Could not load policy list (HTTP $($listResp.Code)). Session key expired? Response: $($listResp.Body)"
}
$allPolicies = $listResp.Body | ConvertFrom-Json

# --- Counters & result lists --------------------------------------------------
$renamed  = 0
$created  = 0
$skipped  = 0
$failed   = 0
$renamedNames = [System.Collections.Generic.List[string]]::new()  # renamed default policies
$createdNames = [System.Collections.Generic.List[string]]::new()  # created child policies

# === Pass 1: enforce the naming convention on ALL default policies =============
# Runs regardless of -Roles, so the whole policy hierarchy stays consistent even
# for categories where no roles were selected.
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
            $default.name = $desiredDefaultName   # keep in-memory copy current for pass 2
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

# === Pass 2: one child policy per selected role ===============================
if ($hasSelection) {
    Write-Host "== Child policies for selected roles =="
    foreach ($nodeClass in $CategoryMeta.Keys) {
        $rolesInClass = @($selected.Values | Where-Object { $_.nodeClass -eq $nodeClass })
        if ($rolesInClass.Count -eq 0) { continue }

        $meta = $CategoryMeta[$nodeClass]

        # Locate the built-in default policy (parent) for this category.
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

# --- Summary ------------------------------------------------------------------
Write-Host "== Summary =="
if ($renamedNames.Count -gt 0) {
    Write-Host ("Renamed default policies ({0}):" -f $renamedNames.Count)
    foreach ($n in $renamedNames) { Write-Host ("  - {0}" -f $n) }
}
if ($createdNames.Count -gt 0) {
    Write-Host ("Created child policies ({0}):" -f $createdNames.Count)
    foreach ($n in $createdNames) { Write-Host ("  - {0}" -f $n) }
}
if ($renamedNames.Count -eq 0 -and $createdNames.Count -eq 0) {
    Write-Host "Nothing changed - everything already matched the convention."
}
Write-Host ""
Write-Host ("Done. Renamed: {0}, Created: {1}, Skipped: {2}, Failed: {3}" -f $renamed, $created, $skipped, $failed)
if ($failed -gt 0) { exit 1 }
