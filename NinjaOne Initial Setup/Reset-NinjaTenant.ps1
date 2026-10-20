<#
.SYNOPSIS
    Teardown counterpart to Initialize-NinjaTenant.ps1: removes everything that script creates so a
    tenant can be reset to its pre-setup state (handy for re-testing the setup from a clean slate).

.DESCRIPTION
    Talks to the same internal /swb/s6/* endpoints as Initialize-NinjaTenant.ps1, authenticated with
    the same short-lived browser session cookie (sessionKey), and uses the same selection grammar
    (-Roles / -Policies / -TechnicianRoles / -Modules). Each switch undoes exactly what its setup
    counterpart creates; omit all of them to only revert the default-policy naming convention. The
    teardown runs in dependency order (dependents before their parents):

      Step 1 - Module conditions + DEX automation (only when -Modules is given)
          Loads every DEFAULT (parent) policy, strips the monitoring conditions whose displayName
          carries a selected module's prefix ("Hardening - " / "DEX - "), and - when "dex" is
          selected - also removes the "DEX Survey" scheduled automation from the Windows Workstation
          default. One GET + one PUT per affected default policy. (MFA-gated, like the setup.)
          GET /swb/s6/policy/{id}  ->  PUT /swb/s6/policy/{id}

      Step 2 - DEX Survey scripts (only when -Modules includes "dex")
          Deletes the three imported "DEX Survey - Script N - ..." scripts from the tenant library.
          Runs AFTER step 1 so the scripts are no longer referenced by the automation.
          GET /swb/s6/scripting/scripts  ->  DELETE /swb/s6/scripting/scripts/{id}

      Step 3 - DEX Survey custom fields (only when -Modules includes "dex")
          Deletes latestUserFeedback + userFeedbackHistory (device) and systemPerformanceReport
          (global). GET /swb/s6/attributes/node/definitionScope/{NODE|GLOBAL} -> DELETE .../node/delete/item/{id}

      Step 4 - Child policies (only when -Policies is given)
          Deletes the child policy created for each selected role (matched under its category default
          by the " - <role>" name suffix, exactly as the setup dedupes them).
          GET /swb/s6/policy/list  ->  DELETE /swb/s6/policy/{id}

      Step 5 - Node roles (only when -Roles is given)
          Deletes each selected custom node role (matched by name + nodeClass).
          GET /swb/s6/noderole/list  ->  DELETE /swb/s6/noderole/{id}

      Step 6 - Technician roles (only when -TechnicianRoles is given)
          Deletes each selected technician role (matched by name, type TECHNICIAN).
          GET /swb/s6/user-roles?roleType=TECHNICIAN  ->  DELETE /swb/s6/user-roles/{id}

      Step 7 - Default policy naming convention (when -Policies is given, or on a bare call)
          Renames every built-in default policy back from "{major}.0 <base>" to "<base>".
          PATCH /swb/s6/policy/{id} { name, description, enabled }

    Idempotent and -WhatIf-safe: an object that is already gone (or already named back) is skipped,
    never treated as an error. Safe to re-run. A delete the API refuses (e.g. a node role still
    assigned to devices, HTTP 409) is reported and counted as failed, and the run continues.

    DELETE on these collections mirrors the REST shape of the GET/POST/PUT the web UI uses on the
    same paths. If a DELETE ever answers 404 it is treated as "already gone"; a 405 would mean the
    path/verb differs for that resource - run with -WhatIf first to preview, then report it.

    The sessionKey is a short-lived session cookie from a logged-in browser session (expires -> 401/
    403; sign in again and pass the current value). Policy writes (removing conditions / the
    automation) are MFA-gated: pass -MfaCode / -MFA (current TOTP) exactly as with the setup. One
    step-up elevates the session; if the window lapses mid-run the script prompts for a fresh code.

.PARAMETER Roles
    Device roles whose custom NODE ROLES should be deleted (Step 5). Same keyword/short-key grammar
    as the setup (server-all, workstation-all, testlab, or individual keys), comma-separated.

.PARAMETER Policies
    Device roles whose CHILD POLICIES should be deleted (Step 4). Same grammar as -Roles. Giving
    -Policies also reverts the default-policy naming convention (Step 7).

.PARAMETER TechnicianRoles
    Technician role profiles to delete (Step 6): 1st-level-support, 2nd-level-support,
    3rd-level-support, system-administrator, or the group keyword tech-all.

.PARAMETER Modules
    Monitoring modules to remove (Steps 1-3): hardening and/or dex. "hardening" removes its
    conditions from the Workstation + Server defaults; "dex" removes its conditions from the
    Workstation default, plus the DEX Survey automation, the three DEX scripts and the three custom
    fields.

.PARAMETER SessionKey
    The sessionKey cookie value from the logged-in NinjaOne browser session. If omitted, read from
    $env:NINJA_SESSION_KEY. NOT stored in the script (secret).

.PARAMETER MfaCode
    Current 6-digit MFA (TOTP) code. Removing conditions / the automation are MFA-gated policy
    writes; supplying the TOTP lets the script elevate the session (query-string step-up, exactly as
    the web UI). One code generated right before the run normally covers everything; if challenged
    again mid-run the script prompts for a fresh code. If omitted, read from $env:NINJA_MFA_CODE.
    NEVER hardcode it (secret, expires in ~30s).

.PARAMETER Region
    The NinjaOne instance subdomain (e.g. 'eu', 'app', 'us2'). Default: eu.

.PARAMETER WhatIf
    Shows what would be deleted / renamed without sending anything.

.EXAMPLE
    $env:NINJA_SESSION_KEY = "<sessionKey-from-browser>"
    .\Reset-NinjaTenant.ps1 -Roles server-all,workstation-all,testlab -Policies server-all,workstation-all,testlab -TechnicianRoles tech-all -Modules hardening,dex -MFA 123456 -WhatIf
    Full dry run: previews removing both modules (conditions, DEX automation/scripts/fields), all
    child policies, all node roles, all technician roles, and reverting the default-policy names.

.EXAMPLE
    .\Reset-NinjaTenant.ps1 -Modules dex -MFA 123456
    Removes only the DEX module: its conditions, the DEX Survey automation, the three DEX scripts and
    the three custom fields. Nothing else is touched.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Position = 0)]
    [string[]] $Roles = @(),

    [Parameter()]
    [string[]] $Policies = @(),

    [Parameter()]
    [string[]] $TechnicianRoles = @(),

    [Parameter()]
    [string[]] $Modules = @(),

    [Parameter()]
    [string] $SessionKey = $env:NINJA_SESSION_KEY,

    [Parameter()]
    [Alias('MFA')]
    [string] $MfaCode = $env:NINJA_MFA_CODE,

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
# Catalogs (trimmed copies of the setup's - teardown only needs names/classes)
# =============================================================================
# Each role: the display name created by the setup + its nodeClass.
$RoleCatalog = [ordered]@{
    datev           = @{ name = "Windows Server - DATEV";             nodeClass = "WINDOWS_SERVER" }
    sql             = @{ name = "Windows Server - SQL Server";        nodeClass = "WINDOWS_SERVER" }
    terminal        = @{ name = "Windows Server - Terminal Server";   nodeClass = "WINDOWS_SERVER" }
    application     = @{ name = "Windows Server - Application Server"; nodeClass = "WINDOWS_SERVER" }
    file            = @{ name = "Windows Server - File Server";        nodeClass = "WINDOWS_SERVER" }
    testserver      = @{ name = "Windows Server - Test Server";        nodeClass = "WINDOWS_SERVER" }
    homeoffice      = @{ name = "Workstation - Home Office";           nodeClass = "WINDOWS_WORKSTATION" }
    vip             = @{ name = "Workstation - VIP";                   nodeClass = "WINDOWS_WORKSTATION" }
    testworkstation = @{ name = "Workstation - Test Workstation";      nodeClass = "WINDOWS_WORKSTATION" }
}

$RoleGroups = @{
    "server-all"      = @("datev", "sql", "terminal", "application", "file")
    "workstation-all" = @("homeoffice", "vip")
    "testlab"         = @("testserver", "testworkstation")
}

# Per-category policy metadata (major number, default base name, role-name prefix) - identical to
# the setup, so the child/default names this script computes match exactly what the setup created.
$CategoryMeta = [ordered]@{
    WINDOWS_WORKSTATION = @{ major = 0; policyBaseName = "Windows Workstation Policy"; rolePrefix = "Workstation - " }
    WINDOWS_SERVER      = @{ major = 1; policyBaseName = "Windows Server Policy";      rolePrefix = "Windows Server - " }
    MAC                 = @{ major = 2; policyBaseName = "Mac Policy";                 rolePrefix = "Mac - " }
    MAC_SERVER          = @{ major = 3; policyBaseName = "Mac Server Policy";          rolePrefix = "Mac Server - " }
    LINUX_WORKSTATION   = @{ major = 4; policyBaseName = "Linux Policy";               rolePrefix = "Linux - " }
    LINUX_SERVER        = @{ major = 5; policyBaseName = "Linux Server Policy";        rolePrefix = "Linux Server - " }
}

# Technician profile key -> the role name the setup creates.
$TechnicianRoleCatalog = [ordered]@{
    "1st-level-support"    = @{ roleName = "1st Level Support" }
    "2nd-level-support"    = @{ roleName = "2nd Level Support" }
    "3rd-level-support"    = @{ roleName = "3rd Level Support" }
    "system-administrator" = @{ roleName = "Sys Admin" }
}
$TechnicianRoleGroups = @{
    "tech-all" = @("1st-level-support", "2nd-level-support", "3rd-level-support", "system-administrator")
}

# Module key -> the displayName prefix the setup stamps on its conditions. The exact emoji prefix is
# the primary match; the ASCII marker is a safety-net fallback (emoji-encoding differences).
$ModulePrefix = [ordered]@{
    hardening = @{ prefix = "🛡️ Hardening - "; marker = "Hardening - " }
    dex       = @{ prefix = "💻 DEX - ";        marker = "DEX - " }
}

# The three DEX Survey script names and the automation name the setup wires (verbatim).
$DexScriptNames = @(
    "DEX Survey - Script 1 - Request User Feedback"
    "DEX Survey - Script 2 - Collect User Feedback"
    "DEX Survey - Script 3 - System Performance Check"
)
$DexAutomationName = "DEX Survey"
$DexCustomFields = @(
    @{ fieldName = "latestUserFeedback";      scope = "NODE" }
    @{ fieldName = "userFeedbackHistory";     scope = "NODE" }
    @{ fieldName = "systemPerformanceReport"; scope = "GLOBAL" }
)

# =============================================================================
# Selection resolvers (same grammar as the setup)
# =============================================================================
function Resolve-NinjaRoleSelection {
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

function Resolve-NinjaTechnicianSelection {
    param([Parameter(Mandatory = $true)] [string[]] $Keys)
    $selected = [System.Collections.Specialized.OrderedDictionary]::new()
    foreach ($token in $Keys) {
        $key = $token.Trim().ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($key)) { continue }
        if ($TechnicianRoleGroups.ContainsKey($key)) {
            foreach ($member in $TechnicianRoleGroups[$key]) {
                if (-not $selected.Contains($member)) { $selected.Add($member, $TechnicianRoleCatalog[$member]) }
            }
        }
        elseif ($TechnicianRoleCatalog.Contains($key)) {
            if (-not $selected.Contains($key)) { $selected.Add($key, $TechnicianRoleCatalog[$key]) }
        }
        else {
            $valid = (@($TechnicianRoleGroups.Keys) + @($TechnicianRoleCatalog.Keys)) -join ", "
            throw "Unknown technician role '$token'. Valid values: $valid"
        }
    }
    if ($selected.Count -eq 0) { throw "No technician roles selected." }
    return $selected
}

# --- Resolve selections (all optional) ----------------------------------------
$cleanRoles       = @($Roles | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
$hasRoleSelection = $cleanRoles.Count -gt 0
$selectedRoles    = if ($hasRoleSelection) { Resolve-NinjaRoleSelection -Roles $cleanRoles } else { $null }

$cleanPolicies      = @($Policies | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
$hasPolicySelection = $cleanPolicies.Count -gt 0
$selectedPolicies   = if ($hasPolicySelection) { Resolve-NinjaRoleSelection -Roles $cleanPolicies } else { $null }

$cleanTech        = @($TechnicianRoles | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
$hasTechSelection = $cleanTech.Count -gt 0
$selectedTech     = if ($hasTechSelection) { Resolve-NinjaTechnicianSelection -Keys $cleanTech } else { $null }

$SupportedModules   = @("hardening", "dex")
$cleanModules       = @($Modules | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique)
$unknownModules     = @($cleanModules | Where-Object { $SupportedModules -notcontains $_ })
if ($unknownModules.Count -gt 0) {
    throw ("Unknown -Modules value(s): {0}. Supported: {1}." -f ($unknownModules -join ", "), ($SupportedModules -join ", "))
}
$hasModuleSelection = $cleanModules.Count -gt 0

# Revert the naming convention with -Policies, or on a bare call (no selection at all). Skipped on a
# roles-only / tech-only / modules-only run so none of those touch the default-policy names.
$runNaming = $hasPolicySelection -or (-not $hasRoleSelection -and -not $hasTechSelection -and -not $hasModuleSelection)

# =============================================================================
# HTTP client (identical transport to the setup)
# =============================================================================
$baseUrl           = "https://$Region.ninjarmm.com"
$noderoleListUri   = "$baseUrl/swb/s6/noderole/list?allRoles=true"
$noderoleUri       = "$baseUrl/swb/s6/noderole"
$policyUri         = "$baseUrl/swb/s6/policy"
$policyListUri     = "$baseUrl/swb/s6/policy/list"
$userRolesEndpoint = "$baseUrl/swb/s6/user-roles"
$attributesNodeUri       = "$baseUrl/swb/s6/attributes/node"
$attributesNodeListUri   = "$baseUrl/swb/s6/attributes/node/definitionScope/NODE"
$attributesGlobalListUri = "$baseUrl/swb/s6/attributes/node/definitionScope/GLOBAL"
$scriptsUri              = "$baseUrl/swb/s6/scripting/scripts"
$userAgent       = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36"

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
function Invoke-NinjaApiRaw {
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

# =============================================================================
# MFA step-up (identical to the setup, incl. the interactive re-prompt loop)
# =============================================================================
$script:MfaElevated    = $false
$script:CurrentMfaCode = if ([string]::IsNullOrWhiteSpace($MfaCode)) { $null } else { $MfaCode.Trim() }

function Test-NinjaCanPrompt {
    try { if ([System.Console]::IsInputRedirected) { return $false } } catch { return $false }
    return $true
}

function Get-NinjaMfaCode {
    param([string] $Prompt)
    if (-not (Test-NinjaCanPrompt)) { return $null }
    try { return (Read-Host -Prompt $Prompt) } catch { return $null }
}

# Sends one request and transparently handles NinjaOne's MFA step-up. A privileged write answers
# HTTP 406 { resultCode:"MFA_REQUIRED", loginToken, mfaType:"TOTP" }; the step-up is a re-send to
# "{Uri}/mfa?token=<loginToken>&mfacode=<TOTP>" (credentials in the QUERY STRING; the body carries
# the full model). The elevation is time-windowed, so a long run can be challenged more than once -
# and a TOTP is single-use - so we loop: elevate with the code we hold; when it is spent/expired ask
# for a fresh one (interactive) and retry against a new loginToken. Non-interactive -> fail fast.
function Invoke-NinjaApi {
    param(
        [Parameter(Mandatory)] [string] $Method,
        [Parameter(Mandatory)] [string] $Uri,
        [string] $Body
    )
    $resp = Invoke-NinjaApiRaw -Method $Method -Uri $Uri -Body $Body
    if ($resp.Code -ne 406) { return $resp }

    while ($true) {
        $mfa = $null
        try { $mfa = $resp.Body | ConvertFrom-Json } catch { }
        $isMfa = $mfa -and $mfa.PSObject.Properties['resultCode'] -and $mfa.resultCode -eq 'MFA_REQUIRED'
        if (-not $isMfa) { return $resp }

        $loginToken = if ($mfa.PSObject.Properties['loginToken']) { [string]$mfa.loginToken } else { $null }

        $code = $script:CurrentMfaCode
        if ([string]::IsNullOrWhiteSpace($code)) {
            $code = Get-NinjaMfaCode -Prompt "MFA required - enter a fresh TOTP code to continue (blank to abort)"
            if ([string]::IsNullOrWhiteSpace($code)) {
                if (-not (Test-NinjaCanPrompt)) {
                    throw ("MFA step-up required but no code is available and stdin is not interactive. " +
                        "Pass a fresh -MFA/-MfaCode generated immediately before the run, or run in an " +
                        "interactive terminal so the script can prompt for a fresh code when challenged.")
                }
                return $resp
            }
        }
        $code = $code.Trim()

        $payload = [ordered]@{}
        if (-not [string]::IsNullOrEmpty($Body)) {
            $parsed = $Body | ConvertFrom-Json -AsHashtable
            if ($parsed -is [System.Collections.IDictionary]) {
                foreach ($k in $parsed.Keys) { $payload[$k] = $parsed[$k] }
            }
        }
        $payload['loginToken'] = $loginToken
        $payload['mfaCode']    = $code
        $mfaBody = $payload | ConvertTo-Json -Depth 100 -Compress
        $qs      = "token={0}&mfacode={1}" -f [System.Uri]::EscapeDataString([string]$loginToken), [System.Uri]::EscapeDataString($code)
        $mfaUri  = ($Uri -replace '/+$', '') + '/mfa?' + $qs

        $elevated = Invoke-NinjaApiRaw -Method $Method -Uri $mfaUri -Body $mfaBody
        # A TOTP is single-use: whether it worked or not, never reuse it for the next challenge.
        $script:CurrentMfaCode = $null
        if ($elevated.Code -lt 400) {
            $script:MfaElevated = $true
            return $elevated
        }

        if (-not (Test-NinjaCanPrompt)) {
            throw ("MFA step-up rejected (HTTP $($elevated.Code)). The one-time code was expired, " +
                "already used, or wrong, and stdin is not interactive so no fresh code can be " +
                "requested. Generate a fresh code immediately before the run, or run interactively.")
        }
        Write-Host "MFA code rejected (HTTP $($elevated.Code)) - it was expired or already used. Enter a fresh one." -ForegroundColor Yellow
        $resp = Invoke-NinjaApiRaw -Method $Method -Uri $Uri -Body $Body
        if ($resp.Code -ne 406) { return $resp }
    }
}

# Prime the MFA step-up up front (same rationale as the setup): spend the fresh TOTP immediately via
# a no-op policy PUT so the gated writes later never race the ~30s code lifetime. Only when a policy
# write is actually going to happen (a module is selected) and we have a code or can prompt.
function Enter-NinjaMfaElevation {
    if ([string]::IsNullOrWhiteSpace($script:CurrentMfaCode) -and -not (Test-NinjaCanPrompt)) { return }

    $listResp = Invoke-NinjaApiRaw -Method "GET" -Uri $policyListUri
    if ($listResp.Code -ge 400) { return }
    $policies = $null
    try { $policies = $listResp.Body | ConvertFrom-Json } catch { }
    $target = @($policies) | Where-Object { $_.id } | Select-Object -First 1
    if (-not $target) { return }

    $getResp = Invoke-NinjaApiRaw -Method "GET" -Uri ("{0}/{1}" -f $policyUri, $target.id)
    if ($getResp.Code -ge 400) { return }
    $pol = $null
    try { $pol = ($getResp.Body | ConvertFrom-Json).policy } catch { }
    if (-not $pol) { return }
    if ($pol.PSObject.Properties['parentPolicyName']) { $pol.PSObject.Properties.Remove('parentPolicyName') }
    $body = $pol | ConvertTo-Json -Depth 100

    [void](Invoke-NinjaApi -Method "PUT" -Uri ("{0}/{1}" -f $policyUri, $target.id) -Body $body)
    if ($script:MfaElevated) {
        Write-Host "MFA: session elevated up front via -MfaCode (step-up accepted)." -ForegroundColor Cyan
        Write-Host ""
    }
}

# =============================================================================
# Banner
# =============================================================================
Write-Host "Target: $baseUrl"
Write-Host "MODE:   TEARDOWN (removes what Initialize-NinjaTenant.ps1 creates)" -ForegroundColor Magenta
if ($hasRoleSelection) {
    Write-Host ("Node roles to delete ({0}): {1}" -f $selectedRoles.Count, (($selectedRoles.Values | ForEach-Object { $_.name }) -join ", "))
}
if ($hasPolicySelection) {
    Write-Host ("Child policies to delete ({0}): {1}" -f $selectedPolicies.Count, (($selectedPolicies.Values | ForEach-Object { $_.name }) -join ", "))
}
if ($hasTechSelection) {
    Write-Host ("Technician roles to delete ({0}): {1}" -f $selectedTech.Count, (($selectedTech.Values | ForEach-Object { $_.roleName }) -join ", "))
}
if ($hasModuleSelection) {
    Write-Host ("Modules to remove ({0}): {1}" -f $cleanModules.Count, ($cleanModules -join ", "))
}
if (-not $hasRoleSelection -and -not $hasPolicySelection -and -not $hasTechSelection -and -not $hasModuleSelection) {
    Write-Host "No selection - reverting the policy naming convention only."
}
Write-Host ""

# Elevate up front only if a module (policy write) is in play.
if ($hasModuleSelection) { Enter-NinjaMfaElevation }

# --- Counters -----------------------------------------------------------------
$conditionsRemoved  = 0
$automationsRemoved = 0
$scriptsDeleted     = 0
$fieldsDeleted      = 0
$childrenDeleted    = 0
$rolesDeleted       = 0
$techDeleted        = 0
$namingReverted     = 0
$skipped            = 0
$failed             = 0

# Load the policy list once (needed for module cleanup, child deletion and naming revert).
$allPolicies = $null
if ($hasModuleSelection -or $hasPolicySelection -or $runNaming) {
    $policyListResp = Invoke-NinjaApi -Method "GET" -Uri $policyListUri
    if ($policyListResp.Code -ge 400) {
        throw "Could not load policy list (HTTP $($policyListResp.Code)). Session key expired? Response: $($policyListResp.Body)"
    }
    $allPolicies = $policyListResp.Body | ConvertFrom-Json
}

# =============================================================================
# Step 1: strip module conditions (+ DEX automation) from the default policies
# =============================================================================
if ($hasModuleSelection) {
    Write-Host "== Remove module conditions / automation (default policies) =="

    # Selected prefixes + markers to match the stamped conditions.
    $selPrefixes = @()
    $selMarkers  = @()
    foreach ($m in $cleanModules) {
        if ($ModulePrefix.Contains($m)) {
            $selPrefixes += [string]$ModulePrefix[$m].prefix
            $selMarkers  += [string]$ModulePrefix[$m].marker
        }
    }
    $removeDexAutomation = ($cleanModules -contains "dex")

    # Only the default (parent) policies ever carry these conditions / the automation.
    $defaults = @($allPolicies | Where-Object { $_.nodeClassDefault -eq $true })
    foreach ($defEntry in $defaults) {
        $getResp = Invoke-NinjaApi -Method "GET" -Uri ("{0}/{1}" -f $policyUri, $defEntry.id)
        if ($getResp.Code -ge 400) {
            Write-Host ("[ERROR {0}] could not load policy '{1}' (id {2}) - {3}" -f $getResp.Code, $defEntry.name, $defEntry.id, $getResp.Body) -ForegroundColor Red
            $failed++
            continue
        }
        # ConvertFrom-Json -AsHashtable yields a hashtable whose missing-key DOT access throws under
        # Set-StrictMode, whereas ['key'] safely returns $null. These policies vary wildly (NMS,
        # built-ins, ...), so every nested access below is index access.
        $policyWrap = $getResp.Body | ConvertFrom-Json -AsHashtable -Depth 100
        $policy = $policyWrap['policy']
        if (-not $policy) {
            Write-Host ("[ERROR] policy payload missing for '{0}' (id {1})." -f $defEntry.name, $defEntry.id) -ForegroundColor Red
            $failed++
            continue
        }
        $policyName = [string]$policy['name']
        $content    = $policy['content']

        $removedCond = 0
        $removedAuto = 0

        # --- conditions ------------------------------------------------------
        $conditions = if ($content) { $content['conditions'] } else { $null }
        if ($conditions) {
            $killKeys = [System.Collections.Generic.List[string]]::new()
            foreach ($k in @($conditions.Keys)) {
                $dn = [string]$conditions[$k]['displayName']
                if ([string]::IsNullOrEmpty($dn)) { continue }
                $isModule = $false
                foreach ($p in $selPrefixes) { if ($dn.StartsWith($p)) { $isModule = $true; break } }
                if (-not $isModule) { foreach ($mk in $selMarkers) { if ($dn -like ("*{0}*" -f $mk)) { $isModule = $true; break } } }
                if ($isModule) { $killKeys.Add([string]$k) }
            }
            foreach ($k in $killKeys) { [void]$conditions.Remove($k); $removedCond++ }
        }

        # --- DEX automation --------------------------------------------------
        $schedules = if ($removeDexAutomation -and $content) { $content['actionsetSchedules'] } else { $null }
        if ($schedules) {
            $killKeys = [System.Collections.Generic.List[string]]::new()
            foreach ($k in @($schedules.Keys)) {
                $nm = [string]$schedules[$k]['actionsetScheduleName']
                if ($nm -eq $DexAutomationName) { $killKeys.Add([string]$k) }
            }
            foreach ($k in $killKeys) { [void]$schedules.Remove($k); $removedAuto++ }
        }

        if ($removedCond -eq 0 -and $removedAuto -eq 0) {
            Write-Host ("[OK] '{0}' has no selected module conditions/automation." -f $policyName) -ForegroundColor DarkGray
            continue
        }

        if ($policy.Contains('parentPolicyName')) { [void]$policy.Remove('parentPolicyName') }
        $putBody = $policy | ConvertTo-Json -Depth 100

        if ($PSCmdlet.ShouldProcess($policyName, ("PUT remove {0} conditions, {1} automation" -f $removedCond, $removedAuto))) {
            $r = Invoke-NinjaApi -Method "PUT" -Uri ("{0}/{1}" -f $policyUri, $defEntry.id) -Body $putBody
            if ($r.Code -lt 400) {
                Write-Host ("[OK {0}] '{1}' -{2} conditions, -{3} automation" -f $r.Code, $policyName, $removedCond, $removedAuto) -ForegroundColor Green
                $conditionsRemoved  += $removedCond
                $automationsRemoved += $removedAuto
            }
            else {
                Write-Host ("[ERROR {0}] '{1}' - {2}" -f $r.Code, $policyName, $r.Body) -ForegroundColor Red
                $failed++
            }
        }
        else {
            Write-Host ("[WhatIf] PUT '{0}'  -{1} conditions, -{2} automation" -f $policyName, $removedCond, $removedAuto)
        }
    }
    Write-Host ""
}

# =============================================================================
# Step 2: delete the DEX Survey scripts from the tenant library
# =============================================================================
if ($hasModuleSelection -and ($cleanModules -contains "dex")) {
    Write-Host "== Delete DEX Survey scripts (tenant library) =="

    $tenantResp = Invoke-NinjaApi -Method "GET" -Uri $scriptsUri
    if ($tenantResp.Code -ge 400) {
        Write-Host ("[ERROR {0}] could not list the tenant script library - {1}" -f $tenantResp.Code, $tenantResp.Body) -ForegroundColor Red
        $failed++
    }
    else {
        $tenantScripts = @($tenantResp.Body | ConvertFrom-Json)
        foreach ($name in $DexScriptNames) {
            $hit = $tenantScripts | Where-Object { $_.name -eq $name } | Select-Object -First 1
            if (-not $hit) {
                Write-Host ("[SKIP] script not in library: '{0}'" -f $name) -ForegroundColor Yellow
                $skipped++
                continue
            }
            $sid = if ($hit.PSObject.Properties['id']) { [string]$hit.id } else { "" }
            if ([string]::IsNullOrWhiteSpace($sid)) {
                Write-Host ("[ERROR] '{0}' has no id - cannot delete." -f $name) -ForegroundColor Red
                $failed++
                continue
            }
            if ($PSCmdlet.ShouldProcess($name, "DELETE tenant script (id $sid)")) {
                $r = Invoke-NinjaApi -Method "DELETE" -Uri ("{0}/{1}" -f $scriptsUri, $sid)
                if ($r.Code -lt 400 -or $r.Code -eq 404) {
                    Write-Host ("[OK {0}] deleted script '{1}' (id {2})" -f $r.Code, $name, $sid) -ForegroundColor Green
                    $scriptsDeleted++
                }
                else {
                    Write-Host ("[ERROR {0}] delete script '{1}' (id {2}) - {3}" -f $r.Code, $name, $sid, $r.Body) -ForegroundColor Red
                    $failed++
                }
            }
            else {
                Write-Host ("[WhatIf] DELETE script '{0}' (id {1})" -f $name, $sid)
            }
        }
    }
    Write-Host ""
}

# =============================================================================
# Step 3: delete the DEX Survey custom fields
# =============================================================================
if ($hasModuleSelection -and ($cleanModules -contains "dex")) {
    Write-Host "== Delete DEX Survey custom fields =="

    # Build fieldName -> id per scope.
    $idByScope = @{ NODE = @{}; GLOBAL = @{} }
    $listOk = $true
    foreach ($scopePair in @(@{ Scope = "NODE"; Uri = $attributesNodeListUri }, @{ Scope = "GLOBAL"; Uri = $attributesGlobalListUri })) {
        $cfListResp = Invoke-NinjaApi -Method "GET" -Uri $scopePair.Uri
        if ($cfListResp.Code -ge 400) {
            Write-Host ("[ERROR {0}] could not list {1} custom fields - {2}" -f $cfListResp.Code, $scopePair.Scope, $cfListResp.Body) -ForegroundColor Red
            $failed++
            $listOk = $false
            continue
        }
        foreach ($f in @($cfListResp.Body | ConvertFrom-Json)) {
            if ($f.PSObject.Properties['fieldName'] -and $f.fieldName -and $f.PSObject.Properties['id'] -and $f.id) {
                $idByScope[$scopePair.Scope][[string]$f.fieldName] = [string]$f.id
            }
        }
    }

    if ($listOk) {
        foreach ($spec in $DexCustomFields) {
            $fn    = [string]$spec['fieldName']
            $scope = [string]$spec['scope']
            if (-not $idByScope[$scope].ContainsKey($fn)) {
                Write-Host ("[SKIP] {0} custom field not present: '{1}'" -f $scope, $fn) -ForegroundColor Yellow
                $skipped++
                continue
            }
            $fid = $idByScope[$scope][$fn]
            if ($PSCmdlet.ShouldProcess($fn, "DELETE $scope custom field (id $fid)")) {
                # Custom fields are removed via the dedicated .../delete/item/{id} path, NOT
                # .../attributes/node/{id} (that path has no DELETE handler and returns 405).
                $r = Invoke-NinjaApi -Method "DELETE" -Uri ("{0}/delete/item/{1}" -f $attributesNodeUri, $fid)
                $deleted = ($r.Code -lt 400 -or $r.Code -eq 404)

                # This endpoint can return a 5xx (e.g. 503) yet still delete the field server-side.
                # On any non-success code, re-list the scope and trust the actual presence of the id.
                if (-not $deleted) {
                    $scopeListUri = if ($scope -eq "GLOBAL") { $attributesGlobalListUri } else { $attributesNodeListUri }
                    $verify = Invoke-NinjaApi -Method "GET" -Uri $scopeListUri
                    if ($verify.Code -lt 400) {
                        $stillPresent = $false
                        foreach ($f in @($verify.Body | ConvertFrom-Json)) {
                            if ($f.PSObject.Properties['id'] -and ([string]$f.id -eq $fid)) { $stillPresent = $true; break }
                        }
                        if (-not $stillPresent) { $deleted = $true }
                    }
                }

                if ($deleted) {
                    Write-Host ("[OK {0}] deleted {1} custom field '{2}' (id {3})" -f $r.Code, $scope, $fn, $fid) -ForegroundColor Green
                    $fieldsDeleted++
                }
                else {
                    Write-Host ("[ERROR {0}] delete custom field '{1}' (id {2}) - {3}" -f $r.Code, $fn, $fid, $r.Body) -ForegroundColor Red
                    $failed++
                }
            }
            else {
                Write-Host ("[WhatIf] DELETE {0} custom field '{1}' (id {2})" -f $scope, $fn, $fid)
            }
        }
    }
    Write-Host ""
}

# =============================================================================
# Step 4: delete the child policies created for the selected roles
# =============================================================================
if ($hasPolicySelection) {
    Write-Host "== Delete child policies =="
    foreach ($nodeClass in $CategoryMeta.Keys) {
        $rolesInClass = @($selectedPolicies.Values | Where-Object { $_.nodeClass -eq $nodeClass })
        if ($rolesInClass.Count -eq 0) { continue }
        $meta = $CategoryMeta[$nodeClass]

        $default = $allPolicies | Where-Object { $_.nodeClass -eq $nodeClass -and $_.nodeClassDefault -eq $true } | Select-Object -First 1
        if (-not $default) {
            Write-Host ("[WARN] No default policy for nodeClass '{0}' - cannot locate its children." -f $nodeClass) -ForegroundColor Yellow
            continue
        }
        $children = @($allPolicies | Where-Object { $_.parentPolicyId -eq $default.id })

        foreach ($role in $rolesInClass) {
            $roleShort = $role.name
            if ($roleShort.StartsWith($meta.rolePrefix)) { $roleShort = $roleShort.Substring($meta.rolePrefix.Length) }
            $suffix = " - $roleShort"

            $existing = $children | Where-Object { $_.name.EndsWith($suffix, [System.StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 1
            if (-not $existing) {
                Write-Host ("[SKIP] no child policy for '{0}' (nothing to delete)." -f $roleShort) -ForegroundColor Yellow
                $skipped++
                continue
            }
            if ($PSCmdlet.ShouldProcess($existing.name, "DELETE child policy (id $($existing.id))")) {
                $r = Invoke-NinjaApi -Method "DELETE" -Uri ("{0}/{1}" -f $policyUri, $existing.id)
                if ($r.Code -lt 400 -or $r.Code -eq 404) {
                    Write-Host ("[OK {0}] deleted child policy '{1}' (id {2})" -f $r.Code, $existing.name, $existing.id) -ForegroundColor Green
                    $childrenDeleted++
                }
                else {
                    Write-Host ("[ERROR {0}] delete '{1}' (id {2}) - {3}" -f $r.Code, $existing.name, $existing.id, $r.Body) -ForegroundColor Red
                    $failed++
                }
            }
            else {
                Write-Host ("[WhatIf] DELETE child policy '{0}' (id {1})" -f $existing.name, $existing.id)
            }
        }
    }
    Write-Host ""
}

# =============================================================================
# Step 5: delete the custom node roles
# =============================================================================
if ($hasRoleSelection) {
    Write-Host "== Delete node roles =="

    $roleListResp = Invoke-NinjaApi -Method "GET" -Uri $noderoleListUri
    if ($roleListResp.Code -ge 400) {
        throw "Could not load node role list (HTTP $($roleListResp.Code)). Session key expired? Response: $($roleListResp.Body)"
    }
    $existingRoles = @($roleListResp.Body | ConvertFrom-Json)

    foreach ($role in $selectedRoles.Values) {
        $hit = $existingRoles | Where-Object { $_.name -eq $role.name -and $_.nodeClass -eq $role.nodeClass } | Select-Object -First 1
        if (-not $hit) {
            Write-Host ("[SKIP] node role not present: '{0}'" -f $role.name) -ForegroundColor Yellow
            $skipped++
            continue
        }
        if ($PSCmdlet.ShouldProcess($role.name, "DELETE node role (id $($hit.id))")) {
            $r = Invoke-NinjaApi -Method "DELETE" -Uri ("{0}/{1}" -f $noderoleUri, $hit.id)
            if ($r.Code -lt 400 -or $r.Code -eq 404) {
                Write-Host ("[OK {0}] deleted node role '{1}' (id {2})" -f $r.Code, $role.name, $hit.id) -ForegroundColor Green
                $rolesDeleted++
            }
            else {
                Write-Host ("[ERROR {0}] delete node role '{1}' (id {2}) - {3}" -f $r.Code, $role.name, $hit.id, $r.Body) -ForegroundColor Red
                $failed++
            }
        }
        else {
            Write-Host ("[WhatIf] DELETE node role '{0}' (id {1})" -f $role.name, $hit.id)
        }
    }
    Write-Host ""
}

# =============================================================================
# Step 6: delete the technician roles
# =============================================================================
if ($hasTechSelection) {
    Write-Host "== Delete technician roles =="

    $techListUri  = "$userRolesEndpoint`?roleType=TECHNICIAN"
    $techListResp = Invoke-NinjaApi -Method "GET" -Uri $techListUri
    if ($techListResp.Code -ge 400) {
        throw "Could not list technician roles (HTTP $($techListResp.Code)). Session key expired? Response: $($techListResp.Body)"
    }
    $existingTechRoles = @($techListResp.Body | ConvertFrom-Json)

    foreach ($kv in $selectedTech.GetEnumerator()) {
        $roleName = $kv.Value.roleName
        $matchesByName = @($existingTechRoles | Where-Object { $_.type -eq "TECHNICIAN" -and $_.name -eq $roleName })
        if ($matchesByName.Count -eq 0) {
            Write-Host ("[SKIP] technician role not present: '{0}'" -f $roleName) -ForegroundColor Yellow
            $skipped++
            continue
        }
        if ($matchesByName.Count -gt 1) {
            $ids = ($matchesByName | ForEach-Object { $_.id }) -join ", "
            Write-Host ("[ERROR] {0} technician roles named '{1}' (ids: {2}) - skipping (ambiguous)." -f $matchesByName.Count, $roleName, $ids) -ForegroundColor Red
            $failed++
            continue
        }
        $techId = [int]$matchesByName[0].id
        if ($PSCmdlet.ShouldProcess($roleName, "DELETE technician role (id $techId)")) {
            $r = Invoke-NinjaApi -Method "DELETE" -Uri ("{0}/{1}" -f $userRolesEndpoint, $techId)
            if ($r.Code -lt 400 -or $r.Code -eq 404) {
                Write-Host ("[OK {0}] deleted technician role '{1}' (id {2})" -f $r.Code, $roleName, $techId) -ForegroundColor Green
                $techDeleted++
            }
            else {
                Write-Host ("[ERROR {0}] delete '{1}' (id {2}) - {3}" -f $r.Code, $roleName, $techId, $r.Body) -ForegroundColor Red
                $failed++
            }
        }
        else {
            Write-Host ("[WhatIf] DELETE technician role '{0}' (id {1})" -f $roleName, $techId)
        }
    }
    Write-Host ""
}

# =============================================================================
# Step 7: revert the default-policy naming convention ("{major}.0 <base>" -> "<base>")
# =============================================================================
if ($runNaming) {
    Write-Host "== Revert default policy naming convention =="
    foreach ($nodeClass in $CategoryMeta.Keys) {
        $meta = $CategoryMeta[$nodeClass]
        $default = $allPolicies | Where-Object { $_.nodeClass -eq $nodeClass -and $_.nodeClassDefault -eq $true } | Select-Object -First 1
        if (-not $default) {
            Write-Host ("[WARN] No default policy found for nodeClass '{0}' - skipping." -f $nodeClass) -ForegroundColor Yellow
            continue
        }
        $conventionName = "{0}.0 {1}" -f $meta.major, $meta.policyBaseName
        $originalName   = [string]$meta.policyBaseName

        if ($default.name -eq $originalName) {
            Write-Host ("[OK] already named '{0}'" -f $originalName) -ForegroundColor DarkGray
            continue
        }
        if ($default.name -ne $conventionName) {
            Write-Host ("[SKIP] '{0}' is not the convention name '{1}' - leaving unchanged." -f $default.name, $conventionName) -ForegroundColor Yellow
            $skipped++
            continue
        }

        $renameBody = [ordered]@{
            name        = $originalName
            description = $default.description
            enabled     = $default.enabled
        } | ConvertTo-Json -Compress

        if ($PSCmdlet.ShouldProcess($default.name, "PATCH rename -> '$originalName'")) {
            $r = Invoke-NinjaApi -Method "PATCH" -Uri ("{0}/{1}" -f $policyUri, $default.id) -Body $renameBody
            if ($r.Code -lt 400) {
                Write-Host ("[RENAMED {0}] '{1}' -> '{2}'" -f $r.Code, $default.name, $originalName) -ForegroundColor Cyan
                $namingReverted++
            }
            else {
                Write-Host ("[ERROR {0}] rename '{1}' - {2}" -f $r.Code, $default.name, $r.Body) -ForegroundColor Red
                $failed++
            }
        }
        else {
            Write-Host ("[WhatIf] rename '{0}' -> '{1}'" -f $default.name, $originalName)
        }
    }
    Write-Host ""
}

# =============================================================================
# Summary
# =============================================================================
Write-Host "== Summary =="
if ($script:MfaElevated) {
    Write-Host "MFA: session elevated via -MfaCode (step-up accepted)." -ForegroundColor Cyan
}
Write-Host ("Done. Conditions removed: {0}, Automations removed: {1}, Scripts deleted: {2}, Custom fields deleted: {3}, Child policies deleted: {4}, Node roles deleted: {5}, Technician roles deleted: {6}, Names reverted: {7}, Skipped: {8}, Failed: {9}" -f `
    $conditionsRemoved, $automationsRemoved, $scriptsDeleted, $fieldsDeleted, $childrenDeleted, $rolesDeleted, $techDeleted, $namingReverted, $skipped, $failed)
