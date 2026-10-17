<#
.SYNOPSIS
    Shared role catalog for the NinjaOne tooling. Dot-source this file; it defines
    $RoleCatalog, $RoleGroups, $CategoryMeta and the Resolve-NinjaRoleSelection helper.

.DESCRIPTION
    Single source of truth so that New-NinjaNodeRole.ps1 (creates the node roles) and
    New-NinjaChildPolicy.ps1 (creates the matching child policies) never drift apart.

    This file intentionally only DEFINES data and a helper function. It performs no HTTP
    calls and has no side effects, so it is safe to dot-source from any script:

        . (Join-Path $PSScriptRoot "..\Shared\NinjaRoleCatalog.ps1")

    Three structures:
      $RoleCatalog  - one entry per role (key = short key used in -Roles)
      $RoleGroups   - group keywords that expand to several roles
      $CategoryMeta - per nodeClass: policy numbering + naming (used by the policy script)
#>

# --- Catalog of all known roles. Key = short key for -Roles. -------------------
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
    # No role names decided yet. Parent ids are already known from
    # GET /swb/s6/noderole/list, so adding a role later is a one-liner - uncomment
    # and rename. Pattern: a custom role's nodeRoleParentId = id of its built-in parent.
    #   <key> = @{ name = "Linux Server - NGINX"; nodeClass = "LINUX_SERVER";      nodeRoleParentId = 21 }
    #   <key> = @{ name = "Linux - Kiosk";        nodeClass = "LINUX_WORKSTATION"; nodeRoleParentId = 3  }
    #   <key> = @{ name = "Mac - Design";         nodeClass = "MAC";               nodeRoleParentId = 4  }
    #   <key> = @{ name = "Mac Server - CI";      nodeClass = "MAC_SERVER";        nodeRoleParentId = 22 }
}

# --- Group keywords that expand to multiple roles. -----------------------------
$RoleGroups = @{
    "server-all"      = @("datev", "sql", "terminal", "application", "file")
    "workstation-all" = @("homeoffice", "vip")
    "testlab"         = @("testserver", "testworkstation")
    # Coming later, once macOS / Linux roles exist:
    # "mac-all"       = @(...)
    # "linux-all"     = @(...)
}

# --- Per-category policy metadata (used by New-NinjaChildPolicy.ps1). ----------
# For each nodeClass:
#   major          - the major number in the policy naming convention ("{major}.0 ...")
#   policyBaseName - the target base name of the default policy after renaming;
#                    also reused in child policy names ("{major}.{minor} {base} - {role}")
#   rolePrefix     - prefix stripped off a role's name to get the short label used in
#                    the child policy name (e.g. "Windows Server - Terminal Server" -> "Terminal Server")
#
# Default policy rename targets (confirmed in tenant):
#   Windows Workstation Policy -> 0.0 Windows Workstation Policy
#   Windows Server Policy      -> 1.0 Windows Server Policy
# Mac/Linux majors are reserved; base names can be fine-tuned once those roles exist.
$CategoryMeta = [ordered]@{
    WINDOWS_WORKSTATION = @{ major = 0; policyBaseName = "Windows Workstation Policy"; rolePrefix = "Workstation - " }
    WINDOWS_SERVER      = @{ major = 1; policyBaseName = "Windows Server Policy";      rolePrefix = "Windows Server - " }
    MAC                 = @{ major = 2; policyBaseName = "Mac Policy";                 rolePrefix = "Mac - " }
    MAC_SERVER          = @{ major = 3; policyBaseName = "Mac Server Policy";          rolePrefix = "Mac Server - " }
    LINUX_WORKSTATION   = @{ major = 4; policyBaseName = "Linux Policy";               rolePrefix = "Linux - " }
    LINUX_SERVER        = @{ major = 5; policyBaseName = "Linux Server Policy";        rolePrefix = "Linux Server - " }
}

# --- Resolve a -Roles selection into an ordered map of key -> catalog entry. ---
# Expands group keywords, deduplicates, preserves order, and throws on unknown keys
# (with the list of valid values). Shared so both scripts select roles identically.
function Resolve-NinjaRoleSelection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]] $Roles
    )

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

    return $selected
}
