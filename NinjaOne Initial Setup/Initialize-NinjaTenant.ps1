<#
.SYNOPSIS
    One-shot NinjaOne tenant initial setup: creates the custom node roles, the matching policy
    hierarchy (default-policy naming convention + child policies) AND the technician permission
    roles (1st/2nd/3rd Level Support + Sys Admin) in a single run.

.DESCRIPTION
    Talks to the internal /swb/s6/* endpoints the web UI uses, authenticated with a short-lived
    browser session cookie (sessionKey). -Roles drives the device/policy side, -TechnicianRoles the
    technician-permission side; either is optional. The script runs in four passes:

      Pass 1 - Node roles (only when -Roles is given)
          Creates one custom node role per selected role.
          POST /swb/s6/noderole

      Pass 2 - Default policy naming convention (when -Roles is given, or on a bare call)
          Renames every built-in default policy to the numbering convention so the whole
          hierarchy stays consistent even for categories without roles:
              Windows Workstation Policy  ->  0.0 Windows Workstation Policy
              Windows Server Policy       ->  1.0 Windows Server Policy
              Mac / Mac Server / Linux / Linux Server -> 2.0 / 3.0 / 4.0 / 5.0 ...
          PATCH /swb/s6/policy/{id}  { name, description, enabled }
          (Skipped on a technician-roles-only run, so a -TechnicianRoles call never touches policies.)

      Pass 3 - Child policies (only when -Roles is given)
          Creates one child policy per selected role, inheriting everything from that role's
          default (its parent). Numbering "{major}.{minor}", e.g.:
              1.1 Windows Server Policy - Terminal Server
              1.2 Windows Server Policy - SQL Server    ...
          POST /swb/s6/policy  { enabled, name, nodeClassDefault:false, nodeClass,
                                 description:null, parentPolicyId }

      Pass 4 - Technician roles (only when -TechnicianRoles is given)
          Create-or-update one technician role per selected profile. The permission model is a flat
          grant list - each entry { entityId, entityType, name, allowed }; an access level like
          "View, run" decomposes into one entry per capability (View AND Run). The role is saved
          with a full-replace PUT /swb/s6/user-roles/{id} (no partial PATCH), so the script GETs the
          role first (or POSTs a new one) to preserve name/type/description/members, then PUTs the
          desired grants. Four built-in profiles form a strict escalation L1 <= L2 <= L3 <= Sys Admin.
          GET/POST/PUT /swb/s6/user-roles

    A child policy links to its parent ONLY via parentPolicyId and inherits the parent's settings;
    it is not tied to the custom node role, so the policy passes do not depend on the role pass.

    Fully idempotent and -WhatIf-safe: existing node roles are skipped, defaults already carrying
    the convention name are left alone, an already-existing child is skipped, and a technician role
    already carrying exactly its profile is skipped. Safe to re-run.

    The sessionKey is a short-lived session cookie from a logged-in browser session. Once it
    expires you get 401/403 back - sign in again in the browser and pass the current value.

.PARAMETER Roles
    Optional. One or more device roles to create (node role + child policy). Group keywords
    (server-all, workstation-all, testlab) and/or individual short keys (comma-separated),
    e.g. -Roles server-all,testworkstation. Omit entirely to only enforce the default-policy
    naming convention (Pass 2) without creating any roles or child policies.

.PARAMETER TechnicianRoles
    Optional. One or more technician permission profiles to create-or-update (Pass 4). Profile keys
    (comma-separated): 1st-level-support, 2nd-level-support, 3rd-level-support, system-administrator;
    or the group keyword tech-all. Each profile maps to a fixed role name (e.g. system-administrator
    -> "Sys Admin"). A technician-roles-only run does not touch the policy hierarchy.

.PARAMETER SessionKey
    The sessionKey cookie value from the logged-in NinjaOne browser session.
    If omitted, the script reads the NINJA_SESSION_KEY environment variable.
    The key is intentionally NOT stored in the script (secret).

.PARAMETER Region
    The NinjaOne instance subdomain (e.g. 'eu', 'app', 'us2'). Default: eu.

.PARAMETER WhatIf
    Shows what would be created/renamed/applied without sending anything.

.EXAMPLE
    $env:NINJA_SESSION_KEY = "<sessionKey-from-browser>"
    .\Initialize-NinjaTenant.ps1 -Roles server-all
    Creates the five Windows Server node roles, renames every default policy to the convention,
    and creates one child policy per server role (1.1 .. 1.5).

.EXAMPLE
    .\Initialize-NinjaTenant.ps1
    No roles: only renames every built-in default policy to the convention (0.0, 1.0, 2.0, ...).

.EXAMPLE
    .\Initialize-NinjaTenant.ps1 -TechnicianRoles tech-all
    Creates (or updates) all four technician roles - 1st/2nd/3rd Level Support and Sys Admin -
    without touching the policy hierarchy.

.EXAMPLE
    .\Initialize-NinjaTenant.ps1 -TechnicianRoles system-administrator
    Creates (or updates) the full-access "Sys Admin" technician role (all 208 grants).

.EXAMPLE
    .\Initialize-NinjaTenant.ps1 -Roles server-all -TechnicianRoles tech-all -WhatIf
    Dry run of the full tenant setup: node roles, policy renames, child policies and all four
    technician roles - sends nothing.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    # Optional: if omitted (and no -TechnicianRoles), only the default-policy naming convention runs.
    [Parameter(Position = 0)]
    [string[]] $Roles = @(),

    # Optional: technician permission profiles to create-or-update (Pass 4).
    [Parameter()]
    [string[]] $TechnicianRoles = @(),

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

# =============================================================================
# Technician role catalog (single source of truth for the permission profiles)
# =============================================================================
# A technician role's permissions are a flat list of grants; each "ENTITY|name"
# token below becomes { entityId = 0; entityType = <ENTITY>; name = <name>; allowed = $true }
# on save. An access level maps to one grant per capability it includes, e.g.
#   "View, run"  -> NODE|View  +  NODE|Run
# A multi-select option is one grant each, e.g. a single allowed remote tool:
#   NODE|RemoteTools.TaskManager.Access
# Role-type default grants (e.g. ticket "View and add public comments") are implied by the
# role type and intentionally NOT stored. The four profiles form a strict escalation
# (1st-level-support subset of 2nd subset of 3rd subset of system-administrator), captured 1:1
# from the live permission editor. Each profile maps to a fixed role name applied in Pass 4.
$TechnicianRoleCatalog = [ordered]@{
    "1st-level-support" = @{
        roleName = "1st Level Support"
        grants   = @(
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

    # ---------------------------------------------------------------------
    # 2nd Level Support - escalation technician. Everything L1 can do, plus:
    # remediate devices, author scripts & scheduled tasks, edit documentation
    # and IT asset data, and a broader ticketing surface. Still read-only on
    # organizations/policies and NO tenant administration.
    # ---------------------------------------------------------------------
    "2nd-level-support" = @{
        roleName = "2nd Level Support"
        grants   = @(
            # --- Devices (NODE): L1 remote toolkit + remediation ----------------
            "NODE|View"
            "NODE|Run"
            "NODE|Update"
            "NODE|Decommission.Access"
            "NODE|NodeApproval.View"
            "NODE|NodeApproval.Approve"
            "NODE|NodeApproval.Reject"
            "NODE|SecureFields.Access"
            "NODE|TOTP.Code.Access"
            "NODE|RemoteTools.TaskManager.Access"
            "NODE|RemoteTools.FileExplorer.Access"
            "NODE|RemoteTools.CommandLine.Access"
            "NODE|RemoteTools.ServicesManager.Access"
            "NODE|RemoteTools.RemoteRegistry.Access"
            "NODE|RemoteAccess.Splashtop.Access"
            "NODE|RemoteAccess.NinjaConnect.Access"

            # --- Organizations / Policies (still read-only) ---------------------
            "ORGANIZATION|View"
            "POLICY|View"

            # --- Automation Library: author + schedule --------------------------
            "SCRIPT_CATEGORY|View"
            "SCRIPT_CATEGORY|Run"
            "SCRIPT_CATEGORY|Create"
            "SCRIPT_CATEGORY|Update"
            "SCRIPT_CATEGORY|Scheduled.Task.View"
            "SCRIPT_CATEGORY|Scheduled.Task.Create"
            "SCRIPT_CATEGORY|Scheduled.Task.Update"
            "SCRIPT_CATEGORY|Scheduled.Task.Delete"

            # --- Ticketing (broader than L1, no ticketing config) ---------------
            "TICKETING|Ticket.View"
            "TICKETING|Ticket.Create"
            "TICKETING|Ticket.Update"
            "TICKETING|Ticketing.Comment.Change.History.View"
            "TICKETING|Ticketing.Relationship.View"
            "TICKETING|Ticketing.Relationship.Manage"
            "TICKETING|Ticketing.Mobile.Access"
            "TICKETING|Private.Comments.View"
            "TICKETING|Private.Comments.Update.Own"
            "TICKETING|Private.Comments.Update.All"
            "TICKETING|Ticketing.Comments.Update.Own"
            "TICKETING|Ticketing.Comments.Update.All"
            "TICKETING|Board.View"
            "TICKETING|Ticketing.ServiceLevelAgreement.Access"
            "TICKETING|Ticketing.RecentTicketsWidget.Access"
            "TICKETING|Manage.Tickets.NoOrg.Access"
            "TICKETING|TimeTracked.Update.All"

            # --- Documentation: author (no delete / no publishing config) -------
            "DOCUMENTATION|Global.KB.Management.View"
            "DOCUMENTATION|Management.View"
            "DOCUMENTATION|Template.View"
            "DOCUMENTATION|Checklist.Management.View"
            "DOCUMENTATION|Checklist.Management.Create"
            "DOCUMENTATION|Checklist.Management.Update"
            "DOCUMENTATION|Checklist.Template.View"
            "DOCUMENTATION|Management.Create"
            "DOCUMENTATION|Management.Update"
            "DOCUMENTATION|Global.KB.Management.Create"
            "DOCUMENTATION|Global.KB.Management.Update"
            "DOCUMENTATION|Template.Create"
            "DOCUMENTATION|Template.Update"
            "DOCUMENTATION|Export.Access"
            "DOCUMENTATION|Management.SecureFields.Access"

            # --- IT Asset Management: edit (no delete / no type admin) ----------
            "ITAM|Itam.SoftwareLicense.View"
            "ITAM|Itam.CoreAssetAttribute.View"
            "ITAM|Itam.CoreAssetAttribute.Update"
            "ITAM|Itam.SoftwareLicense.Create"
            "ITAM|Itam.SoftwareLicense.Update"
            "ITAM|Itam.AssetRelationship.View"
            "ITAM|Itam.AssetRelationship.Create"
            "ITAM|Itam.AssetRelationship.Update"
            "ITAM|Itam.RelationshipType.View"

            # --- System: operational actions, no tenant/integration config -----
            "SYSTEM|MobileApp.Access"
            "SYSTEM|Contact.View"
            "SYSTEM|Contact.Create"
            "SYSTEM|Contact.Update"
            "SYSTEM|Reports.ViewSchedule"
            "SYSTEM|Reports.ViewClaimSchedule"
            "SYSTEM|Reports.FullAccess"
            "SYSTEM|Backup.View"
            "SYSTEM|Backup.Manage"
            "SYSTEM|Backup.Restore"
            "SYSTEM|UninstallSoftware.Access"
            "SYSTEM|UninstallPatch.Access"
            "SYSTEM|MaintenanceMode.Editor.Access"
            "SYSTEM|Device.Administration.Access"
            "SYSTEM|RelatedItem.View"
            "SYSTEM|RelatedItem.Create"
            "SYSTEM|RelatedItem.Update"
            "SYSTEM|RelatedItem.Credentials.Access"
            "SYSTEM|Vulnerability.View"
            "SYSTEM|Discovered.Asset.Management.View"
            "SYSTEM|CustomFields.Administration.View"
            "SYSTEM|BrowserManagement.View"
            "SYSTEM|Itam.Tag.View"
            "SYSTEM|Itam.Tag.Management.View"
            "SYSTEM|CustomSNMP.View"
        )
    }

    # ---------------------------------------------------------------------
    # 3rd Level Support - senior / escalation engineer. Full operational
    # control: device lifecycle, create & update organizations and policies,
    # full automation/documentation/ITAM, approvals, AI, custom fields and
    # reporting. Deliberately withholds PLATFORM ADMINISTRATION (reserved for
    # Sys Admin): RBAC role admin, integration/MDM/PSA/SaaS-backup/SIEM config,
    # caching, custom tabs, and destructive deletion of orgs/policies.
    # ---------------------------------------------------------------------
    "3rd-level-support" = @{
        roleName = "3rd Level Support"
        grants   = @(
            # --- Global search --------------------------------------------------
            "SEARCH|Search.Create"

            # --- Devices (NODE): full lifecycle ---------------------------------
            "NODE|View"
            "NODE|Run"
            "NODE|Create"
            "NODE|Update"
            "NODE|Delete"
            "NODE|Decommission.Access"
            "NODE|NodeApproval.View"
            "NODE|NodeApproval.Approve"
            "NODE|NodeApproval.Reject"
            "NODE|SecureFields.Access"
            "NODE|TOTP.Code.Access"
            "NODE|RemoteTools.TaskManager.Access"
            "NODE|RemoteTools.FileExplorer.Access"
            "NODE|RemoteTools.CommandLine.Access"
            "NODE|RemoteTools.ServicesManager.Access"
            "NODE|RemoteTools.RemoteRegistry.Access"
            "NODE|RemoteAccess.Splashtop.Access"
            "NODE|RemoteAccess.NinjaConnect.Access"

            # --- Organizations / Policies: create + update (NO delete) ----------
            "ORGANIZATION|View"
            "ORGANIZATION|Create"
            "ORGANIZATION|Update"
            "POLICY|View"
            "POLICY|Create"
            "POLICY|Update"

            # --- Automation Library: full --------------------------------------
            "SCRIPT_CATEGORY|View"
            "SCRIPT_CATEGORY|Run"
            "SCRIPT_CATEGORY|Create"
            "SCRIPT_CATEGORY|Update"
            "SCRIPT_CATEGORY|Delete"
            "SCRIPT_CATEGORY|Scheduled.Task.View"
            "SCRIPT_CATEGORY|Scheduled.Task.Create"
            "SCRIPT_CATEGORY|Scheduled.Task.Update"
            "SCRIPT_CATEGORY|Scheduled.Task.Delete"

            # --- Ticketing: full, incl. boards + ticketing config ---------------
            "TICKETING|Ticket.View"
            "TICKETING|Ticket.Create"
            "TICKETING|Ticket.Update"
            "TICKETING|Ticket.Delete"
            "TICKETING|Ticketing.Comment.Change.History.View"
            "TICKETING|Ticketing.Relationship.View"
            "TICKETING|Ticketing.Relationship.Manage"
            "TICKETING|Ticketing.Mobile.Access"
            "TICKETING|Private.Comments.View"
            "TICKETING|Private.Comments.Update.Own"
            "TICKETING|Private.Comments.Update.All"
            "TICKETING|Ticketing.Comments.Update.Own"
            "TICKETING|Ticketing.Comments.Update.All"
            "TICKETING|Board.View"
            "TICKETING|Ticketing.ServiceLevelAgreement.Access"
            "TICKETING|Ticketing.RecentTicketsWidget.Access"
            "TICKETING|Manage.Tickets.NoOrg.Access"
            "TICKETING|TimeTracked.Update.All"
            "TICKETING|Configuration.Ticketing.Access"
            "TICKETING|PendingEmailBoard.View"
            "TICKETING|PendingEmailBoard.Manage"

            # --- Documentation: full -------------------------------------------
            "DOCUMENTATION|Global.KB.Management.View"
            "DOCUMENTATION|Global.KB.Management.Create"
            "DOCUMENTATION|Global.KB.Management.Update"
            "DOCUMENTATION|Global.KB.Management.Delete"
            "DOCUMENTATION|Global.KB.EndUser.Folder.Share.Access"
            "DOCUMENTATION|KB.Management.Access.Restriction.Access"
            "DOCUMENTATION|KB.Management.Public.Links.View"
            "DOCUMENTATION|KB.Management.Public.Links.Create"
            "DOCUMENTATION|KB.Management.Public.Links.Update"
            "DOCUMENTATION|KB.Management.Public.Links.Delete"
            "DOCUMENTATION|Management.View"
            "DOCUMENTATION|Management.Create"
            "DOCUMENTATION|Management.Update"
            "DOCUMENTATION|Management.Delete"
            "DOCUMENTATION|Management.SecureFields.Access"
            "DOCUMENTATION|Template.View"
            "DOCUMENTATION|Template.Create"
            "DOCUMENTATION|Template.Update"
            "DOCUMENTATION|Template.Delete"
            "DOCUMENTATION|Checklist.Management.View"
            "DOCUMENTATION|Checklist.Management.Create"
            "DOCUMENTATION|Checklist.Management.Update"
            "DOCUMENTATION|Checklist.Management.Delete"
            "DOCUMENTATION|Checklist.Template.View"
            "DOCUMENTATION|Checklist.Template.Create"
            "DOCUMENTATION|Checklist.Template.Update"
            "DOCUMENTATION|Checklist.Template.Delete"
            "DOCUMENTATION|Configuration.Access"
            "DOCUMENTATION|Export.Access"
            "DOCUMENTATION|TOTP.Code.Access"

            # --- IT Asset Management: full -------------------------------------
            "ITAM|Itam.SoftwareLicense.View"
            "ITAM|Itam.SoftwareLicense.Create"
            "ITAM|Itam.SoftwareLicense.Update"
            "ITAM|Itam.SoftwareLicense.Delete"
            "ITAM|Itam.CoreAssetAttribute.View"
            "ITAM|Itam.CoreAssetAttribute.Update"
            "ITAM|Itam.AssetRelationship.View"
            "ITAM|Itam.AssetRelationship.Create"
            "ITAM|Itam.AssetRelationship.Update"
            "ITAM|Itam.AssetRelationship.Delete"
            "ITAM|Itam.RelationshipType.View"
            "ITAM|Itam.RelationshipType.Create"
            "ITAM|Itam.RelationshipType.Update"
            "ITAM|Itam.RelationshipType.Delete"

            # --- Approvals + AI -------------------------------------------------
            "APPROVAL_PROCESS|Approval.Process.Ticketing.Actions.Access"
            "APPROVAL_PROCESS|Approval.Process.Administrative.Actions.Access"
            "ARTIFICIAL_INTELLIGENCE|AI.MCP.Access"
            "ARTIFICIAL_INTELLIGENCE|AI.Actions.MCP"

            # --- System: operational + data admin (NO platform/integration cfg)-
            "SYSTEM|MobileApp.Access"
            "SYSTEM|Contact.View"
            "SYSTEM|Contact.Create"
            "SYSTEM|Contact.Update"
            "SYSTEM|Contact.Delete"
            "SYSTEM|Reports.ViewSchedule"
            "SYSTEM|Reports.ViewClaimSchedule"
            "SYSTEM|Reports.FullAccess"
            "SYSTEM|Backup.View"
            "SYSTEM|Backup.Manage"
            "SYSTEM|Backup.Restore"
            "SYSTEM|UninstallSoftware.Access"
            "SYSTEM|UninstallPatch.Access"
            "SYSTEM|MaintenanceMode.Editor.Access"
            "SYSTEM|Device.Administration.Access"
            "SYSTEM|RelatedItem.View"
            "SYSTEM|RelatedItem.Create"
            "SYSTEM|RelatedItem.Update"
            "SYSTEM|RelatedItem.Delete"
            "SYSTEM|RelatedItem.Credentials.Access"
            "SYSTEM|Vulnerability.View"
            "SYSTEM|Discovered.Asset.Management.View"
            "SYSTEM|Discovered.Asset.Management.Create"
            "SYSTEM|Discovered.Asset.Management.Update"
            "SYSTEM|Discovered.Asset.Management.Delete"
            "SYSTEM|CustomFields.Administration.View"
            "SYSTEM|CustomFields.Administration.Create"
            "SYSTEM|CustomFields.Administration.Update"
            "SYSTEM|CustomFields.Administration.Delete"
            "SYSTEM|CustomFields.Export.Access"
            "SYSTEM|GlobalCustomFieldsManagement.Access"
            "SYSTEM|BrowserManagement.View"
            "SYSTEM|Itam.Tag.View"
            "SYSTEM|Itam.Tag.Create"
            "SYSTEM|Itam.Tag.Update"
            "SYSTEM|Itam.Tag.Delete"
            "SYSTEM|Itam.Tag.Management.View"
            "SYSTEM|Itam.Tag.Management.Update"
            "SYSTEM|CustomSNMP.View"
            "SYSTEM|CustomSNMP.Update"
            "SYSTEM|ActiveDirectoryDiscovery.Access"
            "SYSTEM|Configuration.Activities.Access"
            "SYSTEM|EndUserSharing.Access"
            "SYSTEM|Manager.View"
            "SYSTEM|Manager.Update"
            "SYSTEM|Manager.UpdateSelfAccess"
            "SYSTEM|NinjaConnect.BackgroundMode.Access"
        )
    }

    # ---------------------------------------------------------------------
    # System Administrator -> role name "Sys Admin". The complete captured
    # permission catalog (ALL 208 grants across every entity type). Intended to
    # REPLACE the built-in breakglass System Administrator for day-to-day tenant
    # administration (there is no custom "System Administrator" role type, so this
    # is a TECHNICIAN role granted every permission). Apply with:
    #   .\Initialize-NinjaTenant.ps1 -TechnicianRoles system-administrator
    # ---------------------------------------------------------------------
    "system-administrator" = @{
        roleName = "Sys Admin"
        grants   = @(
            # --- SEARCH ---
            "SEARCH|Search.Create"
            # --- NODE ---
            "NODE|Create"
            "NODE|Decommission.Access"
            "NODE|Delete"
            "NODE|NodeApproval.Approve"
            "NODE|NodeApproval.Reject"
            "NODE|NodeApproval.View"
            "NODE|RemoteAccess.NinjaConnect.Access"
            "NODE|RemoteAccess.Splashtop.Access"
            "NODE|RemoteTools.CommandLine.Access"
            "NODE|RemoteTools.FileExplorer.Access"
            "NODE|RemoteTools.RemoteRegistry.Access"
            "NODE|RemoteTools.ServicesManager.Access"
            "NODE|RemoteTools.TaskManager.Access"
            "NODE|Run"
            "NODE|SecureFields.Access"
            "NODE|TOTP.Code.Access"
            "NODE|Update"
            "NODE|View"
            # --- ORGANIZATION ---
            "ORGANIZATION|Create"
            "ORGANIZATION|Delete"
            "ORGANIZATION|Update"
            "ORGANIZATION|View"
            # --- POLICY ---
            "POLICY|Create"
            "POLICY|Delete"
            "POLICY|Update"
            "POLICY|View"
            # --- SCRIPT_CATEGORY ---
            "SCRIPT_CATEGORY|Create"
            "SCRIPT_CATEGORY|Delete"
            "SCRIPT_CATEGORY|Run"
            "SCRIPT_CATEGORY|Scheduled.Task.Create"
            "SCRIPT_CATEGORY|Scheduled.Task.Delete"
            "SCRIPT_CATEGORY|Scheduled.Task.Update"
            "SCRIPT_CATEGORY|Scheduled.Task.View"
            "SCRIPT_CATEGORY|Update"
            "SCRIPT_CATEGORY|View"
            # --- TICKETING ---
            "TICKETING|Board.View"
            "TICKETING|Configuration.Ticketing.Access"
            "TICKETING|Manage.Tickets.NoOrg.Access"
            "TICKETING|PendingEmailBoard.Manage"
            "TICKETING|PendingEmailBoard.View"
            "TICKETING|Private.Comments.Update.All"
            "TICKETING|Private.Comments.Update.Own"
            "TICKETING|Private.Comments.View"
            "TICKETING|Ticket.Create"
            "TICKETING|Ticket.Delete"
            "TICKETING|Ticket.Update"
            "TICKETING|Ticket.View"
            "TICKETING|Ticketing.Comment.Change.History.View"
            "TICKETING|Ticketing.Comments.Update.All"
            "TICKETING|Ticketing.Comments.Update.Own"
            "TICKETING|Ticketing.Mobile.Access"
            "TICKETING|Ticketing.RecentTicketsWidget.Access"
            "TICKETING|Ticketing.Relationship.Manage"
            "TICKETING|Ticketing.Relationship.View"
            "TICKETING|Ticketing.ServiceLevelAgreement.Access"
            "TICKETING|TimeTracked.Update.All"
            # --- DOCUMENTATION ---
            "DOCUMENTATION|Checklist.Management.Create"
            "DOCUMENTATION|Checklist.Management.Delete"
            "DOCUMENTATION|Checklist.Management.Update"
            "DOCUMENTATION|Checklist.Management.View"
            "DOCUMENTATION|Checklist.Template.Create"
            "DOCUMENTATION|Checklist.Template.Delete"
            "DOCUMENTATION|Checklist.Template.Update"
            "DOCUMENTATION|Checklist.Template.View"
            "DOCUMENTATION|Configuration.Access"
            "DOCUMENTATION|Export.Access"
            "DOCUMENTATION|Global.KB.EndUser.Folder.Share.Access"
            "DOCUMENTATION|Global.KB.Management.Create"
            "DOCUMENTATION|Global.KB.Management.Delete"
            "DOCUMENTATION|Global.KB.Management.Update"
            "DOCUMENTATION|Global.KB.Management.View"
            "DOCUMENTATION|KB.Management.Access.Restriction.Access"
            "DOCUMENTATION|KB.Management.Public.Links.Create"
            "DOCUMENTATION|KB.Management.Public.Links.Delete"
            "DOCUMENTATION|KB.Management.Public.Links.Update"
            "DOCUMENTATION|KB.Management.Public.Links.View"
            "DOCUMENTATION|Management.Create"
            "DOCUMENTATION|Management.Delete"
            "DOCUMENTATION|Management.SecureFields.Access"
            "DOCUMENTATION|Management.Update"
            "DOCUMENTATION|Management.View"
            "DOCUMENTATION|TOTP.Code.Access"
            "DOCUMENTATION|Template.Create"
            "DOCUMENTATION|Template.Delete"
            "DOCUMENTATION|Template.Update"
            "DOCUMENTATION|Template.View"
            # --- ITAM ---
            "ITAM|Itam.AssetRelationship.Create"
            "ITAM|Itam.AssetRelationship.Delete"
            "ITAM|Itam.AssetRelationship.Update"
            "ITAM|Itam.AssetRelationship.View"
            "ITAM|Itam.CoreAssetAttribute.Update"
            "ITAM|Itam.CoreAssetAttribute.View"
            "ITAM|Itam.RelationshipType.Create"
            "ITAM|Itam.RelationshipType.Delete"
            "ITAM|Itam.RelationshipType.Update"
            "ITAM|Itam.RelationshipType.View"
            "ITAM|Itam.SoftwareLicense.Create"
            "ITAM|Itam.SoftwareLicense.Delete"
            "ITAM|Itam.SoftwareLicense.Update"
            "ITAM|Itam.SoftwareLicense.View"
            # --- APPROVAL_PROCESS ---
            "APPROVAL_PROCESS|Approval.Process.Administrative.Actions.Access"
            "APPROVAL_PROCESS|Approval.Process.Ticketing.Actions.Access"
            # --- ARTIFICIAL_INTELLIGENCE ---
            "ARTIFICIAL_INTELLIGENCE|AI.Actions.MCP"
            "ARTIFICIAL_INTELLIGENCE|AI.MCP.Access"
            # --- NINJA_PSA ---
            "NINJA_PSA|Configuration.NinjaPSA.Access"
            "NINJA_PSA|Configuration.NinjaPSA.OverrideLaborTicketTimeEntry.Access"
            "NINJA_PSA|Configuration.NinjaPSA.TicketProducts.Create"
            "NINJA_PSA|Configuration.NinjaPSA.TicketProducts.Delete"
            "NINJA_PSA|Configuration.NinjaPSA.TicketProducts.Price.Access"
            "NINJA_PSA|Configuration.NinjaPSA.TicketProducts.Update"
            "NINJA_PSA|Configuration.NinjaPSA.TicketProducts.View"
            # --- MDM ---
            "MDM|Android.Connection.Create"
            "MDM|Android.Connection.Delete"
            "MDM|Android.Connection.Update"
            "MDM|Android.Connection.View"
            "MDM|AppleADE.Connection.Create"
            "MDM|AppleADE.Connection.Delete"
            "MDM|AppleADE.Connection.Update"
            "MDM|AppleADE.Connection.View"
            "MDM|AppleAPN.Connection.Create"
            "MDM|AppleAPN.Connection.Delete"
            "MDM|AppleAPN.Connection.Update"
            "MDM|AppleAPN.Connection.View"
            "MDM|AppleAppsAndBooks.Connection.Create"
            "MDM|AppleAppsAndBooks.Connection.Delete"
            "MDM|AppleAppsAndBooks.Connection.Update"
            "MDM|AppleAppsAndBooks.Connection.View"
            # --- SYSTEM ---
            "SYSTEM|ActiveDirectoryDiscovery.Access"
            "SYSTEM|ActiveDirectoryManagement.Access"
            "SYSTEM|Backup.Manage"
            "SYSTEM|Backup.Restore"
            "SYSTEM|Backup.View"
            "SYSTEM|BrowserManagement.View"
            "SYSTEM|Caching.Create"
            "SYSTEM|Caching.Delete"
            "SYSTEM|Caching.Update"
            "SYSTEM|Caching.View"
            "SYSTEM|Cloudberry.Configure.Access"
            "SYSTEM|Configuration.Activities.Access"
            "SYSTEM|Configuration.MicrosoftIntune.Access"
            "SYSTEM|Configuration.PSA.Access"
            "SYSTEM|Connectwise.Configure.Access"
            "SYSTEM|Contact.Create"
            "SYSTEM|Contact.Delete"
            "SYSTEM|Contact.Update"
            "SYSTEM|Contact.View"
            "SYSTEM|CrowdStrike.Access"
            "SYSTEM|Custom.Tab.Administration.Create"
            "SYSTEM|Custom.Tab.Administration.Delete"
            "SYSTEM|Custom.Tab.Administration.Update"
            "SYSTEM|Custom.Tab.Administration.View"
            "SYSTEM|CustomFields.Administration.Create"
            "SYSTEM|CustomFields.Administration.Delete"
            "SYSTEM|CustomFields.Administration.Update"
            "SYSTEM|CustomFields.Administration.View"
            "SYSTEM|CustomFields.Export.Access"
            "SYSTEM|CustomSNMP.Update"
            "SYSTEM|CustomSNMP.View"
            "SYSTEM|Device.Administration.Access"
            "SYSTEM|Discovered.Asset.Management.Create"
            "SYSTEM|Discovered.Asset.Management.Delete"
            "SYSTEM|Discovered.Asset.Management.Update"
            "SYSTEM|Discovered.Asset.Management.View"
            "SYSTEM|EndUserSharing.Access"
            "SYSTEM|GlobalCustomFieldsManagement.Access"
            "SYSTEM|GravityZone.Access"
            "SYSTEM|GravityZone.Scan.Access"
            "SYSTEM|Itam.Tag.Create"
            "SYSTEM|Itam.Tag.Delete"
            "SYSTEM|Itam.Tag.Management.Update"
            "SYSTEM|Itam.Tag.Management.View"
            "SYSTEM|Itam.Tag.Update"
            "SYSTEM|Itam.Tag.View"
            "SYSTEM|MaintenanceMode.Editor.Access"
            "SYSTEM|ManagedRole.Administration.Create"
            "SYSTEM|ManagedRole.Administration.Delete"
            "SYSTEM|ManagedRole.Administration.Update"
            "SYSTEM|ManagedRole.Administration.View"
            "SYSTEM|Manager.Update"
            "SYSTEM|Manager.UpdateSelfAccess"
            "SYSTEM|Manager.View"
            "SYSTEM|MobileApp.Access"
            "SYSTEM|NinjaConnect.BackgroundMode.Access"
            "SYSTEM|NinjaConnect.Configure.Access"
            "SYSTEM|QuickConnect.Configure.Access"
            "SYSTEM|RelatedItem.Create"
            "SYSTEM|RelatedItem.Credentials.Access"
            "SYSTEM|RelatedItem.Delete"
            "SYSTEM|RelatedItem.Update"
            "SYSTEM|RelatedItem.View"
            "SYSTEM|Reports.FullAccess"
            "SYSTEM|Reports.ViewClaimSchedule"
            "SYSTEM|Reports.ViewSchedule"
            "SYSTEM|SaasBackup.EPP.SuperAdmin"
            "SYSTEM|SaasBackup.EUP.FullAdmin"
            "SYSTEM|SaasBackup.NPP.SuperAdmin"
            "SYSTEM|SaasBackup.Ninja.Allow"
            "SYSTEM|SentinelOne.Access"
            "SYSTEM|SiemExporter.Access"
            "SYSTEM|Splashtop.Configure.Access"
            "SYSTEM|UninstallPatch.Access"
            "SYSTEM|UninstallSoftware.Access"
            "SYSTEM|UnmanagedRole.Administration.Create"
            "SYSTEM|UnmanagedRole.Administration.Delete"
            "SYSTEM|UnmanagedRole.Administration.Update"
            "SYSTEM|UnmanagedRole.Administration.View"
            "SYSTEM|Vulnerability.View"
        )
    }
}

# Group keyword that expands to all technician profiles.
$TechnicianRoleGroups = @{
    "tech-all" = @("1st-level-support", "2nd-level-support", "3rd-level-support", "system-administrator")
}

# Resolve a -TechnicianRoles selection into an ordered map of profile key -> catalog entry.
# Expands the group keyword, deduplicates, preserves order, throws on unknown keys.
function Resolve-NinjaTechnicianSelection {
    [CmdletBinding()]
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

# --- Resolve selections (both optional) ---------------------------------------
$cleanRoles   = @($Roles | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
$hasSelection = $cleanRoles.Count -gt 0
$selected     = if ($hasSelection) { Resolve-NinjaRoleSelection -Roles $cleanRoles } else { $null }

$cleanTech        = @($TechnicianRoles | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
$hasTechSelection = $cleanTech.Count -gt 0
$selectedTech     = if ($hasTechSelection) { Resolve-NinjaTechnicianSelection -Keys $cleanTech } else { $null }

# The naming convention runs with -Roles, or on a bare call (no selection at all), but is skipped on
# a technician-roles-only run so a -TechnicianRoles call never renames policies.
$runNaming = $hasSelection -or (-not $hasTechSelection)

# =============================================================================
# HTTP client
# =============================================================================
$baseUrl           = "https://$Region.ninjarmm.com"
$noderoleUri       = "$baseUrl/swb/s6/noderole"
$noderoleListUri   = "$baseUrl/swb/s6/noderole/list?allRoles=true"
$policyUri         = "$baseUrl/swb/s6/policy"
$policyListUri     = "$baseUrl/swb/s6/policy/list"
$userRolesEndpoint = "$baseUrl/swb/s6/user-roles"
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
if ($hasTechSelection) {
    Write-Host ("Selected technician roles ({0}): {1}" -f $selectedTech.Count, (($selectedTech.Values | ForEach-Object { $_.roleName }) -join ", "))
}
if (-not $hasSelection -and -not $hasTechSelection) {
    Write-Host "No roles selected - enforcing the policy naming convention only."
}
Write-Host ""

# --- Counters & result lists --------------------------------------------------
$rolesCreated = 0
$renamed      = 0
$created      = 0
$skipped      = 0
$failed       = 0
$techCreated  = 0
$techUpdated  = 0
$rolesCreatedNames = [System.Collections.Generic.List[string]]::new()  # created node roles
$renamedNames      = [System.Collections.Generic.List[string]]::new()  # renamed default policies
$createdNames      = [System.Collections.Generic.List[string]]::new()  # created child policies
$techCreatedNames  = [System.Collections.Generic.List[string]]::new()  # created technician roles
$techUpdatedNames  = [System.Collections.Generic.List[string]]::new()  # updated technician roles

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
# Load current policies (needed for passes 2 and 3; skipped on a tech-only run)
# =============================================================================
$allPolicies = $null
if ($runNaming -or $hasSelection) {
    $policyListResp = Invoke-NinjaApi -Method "GET" -Uri $policyListUri
    if ($policyListResp.Code -ge 400) {
        throw "Could not load policy list (HTTP $($policyListResp.Code)). Session key expired? Response: $($policyListResp.Body)"
    }
    $allPolicies = $policyListResp.Body | ConvertFrom-Json
}

# =============================================================================
# Pass 2: enforce the naming convention on the default policies
# =============================================================================
if ($runNaming) {
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
}  # end if ($runNaming)

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
# Pass 4: technician roles (only when -TechnicianRoles is given)
# =============================================================================
# Create-or-update one technician role per selected profile. A full-replace PUT carries the whole
# role envelope, so we GET the existing role first (or POST a new one) to preserve name/type/
# description/members, then PUT the desired grants. Idempotent and -WhatIf-safe.
if ($hasTechSelection) {
    Write-Host "== Technician roles =="

    $techListUri  = "$userRolesEndpoint`?roleType=TECHNICIAN"
    $techListResp = Invoke-NinjaApi -Method "GET" -Uri $techListUri
    if ($techListResp.Code -ge 400) {
        throw "Could not list technician roles (HTTP $($techListResp.Code)). Session key expired? Response: $($techListResp.Body)"
    }
    $existingTechRoles = @($techListResp.Body | ConvertFrom-Json)

    foreach ($kv in $selectedTech.GetEnumerator()) {
        $profileKey    = $kv.Key
        $entry         = $kv.Value
        $roleName      = $entry.roleName
        $desiredTokens = @($entry.grants)

        # Desired grants as a lookup set and as API permission objects.
        $desiredSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($t in $desiredTokens) { [void]$desiredSet.Add($t) }
        $desiredPermissions = foreach ($t in $desiredTokens) {
            $parts = $t.Split("|", 2)
            [ordered]@{ entityId = 0; entityType = $parts[0]; name = $parts[1]; allowed = $true }
        }

        # Resolve the target role by exact (case-insensitive) name.
        $nameMatches = @($existingTechRoles | Where-Object { $_.type -eq "TECHNICIAN" -and $_.name -eq $roleName })
        if ($nameMatches.Count -gt 1) {
            $ids = ($nameMatches | ForEach-Object { $_.id }) -join ", "
            Write-Host ("[ERROR] {0} technician roles named '{1}' (ids: {2}) - skipping (ambiguous)." -f $nameMatches.Count, $roleName, $ids) -ForegroundColor Red
            $failed++
            continue
        }

        $isCreate   = $nameMatches.Count -eq 0
        $currentSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $roleEnv    = $null
        $techId     = 0

        if ($isCreate) {
            $roleEnv = [pscustomobject]@{ name = $roleName; type = "TECHNICIAN"; description = ""; members = @() }
            Write-Host ("No technician role named '{0}' yet - will create it (POST)." -f $roleName)
        }
        else {
            $techId  = [int]$nameMatches[0].id
            $getResp = Invoke-NinjaApi -Method "GET" -Uri ("{0}/{1}" -f $userRolesEndpoint, $techId)
            if ($getResp.Code -ge 400) {
                Write-Host ("[ERROR {0}] could not load role '{1}' (id {2}) - {3}" -f $getResp.Code, $roleName, $techId, $getResp.Body) -ForegroundColor Red
                $failed++
                continue
            }
            $roleEnv = $getResp.Body | ConvertFrom-Json
            if ($roleEnv.type -ne "TECHNICIAN") {
                Write-Host ("[ERROR] role '{0}' (id {1}) is type '{2}', not TECHNICIAN - skipping." -f $roleName, $techId, $roleEnv.type) -ForegroundColor Red
                $failed++
                continue
            }
            foreach ($p in @($roleEnv.permissions)) {
                if ($p.allowed) { [void]$currentSet.Add(("{0}|{1}" -f $p.entityType, $p.name)) }
            }
        }

        # Diff current -> desired.
        $toAdd    = @($desiredTokens | Where-Object { -not $currentSet.Contains($_) } | Sort-Object)
        $toRemove = @($currentSet    | Where-Object { -not $desiredSet.Contains($_) } | Sort-Object)

        if (-not $isCreate -and $toAdd.Count -eq 0 -and $toRemove.Count -eq 0) {
            Write-Host ("[SKIP] '{0}' already carries exactly the '{1}' profile ({2} grants)." -f $roleName, $profileKey, $desiredTokens.Count) -ForegroundColor Yellow
            $skipped++
            continue
        }

        $action = if ($isCreate) {
            "CREATE technician role '{0}' then PUT {1} grants" -f $roleName, $desiredTokens.Count
        } else {
            "PUT {0} grants to '{1}' (add {2}, remove {3})" -f $desiredTokens.Count, $roleName, $toAdd.Count, $toRemove.Count
        }

        if ($PSCmdlet.ShouldProcess($roleName, $action)) {
            if ($isCreate) {
                # Mint the role with an empty permission list; the response body is the new id.
                $createBody = [ordered]@{
                    name              = $roleEnv.name
                    type              = $roleEnv.type
                    description       = $roleEnv.description
                    permissions       = @()
                    members           = @()
                    globalPermissions = @()
                } | ConvertTo-Json -Depth 10 -Compress

                $cr = Invoke-NinjaApi -Method "POST" -Uri $userRolesEndpoint -Body $createBody
                if ($cr.Code -ge 400) {
                    Write-Host ("[ERROR {0}] create '{1}' failed - {2}" -f $cr.Code, $roleName, $cr.Body) -ForegroundColor Red
                    $failed++
                    continue
                }
                $newId = ($cr.Body).Trim().Trim('"')
                if ($newId -notmatch '^\d+$') {
                    Write-Host ("[ERROR] create '{0}' returned no role id: '{1}'" -f $roleName, $cr.Body) -ForegroundColor Red
                    $failed++
                    continue
                }
                $techId = [int]$newId
                Write-Host ("[OK {0}] created technician role '{1}' (id {2})." -f $cr.Code, $roleName, $techId) -ForegroundColor Green
            }

            # Full-replace save: round-trip members untouched so no technician is deassigned.
            $putBody = [ordered]@{
                name              = $roleEnv.name
                type              = $roleEnv.type
                description       = $roleEnv.description
                permissions       = @($desiredPermissions)
                members           = @($roleEnv.members)
                globalPermissions = @()
            } | ConvertTo-Json -Depth 10 -Compress

            $r = Invoke-NinjaApi -Method "PUT" -Uri ("{0}/{1}" -f $userRolesEndpoint, $techId) -Body $putBody
            if ($r.Code -lt 400) {
                if ($isCreate) {
                    Write-Host ("[OK {0}] created + applied '{1}' profile to '{2}' (id {3}, {4} grants)." -f $r.Code, $profileKey, $roleName, $techId, $desiredTokens.Count) -ForegroundColor Green
                    $techCreatedNames.Add($roleName); $techCreated++
                }
                else {
                    Write-Host ("[OK {0}] applied '{1}' profile to '{2}' (id {3}; +{4}/-{5})." -f $r.Code, $profileKey, $roleName, $techId, $toAdd.Count, $toRemove.Count) -ForegroundColor Green
                    $techUpdatedNames.Add($roleName); $techUpdated++
                }
            }
            else {
                Write-Host ("[ERROR {0}] PUT '{1}' failed - {2}" -f $r.Code, $roleName, $r.Body) -ForegroundColor Red
                $failed++
            }
        }
        else {
            if ($isCreate) {
                Write-Host ("[WhatIf] would CREATE technician role '{0}' then PUT {1} grants." -f $roleName, $desiredTokens.Count)
            }
            else {
                Write-Host ("[WhatIf] would PUT {0} grants to '{1}' (add {2}, remove {3})." -f $desiredTokens.Count, $roleName, $toAdd.Count, $toRemove.Count)
            }
        }
    }
    Write-Host ""
}

# =============================================================================
# Summary
# =============================================================================
Write-Host "== Summary =="
if ($techCreatedNames.Count -gt 0) {
    Write-Host ("Created technician roles ({0}):" -f $techCreatedNames.Count)
    foreach ($n in $techCreatedNames) { Write-Host ("  - {0}" -f $n) }
}
if ($techUpdatedNames.Count -gt 0) {
    Write-Host ("Updated technician roles ({0}):" -f $techUpdatedNames.Count)
    foreach ($n in $techUpdatedNames) { Write-Host ("  - {0}" -f $n) }
}
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
if ($rolesCreatedNames.Count -eq 0 -and $renamedNames.Count -eq 0 -and $createdNames.Count -eq 0 -and `
    $techCreatedNames.Count -eq 0 -and $techUpdatedNames.Count -eq 0) {
    Write-Host "Nothing changed - everything already matched the desired state."
}
Write-Host ""
Write-Host ("Done. Node roles: {0}, Renamed: {1}, Child policies: {2}, Tech roles: +{3}/~{4}, Skipped: {5}, Failed: {6}" -f `
    $rolesCreated, $renamed, $created, $techCreated, $techUpdated, $skipped, $failed)
if ($failed -gt 0) { exit 1 }
