<#
.SYNOPSIS
    One-shot NinjaOne tenant initial setup: creates the custom node roles, the matching policy
    hierarchy (default-policy naming convention + child policies), the technician permission
    roles (1st/2nd/3rd Level Support + Sys Admin) AND applies monitoring modules (e.g. the
    "hardening" security-monitoring condition set) to the default policies in a single run.

.DESCRIPTION
    Talks to the internal /swb/s6/* endpoints the web UI uses, authenticated with a short-lived
    browser session cookie (sessionKey). -Roles drives the node-role side, -Policies the policy
    hierarchy, -TechnicianRoles the technician-permission side and -Modules the monitoring modules;
    each is optional and independent, so selecting a role no longer forces its policy to be created.
    The script runs in five passes:

      Pass 1 - Node roles (only when -Roles is given)
          Creates one custom node role per selected role.
          POST /swb/s6/noderole

      Pass 2 - Default policy naming convention (when -Policies is given, or on a bare call)
          Renames every built-in default policy to the numbering convention so the whole
          hierarchy stays consistent even for categories without child policies:
              Windows Workstation Policy  ->  0.0 Windows Workstation Policy
              Windows Server Policy       ->  1.0 Windows Server Policy
              Mac / Mac Server / Linux / Linux Server -> 2.0 / 3.0 / 4.0 / 5.0 ...
          PATCH /swb/s6/policy/{id}  { name, description, enabled }
          (Skipped on a roles-only or technician-roles-only run, so neither touches the policies.)

      Pass 3 - Child policies (only when -Policies is given)
          Creates one child policy per selected policy, inheriting everything from that category's
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

      Pass 5 - Monitoring modules (only when -Modules is given)
          Applies curated sets of monitoring conditions to the DEFAULT (parent) policies so every
          child policy inherits them. Modules are embedded directly in this script (no companion data
          file needed) and each condition's display name carries a module-specific prefix:
            - "hardening" - a security-monitoring condition set (Windows Event Log + Windows Service
              conditions), prefix "Hardening - ". Its 'common' set lands on both the Windows
              Workstation (0.0) and Windows Server (1.0) defaults; the 'serverOnly' set is added to
              the Windows Server default as well.
            - "dex" - a Digital Employee Experience set, prefix "DEX - ", applied to the Windows
              Workstation (0.0) default only. Stage 1 is event-only (slow boot / app / driver /
              service startup, slow shutdown, application & system crashes); Stage 2 adds
              performance / health "metric" conditions (high CPU & memory, low disk free space,
              long uptime, degraded SMART status, worn-out battery).
          Each targeted default policy is loaded whole (GET returns { resultCode, policy }), missing
          conditions are merged into content.conditions (keyed by a fresh UUID, deduped by display
          name), the read-only parentPolicyName field is dropped, and the full policy is saved back.
          GET /swb/s6/policy/{id}  ->  PUT /swb/s6/policy/{id}  (full unwrapped policy object)

      Pass 6 - DEX Survey custom fields (only when -Modules includes "dex")
          Provisions the custom fields the "DEX Survey" scripts write to, named so the field names
          line up with the scripts' parameter defaults (device fields) or with the name Pass 8 wires
          into the automation (the global field): latestUserFeedback (Multi-line, device) and
          userFeedbackHistory (WYSIWYG, device), each with Automations = Read/Write so the SYSTEM-run
          DEX scripts can write them; plus systemPerformanceReport (WYSIWYG, GLOBAL / system custom
          field) written WRITE_ONLY by "System Performance Check". The UI default (None) would silently
          block any script write. Custom fields are tenant-wide, so this pass is independent of the
          policy the dex module targets. Idempotent: an existing field (matched by fieldName within
          the same scope) is skipped.
          GET /swb/s6/attributes/node/definitionScope/{NODE|GLOBAL}  ->  POST /swb/s6/attributes/node

      Pass 7 - Import DEX Survey scripts into the tenant library (only when -Modules includes "dex")
          Copies the three DEX Survey scripts (Request User Feedback, Collect User Feedback, System
          Performance Check) from the read-only NinjaOne global template library into the tenant's own
          Automation library so they can be scheduled. Each template is loaded whole (code +
          scriptVariables + uid) and POSTed to the tenant library carrying sourceGlobalScriptUid.
          Idempotent: a tenant script already linked to the same template or sharing its name is reused.
          GET /swb/s6/global-scripting/scripts[/{id}]  +  GET/POST /swb/s6/scripting/scripts

      Pass 8 - Wire DEX Survey as a scheduled automation (only when -Modules includes "dex")
          Schedules the three imported scripts as ONE ordered actionset ("DEX Survey") on the Windows
          Workstation default policy (same policy Pass 5 targets), so every workstation child policy
          inherits it. Runs weekly (Monday 10:00 local); scripts run in order (Request as the logged-on
          user, then Collect and Performance as SYSTEM). Script 3's "WYSIWYG Custom Field Name" variable
          is pointed at the global systemPerformanceReport field from Pass 6. The entry is spliced into
          policy.content.actionsetSchedules (idempotent on actionsetScheduleName) and the whole policy
          is saved back. GET /swb/s6/policy/{id}  ->  PUT /swb/s6/policy/{id}

    A child policy links to its parent ONLY via parentPolicyId and inherits the parent's settings;
    it is not tied to the custom node role, so the policy passes do not depend on the role pass. This
    is why -Roles and -Policies are independent: pass the same keys to both to get node roles AND
    their policies, or just one of them to get only that side.

    Fully idempotent and -WhatIf-safe: existing node roles are skipped, defaults already carrying
    the convention name are left alone, an already-existing child is skipped, a technician role
    already carrying exactly its profile is skipped, and a module condition already present on a
    default policy (matched by display name) is not re-added. Safe to re-run.

    The sessionKey is a short-lived session cookie from a logged-in browser session. Once it
    expires you get 401/403 back - sign in again in the browser and pass the current value.

    Privileged writes (Pass 5 conditions, Pass 8 automation) are MFA-gated: without an elevated
    session they answer HTTP 406 with { resultCode:"MFA_REQUIRED", loginToken, mfaType:"TOTP" }.
    Passing -MfaCode (the current TOTP) lets the script elevate non-interactively - on the first
    406 it re-sends the request to "{url}/mfa" with the loginToken plus the code, exactly as the web
    UI does. One successful step-up lifts the whole session for a short window, covering the run.

.PARAMETER Roles
    Optional. One or more device roles to create as custom node roles (Pass 1 only - no policies).
    Group keywords (server-all, workstation-all, testlab) and/or individual short keys
    (comma-separated), e.g. -Roles server-all,testworkstation.

.PARAMETER Policies
    Optional. One or more device roles to create as child policies (Pass 3), independent of -Roles.
    Same keyword/short-key grammar as -Roles, e.g. -Policies server-all,testworkstation. Giving
    -Policies also enforces the default-policy naming convention (Pass 2). Omit -Roles, -Policies and
    -TechnicianRoles entirely to only enforce the naming convention without creating anything.

.PARAMETER TechnicianRoles
    Optional. One or more technician permission profiles to create-or-update (Pass 4). Profile keys
    (comma-separated): 1st-level-support, 2nd-level-support, 3rd-level-support, system-administrator;
    or the group keyword tech-all. Each profile maps to a fixed role name (e.g. system-administrator
    -> "Sys Admin"). A technician-roles-only run does not touch the policy hierarchy.

.PARAMETER Modules
    Optional. One or more monitoring modules to apply to the default (parent) policies (Pass 5).
    Supported values (comma-separated): hardening (a curated security-monitoring condition set,
    prefixed "Hardening - ", applied to the Workstation and Server defaults) and dex (a Digital
    Employee Experience set, prefixed "DEX - ", applied to the Workstation default only; event-based
    stage 1 plus performance / health metric conditions in stage 2). e.g. -Modules hardening,dex.
    Selecting "dex" also (a) provisions the DEX Survey custom fields (Pass 6): latestUserFeedback
    (Multi-line, device) and userFeedbackHistory (WYSIWYG, device), each with Automations = Read/Write,
    plus systemPerformanceReport (WYSIWYG, global/system) written WRITE_ONLY; (b) imports the three
    DEX Survey scripts into the tenant library (Pass 7); and (c) wires them as one weekly scheduled
    automation ("DEX Survey") on the Windows Workstation default policy (Pass 8). A modules-only run
    loads the policies but does not rename them or create node roles / child policies / technician roles.

.PARAMETER SessionKey
    The sessionKey cookie value from the logged-in NinjaOne browser session.
    If omitted, the script reads the NINJA_SESSION_KEY environment variable.
    The key is intentionally NOT stored in the script (secret).

.PARAMETER MfaCode
    Optional. The current 6-digit MFA (TOTP) code for the signed-in user. Privileged writes
    (applying monitoring conditions in Pass 5, wiring the scheduled automation in Pass 8) answer
    HTTP 406 (MFA_REQUIRED) until the session is elevated. When supplied, the script performs the
    same step-up the web UI does: on the first 406 it re-sends the request to "{url}/mfa" with the
    one-time loginToken from the 406 plus this code. A successful step-up elevates the whole session
    for a short window, so one code generated immediately before the run normally covers every gated
    write. If omitted, those writes fail with 406 and the response explains MFA is required.
    If omitted, the script reads the NINJA_MFA_CODE environment variable. NEVER hardcode it (secret,
    and it expires within ~30 seconds).

.PARAMETER Region
    The NinjaOne instance subdomain (e.g. 'eu', 'app', 'us2'). Default: eu.

.PARAMETER WhatIf
    Shows what would be created/renamed/applied without sending anything.

.EXAMPLE
    $env:NINJA_SESSION_KEY = "<sessionKey-from-browser>"
    .\Initialize-NinjaTenant.ps1 -Roles server-all
    Creates the five Windows Server node roles only - no policies are touched.

.EXAMPLE
    .\Initialize-NinjaTenant.ps1 -Policies server-all
    Renames every default policy to the convention and creates one child policy per server role
    (1.1 .. 1.5) - without creating any node role.

.EXAMPLE
    .\Initialize-NinjaTenant.ps1 -Roles server-all -Policies server-all
    Full server setup: the five node roles AND their five child policies (plus the naming convention).

.EXAMPLE
    .\Initialize-NinjaTenant.ps1
    No selection: only renames every built-in default policy to the convention (0.0, 1.0, 2.0, ...).

.EXAMPLE
    .\Initialize-NinjaTenant.ps1 -TechnicianRoles tech-all
    Creates (or updates) all four technician roles - 1st/2nd/3rd Level Support and Sys Admin -
    without touching the policy hierarchy.

.EXAMPLE
    .\Initialize-NinjaTenant.ps1 -TechnicianRoles system-administrator
    Creates (or updates) the full-access "Sys Admin" technician role (all 208 grants).

.EXAMPLE
    .\Initialize-NinjaTenant.ps1 -Modules hardening
    Applies the curated "hardening" monitoring conditions to the Windows Workstation and Windows
    Server default policies (so every child policy inherits them) - nothing else is touched.

.EXAMPLE
    .\Initialize-NinjaTenant.ps1 -Modules hardening,dex
    Applies the "hardening" set (Workstation + Server defaults) and the "dex" performance/stability
    set (Workstation default only) so every child policy inherits them - nothing else is touched.

.EXAMPLE
    .\Initialize-NinjaTenant.ps1 -Modules dex -MfaCode 123456
    Applies the full "dex" module (conditions, custom fields, script import, scheduled automation).
    Because those are MFA-gated writes, the current TOTP is passed so the script elevates the session
    non-interactively on the first 406. Generate the code immediately before running (it expires fast).

.EXAMPLE
    .\Initialize-NinjaTenant.ps1 -Roles server-all -Policies server-all -TechnicianRoles tech-all -Modules hardening,dex -WhatIf
    Dry run of the full tenant setup: node roles, policy renames, child policies, all four
    technician roles and both monitoring modules (hardening + dex) - sends nothing.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    # Optional: device roles to create as custom node roles (Pass 1). Does NOT create any policies.
    [Parameter(Position = 0)]
    [string[]] $Roles = @(),

    # Optional: device roles to create as child policies (Pass 3). Independent of -Roles.
    [Parameter()]
    [string[]] $Policies = @(),

    # Optional: technician permission profiles to create-or-update (Pass 4).
    [Parameter()]
    [string[]] $TechnicianRoles = @(),

    # Optional: monitoring modules to apply to the default (parent) policies (Pass 5).
    # Currently supported: "hardening" (a curated set of security monitoring conditions).
    [Parameter()]
    [string[]] $Modules = @(),

    [Parameter()]
    [string] $SessionKey = $env:NINJA_SESSION_KEY,

    # Optional: current 6-digit MFA (TOTP) code. Privileged writes (e.g. applying monitoring
    # conditions in Pass 5, wiring scheduled automations in Pass 8) answer HTTP 406
    # (MFA_REQUIRED) until the session is elevated. Supplying the TOTP lets the script elevate
    # the session non-interactively: on the first 406 it re-sends the request to "{uri}/mfa"
    # with the one-time loginToken plus this code. NinjaOne then elevates the whole session for
    # a short window, so a single code generated right before the run normally covers every
    # gated write. NEVER hardcode this - pass it at runtime (or via $env:NINJA_MFA_CODE).
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

# --- Resolve selections (all optional) ----------------------------------------
# -Roles drives node roles only (Pass 1); -Policies drives the policy hierarchy (Pass 3). They are
# independent, so selecting a role no longer forces its policy to be created.
$cleanRoles       = @($Roles | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
$hasRoleSelection = $cleanRoles.Count -gt 0
$selectedRoles    = if ($hasRoleSelection) { Resolve-NinjaRoleSelection -Roles $cleanRoles } else { $null }

$cleanPolicies      = @($Policies | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
$hasPolicySelection = $cleanPolicies.Count -gt 0
$selectedPolicies   = if ($hasPolicySelection) { Resolve-NinjaRoleSelection -Roles $cleanPolicies } else { $null }

$cleanTech        = @($TechnicianRoles | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
$hasTechSelection = $cleanTech.Count -gt 0
$selectedTech     = if ($hasTechSelection) { Resolve-NinjaTechnicianSelection -Keys $cleanTech } else { $null }

# -Modules drives monitoring modules applied to the default (parent) policies (Pass 5).
$SupportedModules  = @("hardening", "dex")
$cleanModules      = @($Modules | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique)
$unknownModules    = @($cleanModules | Where-Object { $SupportedModules -notcontains $_ })
if ($unknownModules.Count -gt 0) {
    throw ("Unknown -Modules value(s): {0}. Supported: {1}." -f ($unknownModules -join ", "), ($SupportedModules -join ", "))
}
$hasModuleSelection = $cleanModules.Count -gt 0

# The naming convention runs with -Policies, or on a bare call (no selection at all). It is skipped on
# a roles-only or technician-roles-only run so neither touches the policy hierarchy.
$runNaming = $hasPolicySelection -or (-not $hasRoleSelection -and -not $hasTechSelection -and -not $hasModuleSelection)

# =============================================================================
# HTTP client
# =============================================================================
$baseUrl           = "https://$Region.ninjarmm.com"
$noderoleUri       = "$baseUrl/swb/s6/noderole"
$noderoleListUri   = "$baseUrl/swb/s6/noderole/list?allRoles=true"
$policyUri         = "$baseUrl/swb/s6/policy"
$policyListUri     = "$baseUrl/swb/s6/policy/list"
$userRolesEndpoint = "$baseUrl/swb/s6/user-roles"
$attributesNodeUri        = "$baseUrl/swb/s6/attributes/node"                         # POST create a custom field (device or global)
$attributesNodeListUri    = "$baseUrl/swb/s6/attributes/node/definitionScope/NODE"    # GET list device (NODE) custom fields
$attributesGlobalListUri  = "$baseUrl/swb/s6/attributes/node/definitionScope/GLOBAL"  # GET list global/system custom fields
$globalScriptsUri         = "$baseUrl/swb/s6/global-scripting/scripts"                # GET NinjaOne template library (list + /{id} detail)
$scriptsUri               = "$baseUrl/swb/s6/scripting/scripts"                       # GET tenant script library / POST import a script
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

# Tracks whether an MFA step-up has already succeeded this run (for the summary only).
$script:MfaElevated = $false

# The one-time TOTP currently available for a step-up. Seeded from -MfaCode; a TOTP is single-use,
# so it is cleared after every step-up attempt (success or failure) and refilled interactively when
# another challenge appears mid-run.
$script:CurrentMfaCode = if ([string]::IsNullOrWhiteSpace($MfaCode)) { $null } else { $MfaCode.Trim() }

# True only when stdin is an interactive console, i.e. the script may Read-Host a fresh code. In a
# pipe/CI (input redirected) prompting would hang, so we fail fast with guidance instead.
function Test-NinjaCanPrompt {
    try { if ([System.Console]::IsInputRedirected) { return $false } } catch { return $false }
    return $true
}

# Ask the operator for a fresh TOTP. Returns $null (never blocks) when input is non-interactive.
function Get-NinjaMfaCode {
    param([string] $Prompt)
    if (-not (Test-NinjaCanPrompt)) { return $null }
    try { return (Read-Host -Prompt $Prompt) } catch { return $null }
}

# Sends one request and transparently handles NinjaOne's MFA step-up. Privileged writes
# answer HTTP 406 with a body like
#   { "resultCode":"MFA_REQUIRED", "loginToken":"<uuid>", "mfaType":"TOTP", ... }
# The web UI then re-saves the same model to "{url}/mfa" with the one-time loginToken and the
# user's TOTP (mfaCode) merged into the body. We replicate exactly that: on a 406, if -MfaCode
# was supplied, re-send the identical request to "{Uri}/mfa" with loginToken + mfaCode added at
# the top level of the JSON body. A successful elevation lifts the whole session for a short
# window, so subsequent writes in the same run simply return < 400 and never reach this branch.
function Invoke-NinjaApi {
    param(
        [Parameter(Mandatory)] [string] $Method,
        [Parameter(Mandatory)] [string] $Uri,
        [string] $Body
    )
    $resp = Invoke-NinjaApiRaw -Method $Method -Uri $Uri -Body $Body
    if ($resp.Code -ne 406) { return $resp }

    # A 406 may be NinjaOne's MFA step-up challenge. The session elevation that a step-up grants is
    # time-windowed, so a long run can be challenged more than once - and a TOTP is single-use, so a
    # single supplied code cannot answer every challenge. Loop: elevate with the code we currently
    # hold; whenever that code is spent/expired, ask the operator for a fresh one (interactive) and
    # retry against a brand-new loginToken. In a non-interactive shell we stop with guidance instead.
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

        # Merge the current body (an object) with loginToken + mfaCode. -AsHashtable keeps the nested
        # structure intact; booleans/nulls/numbers round-trip through ConvertTo-Json. The body carries
        # the full model (plus loginToken/mfaCode) exactly as the UI sends it, but NinjaOne reads the
        # step-up credentials from the QUERY STRING (token, mfacode) - captured from the UI's own
        # request: PUT {url}/mfa?token=<loginToken>&mfacode=<TOTP>.
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

        # Code rejected (expired/used/wrong). If we cannot ask for another one, stop with guidance.
        if (-not (Test-NinjaCanPrompt)) {
            throw ("MFA step-up rejected (HTTP $($elevated.Code)). The one-time code was expired, " +
                "already used, or wrong, and stdin is not interactive so no fresh code can be " +
                "requested. TOTP codes live ~30s and are single-use: generate a fresh code " +
                "immediately before the run, or run in an interactive terminal so the script can " +
                "prompt for a fresh code when challenged.")
        }
        Write-Host "MFA code rejected (HTTP $($elevated.Code)) - it was expired or already used. Enter a fresh one." -ForegroundColor Yellow
        # Re-trigger the original request to obtain a brand-new loginToken for the next attempt.
        $resp = Invoke-NinjaApiRaw -Method $Method -Uri $Uri -Body $Body
        if ($resp.Code -ne 406) { return $resp }
    }
}

# Prime the MFA step-up up front. A single successful step-up elevates the whole session
# server-side (bound to the sessionKey), so every later gated write then returns < 400. Doing
# that step-up lazily - only on the first gated write in Pass 5 - forces the one-time TOTP to
# survive the ~25 preceding setup calls (node roles, renames, child policies) and it often
# expires first. Instead we spend the fresh code immediately: a no-op policy PUT (re-sends the
# model unchanged, so changedSections stays empty and nothing is persisted) answers 406 while
# un-elevated, and Invoke-NinjaApi performs the step-up on the spot (throwing fail-fast if the
# code is rejected). If the session is already elevated the no-op simply returns 200. Only runs
# when a code was supplied; if the policy list cannot be loaded it silently defers to the lazy path.
function Enter-NinjaMfaElevation {
    # Front-load the single step-up whenever we have a code or can prompt for one. Nothing to do if
    # no code was supplied and we also cannot ask for one interactively (the lazy path handles it).
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

# Build one fully-formed monitoring condition in the shape NinjaOne persists inside
# policy.content.conditions (keyed by a UUID). Three condition types are supported:
#   - "event"   : a Windows Event Log condition    (conditionUid = event GUID)
#   - "service" : a Windows Service state condition (conditionUid = service GUID)
#   - "metric"  : a performance / health condition (CPU, Memory, Disk Free Space,
#                 System Uptime, SMART, Battery, ...). Every metric type has its own
#                 conditionUid and its own parameters shape, so the caller supplies a
#                 pre-built -Parameters hashtable (and -ConditionName) verbatim.
# The type is carried by conditionUid; parameters define the specific condition.
function Build-ModuleCondition {
    param(
        [Parameter(Mandatory)] [ValidateSet("event", "service", "metric")] [string] $Type,
        [Parameter(Mandatory)] [string] $DisplayName,
        [string[]] $EventIds,
        [string[]] $Include,
        [string] $EventSource,
        [int] $ResetThreshold = 14400,
        [string] $ConditionHealthStatus = "NEEDS_ATTENTION",
        [int] $AlertingDelayMinutes = 3,
        [Parameter(Mandatory)] [string] $ConditionUid,
        # "metric" only: the exact conditionName and parameters NinjaOne persists for
        # this condition type, plus an optional top-level trigger-uptime delay (seconds).
        # IDictionary accepts both Hashtable and the OrderedHashtable that
        # ConvertFrom-Json -AsHashtable produces, without a lossy re-coercion.
        [string] $ConditionName,
        [System.Collections.IDictionary] $Parameters,
        [int] $TriggerUptimeSeconds = 0
    )

    $cond = [ordered]@{
        enabled               = $true
        displayName           = $DisplayName
        conditionName         = $null
        conditionUid          = $ConditionUid
        resetThreshold        = $ResetThreshold
        ticketingAction       = "NONE"
        notificationAction    = "NONE"
        parameters            = $null
        ticketRulesetId       = "NONE"
        createNinjaTicket     = $false
        useGlobalHealthStatus = $true
        conditionHealthStatus = $ConditionHealthStatus
        scripts               = @()
        packName              = $null
        inheritance           = [ordered]@{
            inherited        = $false
            dynamic          = $false
            overridden       = $false
            sourcePolicyId   = $null
            sourcePolicyName = ""
        }
    }

    if ($Type -eq "event") {
        $cond.conditionName = 'Event "all" is triggered'
        $cond.parameters = [ordered]@{
            state      = "STOPPED"
            source     = $EventSource
            eventIds   = @($EventIds)
            textValues = @()
            contain    = "do"
            include    = "all"
        }
    }
    elseif ($Type -eq "metric") {
        # Performance / health condition: the caller hands over the verbatim
        # conditionName and parameters captured from NinjaOne, so the builder only
        # wraps the shared envelope. Disk Free Space carries a top-level trigger delay.
        $cond.conditionName           = $ConditionName
        $cond.parameters              = $Parameters
        $cond.resetIfNotPresentSeconds = 0
        $cond.notifyOnReset            = $false
        if ($TriggerUptimeSeconds -gt 0) { $cond.triggerUptimeSeconds = $TriggerUptimeSeconds }
    }
    else {
        $joined = ($Include -join " OR ")
        $cond.conditionName = ("Windows Service {0} is Down. Start alerting after {1} minutes" -f $joined, $AlertingDelayMinutes)
        $cond.parameters = [ordered]@{
            include                                    = @($Include)
            state                                      = "STOPPED"
            triggerConditionAgainIfStillTrueAfterReset = $false
            ignoreIfServiceIsDisabled                  = $false
            ignoreIfServiceIsManual                    = $false
            alertingDelay                              = $AlertingDelayMinutes
            alertingDelayTimeUnit                      = "MINUTE"
        }
        $cond.resetIfNotPresentSeconds = 0
        $cond.notifyOnReset            = $false
    }

    return $cond
}

Write-Host "Target: $baseUrl"
if ($hasRoleSelection) {
    Write-Host ("Selected node roles ({0}): {1}" -f $selectedRoles.Count, (($selectedRoles.Values | ForEach-Object { $_.name }) -join ", "))
}
if ($hasPolicySelection) {
    Write-Host ("Selected policies ({0}): {1}" -f $selectedPolicies.Count, (($selectedPolicies.Values | ForEach-Object { $_.name }) -join ", "))
}
if ($hasTechSelection) {
    Write-Host ("Selected technician roles ({0}): {1}" -f $selectedTech.Count, (($selectedTech.Values | ForEach-Object { $_.roleName }) -join ", "))
}
if ($hasModuleSelection) {
    Write-Host ("Selected modules ({0}): {1}" -f $cleanModules.Count, ($cleanModules -join ", "))
}
if (-not $hasRoleSelection -and -not $hasPolicySelection -and -not $hasTechSelection -and -not $hasModuleSelection) {
    Write-Host "No selection - enforcing the policy naming convention only."
}
Write-Host ""

# Elevate the session now, while the supplied TOTP is still fresh, so gated writes later in the
# run never have to race the code's ~30s lifetime.
Enter-NinjaMfaElevation

# --- Counters & result lists --------------------------------------------------
$rolesCreated = 0
$renamed      = 0
$created      = 0
$skipped      = 0
$failed       = 0
$techCreated  = 0
$techUpdated  = 0
$modulesApplied = 0
$customFieldsCreated = 0
$scriptsImported  = 0
$automationsWired = 0
$rolesCreatedNames = [System.Collections.Generic.List[string]]::new()  # created node roles
$renamedNames      = [System.Collections.Generic.List[string]]::new()  # renamed default policies
$createdNames      = [System.Collections.Generic.List[string]]::new()  # created child policies
$techCreatedNames  = [System.Collections.Generic.List[string]]::new()  # created technician roles
$techUpdatedNames  = [System.Collections.Generic.List[string]]::new()  # updated technician roles
$moduleNames       = [System.Collections.Generic.List[string]]::new()  # "<module> -> <policy> (+N)" for applied conditions
$customFieldNames  = [System.Collections.Generic.List[string]]::new()  # "<fieldName> (<type>)" for created custom fields
$scriptLibNames    = [System.Collections.Generic.List[string]]::new()  # "<name> (id <n>)" for imported DEX Survey scripts
$automationNames   = [System.Collections.Generic.List[string]]::new()  # "<automation> -> <policy>" for wired scheduled automations

# =============================================================================
# Pass 1: create custom node roles (only when -Roles is given)
# =============================================================================
if ($hasRoleSelection) {
    Write-Host "== Node roles =="

    $roleListResp = Invoke-NinjaApi -Method "GET" -Uri $noderoleListUri
    if ($roleListResp.Code -ge 400) {
        throw "Could not load node role list (HTTP $($roleListResp.Code)). Session key expired? Response: $($roleListResp.Body)"
    }
    $existingRoles = @($roleListResp.Body | ConvertFrom-Json)

    foreach ($role in $selectedRoles.Values) {
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
if ($runNaming -or $hasPolicySelection -or $hasModuleSelection) {
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
if ($hasPolicySelection) {
    Write-Host "== Child policies for selected policies =="
    foreach ($nodeClass in $CategoryMeta.Keys) {
        $rolesInClass = @($selectedPolicies.Values | Where-Object { $_.nodeClass -eq $nodeClass })
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
# Pass 5: apply monitoring modules to the DEFAULT (parent) policies so every
#         child policy inherits them (only when -Modules is given).
#         Supported modules: "hardening" (security), "dex" (Digital Employee
#         Experience).
# =============================================================================
# Every module's curated condition set is embedded directly in this script (see the
# here-strings below), so a single .ps1 is all you need to run - no companion data
# file. For each target nodeClass we load the full policy object (GET returns
# { resultCode, policy }), add any missing conditions into content.conditions
# (keyed by a fresh UUID, deduped by displayName so re-runs are idempotent), drop
# the read-only parentPolicyName field, then PUT the whole unwrapped policy back.
# The apply logic below is module-agnostic: it is driven by $moduleCatalog, so
# adding a module is just another embedded here-string plus a catalog entry.
if ($hasModuleSelection) {

    # Curated hardening condition set — embedded as a here-string so the script is
    # fully self-contained (no external data file needed). 'common' goes on both the
    # Windows Workstation (0.0) and Windows Server (1.0) default policies; 'serverOnly'
    # is added to the Windows Server default only.
    $hardeningJson = @'
{
  "prefix": "🛡️ Hardening - ",
  "eventSource": "Microsoft-Windows-Security-Auditing",
  "resetThreshold": 14400,
  "conditionHealthStatus": "NEEDS_ATTENTION",
  "alertingDelayMinutes": 3,
  "conditionUid": {
    "event": "b979707b-b370-40bc-b3bf-d498953ed8a2",
    "service": "347443f1-c019-423c-8ab0-2f8ece3908d6"
  },
  "common": {
    "events": [
      { "name": "Windows Security Event Log Cleared", "eventIds": ["1102"] },
      { "name": "Windows Security Event Log is Full", "eventIds": ["1104"] },
      { "name": "Windows Firewall Service Stopped", "eventIds": ["5025", "5034"] },
      { "name": "Windows Firewall Security Policy Issue", "eventIds": ["5027", "5028", "5029"] },
      { "name": "Windows Firewall Failed", "eventIds": ["5030", "5035", "5037"] },
      { "name": "Change Made to Windows Firewall Exceptions", "eventIds": ["4946", "4947", "4948"] },
      { "name": "Windows Firewall Settings Changed", "eventIds": ["4950", "4951", "4854", "4956"] },
      { "name": "DoS Attack Detected via Windows Filtering Platform", "eventIds": ["5148"] },
      { "name": "Windows Filtering Platform Blocked a Packet", "eventIds": ["5150", "5151", "5152", "5153"] },
      { "name": "Windows Filtering Platform Blocked a Connection", "eventIds": ["5155", "5157", "5159"] },
      { "name": "Image File Hashes Incorrect", "eventIds": ["5038", "6281"] },
      { "name": "User Account Created or Enabled", "eventIds": ["4720", "4722"] },
      { "name": "User Account Disabled or Deleted", "eventIds": ["4725", "4726"] },
      { "name": "User Account Password Change or Reset", "eventIds": ["4723", "4724"] },
      { "name": "User Account Failed to Login", "eventIds": ["4625"] },
      { "name": "User Account Locked Out", "eventIds": ["4740", "6279"] },
      { "name": "User Account Unlocked", "eventIds": ["4767", "6280"] },
      { "name": "Security-Enabled Group Created", "eventIds": ["4727", "4731", "4754"] },
      { "name": "Security-Enabled Group Changed", "eventIds": ["4735", "4737"] },
      { "name": "Security-Enabled Group Deleted", "eventIds": ["4730", "4734", "4758"] },
      { "name": "Member Added to Security-Enabled Group", "eventIds": ["4728", "4732", "4756"] },
      { "name": "Member Removed From Security-Enabled Group", "eventIds": ["4729", "4733", "4757"] },
      { "name": "Security Group's Type Changed", "eventIds": ["4764"] },
      { "name": "Failed Login Attempts: Event ID 2", "eventIds": ["4777"] },
      { "name": "Failed Login Attempts: Event ID 1", "eventIds": ["4625"] }
    ],
    "services": [
      { "name": "Windows Defender: Service Down", "include": ["windefend", "mpssvc", "MsMpEng", "Windows Defender Service"] },
      { "name": "Windows Security Center Service is Down", "include": ["wscvsvc"] },
      { "name": "Windows Security Account Manager is Down", "include": ["SamSs"] }
    ]
  },
  "serverOnly": {
    "events": [
      { "name": "Domain Controller Failed to Validate Credentials", "eventIds": ["4777"] }
    ],
    "services": [
      { "name": "Windows Server Update Services", "include": ["WSUSservice"] }
    ]
  }
}
'@

    # Curated DEX (Digital Employee Experience) condition set — workstation-only.
    #   Stage 1 ("workstation") is event-only: slow boot / app / driver / service
    #     startup, slow shutdown, and application/system crashes that degrade day-to-
    #     day usability. Each event carries its own log 'source' (they span several
    #     providers), overriding the module-level eventSource (null here).
    #   Stage 2 ("workstationStage2") adds performance / health "metric" conditions:
    #     high CPU / memory, low disk free space, long uptime (no reboot), degraded
    #     SMART status and worn-out battery. Each metric type has its own conditionUid
    #     and a verbatim parameters block captured from NinjaOne.
    $dexJson = @'
{
  "prefix": "💻 DEX - ",
  "eventSource": null,
  "resetThreshold": 14400,
  "conditionHealthStatus": "NEEDS_ATTENTION",
  "alertingDelayMinutes": 3,
  "conditionUid": {
    "event": "b979707b-b370-40bc-b3bf-d498953ed8a2",
    "service": "347443f1-c019-423c-8ab0-2f8ece3908d6"
  },
  "workstation": {
    "events": [
      { "name": "Slow Boot", "source": "Microsoft-Windows-Diagnostics-Performance", "eventIds": ["100"] },
      { "name": "Slow Application Startup", "source": "Microsoft-Windows-Diagnostics-Performance", "eventIds": ["101"] },
      { "name": "Slow Driver Initialization", "source": "Microsoft-Windows-Diagnostics-Performance", "eventIds": ["102"] },
      { "name": "Slow Service Startup", "source": "Microsoft-Windows-Diagnostics-Performance", "eventIds": ["103"] },
      { "name": "Slow Shutdown", "source": "Microsoft-Windows-Diagnostics-Performance", "eventIds": ["200"] },
      { "name": "Application Crash", "source": "Application Error", "eventIds": ["1000"] },
      { "name": "Application Hang", "source": "Application Hang", "eventIds": ["1002"] },
      { "name": "Unexpected Shutdown", "source": "EventLog", "eventIds": ["6008"] },
      { "name": "Unexpected Power Loss or System Crash", "source": "Microsoft-Windows-Kernel-Power", "eventIds": ["41"] },
      { "name": "Blue Screen Crash (Bugcheck)", "source": "BugCheck", "eventIds": ["1001"] }
    ]
  },
  "workstationStage2": {
    "metrics": [
      {
        "name": "High CPU Usage",
        "conditionUid": "61147e9c-c5bd-4f3a-ac98-b5ecfc9ab579",
        "conditionName": "Aggregate CPU Usage is greater than or equal to 90 % for 5 minutes",
        "parameters": { "duration": 5, "operator": "GE", "threshold": 90, "unit": "PERCENT" }
      },
      {
        "name": "High Memory Usage",
        "conditionUid": "223bbcc1-83d4-48a0-8ae5-546573b61fea",
        "conditionName": "Memory Usage is greater than or equal to 90 % for 5 minutes",
        "parameters": { "duration": 5, "operator": "GE", "threshold": 90, "unit": "PERCENT" }
      },
      {
        "name": "Long Uptime (No Reboot)",
        "conditionUid": "7f19f7b2-b2ff-42fb-8a8a-7e0c1fb67ff1",
        "conditionName": "Device has not rebooted in 14 day(s)",
        "parameters": { "threshold": 14 }
      },
      {
        "name": "Low Disk Free Space",
        "conditionUid": "1045af6c-c6b8-4049-bbf4-5a92e422ca6d",
        "conditionName": "Disk Free Space is less than or equal to 10% for 30 minutes, start alerting after 10 minutes",
        "parameters": { "duration": 30, "operator": "LE", "threshold": 10, "unit": "PERCENT", "bootVolumeOnly": false, "volumeLabelsMode": "EXCLUDE", "exclude": ["RECOVERY_VOLUME", "REMOVABLE_DISK"], "include": [] },
        "triggerUptimeSeconds": 600
      },
      {
        "name": "Disk SMART Status Degraded",
        "conditionUid": "0ffc1334-2ced-45f5-bec2-4ddba88a5ff6",
        "conditionName": "Windows SMART Status Degraded",
        "parameters": { "checkPredFail": false }
      },
      {
        "name": "Degraded Battery Health",
        "conditionUid": "6a626396-d869-43d9-b813-e21422f6bbea",
        "conditionName": "Battery Monitoring: Battery Capacity is less than 50%",
        "parameters": { "appliedCondition": "BATTERY_CAPACITY", "operator": "LT", "threshold": 50, "unit": "PERCENT" }
      }
    ]
  }
}
'@

    # Module catalog: key -> (human title, embedded JSON, nodeClass -> buckets map).
    # Only the modules named in -Modules run, in this stable order. Adding a module
    # later means one more here-string above plus one more entry here.
    $moduleCatalog = @(
        [pscustomobject]@{
            Key     = "hardening"
            Title   = "Hardening monitoring conditions"
            Json    = $hardeningJson
            Targets = [ordered]@{ WINDOWS_WORKSTATION = @("common"); WINDOWS_SERVER = @("common", "serverOnly") }
        }
        [pscustomobject]@{
            Key     = "dex"
            Title   = "DEX (Digital Employee Experience) monitoring conditions"
            Json    = $dexJson
            Targets = [ordered]@{ WINDOWS_WORKSTATION = @("workstation", "workstationStage2") }
        }
    )

    foreach ($module in $moduleCatalog) {
        if ($cleanModules -notcontains $module.Key) { continue }
        Write-Host ("== {0} (default policies) ==" -f $module.Title)

        $def = $null
        try { $def = $module.Json | ConvertFrom-Json -AsHashtable -Depth 100 } catch { }
        if (-not $def) {
            Write-Host ("[ERROR] Could not parse the embedded '{0}' definition." -f $module.Key) -ForegroundColor Red
            $failed++
            Write-Host ""
            continue
        }

        $prefix        = [string]$def.prefix
        $defaultSource = [string]$def.eventSource
        $resetThresh   = [int]$def.resetThreshold
        $healthStatus  = [string]$def.conditionHealthStatus
        $alertMinutes  = [int]$def.alertingDelayMinutes
        $eventUid      = [string]$def.conditionUid.event
        $serviceUid    = [string]$def.conditionUid.service
        $moduleTargets = $module.Targets

        foreach ($nodeClass in $moduleTargets.Keys) {
            $default = $allPolicies | Where-Object { $_.nodeClass -eq $nodeClass -and $_.nodeClassDefault -eq $true } | Select-Object -First 1
            if (-not $default) {
                Write-Host ("[WARN] No default policy found for nodeClass '{0}' - skipping {1}." -f $nodeClass, $module.Key) -ForegroundColor Yellow
                continue
            }

            # Collect the condition definitions that apply to this nodeClass. Buckets only
            # carry the kinds they need (e.g. DEX stage 1 has events only, stage 2 metrics
            # only), so read each kind with index access: ConvertFrom-Json -AsHashtable
            # yields an OrderedHashtable whose missing-key DOT access throws under
            # Set-StrictMode, whereas ['key'] safely returns $null.
            $eventDefs   = [System.Collections.Generic.List[object]]::new()
            $serviceDefs = [System.Collections.Generic.List[object]]::new()
            $metricDefs  = [System.Collections.Generic.List[object]]::new()
            foreach ($bucket in $moduleTargets[$nodeClass]) {
                $b = $def[$bucket]
                if (-not $b) { continue }
                if ($b['events'])   { foreach ($e in $b['events'])   { $eventDefs.Add($e) } }
                if ($b['services']) { foreach ($s in $b['services']) { $serviceDefs.Add($s) } }
                if ($b['metrics'])  { foreach ($m in $b['metrics'])  { $metricDefs.Add($m) } }
            }

            # Load the full policy object (GET returns { resultCode, policy }).
            $getResp = Invoke-NinjaApi -Method "GET" -Uri ("{0}/{1}" -f $policyUri, $default.id)
            if ($getResp.Code -ge 400) {
                Write-Host ("[ERROR {0}] could not load policy '{1}' (id {2}) - {3}" -f $getResp.Code, $default.name, $default.id, $getResp.Body) -ForegroundColor Red
                $failed++
                continue
            }
            $policyWrap = $getResp.Body | ConvertFrom-Json -AsHashtable -Depth 100
            $policy = $policyWrap.policy
            if (-not $policy) {
                Write-Host ("[ERROR] policy payload missing for '{0}' (id {1})." -f $default.name, $default.id) -ForegroundColor Red
                $failed++
                continue
            }

            if (-not $policy.content)            { $policy.content = [ordered]@{} }
            if (-not $policy.content.conditions) { $policy.content.conditions = [ordered]@{} }
            $conditions = $policy.content.conditions

            # Existing displayNames -> idempotency (skip conditions already present).
            $existingNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($c in $conditions.Values) {
                if ($c.displayName) { [void]$existingNames.Add([string]$c.displayName) }
            }

            $addedThisPolicy   = 0
            $skippedThisPolicy = 0

            foreach ($e in $eventDefs) {
                $displayName = $prefix + [string]$e.name
                if ($existingNames.Contains($displayName)) { $skippedThisPolicy++; continue }
                # Per-event source wins over the module default (DEX events span providers).
                # Index access: hardening events carry no 'source' key, and a missing-key
                # DOT access on the OrderedHashtable would throw under Set-StrictMode.
                $evSource = if ($e['source']) { [string]$e['source'] } else { $defaultSource }
                $cond = Build-ModuleCondition -Type "event" -DisplayName $displayName `
                    -EventIds @($e.eventIds) -EventSource $evSource `
                    -ResetThreshold $resetThresh -ConditionHealthStatus $healthStatus `
                    -AlertingDelayMinutes $alertMinutes -ConditionUid $eventUid
                $conditions[[guid]::NewGuid().ToString()] = $cond
                [void]$existingNames.Add($displayName)
                $addedThisPolicy++
            }

            foreach ($s in $serviceDefs) {
                $displayName = $prefix + [string]$s.name
                if ($existingNames.Contains($displayName)) { $skippedThisPolicy++; continue }
                $cond = Build-ModuleCondition -Type "service" -DisplayName $displayName `
                    -Include @($s.include) `
                    -ResetThreshold $resetThresh -ConditionHealthStatus $healthStatus `
                    -AlertingDelayMinutes $alertMinutes -ConditionUid $serviceUid
                $conditions[[guid]::NewGuid().ToString()] = $cond
                [void]$existingNames.Add($displayName)
                $addedThisPolicy++
            }

            foreach ($m in $metricDefs) {
                $displayName = $prefix + [string]$m['name']
                if ($existingNames.Contains($displayName)) { $skippedThisPolicy++; continue }
                # Each metric type carries its own conditionUid and a verbatim parameters
                # block; only Disk Free Space carries a top-level triggerUptimeSeconds, so
                # read it with index access (missing-key DOT access throws under StrictMode).
                $trig = if ($m['triggerUptimeSeconds']) { [int]$m['triggerUptimeSeconds'] } else { 0 }
                $cond = Build-ModuleCondition -Type "metric" -DisplayName $displayName `
                    -ConditionName ([string]$m['conditionName']) -Parameters $m['parameters'] `
                    -TriggerUptimeSeconds $trig `
                    -ResetThreshold $resetThresh -ConditionHealthStatus $healthStatus `
                    -ConditionUid ([string]$m['conditionUid'])
                $conditions[[guid]::NewGuid().ToString()] = $cond
                [void]$existingNames.Add($displayName)
                $addedThisPolicy++
            }

            $skipped += $skippedThisPolicy

            if ($addedThisPolicy -eq 0) {
                Write-Host ("[OK] '{0}' already has all {1} {2} conditions." -f $policy.name, $skippedThisPolicy, $module.Key) -ForegroundColor DarkGray
                continue
            }

            # PUT body is the full, unwrapped policy object; parentPolicyName is read-only.
            if ($policy.Contains('parentPolicyName')) { [void]$policy.Remove('parentPolicyName') }
            $putBody = $policy | ConvertTo-Json -Depth 100

            if ($PSCmdlet.ShouldProcess($policy.name, ("PUT add {0} {1} conditions" -f $addedThisPolicy, $module.Key))) {
                $r = Invoke-NinjaApi -Method "PUT" -Uri ("{0}/{1}" -f $policyUri, $default.id) -Body $putBody
                if ($r.Code -lt 400) {
                    Write-Host ("[OK {0}] '{1}' +{2} {3} conditions ({4} already present)" -f $r.Code, $policy.name, $addedThisPolicy, $module.Key, $skippedThisPolicy) -ForegroundColor Green
                    $modulesApplied += $addedThisPolicy
                    $moduleNames.Add(("{0} -> {1}  (+{2})" -f $module.Key, $policy.name, $addedThisPolicy))
                }
                else {
                    Write-Host ("[ERROR {0}] '{1}' - {2}" -f $r.Code, $policy.name, $r.Body) -ForegroundColor Red
                    $failed++
                }
            }
            else {
                Write-Host ("[WhatIf] PUT '{0}'  +{1} {2} conditions ({3} already present)" -f $policy.name, $addedThisPolicy, $module.Key, $skippedThisPolicy)
            }
        }
        Write-Host ""
    }
}

# =============================================================================
# Pass 6: DEX Survey custom fields (only when -Modules includes "dex")
# =============================================================================
# The "DEX Survey" scripts from the NinjaOne script template library ("Request User
# Feedback", "Collect User Feedback", "System Performance Check") persist their results
# into custom fields via Ninja-Property-Set. Those scripts run under SYSTEM (or the
# logged-on user), and a script write only succeeds if the field's Automations permission
# allows writing; the UI default is None, which silently blocks the write. This pass
# provisions the fields the DEX Survey scripts write to, named so the field names line up
# with the scripts' own parameter defaults (device fields) or with the name Pass 8 wires
# into the automation (the global field):
#   - latestUserFeedback    (Multi-line, NODE)   <- "Collect User Feedback" $MultilineCustomFieldName
#   - userFeedbackHistory   (WYSIWYG,    NODE)   <- "Collect User Feedback" $WYSIWYGCustomFieldName
#   - systemPerformanceReport (WYSIWYG, GLOBAL)  <- "System Performance Check" $WYSIWYGCustomFieldName (wired in Pass 8)
# The first two are DEVICE (NODE) fields, scriptPermission Read/Write (SYSTEM scripts
# write them). The third is a GLOBAL / system custom field (Administration > General >
# System custom fields), written WRITE_ONLY by "System Performance Check" - that script's
# WYSIWYG target has no prescribed default name, so we create the field here and point the
# scheduled automation (Pass 8) at it by name. Custom fields are tenant-wide (not policy-
# scoped), so this pass is independent of which default policy the dex module (Pass 5)
# targets. Idempotent: an existing field (matched by fieldName within the same scope,
# case-insensitive) is skipped.
#   GET  /swb/s6/attributes/node/definitionScope/NODE     (existing device fields - idempotency)
#   GET  /swb/s6/attributes/node/definitionScope/GLOBAL   (existing global fields - idempotency)
#   POST /swb/s6/attributes/node                           (create one missing field)
if ($hasModuleSelection -and ($cleanModules -contains "dex")) {
    Write-Host "== DEX Survey custom fields =="

    # The fields the DEX Survey scripts write to, named exactly as the scripts expect.
    # attributeType drives the field type; advancedSettings is WYSIWYG-only (null otherwise).
    # scope selects the field's definitionScope (NODE = per-device, GLOBAL = system-level);
    # scriptPermission is the Automations permission (READ_WRITE lets scripts read+write,
    # WRITE_ONLY lets them only write - enough for a report field the script only fills).
    $dexCustomFields = @(
        [ordered]@{ fieldName = "latestUserFeedback";      label = "Latest User Feedback";      attributeType = "TEXT_MULTILINE"; advancedSettings = $null;                                              scope = "NODE";   scriptPermission = "READ_WRITE" }
        [ordered]@{ fieldName = "userFeedbackHistory";     label = "User Feedback History";     attributeType = "WYSIWYG";        advancedSettings = [ordered]@{ expandLargeValueOnRender = $false };     scope = "NODE";   scriptPermission = "READ_WRITE" }
        [ordered]@{ fieldName = "systemPerformanceReport"; label = "System Performance Report"; attributeType = "WYSIWYG";        advancedSettings = [ordered]@{ expandLargeValueOnRender = $false };     scope = "GLOBAL"; scriptPermission = "WRITE_ONLY" }
    )

    # Existing custom fields per scope -> case-insensitive sets of field names for idempotency.
    # A field name can legitimately exist in both scopes, so each scope is tracked separately.
    $existingByScope = @{
        NODE   = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        GLOBAL = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    }
    $cfListOk = $true
    foreach ($scopePair in @(@{ Scope = "NODE"; Uri = $attributesNodeListUri }, @{ Scope = "GLOBAL"; Uri = $attributesGlobalListUri })) {
        $cfListResp = Invoke-NinjaApi -Method "GET" -Uri $scopePair.Uri
        if ($cfListResp.Code -ge 400) {
            Write-Host ("[ERROR {0}] could not list {1} custom fields - {2}" -f $cfListResp.Code, $scopePair.Scope, $cfListResp.Body) -ForegroundColor Red
            $failed++
            $cfListOk = $false
            continue
        }
        foreach ($f in @($cfListResp.Body | ConvertFrom-Json)) {
            if ($f.PSObject.Properties['fieldName'] -and $f.fieldName) { [void]$existingByScope[$scopePair.Scope].Add([string]$f.fieldName) }
        }
    }

    if ($cfListOk) {
        foreach ($spec in $dexCustomFields) {
            $scope     = [string]$spec['scope']
            $scopeWord = if ($scope -eq "GLOBAL") { "global custom field" } else { "device custom field" }
            if ($existingByScope[$scope].Contains($spec['fieldName'])) {
                Write-Host ("[skip] {0} '{1}' already exists" -f $scopeWord, $spec['fieldName']) -ForegroundColor DarkGray
                continue
            }

            # Create body captured verbatim from the web UI's POST; scriptPermission
            # (Automations) lets the DEX scripts write the field, definitionScope selects
            # device (NODE) vs global/system (GLOBAL).
            $content = [ordered]@{
                values           = @()
                required         = $false
                footerText       = ""
                tooltipText      = ""
                advancedSettings = $spec['advancedSettings']
            }
            $createBody = [ordered]@{
                addToDefaultTab       = $true
                name                  = $spec['label']
                fieldName             = $spec['fieldName']
                attributeType         = $spec['attributeType']
                description           = ""
                defaultValue          = $null
                technicianOption      = "OPTIONAL"
                scriptPermission      = $spec['scriptPermission']   # Automations permission (lets DEX scripts write)
                apiPermission         = "NONE"
                technicianPermission  = "EDITABLE"
                technicianPermissions = @()
                definitionScope       = @($scope)
                content               = $content
                attributeScope        = "NODE_ROLE"
            } | ConvertTo-Json -Depth 8

            if ($PSCmdlet.ShouldProcess($spec['fieldName'], "POST create $scopeWord ($($spec['attributeType']))")) {
                $r = Invoke-NinjaApi -Method "POST" -Uri $attributesNodeUri -Body $createBody
                if ($r.Code -lt 400) {
                    Write-Host ("[OK {0}] created {1} '{2}' ({3})" -f $r.Code, $scopeWord, $spec['fieldName'], $spec['attributeType']) -ForegroundColor Green
                    $customFieldsCreated++
                    $customFieldNames.Add(("{0} ({1}, {2})" -f $spec['fieldName'], $spec['attributeType'], $scope))
                }
                else {
                    Write-Host ("[ERROR {0}] '{1}' - {2}" -f $r.Code, $spec['fieldName'], $r.Body) -ForegroundColor Red
                    $failed++
                }
            }
            else {
                Write-Host ("[WhatIf] POST create {0} '{1}' ({2})" -f $scopeWord, $spec['fieldName'], $spec['attributeType'])
            }
        }
    }
    Write-Host ""
}

# =============================================================================
# Pass 7: import the DEX Survey scripts into the tenant script library
#         (only when -Modules includes "dex")
# =============================================================================
# The three DEX Survey scripts live in the NinjaOne global template library (read-only,
# shared across tenants). To schedule them in a policy they must first be copied into the
# tenant's OWN Automation library. For each template script we GET its full definition
# (code + scriptVariables + uid), then POST it to the tenant library, carrying
# sourceGlobalScriptUid so NinjaOne records the template it came from. Idempotent: a tenant
# script already linked to the same template (sourceGlobalScriptUid) or sharing its name is
# reused, not re-imported. The resulting numeric tenant script ids feed Pass 8.
#   GET  /swb/s6/global-scripting/scripts        (template library list - resolve by name)
#   GET  /swb/s6/global-scripting/scripts/{id}   (full template definition)
#   GET  /swb/s6/scripting/scripts               (tenant library - idempotency)
#   POST /swb/s6/scripting/scripts               (import one script)
$dexImportedScripts = [ordered]@{}   # template-name -> @{ id; name; runAs; scriptVariables }
if ($hasModuleSelection -and ($cleanModules -contains "dex")) {
    Write-Host "== DEX Survey scripts (import into tenant library) =="

    # The three template scripts, in run order, with the account each should run under in
    # the scheduled automation (Pass 8). runAs: "loggedonuser" = Current Logged-on User
    # (Script 1 prompts the user interactively); "system" = SYSTEM (Scripts 2 and 3 run
    # unattended). The import itself always lands defaultRunAs = system (verified value); the
    # per-script run context is set on the automation, not the library copy.
    $dexScriptSpecs = @(
        [ordered]@{ name = "DEX Survey - Script 1 - Request User Feedback";   runAs = "loggedonuser" }
        [ordered]@{ name = "DEX Survey - Script 2 - Collect User Feedback";    runAs = "system" }
        [ordered]@{ name = "DEX Survey - Script 3 - System Performance Check"; runAs = "system" }
    )

    $tmplResp   = Invoke-NinjaApi -Method "GET" -Uri $globalScriptsUri
    $tenantResp = Invoke-NinjaApi -Method "GET" -Uri $scriptsUri
    if ($tmplResp.Code -ge 400) {
        Write-Host ("[ERROR {0}] could not list the template library - {1}" -f $tmplResp.Code, $tmplResp.Body) -ForegroundColor Red
        $failed++
    }
    elseif ($tenantResp.Code -ge 400) {
        Write-Host ("[ERROR {0}] could not list the tenant script library - {1}" -f $tenantResp.Code, $tenantResp.Body) -ForegroundColor Red
        $failed++
    }
    else {
        $tmplScripts   = @($tmplResp.Body | ConvertFrom-Json)
        $tenantScripts = @($tenantResp.Body | ConvertFrom-Json)

        foreach ($spec in $dexScriptSpecs) {
            $tmpl = $tmplScripts | Where-Object { $_.name -eq $spec['name'] } | Select-Object -First 1
            if (-not $tmpl) {
                Write-Host ("[WARN] template script '{0}' not found in the library - skipping." -f $spec['name']) -ForegroundColor Yellow
                continue
            }
            $tmplUid = if ($tmpl.PSObject.Properties['uid'] -and $tmpl.uid) { [string]$tmpl.uid } else { "" }

            # Load the full template definition (code + scriptVariables); needed both to
            # import and to wire the variables in Pass 8.
            $detailResp = Invoke-NinjaApi -Method "GET" -Uri ("{0}/{1}" -f $globalScriptsUri, $tmpl.id)
            if ($detailResp.Code -ge 400) {
                Write-Host ("[ERROR {0}] could not load template '{1}' (id {2}) - {3}" -f $detailResp.Code, $spec['name'], $tmpl.id, $detailResp.Body) -ForegroundColor Red
                $failed++
                continue
            }
            $detail    = $detailResp.Body | ConvertFrom-Json
            $tmplVars  = if ($detail.PSObject.Properties['scriptVariables'] -and $detail.scriptVariables) { @($detail.scriptVariables) } else { @() }

            # Idempotency: reuse a tenant script already imported from this template
            # (sourceGlobalScriptUid match) or sharing its exact name.
            $existing = $tenantScripts | Where-Object {
                ($_.PSObject.Properties['sourceGlobalScriptUid'] -and $_.sourceGlobalScriptUid -and ([string]$_.sourceGlobalScriptUid -eq $tmplUid)) -or
                ($_.name -eq $spec['name'])
            } | Select-Object -First 1

            if ($existing) {
                Write-Host ("[skip] '{0}' already in the tenant library (id {1})" -f $spec['name'], $existing.id) -ForegroundColor DarkGray
                $dexImportedScripts[$spec['name']] = [ordered]@{ id = [int]$existing.id; name = $spec['name']; runAs = $spec['runAs']; scriptVariables = $tmplVars }
                continue
            }

            # Build the import body (schema captured verbatim from the web UI's POST).
            $importBody = [ordered]@{
                architecture                      = @($detail.architecture)
                categoriesIds                     = @($detail.categoriesIds)
                code                              = [string]$detail.code
                defaultRunAs                      = "system"
                description                       = [string]$detail.description
                language                          = [string]$detail.language
                name                              = $spec['name']
                operatingSystems                  = @($detail.operatingSystems)
                scriptParameters                  = @()
                scriptVariables                   = $tmplVars
                sourceGlobalScriptUid             = $tmplUid
                useFirstParametersOptionAsDefault = $false
            } | ConvertTo-Json -Depth 20

            if ($PSCmdlet.ShouldProcess($spec['name'], "POST import DEX script into tenant library")) {
                $r = Invoke-NinjaApi -Method "POST" -Uri $scriptsUri -Body $importBody
                if ($r.Code -lt 400) {
                    $new   = $r.Body | ConvertFrom-Json
                    $newId = if ($new.PSObject.Properties['id'] -and $new.id) { [int]$new.id } else { 0 }
                    Write-Host ("[OK {0}] imported '{1}' (id {2})" -f $r.Code, $spec['name'], $newId) -ForegroundColor Green
                    $scriptsImported++
                    $scriptLibNames.Add(("{0} (id {1})" -f $spec['name'], $newId))
                    $dexImportedScripts[$spec['name']] = [ordered]@{ id = $newId; name = $spec['name']; runAs = $spec['runAs']; scriptVariables = $tmplVars }
                }
                else {
                    Write-Host ("[ERROR {0}] import '{1}' - {2}" -f $r.Code, $spec['name'], $r.Body) -ForegroundColor Red
                    $failed++
                }
            }
            else {
                Write-Host ("[WhatIf] POST import DEX script '{0}' into tenant library" -f $spec['name'])
                # Placeholder (id 0) so Pass 8 can still render its -WhatIf plan.
                $dexImportedScripts[$spec['name']] = [ordered]@{ id = 0; name = $spec['name']; runAs = $spec['runAs']; scriptVariables = $tmplVars }
            }
        }
    }
    Write-Host ""
}

# =============================================================================
# Pass 8: wire the DEX Survey scripts as a scheduled automation on the Windows
#         Workstation default policy (only when -Modules includes "dex")
# =============================================================================
# "Weg B": the three imported scripts are scheduled as ONE ordered actionset ("DEX Survey")
# on the Windows Workstation default policy - consistent with Pass 5, which adds the DEX
# conditions to that same policy - so every workstation child policy inherits it. The three
# scripts run in order (Request -> Collect -> Performance) weekly (Monday 10:00 local, so the
# interactive Script 1 lands in working hours). Script 3's "WYSIWYG Custom Field Name" variable
# is pointed at the global systemPerformanceReport field created in Pass 6. Scheduled automations
# live in policy.content.actionsetSchedules (keyed by UUID); we GET the policy, splice in one
# entry (idempotent on actionsetScheduleName), drop the read-only parentPolicyName, then PUT the
# whole unwrapped policy back.
#   GET /swb/s6/policy/{id}  ->  PUT /swb/s6/policy/{id}
if ($hasModuleSelection -and ($cleanModules -contains "dex")) {
    Write-Host "== DEX Survey scheduled automation (Windows Workstation default policy) =="

    $automationName = "DEX Survey"
    $perfFieldName  = "systemPerformanceReport"   # the global WYSIWYG field from Pass 6

    # Weekly schedule - the object always carries every field; scheduleType selects which
    # apply (weekDays for WEEKLY, dayOfMonth for MONTHLY, ...).
    $dexSchedule = [ordered]@{
        scheduleType   = "WEEKLY"
        weekDays       = @("MON")
        scheduleHour   = 10
        scheduleMinute = 0
        dayOfMonth     = 1
        timeZone       = "_Local"
    }

    # The three scripts, in run order; all three are required to wire the actionset.
    $orderedDexNames = @(
        "DEX Survey - Script 1 - Request User Feedback"
        "DEX Survey - Script 2 - Collect User Feedback"
        "DEX Survey - Script 3 - System Performance Check"
    )
    $missingDex = @($orderedDexNames | Where-Object { -not $dexImportedScripts.Contains($_) })
    if ($missingDex.Count -gt 0) {
        Write-Host ("[WARN] not all DEX scripts are available ({0} missing) - skipping automation wiring." -f $missingDex.Count) -ForegroundColor Yellow
    }
    else {
        $wsDefault = $allPolicies | Where-Object { $_.nodeClass -eq "WINDOWS_WORKSTATION" -and $_.nodeClassDefault -eq $true } | Select-Object -First 1
        if (-not $wsDefault) {
            Write-Host "[WARN] No default Windows Workstation policy found - skipping automation wiring." -ForegroundColor Yellow
        }
        else {
            $getResp = Invoke-NinjaApi -Method "GET" -Uri ("{0}/{1}" -f $policyUri, $wsDefault.id)
            if ($getResp.Code -ge 400) {
                Write-Host ("[ERROR {0}] could not load policy '{1}' (id {2}) - {3}" -f $getResp.Code, $wsDefault.name, $wsDefault.id, $getResp.Body) -ForegroundColor Red
                $failed++
            }
            else {
                $policyWrap = $getResp.Body | ConvertFrom-Json -AsHashtable -Depth 100
                $policy = $policyWrap.policy
                if (-not $policy) {
                    Write-Host ("[ERROR] policy payload missing for '{0}' (id {1})." -f $wsDefault.name, $wsDefault.id) -ForegroundColor Red
                    $failed++
                }
                else {
                    if (-not $policy.content)                    { $policy.content = [ordered]@{} }
                    if (-not $policy.content.actionsetSchedules) { $policy.content.actionsetSchedules = [ordered]@{} }
                    $schedules = $policy.content.actionsetSchedules

                    # Idempotency: an entry already named "DEX Survey" means it is wired.
                    $alreadyWired = $false
                    foreach ($entry in $schedules.Values) {
                        if ($entry['actionsetScheduleName'] -and ([string]$entry['actionsetScheduleName'] -eq $automationName)) { $alreadyWired = $true; break }
                    }

                    if ($alreadyWired) {
                        Write-Host ("[OK] '{0}' already has the '{1}' scheduled automation." -f $policy.name, $automationName) -ForegroundColor DarkGray
                    }
                    else {
                        # Build the ordered scripts array. Each carries its run context (runAs)
                        # and its scriptVariables (value = template default), with Script 3's
                        # "WYSIWYG Custom Field Name" pointed at the global report field.
                        $scriptEntries = foreach ($nm in $orderedDexNames) {
                            $imp  = $dexImportedScripts[$nm]
                            $vars = @()
                            foreach ($v in @($imp['scriptVariables'])) {
                                $hasDefault = $v.PSObject.Properties['defaultValue'] -and ($null -ne $v.defaultValue)
                                $val = if ($hasDefault) { [string]$v.defaultValue } else { "" }
                                if ($v.name -eq "WYSIWYG Custom Field Name") { $val = $perfFieldName }
                                $vars += [ordered]@{
                                    name           = [string]$v.name
                                    calculatedName = [string]$v.calculatedName
                                    type           = [string]$v.type
                                    value          = $val
                                    source         = "LITERAL"
                                    valueList      = @()
                                    required       = [bool]$v.required
                                    description    = if ($v.PSObject.Properties['description'] -and $v.description) { [string]$v.description } else { "" }
                                    defaultValue   = if ($hasDefault) { [string]$v.defaultValue } else { $null }
                                }
                            }
                            [ordered]@{
                                scriptName      = "Run " + $nm
                                scriptId        = [int]$imp['id']
                                parameters      = [ordered]@{ runAs = [string]$imp['runAs']; scriptParam = "" }
                                scriptVariables = @($vars)
                            }
                        }

                        $schedules[[guid]::NewGuid().ToString()] = [ordered]@{
                            enabled                      = $true
                            actionsetScheduleName        = $automationName
                            actionsetScheduleDescription = ""
                            ticketingAction              = "NONE"
                            notificationAction           = "NONE"
                            ticketTemplateId             = $null
                            inheritance                  = [ordered]@{ inherited = $false; overridden = $false; sourcePolicyId = $null }
                            schedule                     = $dexSchedule
                            scripts                      = @($scriptEntries)
                        }

                        if ($policy.Contains('parentPolicyName')) { [void]$policy.Remove('parentPolicyName') }
                        $putBody = $policy | ConvertTo-Json -Depth 100

                        if ($PSCmdlet.ShouldProcess($policy.name, "PUT wire '$automationName' scheduled automation (weekly, 3 scripts)")) {
                            $r = Invoke-NinjaApi -Method "PUT" -Uri ("{0}/{1}" -f $policyUri, $wsDefault.id) -Body $putBody
                            if ($r.Code -lt 400) {
                                Write-Host ("[OK {0}] '{1}' <- '{2}' scheduled automation (3 scripts, weekly)" -f $r.Code, $policy.name, $automationName) -ForegroundColor Green
                                $automationsWired++
                                $automationNames.Add(("{0} -> {1}" -f $automationName, $policy.name))
                            }
                            else {
                                Write-Host ("[ERROR {0}] '{1}' - {2}" -f $r.Code, $policy.name, $r.Body) -ForegroundColor Red
                                $failed++
                            }
                        }
                        else {
                            Write-Host ("[WhatIf] PUT wire '{0}' scheduled automation on '{1}' (3 scripts, weekly)" -f $automationName, $policy.name)
                        }
                    }
                }
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
if ($moduleNames.Count -gt 0) {
    Write-Host ("Module conditions applied to default policies ({0}):" -f $moduleNames.Count)
    foreach ($n in $moduleNames) { Write-Host ("  - {0}" -f $n) }
}
if ($customFieldNames.Count -gt 0) {
    Write-Host ("Created custom fields ({0}):" -f $customFieldNames.Count)
    foreach ($n in $customFieldNames) { Write-Host ("  - {0}" -f $n) }
}
if ($scriptLibNames.Count -gt 0) {
    Write-Host ("Imported DEX Survey scripts ({0}):" -f $scriptLibNames.Count)
    foreach ($n in $scriptLibNames) { Write-Host ("  - {0}" -f $n) }
}
if ($automationNames.Count -gt 0) {
    Write-Host ("Wired scheduled automations ({0}):" -f $automationNames.Count)
    foreach ($n in $automationNames) { Write-Host ("  - {0}" -f $n) }
}
if ($script:MfaElevated) {
    Write-Host "MFA: session elevated via -MfaCode (step-up accepted)." -ForegroundColor Cyan
}
if ($rolesCreatedNames.Count -eq 0 -and $renamedNames.Count -eq 0 -and $createdNames.Count -eq 0 -and `
    $techCreatedNames.Count -eq 0 -and $techUpdatedNames.Count -eq 0 -and $moduleNames.Count -eq 0 -and `
    $customFieldNames.Count -eq 0 -and $scriptLibNames.Count -eq 0 -and $automationNames.Count -eq 0) {
    Write-Host "Nothing changed - everything already matched the desired state."
}
Write-Host ""
Write-Host ("Done. Node roles: {0}, Renamed: {1}, Child policies: {2}, Tech roles: +{3}/~{4}, Modules: +{5}, Custom fields: +{6}, Scripts: +{7}, Automations: +{8}, Skipped: {9}, Failed: {10}" -f `
    $rolesCreated, $renamed, $created, $techCreated, $techUpdated, $modulesApplied, $customFieldsCreated, $scriptsImported, $automationsWired, $skipped, $failed)
if ($failed -gt 0) { exit 1 }
