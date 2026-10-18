<#
.SYNOPSIS
    Sets the permission set of a NinjaOne technician role in one run - ships escalating
    least-privilege "1st / 2nd / 3rd Level Support" profiles plus a full-access "Sys Admin"
    profile, and applies the chosen one with a single PUT.

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

    The built-in $Profiles catalog holds four permission sets captured from the web UI:
    "1st-level-support", "2nd-level-support" and "3rd-level-support" (escalating least-privilege),
    and "system-administrator" (the complete captured catalog - ALL grants). Adjust that catalog
    (or add another named profile) to change what gets applied - no other code changes needed.

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
    Valid values: "1st-level-support", "2nd-level-support", "3rd-level-support",
    "system-administrator".

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

.EXAMPLE
    .\Set-NinjaTechnicianRole.ps1 -RoleName "2nd Level Support" -ProfileName 2nd-level-support
    Creates (or updates) a "2nd Level Support" technician role with the escalated L2 profile.

.EXAMPLE
    .\Set-NinjaTechnicianRole.ps1 -RoleName "Sys Admin" -ProfileName system-administrator
    Creates (or updates) a full-access "Sys Admin" technician role carrying every captured grant,
    intended to replace the built-in breakglass System Administrator for day-to-day admin work.
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

    # ---------------------------------------------------------------------
    # 2nd Level Support - escalation technician.
    # Everything L1 can do, plus: remediate devices (update / decommission /
    # device approvals / remote registry / secure fields), author scripts and
    # scheduled tasks, edit documentation and IT asset data, and a broader
    # ticketing surface (private comments, SLA, boards view, time tracked).
    # Still read-only on organizations/policies and NO tenant administration.
    # ---------------------------------------------------------------------
    "2nd-level-support" = @(
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

    # ---------------------------------------------------------------------
    # 3rd Level Support - senior / escalation engineer.
    # Full operational control: device lifecycle (create/delete), create &
    # update organizations and policies, full automation/documentation/ITAM,
    # approvals, AI, discovered assets, custom fields and reporting.
    # Deliberately withholds PLATFORM ADMINISTRATION (reserved for Sys Admin):
    # RBAC role administration, integration/MDM/PSA/SaaS-backup/SIEM config,
    # caching, custom tabs, and destructive deletion of orgs/policies.
    # ---------------------------------------------------------------------
    "3rd-level-support" = @(
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

    # ---------------------------------------------------------------------
    # System Administrator -> role name "Sys Admin".
    # The complete captured permission catalog (ALL 208 grants across every
    # entity type). Intended to REPLACE the built-in breakglass System
    # Administrator for day-to-day tenant administration. Apply with:
    #   .\Set-NinjaTechnicianRole.ps1 -RoleName "Sys Admin" -ProfileName system-administrator
    # ---------------------------------------------------------------------
    "system-administrator" = @(
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
