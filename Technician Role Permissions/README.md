# Technician Role Permissions

One PowerShell script that applies a least-privilege permission profile to a NinjaOne **technician
role** in a single run. Ships with a ready-made **1st Level Support** profile.

One script: [`Set-NinjaTechnicianRole.ps1`](Set-NinjaTechnicianRole.ps1).

---

## TL;DR

- Authenticates with a **session cookie** (`sessionKey`) from a logged-in browser session.
- **The session key is NOT stored in the script.** It comes from the `NINJA_SESSION_KEY`
  environment variable or the `-SessionKey` parameter.
- `GET`s the role, then `PUT`s the whole role back with the desired grants. The role envelope
  (name / type / description / **members**) is preserved - members are never deassigned.
- Idempotent: if the role already carries exactly the profile, the `PUT` is skipped. `-WhatIf`
  prints the add/remove diff and sends nothing.

```powershell
$env:NINJA_SESSION_KEY = "<sessionKey-from-browser>"
.\Set-NinjaTechnicianRole.ps1          # applies "1st-level-support" to role id 8
```

---

## The permission model

A technician role's permissions are a **flat list of grants**, each one:

```json
{ "entityId": 0, "entityType": "NODE", "name": "View", "allowed": true }
```

Two things are easy to get wrong:

1. **Access levels are not a single enum.** In the UI "View, run" is one dropdown value, but it is
   stored as **two** grants: `NODE|View` **and** `NODE|Run`. "View, update, create" on a ticket is
   three grants, and so on.
2. **Multi-selects are one grant each.** Every allowed remote tool / remote-access app is its own
   grant, e.g. `NODE|RemoteTools.TaskManager.Access`, `NODE|RemoteAccess.Splashtop.Access`.

Role-type **default** grants (e.g. ticket "View and add public comments") are implied by the role
type and are intentionally **not** stored, so they don't appear in the list.

The save is a full replace: `PUT /swb/s6/user-roles/{id}` always carries the **entire** permission
list (there is no partial PATCH). That's why the script GETs first and round-trips name / type /
description / members unchanged.

---

## The "1st Level Support" profile

A least-privilege profile for a 1st Level Support technician:

| Area | What the profile grants |
| --- | --- |
| **Devices** | View + run; remote tools: Task Manager, File Explorer, Command Line, Services Manager; remote access: Splashtop + NinjaOne Remote |
| **Organizations** | View (read-only) |
| **Policies** | View (see which policy applies, no edits) |
| **Automation Library** | View + run approved automations (no create/delete) |
| **Ticketing** | Create / view / update tickets, comment history, relations (view + manage), mobile access. **No** administrative actions (boards, triggers, SLAs stay with L2/admins) |
| **Documentation** | Read knowledge base, org documentation and templates |
| **IT Asset Management** | Read software licenses and asset fields |
| **System** | Use the mobile app, view contacts, view & schedule reports |

Everything else (uninstall software/patch, backup, SNMP, billing, MDM, approvals, delete anywhere,
admin toggles) is left at **No access**.

The exact grant list lives in the `$Profiles` catalog near the top of the script. Edit that catalog
(or add another named profile) to change what gets applied - no other code changes needed.

---

## Getting the session key

The `sessionKey` is a **short-lived session cookie** from a logged-in NinjaOne session, not an
API token:

1. Sign in to NinjaOne in the browser (e.g. `https://eu.ninjarmm.com`).
2. Open DevTools -> **Application/Storage -> Cookies** -> copy the value of `sessionKey`.
3. Set it as an environment variable (keeps it out of shell history and out of the code):

   ```powershell
   $env:NINJA_SESSION_KEY = "<your-sessionKey>"
   ```

When the session expires you get `401`/`403` back - sign in again and grab the current value.

> The key is like a password: don't commit it, don't post it in tickets/chats.

---

## Usage

Apply the 1st Level Support profile to the default role id (8):

```powershell
.\Set-NinjaTechnicianRole.ps1
```

Dry run - show which grants would be added/removed, send nothing:

```powershell
.\Set-NinjaTechnicianRole.ps1 -RoleId 8 -WhatIf
```

A different role id, one-off session key, different instance:

```powershell
.\Set-NinjaTechnicianRole.ps1 -RoleId 12 -SessionKey "<your-sessionKey>" -Region app
```

---

## Parameters

| Parameter | Required | Default | Description |
| --- | --- | --- | --- |
| `-RoleId` | no | `8` | Numeric id of the technician role (from the role editor URL `#/editor/role/<id>/...`) |
| `-ProfileName` | no | `1st-level-support` | Which profile from the built-in `$Profiles` catalog to apply |
| `-SessionKey` | no | `$env:NINJA_SESSION_KEY` | Session cookie value. If both are missing, the script aborts with a clear message |
| `-Region` | no | `eu` | Instance subdomain (`eu` -> `eu.ninjarmm.com`) |
| `-WhatIf` | no | - | Dry run, prints the diff, sends no request |

---

## How it maps to the API

Discovered from the web UI (the same routes the UI uses); not an official API. Uses .NET
`HttpClient` with `AllowAutoRedirect` disabled, so the session cookie is never sent over an http
redirect.

- `GET /swb/s6/user-roles/{id}` - read the current role (name, type, description, members,
  permissions, globalPermissions).
- **Save** the role: `PUT /swb/s6/user-roles/{id}` with
  `{ "name", "type", "description", "permissions":[…], "members":[…], "globalPermissions":[] }`.
  Returns `204 No Content`.

The script only touches `TECHNICIAN` roles (it refuses any other type) and replaces
`permissions` + `globalPermissions` while preserving the rest of the envelope.

---

## Safety

- Idempotent: re-running after a successful apply reports "nothing to do".
- `members` are round-tripped from the GET, so applying a profile never removes assigned
  technicians from the role.
- `-WhatIf` shows the full add/remove diff before anything is sent.
- Refuses to run against a role whose `type` is not `TECHNICIAN`.
