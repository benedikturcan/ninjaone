# NinjaOne Initial Setup

One PowerShell script that bootstraps a fresh NinjaOne tenant in a single run: it creates the
custom **node roles** and the matching **policy hierarchy** (default-policy naming convention +
child policies) from a `-Roles` selection, and the **technician permission roles** (1st/2nd/3rd
Level Support + Sys Admin) from a `-TechnicianRoles` selection.

One script: [`Initialize-NinjaTenant.ps1`](Initialize-NinjaTenant.ps1).

---

## TL;DR

- Authenticates with a **session cookie** (`sessionKey`) from a logged-in browser session.
- **The session key is NOT stored in the script.** It comes from the `NINJA_SESSION_KEY`
  environment variable or the `-SessionKey` parameter.
- `-Roles` and `-TechnicianRoles` are both **optional**: `-Roles server-all` for all server roles
  (or short keys `sql,terminal`, …); `-TechnicianRoles tech-all` for all four technician profiles
  (or individual keys).
- Four passes in one run:
  1. **Node roles** (only with `-Roles`): one custom node role per selected role.
  2. **Default policy naming** (with `-Roles`, or on a bare call): renames every built-in default
     policy to the convention (`0.0`, `1.0`, `2.0`, …). Skipped on a technician-roles-only run.
  3. **Child policies** (only with `-Roles`): one child policy per selected role, inheriting from
     its default.
  4. **Technician roles** (only with `-TechnicianRoles`): create-or-update one technician role per
     selected permission profile.
- Idempotent: existing roles, already-renamed defaults, already-existing children and technician
  roles already carrying their profile are skipped. `-WhatIf` for a safe dry run.

```powershell
$env:NINJA_SESSION_KEY = "<sessionKey-from-browser>"
.\Initialize-NinjaTenant.ps1 -Roles server-all
.\Initialize-NinjaTenant.ps1 -TechnicianRoles tech-all
```

---

## Available roles

**Windows Server** roles (under parent `WINDOWS_SERVER`, `nodeRoleParentId = 1`):

| Short key | Role created |
| --- | --- |
| `datev` | Windows Server - DATEV |
| `sql` | Windows Server - SQL Server |
| `terminal` | Windows Server - Terminal Server |
| `application` | Windows Server - Application Server |
| `file` | Windows Server - File Server |
| `testserver` | Windows Server - Test Server |

**Windows Workstation** roles (under parent `WINDOWS_WORKSTATION`, `nodeRoleParentId = 2`):

| Short key | Role created |
| --- | --- |
| `homeoffice` | Workstation - Home Office |
| `vip` | Workstation - VIP |
| `testworkstation` | Workstation - Test Workstation |

**Group keywords:**

| Keyword | Expands to |
| --- | --- |
| `server-all` | `datev, sql, terminal, application, file` |
| `workstation-all` | `homeoffice, vip` |
| `testlab` | `testserver, testworkstation` |

---

## Technician roles

`-TechnicianRoles` create-or-updates NinjaOne **technician** roles from four built-in permission
profiles, captured 1:1 from the live permission editor and forming a strict escalation
(**L1 ⊆ L2 ⊆ L3 ⊆ Sys Admin**). Each profile maps to a fixed role name:

| Profile key (`-TechnicianRoles`) | Role created/updated | Grants | For whom |
| --- | --- | --- | --- |
| `1st-level-support` | 1st Level Support | 27 | Helpdesk / dispatch - read + run + ticket handling |
| `2nd-level-support` | 2nd Level Support | 92 | Field technician - remediate devices, author scripts & docs |
| `3rd-level-support` | 3rd Level Support | 150 | Senior / escalation engineer - full operations, no platform admin |
| `system-administrator` | Sys Admin | 208 | The complete catalog - replaces the breakglass System Administrator |

**Group keyword:** `tech-all` expands to all four profiles.

A technician role's permissions are a **flat list of grants** (`{ entityId, entityType, name,
allowed }`). An access level like "View, run" is stored as **two** grants (`NODE|View` + `NODE|Run`),
and every allowed remote tool / remote-access app is its own grant. The save is a full replace
(`PUT /swb/s6/user-roles/{id}`), so Pass 4 GETs the role first (or POSTs a new one) and round-trips
its name / type / description / **members** - applying a profile never deassigns technicians. NinjaOne
has no custom "System Administrator" *role type*, so `system-administrator` is a `TECHNICIAN` role
granted every permission.

```powershell
.\Initialize-NinjaTenant.ps1 -TechnicianRoles system-administrator   # just the Sys Admin role
.\Initialize-NinjaTenant.ps1 -TechnicianRoles tech-all               # all four roles
```

The exact grant lists live in the `$TechnicianRoleCatalog` near the top of the script - edit that
catalog (or add another named profile) to change what gets applied, no other code changes needed.

---

## Policy naming convention

Each category (`nodeClass`) gets a **major** number. The built-in default policy becomes
`{major}.0`, every child policy for a role becomes `{major}.{minor}`:

| Category (`nodeClass`) | Major | Default policy is renamed to |
| --- | --- | --- |
| `WINDOWS_WORKSTATION` | 0 | `0.0 Windows Workstation Policy` |
| `WINDOWS_SERVER` | 1 | `1.0 Windows Server Policy` |
| `MAC` | 2 | `2.0 Mac Policy` |
| `MAC_SERVER` | 3 | `3.0 Mac Server Policy` |
| `LINUX_WORKSTATION` | 4 | `4.0 Linux Policy` |
| `LINUX_SERVER` | 5 | `5.0 Linux Server Policy` |

Child policies count up per category. Example for `-Roles terminal,sql`:

```
1.0 Windows Server Policy                       (default, renamed)
 └─ 1.1 Windows Server Policy - Terminal Server (child, inherits from 1.0)
 └─ 1.2 Windows Server Policy - SQL Server      (child, inherits from 1.0)
```

The child name is `{major}.{minor} {base} - {role}`, where `{role}` is the role name with its
category prefix stripped (e.g. `Windows Server - Terminal Server` → `Terminal Server`).

> Only the Windows categories (0, 1) have roles today. Mac/Linux majors are reserved so they
> slot in cleanly once those roles exist - see "Adding more roles" below.

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

Full setup for all server roles (roles + renames + child policies `1.1`, `1.2`, …):

```powershell
.\Initialize-NinjaTenant.ps1 -Roles server-all
```

Only enforce the naming convention on the default policies (no roles, no child policies):

```powershell
.\Initialize-NinjaTenant.ps1
```

Only selected roles:

```powershell
.\Initialize-NinjaTenant.ps1 -Roles sql,terminal
```

Mix groups and individual roles:

```powershell
.\Initialize-NinjaTenant.ps1 -Roles server-all,testworkstation,testserver
```

Dry run - shows the planned roles, renames and child creates, sends nothing:

```powershell
.\Initialize-NinjaTenant.ps1 -Roles server-all -WhatIf
```

Technician roles only (no device roles, no policy renames):

```powershell
.\Initialize-NinjaTenant.ps1 -TechnicianRoles tech-all
```

Everything in one run - device roles, policy hierarchy and technician roles:

```powershell
.\Initialize-NinjaTenant.ps1 -Roles server-all -TechnicianRoles tech-all
```

Session key for a single run, and a different instance:

```powershell
.\Initialize-NinjaTenant.ps1 -Roles sql -SessionKey "<your-sessionKey>" -Region app
```

---

## Parameters

| Parameter | Required | Default | Description |
| --- | --- | --- | --- |
| `-Roles` | no | (none) | Group keywords (`server-all`, `workstation-all`, `testlab`) and/or short keys (`datev,sql,terminal,…`). Omit to only enforce the default-policy naming convention |
| `-TechnicianRoles` | no | (none) | Technician permission profiles: `1st-level-support`, `2nd-level-support`, `3rd-level-support`, `system-administrator`, or the group `tech-all`. Create-or-update by name |
| `-SessionKey` | no | `$env:NINJA_SESSION_KEY` | Session cookie value. If both are missing, the script aborts with a clear message |
| `-Region` | no | `eu` | Instance subdomain (`eu` -> `eu.ninjarmm.com`) |
| `-WhatIf` | no | - | Dry run, sends no request |

---

## How it maps to the API

Discovered from the web UI (the same routes the UI uses); not an official API. Uses .NET
`HttpClient` with `AllowAutoRedirect` disabled, so the session cookie is never sent over an http
redirect.

- `GET /swb/s6/noderole/list?allRoles=true` - read existing node roles (to skip duplicates).
- **Create** a node role: `POST /swb/s6/noderole` with
  `{ "nodeClass", "custom": true, "nodeRoleParentId", "name", "chassisType": "UNKNOWN", "description": "" }`.
- `GET /swb/s6/policy/list` - read all policies (default per category, existing children).
- **Rename** a default: `PATCH /swb/s6/policy/{id}` with `{ "name", "description", "enabled" }`.
- **Create** a child policy: `POST /swb/s6/policy` with
  `{ "enabled": true, "name", "nodeClassDefault": false, "nodeClass", "description": null, "parentPolicyId" }`.

A child policy links to its parent **only** via `parentPolicyId` and inherits all settings - it
is not tied to the custom node role, so the policy passes don't depend on the node-role pass.

Technician roles (Pass 4):

- `GET /swb/s6/user-roles?roleType=TECHNICIAN` - list existing technician roles (resolve by name).
- `GET /swb/s6/user-roles/{id}` - read a role before updating (round-trips name / type /
  description / members so a profile apply never deassigns technicians).
- **Create** a role: `POST /swb/s6/user-roles` to mint an id, then **replace** its permissions.
- **Save** permissions: `PUT /swb/s6/user-roles/{id}` - a **full replace** of the grant list, not a
  partial patch.

---

## Adding more roles

No code needed - just add data to the catalog near the top of `Initialize-NinjaTenant.ps1`:

- **`$RoleCatalog`** - one line per role (`key = @{ name; nodeClass; nodeRoleParentId }`).
- **`$RoleGroups`** - group keywords that expand to several roles.
- **`$CategoryMeta`** - per `nodeClass`: the `major` number, the `policyBaseName` used in the
  policy names, and the `rolePrefix` stripped off the role name for the child label.

Each parent category has its **own `nodeRoleParentId`** (the id of the built-in parent role a
custom role hangs under), already known from `GET /swb/s6/noderole/list`:

| `nodeClass` | `nodeRoleParentId` |
| --- | --- |
| `WINDOWS_SERVER` | `1` |
| `WINDOWS_WORKSTATION` | `2` |
| `LINUX_WORKSTATION` | `3` |
| `LINUX_SERVER` | `21` |
| `MAC` | `4` |
| `MAC_SERVER` | `22` |

macOS/Linux roles are **not defined yet** (no names decided) - the catalog has commented
placeholders. Adding one later is a single catalog line; its category already has a reserved
major number and base name in `$CategoryMeta`.

To change the **technician** roles, edit the two catalogs near the top of the script instead:

- **`$TechnicianRoleCatalog`** - one entry per profile (`key = @{ roleName; grants }`), where
  `grants` is the flat list of `ENTITY|name` tokens applied to the role.
- **`$TechnicianRoleGroups`** - group keywords that expand to several profiles (e.g. `tech-all`).

---

## Notes

- Safe to re-run: existing node roles are skipped, defaults already carrying the convention name
  are skipped, and a child whose role already exists under the parent is skipped (no duplicates).
- Minor numbers continue from the highest existing child under each default.
- Each action reports its status (`[OK <code>]` / `[RENAMED <code>]` / `[SKIP]` / `[ERROR <code>]`),
  with a per-item summary of what was created/renamed at the end. Exit code `1` if at least one
  action failed.
