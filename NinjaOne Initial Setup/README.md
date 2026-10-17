# NinjaOne Initial Setup

One PowerShell script that bootstraps a fresh NinjaOne tenant in a single run: it creates the
custom **node roles** and the matching **policy hierarchy** (default-policy naming convention +
child policies) from the same `-Roles` selection.

One script: [`Initialize-NinjaTenant.ps1`](Initialize-NinjaTenant.ps1).

---

## TL;DR

- Authenticates with a **session cookie** (`sessionKey`) from a logged-in browser session.
- **The session key is NOT stored in the script.** It comes from the `NINJA_SESSION_KEY`
  environment variable or the `-SessionKey` parameter.
- `-Roles` is **optional** and drives everything: `server-all` for all server roles, or individual
  short keys (`sql,terminal`, …).
- Three passes in one run:
  1. **Node roles** (only with `-Roles`): one custom node role per selected role.
  2. **Default policy naming** (**always**): renames every built-in default policy to the
     convention (`0.0`, `1.0`, `2.0`, …), so the hierarchy stays consistent even without roles.
  3. **Child policies** (only with `-Roles`): one child policy per selected role, inheriting from
     its default.
- Idempotent: existing roles, already-renamed defaults and already-existing children are skipped.
  `-WhatIf` for a safe dry run.

```powershell
$env:NINJA_SESSION_KEY = "<sessionKey-from-browser>"
.\Initialize-NinjaTenant.ps1 -Roles server-all
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

Session key for a single run, and a different instance:

```powershell
.\Initialize-NinjaTenant.ps1 -Roles sql -SessionKey "<your-sessionKey>" -Region app
```

---

## Parameters

| Parameter | Required | Default | Description |
| --- | --- | --- | --- |
| `-Roles` | no | (none) | Group keywords (`server-all`, `workstation-all`, `testlab`) and/or short keys (`datev,sql,terminal,…`). Omit to only enforce the default-policy naming convention |
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

---

## Notes

- Safe to re-run: existing node roles are skipped, defaults already carrying the convention name
  are skipped, and a child whose role already exists under the parent is skipped (no duplicates).
- Minor numbers continue from the highest existing child under each default.
- Each action reports its status (`[OK <code>]` / `[RENAMED <code>]` / `[SKIP]` / `[ERROR <code>]`),
  with a per-item summary of what was created/renamed at the end. Exit code `1` if at least one
  action failed.
