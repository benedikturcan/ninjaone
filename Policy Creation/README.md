# NinjaOne Child Policy Creation

Creates custom **child policies** in NinjaOne via script - one policy per device role you
selected, hung underneath the matching built-in **default policy**, plus a consistent naming
convention on those defaults. Companion to the [Node Role Creation](../Node%20Role%20Creation/)
script: you pick the same roles, and this creates the policies for them.

One script: [`New-NinjaChildPolicy.ps1`](New-NinjaChildPolicy.ps1).

---

## TL;DR

- Authenticates with a **session cookie** (`sessionKey`) from a logged-in browser session.
- **The session key is NOT stored in the script.** It comes from the `NINJA_SESSION_KEY`
  environment variable or the `-SessionKey` parameter.
- `-Roles` takes the **same values** as the node-role script (`server-all`, `sql,terminal`, …),
  and is **optional**.
- Two passes:
  1. **Pass 1 (always):** renames **all** built-in default policies to the convention name
     (`0.0`, `1.0`, `2.0`, …) - runs regardless of `-Roles` so the hierarchy stays consistent.
  2. **Pass 2 (selected roles):** creates a child policy per selected role, inheriting everything
     from its default. Omit `-Roles` to run Pass 1 only.
- Idempotent: already-renamed defaults and already-existing children are left alone. `-WhatIf`
  for a safe dry run.

```powershell
$env:NINJA_SESSION_KEY = "<sessionKey-from-browser>"
.\New-NinjaChildPolicy.ps1 -Roles server-all
```

---

## Naming convention

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
1.0 Windows Server Policy                      (default, renamed)
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

Create policies for all server roles (renames **all** defaults, then creates `1.1`, `1.2`, …):

```powershell
.\New-NinjaChildPolicy.ps1 -Roles server-all
```

Only enforce the naming convention on the default policies (no roles, no child policies):

```powershell
.\New-NinjaChildPolicy.ps1
```

Only selected roles:

```powershell
.\New-NinjaChildPolicy.ps1 -Roles sql,terminal
```

Dry run - shows the planned renames and child creates, sends nothing:

```powershell
.\New-NinjaChildPolicy.ps1 -Roles server-all -WhatIf
```

Session key for a single run, and a different instance:

```powershell
.\New-NinjaChildPolicy.ps1 -Roles sql -SessionKey "<your-sessionKey>" -Region app
```

Typical flow is to run the two scripts back to back with the same `-Roles`:

```powershell
..\"Node Role Creation"\New-NinjaNodeRole.ps1   -Roles server-all   # create the roles
.\New-NinjaChildPolicy.ps1                      -Roles server-all   # create their policies
```

---

## Parameters

| Parameter | Required | Default | Description |
| --- | --- | --- | --- |
| `-Roles` | no | (none) | Same values as the node-role script: group keywords (`server-all`, `workstation-all`, `testlab`) and/or short keys (`datev,sql,terminal,…`). Omit to only enforce the default-policy naming convention |
| `-SessionKey` | no | `$env:NINJA_SESSION_KEY` | Session cookie value. If both are missing, the script aborts with a clear message |
| `-Region` | no | `eu` | Instance subdomain (`eu` -> `eu.ninjarmm.com`) |
| `-WhatIf` | no | - | Dry run, sends no request |

---

## How it maps to the API

Discovered from the web UI (the same routes the UI uses); not an official API.

- `GET /swb/s6/policy/list` - read all policies (find the default per category, existing children).
- **Rename** a default: `PATCH /swb/s6/policy/{id}` with `{ "name", "description", "enabled" }`.
- **Create** a child: `POST /swb/s6/policy` with
  `{ "enabled": true, "name", "nodeClassDefault": false, "nodeClass", "description": null, "parentPolicyId" }`.

A child policy links to its parent **only** via `parentPolicyId` and inherits all settings - it
is not tied to the custom node role, so this script does not need the node roles to exist first.

---

## Adding more roles

Roles, groups and the per-category naming all live in one shared file,
[`../Shared/NinjaRoleCatalog.ps1`](../Shared/NinjaRoleCatalog.ps1), which **both** this script
and the node-role script dot-source (so they never drift apart).

- **`$RoleCatalog`** - one line per role (`key = @{ name; nodeClass; nodeRoleParentId }`).
- **`$RoleGroups`** - group keywords that expand to several roles.
- **`$CategoryMeta`** - per `nodeClass`: the `major` number, the `policyBaseName` used in the
  policy names, and the `rolePrefix` stripped off the role name for the child label.

Adding a macOS/Linux role later is a single catalog line; its category already has a reserved
major number and base name in `$CategoryMeta`.

---

## Notes

- Safe to re-run: defaults already carrying the convention name are skipped, and a child whose
  role already exists under the parent is skipped (no duplicates).
- Minor numbers continue from the highest existing child under each default.
- Each action reports its status (`[RENAMED]` / `[OK <code>]` / `[SKIP]` / `[ERROR <code>]`),
  with a summary at the end. Exit code `1` if at least one action failed.
- Uses .NET `HttpClient` with `AllowAutoRedirect` disabled, same as the node-role script, so the
  session cookie is never sent over an http redirect.
