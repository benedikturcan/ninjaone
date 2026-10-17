# NinjaOne Node Role Creation

Creates custom **node roles** in NinjaOne via script - parameter-driven selection of which roles
to create. Handy when you repeatedly need the same set of server roles in a tenant and don't want
to click them together by hand in the UI.

One script: [`New-NinjaNodeRole.ps1`](New-NinjaNodeRole.ps1).

---

## TL;DR

- Authenticates with a **session cookie** (`sessionKey`) from a logged-in browser session and
  sends one `POST /swb/s6/noderole` per role.
- **The session key is NOT stored in the script.** It comes from the `NINJA_SESSION_KEY`
  environment variable or the `-SessionKey` parameter.
- `-Roles` controls what gets created: `server-all` for all, or individual short keys
  (`sql,terminal`).
- `-WhatIf` for a safe dry run.

```powershell
$env:NINJA_SESSION_KEY = "<sessionKey-from-browser>"
.\New-NinjaNodeRole.ps1 -Roles server-all
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

## Getting the session key

The `sessionKey` is a **short-lived session cookie** from a logged-in NinjaOne session, not an
API token. How to get it:

1. Sign in to NinjaOne in the browser (e.g. `https://eu.ninjarmm.com`).
2. Open DevTools -> **Application/Storage -> Cookies** -> copy the value of `sessionKey`
   (alternatively from the **Network** tab on any request under the request headers).
3. Set it as an environment variable (keeps it out of shell history and out of the code):

   ```powershell
   $env:NINJA_SESSION_KEY = "<your-sessionKey>"
   ```

When the session expires you get `401`/`403` back - sign in again and grab the current value.

> The key is like a password: don't commit it, don't post it in tickets/chats.

---

## Usage

Create all server roles:

```powershell
.\New-NinjaNodeRole.ps1 -Roles server-all
```

Only individual roles (comma-separated, order and case don't matter):

```powershell
.\New-NinjaNodeRole.ps1 -Roles sql,terminal
```

Mix groups and individual roles (e.g. all servers plus the test lab roles):

```powershell
.\New-NinjaNodeRole.ps1 -Roles server-all,testworkstation,testserver
```

Dry run - shows the planned requests but sends nothing:

```powershell
.\New-NinjaNodeRole.ps1 -Roles server-all -WhatIf
```

Session key for a single run instead of via the environment variable:

```powershell
.\New-NinjaNodeRole.ps1 -Roles sql -SessionKey "<your-sessionKey>"
```

A different instance than `eu` (e.g. `app`, `us2`):

```powershell
.\New-NinjaNodeRole.ps1 -Roles server-all -Region app
```

---

## Parameters

| Parameter | Required | Default | Description |
| --- | --- | --- | --- |
| `-Roles` | yes | - | One/more roles: group keywords (`server-all`, `workstation-all`, `testlab`) and/or short keys (`datev,sql,terminal,application,file,testserver,homeoffice,vip,testworkstation`) |
| `-SessionKey` | no | `$env:NINJA_SESSION_KEY` | Session cookie value. If both are missing, the script aborts with a clear message |
| `-Region` | no | `eu` | Instance subdomain (`eu` -> `eu.ninjarmm.com`) |
| `-WhatIf` | no | - | Dry run, sends no request |

---

## Adding more roles

No code needed - just add data. There are two structures at the top of the script:

- **`$RoleCatalog`** - one line per role (key = short key):

  ```powershell
  rdp = @{ name = "Workstation - RDP Client"; nodeClass = "WINDOWS_WORKSTATION"; nodeRoleParentId = <ID> }
  ```

- **`$RoleGroups`** - group keywords that expand to multiple roles:

  ```powershell
  "workstation-all" = @("rdp","kiosk")
  ```

**Note:** each parent category has its **own `nodeRoleParentId`** - the id of the built-in parent
role the custom role hangs under. These are already known (read from
`GET /swb/s6/noderole/list?allRoles=true` while signed in):

| `nodeClass` | `nodeRoleParentId` | For custom roles like |
| --- | --- | --- |
| `WINDOWS_SERVER` | `1` | Windows Server - … |
| `WINDOWS_WORKSTATION` | `2` | Workstation - … |
| `LINUX_WORKSTATION` | `3` | Linux - … |
| `LINUX_SERVER` | `21` | Linux Server - … |
| `MAC` | `4` | Mac - … |
| `MAC_SERVER` | `22` | Mac Server - … |

macOS and Linux roles are **not defined yet** (no role names decided) - the script has commented
placeholders for them. Adding one later is a single catalog line with the matching `nodeClass`
and `nodeRoleParentId` from the table above.

---

## Notes

- Duplicate entries (e.g. `server-all,datev`) are deduplicated.
- Unknown short keys abort with a list of valid values.
- Each role reports its status (`[OK 201]` / `[ERROR <code>]`), with a summary at the end.
  Exit code `1` if at least one role failed.
- The script talks directly to the internal `/swb/s6/noderole` endpoint via .NET `HttpClient`
  (the same route the web UI uses, with `AllowAutoRedirect` disabled so the session cookie is
  never sent over http). It is not an official API - behavior may change when the UI changes.
