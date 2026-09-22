# NinjaOne Software And Service Tagging

Check a device for installed software, Windows services, running processes or listening TCP ports and write the result into a **text custom field** - for example `Has Veeam installed` on every backup server.

The script does **not** change the NinjaOne device role. It only writes the one custom field it is pointed at; everything else it does is read-only.

---

## TL;DR

- One PowerShell script: [`Set-SoftwareServiceTag.ps1`](Set-SoftwareServiceTag.ps1), Windows PowerShell 5.1, no dependencies, no API credentials.
- **Two script variables:** `customFieldName` (where to write) and `checks` (what to look for). Nothing else to configure.
- Every rule that matches produces one text; several matches are written one per line.
- The value is written with `Ninja-Property-Set`, into a **Multi-line** custom field (one match per line) or a single-line **Text** field.
- Installed software is read from the uninstall registry keys - **never** `Win32_Product`, which would reconfigure every MSI package on the device.
- Exit codes: `0` = field written, `1` = error.

Simplest possible run: `customFieldName = softwareTag`, `checks = Veeam` -> the field contains `Has Veeam installed` on every device that has Veeam.

---

## Script variables

| Variable | Type | Description |
| --- | --- | --- |
| `customFieldName` | Text | Name of the target custom field (the machine name shown in the field configuration, e.g. `softwareTag`). |
| `checks` | Text / Multi-line | The rules, one per line or separated by `;`. |

Both are required. Use exactly these calculated names - that is how the script reads them from the environment.

Optional, not a script variable: `-DryRun` only logs the value instead of writing it. It can be passed in the **Script parameters** field when running or scheduling the automation.

---

## Rule syntax

```
[type:]pattern[=text]
```

| Part | Meaning |
| --- | --- |
| `type` | `software`, `service`, `process`, `port` or `any`. Optional, default `any`. |
| `pattern` | What to look for: a case-insensitive substring; `*` and `?` turn it into a wildcard match. For `port:` a port number. |
| `text` | Optional. The exact text written into the custom field instead of the default sentence. |

`any` checks software first, then services, then processes, and stops at the first hit - so one rule produces at most one entry.

| Rule | Result when it matches |
| --- | --- |
| `Veeam` | `Has Veeam installed` |
| `service:VeeamBackupSvc` | `Has service VeeamBackupSvc` |
| `service:VeeamBackupSvc=Backup Server` | `Backup Server` |
| `service:*SQL*=SQL Server` | `SQL Server` |
| `software:Microsoft SQL Server` | `Has Microsoft SQL Server installed` |
| `process:sqlservr=SQL Server` | `SQL Server` |
| `port:3389` | `Listening on port 3389` |
| `# comment` | ignored |

Several rules in one variable, separated by `;` or one per line:

```
service:VeeamBackupSvc=Backup Server; service:NTDS=Domain Controller; software:Microsoft SQL Server=SQL Server
```
-> the custom field contains:

```
Backup Server
Domain Controller
SQL Server
```

---

## Defaults in the script

These are constants at the top of [`Set-SoftwareServiceTag.ps1`](Set-SoftwareServiceTag.ps1), not script variables - they are set once for the whole environment instead of on every automation:

| Constant | Default | Description |
| --- | --- | --- |
| `$SoftwareText` | `Has {0} installed` | Sentence for a software match, `{0}` = the pattern of the rule. |
| `$ServiceText` | `Has service {0}` | Sentence for a service match. |
| `$ProcessText` | `Has {0} running` | Sentence for a process match. |
| `$PortText` | `Listening on port {0}` | Sentence for a port match. |
| `$Separator` | newline (`` "`r`n" ``) | Joins several matches - one per line for a multi-line field. Use `', '` for a single-line text field. |
| `$NoMatchValue` | *(empty)* | Written when no rule matches; empty clears the field. |
| `$MaxLength` | `10000` | Length limit of the custom field. Use `255` for a single-line text field. Entries that do not fit are dropped (logged), a single oversized entry is truncated. |
| `$RequireServiceRunning` | `$false` | `$true`: a service only counts while it is running, a stopped service is not a match. |

---

## How it works

1. **Read the rules** from `checks`.
2. **Build the inventory** (only for the types actually used, each one is collected once per run):
   - **software**: `HKLM\...\Uninstall` (64 bit + `WOW6432Node`) and the same keys in every loaded user hive under `HKEY_USERS`.
   - **service**: `Win32_Service` (name, display name and state), fallback `Get-Service`.
   - **process**: `Get-Process` (process name and file description).
   - **port**: listening TCP ports via `Get-NetTCPConnection`, fallback `netstat -an`.
3. **Match** each rule against the inventory.
4. **Write the custom field** via `Ninja-Property-Set` (or `Ninja-Property-Set-Piped` when available, so quotes and spaces cannot break the call), then read it back for the log.

Example output in the activity log:

```
[09:12:03] Device SRV-BACKUP01: 3 rule(s), target field: softwareTag
[09:12:03] Rule [any] "Veeam"
[09:12:04]   Inventory: 87 installed software entries
[09:12:04]   Match (software): Veeam Backup & Replication Console -> "Has Veeam installed"
[09:12:04] Rule [service] "MSSQLSERVER"
[09:12:04]   Inventory: 214 services
[09:12:04]   No match
[09:12:04] Rule [port] "3389"
[09:12:04]   Inventory: 31 listening TCP ports
[09:12:04]   Match (port): 3389 -> "Listening on port 3389"
[09:12:05] Custom field "softwareTag" set to "Has Veeam installed | Listening on port 3389" (via Ninja-Property-Set-Piped)
[09:12:05]   Read back: "Has Veeam installed | Listening on port 3389"
```

---

## Setup

### Step 1: Create the custom field
1. **Administration -> Devices -> Custom Fields -> Add**.
2. Field type: **Multi-line** (the default here, one match per line) or **Text** (single line, 255 characters - then set `$Separator = ', '` and `$MaxLength = 255`).
3. Note the **machine name** of the field (e.g. `softwareTag`) - that is what goes into `customFieldName`.
4. Under **Technician / Script permissions** set the field to **Read/Write** for scripts. Without write permission for automations `Ninja-Property-Set` fails with a permission error.

### Step 2: Add the script
1. **Administration -> Library -> Automation -> Add -> New Script**.
2. Name: `Software And Service Tagging`, language: **PowerShell**, operating system: **Windows**, architecture: **All**.
3. Paste the content of [`Set-SoftwareServiceTag.ps1`](Set-SoftwareServiceTag.ps1).
4. Add the two script variables `customFieldName` and `checks`.
5. Run as: **System**. Per-user installed software is still detected via the loaded user hives.

### Step 3: Run it
- **One-off / test:** run the script on a device with `-DryRun` in the script parameters and check the activity log.
- **Scheduled:** add the script to a policy as a **scheduled automation** (e.g. daily) so the field stays current when software is installed or removed.
- **On demand:** run it from a device view over a selection of devices.

### Step 4: Use the field
- **Device search / filter:** filter on the custom field, e.g. `softwareTag contains Veeam`.
- **Condition:** custom field condition plus an alert when the value changes.
- **Reports and dynamic groups:** the field is available as a column and as a group criterion.

---

## Notes and limits

- **Field limits:** a single-line text field holds 255 characters, a multi-line field far more. `$MaxLength` caps the value on the script side: entries that do not fit are dropped and reported in the activity log, so the longest list still writes cleanly.
- **Multi-line values** are written with `Ninja-Property-Set-Piped` when the agent provides it, so line breaks survive. The activity log shows the value on one line with `|` between the entries.
- **No `Win32_Product`:** the script reads the uninstall registry keys. `Win32_Product` triggers a consistency check of every installed MSI package and can take minutes and change the device state.
- **Registry-only software:** applications that do not register an uninstall entry (portable tools, some store apps) are not found as `software` - use `service:` or `process:` for those.
- **Services** match by default as soon as the service exists, running or not - a stopped Veeam service still means "this is a backup server". Set `$RequireServiceRunning = $true` to require a running service.
- **Processes are a snapshot:** a `process:` rule only sees what runs at that moment. For a role, `software:` or `service:` is the more stable signal.
- **Ports:** only listening **TCP** ports are checked, UDP is not.
- **Local testing:**

```powershell
.\Set-SoftwareServiceTag.ps1 -CustomFieldName softwareTag -Checks 'Veeam; port:3389' -DryRun
```
