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

---
---

# AI Detection Tagging

A second, purpose-built script in this folder: [`Set-AiDetectionTag.ps1`](Set-AiDetectionTag.ps1). It answers the recurring customer question *"can we tell from the endpoint whether AI is installed or running?"* - surfacing **shadow AI** on a device (local LLM runtimes, AI desktop apps, coding-assistant integrations, AI CLIs, model files, AI API keys) into a **Multi-line text custom field**.

Same conventions as the tagging script above: Windows PowerShell 5.1, ASCII-only, read-only inventory (**never** `Win32_Product`), `Ninja-Property-Set`, `-DryRun`, exit `0` / `1`. It only writes the one custom field it is pointed at.

---

## TL;DR

- One script, [`Set-AiDetectionTag.ps1`](Set-AiDetectionTag.ps1), no dependencies, no API credentials.
- **One required script variable:** `customFieldName`. Optional `disabledVectors` to switch vectors off.
- **Detection is hybrid:** a catalog names known tools (e.g. `Ollama (running, port 11434)`), and generic heuristics catch unknown / renamed tooling by its technology and behaviour (`Possible local AI (ML runtime loaded): ...`, `Local LLM server (OpenAI-compatible API, port 8000)`).
- Adding a known tool is one `New-AiSignature` line in `$AiCatalog` - not code.
- Browser extensions are **intentionally not** scanned.

Simplest run: `customFieldName = aiTag` -> the field lists whatever AI tooling the device carries, one finding per line.

---

## Detection vectors

Thirteen vectors, each switchable off via `disabledVectors`. The first nine are **catalog / named** (they name the tool); the last four are **generic** (they need no product name).

| Vector | What it finds | Kind | Example finding |
| --- | --- | --- | --- |
| `software` | installed software (uninstall registry, HKLM 32/64 + user hives) | named | `LM Studio (installed)` |
| `process` | running processes (name + file description) - "active now" | named | `Ollama (running)` |
| `service` | Windows services (service + display name) | named | `Ollama (service)` |
| `port` | listening TCP ports of known local LLM servers | named | `Ollama (port 11434)` |
| `artifact` | known local model directories (Ollama, LM Studio, GPT4All, HF cache, Jan) + size | named | `Local AI models: Ollama models (4.2 GB)` |
| `ide` | AI coding assistants as VS Code / Cursor / JetBrains extensions | named | `GitHub Copilot (IDE plugin)` |
| `cli` | AI command-line tools on PATH or in per-user tool dirs | named | `Claude Code (CLI)` |
| `config` | a tool's config file / dir in a user profile (`.claude`, `.continue`, ...) | named | `Claude Code (CLI, config dir)` |
| `env` | environment variable **names** that look like AI API keys (value never read) | generic | `AI API keys in environment: ANTHROPIC_API_KEY` |
| `pkg` | AI SDKs installed via pip / npm (vendor-agnostic) | generic | `AI SDKs installed: anthropic (pip), openai (pip)` |
| `mldll` | a process with an ML runtime loaded (ggml/onnxruntime/torch/...) not already named | generic | `Possible local AI (ML runtime loaded): app.exe (onnxruntime)` |
| `apiprobe` | a listening port that answers like an LLM API (Ollama `/api/tags`, OpenAI `/v1/models`) | generic | `Local LLM server (OpenAI-compatible API, port 8000)` |
| `modelscan` | model weight files (`*.gguf`, `*.safetensors`, `*.onnx`, ...) in the user data folders | generic | `Local model files: 4 file(s), 14.5 GB (.gguf, .safetensors)` |

The heuristic vectors run **after** the named pass and skip what the catalog already matched (process names and ports), so they surface only the unknowns - no double reporting.

---

## Cloud vs. local (why "OpenAI" appears more than "Anthropic")

`apiprobe`'s **"OpenAI-compatible API"** is the *wire protocol* almost every **local** LLM server speaks (Ollama, LM Studio, llama.cpp, vLLM, LocalAI ...), whatever model it serves - not a statement about the vendor.

Cloud assistants such as **Anthropic Claude** and **OpenAI ChatGPT** run **no local server**, so they leave no trace in the local-runtime vectors (`port`, `apiprobe`, `mldll`, `modelscan`). They are detected through the vectors where they actually leave traces, symmetrically per vendor:

| Anthropic usage | Vector | Finding |
| --- | --- | --- |
| Claude Desktop app | `software` / `process` | `Claude Desktop (installed, running)` |
| Claude Code CLI | `cli` + `config` | `Claude Code (CLI, config dir)` |
| API key set | `env` | `AI API keys in environment: ANTHROPIC_API_KEY` |
| SDK used in code | `pkg` | `AI SDKs installed: anthropic (pip)` |

---

## Script variables

| Variable | Type | Description |
| --- | --- | --- |
| `customFieldName` | Text | Name of the target custom field (e.g. `aiTag`). Required, must be writable by scripts. |
| `disabledVectors` | Text | Optional. Comma/space separated vectors to skip, e.g. `pkg, modelscan`. Unknown names are ignored with a warning. |

`-DryRun` (Script parameters) only logs the value instead of writing it.

Turn off the more false-positive-prone heuristics if they are too noisy in your estate:

```
disabledVectors = mldll, modelscan
```

---

## Defaults in the script

Constants at the top of [`Set-AiDetectionTag.ps1`](Set-AiDetectionTag.ps1), plus the catalog and heuristic lists:

| Constant | Default | Description |
| --- | --- | --- |
| `$Separator` | newline | Joins findings, one per line (multi-line field). Use `', '` and `$MaxLength = 255` for a single-line text field. |
| `$MaxLength` | `10000` | Value cap; entries that do not fit are dropped (logged). |
| `$RequireServiceRunning` | `$false` | `$true`: a service only counts while running. |
| `$MinModelBytes` | `50MB` | A known model directory (`artifact`) is only reported above this size. |
| `$MinModelFileBytes` | `10MB` | A single file (`modelscan`) below this size is ignored. |
| `$AiCatalog` | *(see script)* | One `New-AiSignature` per known tool - patterns per vector. Add a tool = add a line. |
| `$MlDllPatterns` | ggml, onnxruntime, torch, cudnn, directml, ... | ML runtime module names for `mldll`. Kept ML-specific to limit false positives. |
| `$ApiProbePorts` | 11434, 1234, 1337, 8080, 5000, 7860, 8000, ... | Ports `apiprobe` may probe - only if listening, only with a harmless GET. |
| `$ModelExtensions` | `*.gguf`, `*.safetensors`, `*.onnx`, `*.ggml`, `*.pt`, `*.pth` | Model file extensions for `modelscan` (`.bin` deliberately excluded). |
| `$PipPackages` / `$NpmPackages` | anthropic, openai, ... | AI SDK names for the `pkg` vector (vendor-agnostic). |

---

## How it works

1. **Read the config** (`customFieldName`, `disabledVectors`).
2. **Named pass:** for every catalog signature, test each enabled named vector and collect the evidence (`installed`, `running`, `service`, `port N`, `IDE plugin`, `CLI`, `config dir`). Matched process names and ports are remembered.
3. **Generic pass:** `env`, `pkg`, then the heuristics `mldll`, `apiprobe`, `modelscan` - the heuristics skip what the named pass already covered.
4. **Write the custom field** via `Ninja-Property-Set` (piped when available), then read it back for the log.

Example output in the activity log:

```
[09:41:10] Device DEV-LAPTOP07: target field "aiTag", active vectors: software, process, service, port, artifact, ide, cli, config, env, pkg, mldll, apiprobe, modelscan
[09:41:11]   Inventory: 2 user profile(s)
[09:41:11]   Inventory: 143 installed software entries
[09:41:12]   Detected: Ollama (running, port 11434)
[09:41:12]   Detected: Cursor (installed, running, config dir)
[09:41:12]   Detected: GitHub Copilot (IDE plugin)
[09:41:12]   Detected: Claude Code (CLI, config dir)
[09:41:13]   Detected: Local AI models: Ollama models (8.1 GB)
[09:41:13]   Detected: AI API keys in environment: ANTHROPIC_API_KEY, OPENAI_API_KEY
[09:41:13]   Detected: AI SDKs installed: anthropic (pip), openai (pip)
[09:41:14] Custom field "aiTag" set to "Ollama (running, port 11434) | Cursor (installed, running, config dir) | GitHub Copilot (IDE plugin) | Claude Code (CLI, config dir) | Local AI models: Ollama models (8.1 GB) | AI API keys in environment: ANTHROPIC_API_KEY, OPENAI_API_KEY | AI SDKs installed: anthropic (pip), openai (pip)" (via Ninja-Property-Set-Piped)
```

---

## Setup

Identical to the tagging script above (create a **Multi-line** Read/Write custom field, add the script as a Windows PowerShell automation, **Run as: System**), with these deltas:

- Only **one** required script variable, `customFieldName`; `disabledVectors` is optional.
- **Run as System** is important: per-user artifacts (model dirs, IDE extensions, config dirs, user API-key variables) are enumerated across every user profile and loaded `HKEY_USERS` hive, not just System's own.
- Schedule it (e.g. daily) so the tag stays current, and filter / build dynamic groups on the field, e.g. `aiTag contains LLM server`.

---

## Notes and limits

- **Heuristics can produce false positives:** `mldll` and `modelscan` key on ML technology, so a game using DirectML or a photo app with ONNX can trigger them - therefore worded as *"Possible local AI ..."* and individually switchable via `disabledVectors`.
- **`apiprobe` + system proxy:** if a system proxy does not bypass `127.0.0.1`, the probe fails (then no detection - it never raises a false alarm). In practice almost all proxies bypass localhost.
- **`cli` under System:** `Get-Command` sees the System PATH; user-installed tools (npm global, pipx, scoop) are additionally probed in the common per-user tool directories, but exotic install paths can be missed.
- **`pkg` scope:** pip site-packages and the **global** npm store are scanned; packages inside project-local `node_modules` or arbitrary virtualenvs are not.
- **API keys:** only the variable **name** is inspected and reported (e.g. `OPENAI_API_KEY`); the secret value is **never** read.
- **Cloud web usage is out of scope:** pure browser use of chatgpt.com / claude.ai leaves no local artefact and belongs on the network / DNS / proxy layer, not on the endpoint.
- **Local testing:**

```powershell
.\Set-AiDetectionTag.ps1 -CustomFieldName aiTag -DisabledVectors 'modelscan' -DryRun
```
