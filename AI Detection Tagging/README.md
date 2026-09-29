# NinjaOne AI Detection Tagging

Answer the recurring customer question *"can we tell from the endpoint whether AI is installed or running?"* - surface **shadow AI** on a device (local LLM runtimes, AI desktop apps, coding-assistant integrations, AI CLIs, model files, AI API keys) into a **Multi-line text custom field**.

One PowerShell script: [`Set-AiDetectionTag.ps1`](Set-AiDetectionTag.ps1). Windows PowerShell 5.1, ASCII-only, read-only inventory (**never** `Win32_Product`), `Ninja-Property-Set`, `-DryRun`, exit `0` / `1`. It only writes the one custom field it is pointed at; everything else it does is read-only. It does **not** change the NinjaOne device role.

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

### Step 1: Create the custom field
1. **Administration -> Devices -> Custom Fields -> Add**.
2. Field type: **Multi-line** (one finding per line) or **Text** (single line, 255 characters - then set `$Separator = ', '` and `$MaxLength = 255`).
3. Note the **machine name** of the field (e.g. `aiTag`) - that is what goes into `customFieldName`.
4. Under **Technician / Script permissions** set the field to **Read/Write** for scripts. Without write permission for automations `Ninja-Property-Set` fails with a permission error.

### Step 2: Add the script
1. **Administration -> Library -> Automation -> Add -> New Script**.
2. Name: `AI Detection Tagging`, language: **PowerShell**, operating system: **Windows**, architecture: **All**.
3. Paste the content of [`Set-AiDetectionTag.ps1`](Set-AiDetectionTag.ps1).
4. Add the script variable `customFieldName` (and optionally `disabledVectors`).
5. **Run as: System.** Important: per-user artifacts (model dirs, IDE extensions, config dirs, user API-key variables) are enumerated across every user profile and loaded `HKEY_USERS` hive, not just System's own.

### Step 3: Run it
- **One-off / test:** run the script on a device with `-DryRun` in the script parameters and check the activity log.
- **Scheduled:** add the script to a policy as a **scheduled automation** (e.g. daily) so the tag stays current.
- **On demand:** run it from a device view over a selection of devices.

### Step 4: Use the field
- **Device search / filter:** filter on the custom field, e.g. `aiTag contains LLM server`.
- **Condition:** custom field condition plus an alert when the value changes.
- **Reports and dynamic groups:** the field is available as a column and as a group criterion.

---

## Notes and limits

- **Heuristics can produce false positives:** `mldll` and `modelscan` key on ML technology, so a game using DirectML or a photo app with ONNX can trigger them - therefore worded as *"Possible local AI ..."* and individually switchable via `disabledVectors`.
- **`apiprobe` + system proxy:** if a system proxy does not bypass `127.0.0.1`, the probe fails (then no detection - it never raises a false alarm). In practice almost all proxies bypass localhost.
- **`cli` under System:** `Get-Command` sees the System PATH; user-installed tools (npm global, pipx, scoop) are additionally probed in the common per-user tool directories, but exotic install paths can be missed.
- **`pkg` scope:** pip site-packages and the **global** npm store are scanned; packages inside project-local `node_modules` or arbitrary virtualenvs are not.
- **API keys:** only the variable **name** is inspected and reported (e.g. `OPENAI_API_KEY`); the secret value is **never** read.
- **No `Win32_Product`:** installed software is read from the uninstall registry keys. `Win32_Product` triggers a consistency check of every installed MSI package and can take minutes and change the device state.
- **Cloud web usage is out of scope:** pure browser use of chatgpt.com / claude.ai leaves no local artefact and belongs on the network / DNS / proxy layer, not on the endpoint.
- **Local testing:**

```powershell
.\Set-AiDetectionTag.ps1 -CustomFieldName aiTag -DisabledVectors 'modelscan' -DryRun
```
