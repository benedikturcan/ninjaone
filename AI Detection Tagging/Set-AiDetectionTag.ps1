<#
.SYNOPSIS
    NinjaOne AI detection tagging: scans a device for locally installed or running AI tooling
    (local LLM runtimes, AI desktop apps, coding-assistant integrations, AI CLIs, model files,
    AI API keys) and writes the findings into a text custom field.

.DESCRIPTION
    Runs as a NinjaOne automation (Windows PowerShell 5.1) or locally for testing. It is meant to
    surface "shadow AI" on endpoints - what is present, and what is actually running right now.

    Detection is catalog-driven: '$AiCatalog' holds one signature per tool with the patterns to look
    for per vector. Adding a new tool is one line, not code. On top of the catalog, two generic
    vectors (model files, AI API keys) also catch renamed or unknown tooling.

    Thirteen vectors (each can be turned off via the 'disabledVectors' script variable). The first
    nine are catalog/named (they name the tool); the last four are generic and catch unknown or
    renamed tooling by its technology and behaviour instead of its product name:
        software   installed software from the uninstall registry keys (HKLM 32/64 bit + user hives)
        process    running processes (name + file description) -> "active right now"
        service    Windows services (service name + display name)
        port        listening TCP ports of known local LLM servers (e.g. 11434 Ollama, 1234 LM Studio)
        artifact    known local model directories (Ollama, LM Studio, GPT4All, HF cache, Jan) + size
        ide          AI coding assistants installed as VS Code / Cursor / JetBrains extensions
        cli          AI command-line tools on PATH or in the common per-user tool directories
        config      a tool's config file / directory in a user profile (e.g. .claude, .continue)
        env          environment variable NAMES that look like AI API keys (the value is never read)
        pkg          AI SDKs installed via pip or npm (anthropic, openai, google, cohere, ... alike)
        mldll       any process with an ML inference runtime loaded (ggml/onnxruntime/torch/...) that
                     the catalog did not already name -> "possible local AI"
        apiprobe    listening ports (not already tied to a known tool) that answer like an LLM API
                     (Ollama /api/tags, OpenAI-compatible /v1/models) -> "local LLM server"
        modelscan   model weight files (*.gguf, *.safetensors, *.onnx, ...) in the user data folders

    Note on cloud vs local: cloud assistants (Anthropic Claude, OpenAI ChatGPT) run no local server,
    so they surface through the software/process/config/env/pkg vectors (desktop app, CLI, config
    dir, API-key variable, SDK), not through the local-runtime vectors (port/apiprobe/mldll).
    "OpenAI-compatible API" in apiprobe is the wire protocol most LOCAL servers speak, not a vendor.

    Named vectors give clean tool names for auto-tagging; the heuristics surface the rest as
    "Possible local AI ..." for a human to review, and are the more false-positive-prone ones -
    disable an individual heuristic via 'disabledVectors' (e.g. "mldll") if it is too noisy.

    Browser extensions are intentionally NOT scanned.

    Each detected tool becomes one line, e.g.:
        Ollama (running, port 11434)
        LM Studio (installed)
        GitHub Copilot (IDE plugin, CLI)
    Generic findings add their own lines, e.g.:
        Local AI models: Ollama models (4.2 GB), Hugging Face cache (11.8 GB)
        AI API keys in environment: OPENAI_API_KEY, ANTHROPIC_API_KEY

    Installed software is read from the registry on purpose. Win32_Product (Get-WmiObject Win32_Product)
    would trigger an MSI reconfiguration of every installed package and is far too slow and invasive.

    Because the automation runs as SYSTEM, per-user artifacts (model dirs, IDE extensions, user API
    key variables) are enumerated across every user profile / loaded user hive, not just SYSTEM's own.

    NinjaOne script variables (injected as environment variables, use these calculated names):
        customFieldName    Name of the target custom field (required, must be writable by scripts)
        dataFieldName      Optional: a second (multi-line text) device field the script writes a
                           compact JSON of the same findings into. This is what the central dashboard
                           script (Set-AiDashboard.ps1) reads to aggregate the whole fleet. Leave it
                           empty on devices where you only want the human-readable tag.
        disabledVectors    Optional: comma/space separated list of vectors to skip
                           (software, process, service, port, artifact, ide, cli, env)
        writeEventLog      Optional: 'true' to also write Windows events (source 'NinjaAIDetection'
                           in the Application log) so detections are traceable and NinjaOne / SIEM
                           can alert on them. Off unless set. Events are written on change (a local
                           cache prevents a scheduled run from re-logging unchanged findings), plus
                           one summary event per run. Event IDs: 5000 summary, 5001 local LLM server,
                           5002 unidentified ML runtime, 5003 API key, 5004 named tool, 5010 cleared.

    Two-component design:
        1. This script runs per device (agent, as SYSTEM) and writes both the human-readable tag
           and, when 'dataFieldName' is set, a machine-readable JSON of the findings.
        2. Set-AiDashboard.ps1 runs centrally (API, on one device) and reads every device's JSON
           field to build one fleet-wide WYSIWYG dashboard.

    Everything else is a constant in the "Defaults" block below - change it there if needed.
    -DryRun only logs the values instead of writing them; it can be passed in the NinjaOne
    "Script parameters" field of a run or schedule.

    Exit codes: 0 = custom field(s) written, 1 = error.

    The source is kept ASCII-only on purpose: Windows PowerShell 5.1 reads BOM-less scripts as ANSI.

.EXAMPLE
    .\Set-AiDetectionTag.ps1 -CustomFieldName aiTag
    Scans every vector and writes the findings into custom field 'aiTag'.

.EXAMPLE
    .\Set-AiDetectionTag.ps1 -CustomFieldName aiTag -DataFieldName aiData
    Also writes a JSON of the findings into 'aiData' for the fleet dashboard to aggregate.

.EXAMPLE
    .\Set-AiDetectionTag.ps1 -CustomFieldName aiTag -DisabledVectors 'env, cli' -DryRun
    Skips the API-key and CLI vectors and only logs what it would write.
#>
param(
    [string]$CustomFieldName = $env:customFieldName,
    [string]$DataFieldName = $env:dataFieldName,
    [string]$DisabledVectors = $env:disabledVectors,
    [string]$WriteEventLog = $env:writeEventLog,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

#region Defaults

# Deliberately constants and not script variables: these are set once for the whole environment.
# Multi-line custom field: one match per line. Single-line text field: use ', ' and 255 instead.
$Separator = "`r`n"                      # joins several findings
$NoMatchValue = ''                       # written when nothing is found, empty clears the field
$MaxLength = 10000                       # length limit of the custom field (single-line text: 255)
$RequireServiceRunning = $false          # $true: a service only counts while it is running
$MinModelBytes = 50MB                    # a model directory is only reported above this size

# Windows Event Log (only used when the 'writeEventLog' variable is enabled)
$EventSource = 'NinjaAIDetection'        # event source, created once in the Application log
$EventLogName = 'Application'
$EventCacheDir = if ($env:NINJA_DATA_PATH) { $env:NINJA_DATA_PATH } elseif ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$EventCachePath = Join-Path $EventCacheDir 'ai-detection-events-cache.json'

#endregion

# Write-Host instead of Write-Output: log lines inside functions must not end up in their return values
function Write-Log([string]$Message) {
    Write-Host ('[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss'), $Message)
}

function Format-Size([long]$Bytes) {
    if ($Bytes -ge 1GB) { return ('{0:N1} GB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N0} MB' -f ($Bytes / 1MB)) }
    return ('{0:N0} KB' -f ($Bytes / 1KB))
}

#region AI catalog

# One signature per tool. Every field is optional; empty arrays are simply skipped.
#   Software/Process/Service/Ide/Cli : patterns (substring, or wildcard when they contain * or ?)
#   Port                              : numeric listening TCP ports of the tool's local server
function New-AiSignature {
    param([string]$Name, [string[]]$Software = @(), [string[]]$Process = @(),
          [string[]]$Service = @(), [int[]]$Port = @(), [string[]]$Ide = @(), [string[]]$Cli = @(),
          [string[]]$Config = @())
    [pscustomobject]@{
        Name = $Name; Software = $Software; Process = $Process; Service = $Service
        Port = $Port; Ide = $Ide; Cli = $Cli; Config = $Config
    }
}

$AiCatalog = @(
    # Local LLM runtimes
    New-AiSignature -Name 'Ollama'                 -Software 'Ollama' -Process 'ollama' -Service 'Ollama' -Port 11434 -Cli 'ollama' -Config '.ollama'
    New-AiSignature -Name 'LM Studio'              -Software 'LM Studio' -Process 'LM Studio','lms' -Port 1234 -Cli 'lms' -Config '.lmstudio'
    New-AiSignature -Name 'GPT4All'                -Software 'GPT4All' -Process 'gpt4all'
    New-AiSignature -Name 'Jan'                    -Software 'Jan AI','Jan (' -Port 1337
    New-AiSignature -Name 'AnythingLLM'            -Software 'AnythingLLM' -Process 'anythingllm'
    New-AiSignature -Name 'Text Generation WebUI'  -Process 'text-generation' -Port 7860
    New-AiSignature -Name 'llama.cpp server'       -Process 'llama-server','llama-cpp' -Port 8080
    # AI desktop apps
    New-AiSignature -Name 'ChatGPT Desktop'        -Software 'ChatGPT' -Process 'ChatGPT'
    New-AiSignature -Name 'Claude Desktop'         -Software 'Claude' -Process 'Claude'
    New-AiSignature -Name 'Microsoft Copilot'      -Software 'Microsoft Copilot' -Process 'Copilot'
    New-AiSignature -Name 'Perplexity'             -Software 'Perplexity' -Process 'Perplexity'
    # AI-first / AI-integrated editors
    New-AiSignature -Name 'Cursor'                 -Software 'Cursor' -Process 'Cursor' -Config '.cursor'
    New-AiSignature -Name 'Windsurf'               -Software 'Windsurf' -Process 'Windsurf' -Ide 'windsurf','codeium' -Config '.codeium','.windsurf'
    # Coding-assistant IDE extensions
    New-AiSignature -Name 'GitHub Copilot'         -Ide 'github.copilot' -Cli 'copilot'
    New-AiSignature -Name 'Codeium'                -Ide 'codeium.codeium' -Config '.codeium'
    New-AiSignature -Name 'Continue'               -Ide 'continue.continue' -Config '.continue'
    New-AiSignature -Name 'Tabnine'                -Software 'Tabnine' -Process 'tabnine' -Ide 'tabnine.tabnine'
    New-AiSignature -Name 'Sourcegraph Cody'       -Ide 'sourcegraph.cody' -Cli 'cody'
    New-AiSignature -Name 'Amazon Q / CodeWhisperer' -Ide 'amazonwebservices.amazon-q','amazonwebservices.aws-toolkit'
    New-AiSignature -Name 'Supermaven'             -Ide 'supermaven.supermaven'
    # AI command-line tools
    New-AiSignature -Name 'Claude Code'            -Cli 'claude' -Config '.claude','.claude.json'
    New-AiSignature -Name 'Aider'                  -Cli 'aider' -Config '.aider.conf.yml'
    New-AiSignature -Name 'llm (CLI)'              -Cli 'llm'
    New-AiSignature -Name 'ShellGPT'               -Cli 'sgpt'
    New-AiSignature -Name 'Gemini CLI'             -Cli 'gemini'
    New-AiSignature -Name 'Hugging Face CLI'       -Cli 'huggingface-cli'
)

# Generic model directories (relative to each user profile) with a friendly label.
$ModelDirSpecs = @(
    [pscustomobject]@{ Label = 'Ollama models';       Rel = '.ollama\models' }
    [pscustomobject]@{ Label = 'LM Studio models';    Rel = '.lmstudio\models' }
    [pscustomobject]@{ Label = 'LM Studio models';    Rel = '.cache\lm-studio\models' }
    [pscustomobject]@{ Label = 'GPT4All models';      Rel = 'AppData\Local\nomic.ai\GPT4All' }
    [pscustomobject]@{ Label = 'Hugging Face cache';  Rel = '.cache\huggingface\hub' }
    [pscustomobject]@{ Label = 'Jan models';          Rel = 'AppData\Roaming\Jan\data\models' }
)

# VS Code family and JetBrains extension/plugin locations (relative to each user profile).
$IdeExtensionDirs = @(
    '.vscode\extensions', '.vscode-insiders\extensions', '.vscode-oss\extensions',
    '.cursor\extensions', '.windsurf\extensions', '.vscode-server\extensions'
)

# Per-user directories that hold user-installed CLI tools not on the SYSTEM PATH.
$CliProbeDirs = @('AppData\Roaming\npm', '.local\bin', 'AppData\Local\Programs\Python\*\Scripts', 'scoop\shims')

# Environment variable NAMES that look like an AI provider credential. Only the name is inspected.
$EnvProviderPattern = '(?i)^(OPENAI|AZURE_OPENAI|ANTHROPIC|CLAUDE|GEMINI|GOOGLE_GENAI|VERTEX|MISTRAL|GROQ|COHERE|PERPLEXITY|HUGGINGFACE|HUGGING_FACE|HF|XAI|GROK|DEEPSEEK|TOGETHER|REPLICATE|OPENROUTER|STABILITY|ELEVENLABS|OLLAMA)'
$EnvSecretPattern   = '(?i)(API_?KEY|_TOKEN|_HOST|SECRET_KEY)'

# --- Heuristic vectors: catch unknown / renamed tooling by technology, not by product name ---

# 'mldll' - loaded module names that mean a process is doing local ML inference. Kept ML-specific
# on purpose (e.g. no generic cublas/cudart) to limit false positives from games and photo apps.
$MlDllPatterns = @('ggml', 'llama', 'onnxruntime', 'torch', 'cudnn', 'tensorrt', 'tensorflow',
                   'directml', 'openvino', 'whisper', 'ctranslate2', 'sentencepiece')

# 'apiprobe' - only listening ports on this list are probed, and only with a harmless GET. A hit
# requires the response to actually look like an LLM API, so the port number alone never tags.
$ApiProbePorts = @(11434, 1234, 1337, 8080, 5000, 7860, 8000, 4891, 8081, 11435)

# 'modelscan' - model file extensions searched under the user data dirs below. '.bin' is left out
# on purpose (far too many unrelated .bin files); these extensions are unambiguously ML weights.
$ModelExtensions   = @('*.gguf', '*.safetensors', '*.onnx', '*.ggml', '*.pt', '*.pth')
$ModelScanRelDirs  = @('Downloads', 'Documents', 'Desktop')
$MinModelFileBytes = 10MB                # a single file below this size is ignored by 'modelscan'

# 'pkg' - AI SDKs found in Python (pip) and Node (npm) package stores. Vendor-agnostic: OpenAI,
# Anthropic, Google, Cohere, Mistral etc. are treated the same. Names are compared after PEP 503
# normalisation ([-_.] -> '-', lower case), so pip dist-info folder spellings still match.
$PipPackages = @('anthropic', 'openai', 'cohere', 'mistralai', 'google-generativeai',
                 'langchain', 'langchain-anthropic', 'langchain-openai', 'llama-cpp-python',
                 'transformers', 'ollama')
$NpmPackages = @('@anthropic-ai/sdk', '@anthropic-ai/claude-code', 'openai',
                 '@google/generative-ai', 'ai', 'langchain', 'cohere-ai')

# Where to look for pip site-packages (relative to each user profile) and npm's global store.
$SitePackagesRelDirs = @('AppData\Local\Programs\Python\Python*\Lib\site-packages',
                         'AppData\Roaming\Python\Python*\site-packages',
                         'anaconda3\Lib\site-packages', 'miniconda3\Lib\site-packages',
                         'AppData\Local\anaconda3\Lib\site-packages')
$NpmGlobalRelDir     = 'AppData\Roaming\npm\node_modules'

#endregion

#region Inventory

$script:SoftwareInventory = $null
$script:ServiceInventory  = $null
$script:ProcessInventory  = $null
$script:PortInventory     = $null
$script:ProfileRoots      = $null
$script:IdeInventory      = $null
$script:EnvNameInventory  = $null

# Populated by the named-catalog pass so the heuristic vectors do not re-report known tools
$script:MatchedProcessNames = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
$script:MatchedPorts        = New-Object System.Collections.Generic.HashSet[int]

# Structured findings, filled alongside the human-readable strings, serialised to JSON for the dashboard
$script:DataTools     = New-Object System.Collections.Generic.List[object]   # {n=name; e=evidence[]; a=active}
$script:DataModels    = @{}                                                  # label -> bytes (known model dirs)
$script:DataApiKeys   = New-Object System.Collections.Generic.List[string]
$script:DataPackages  = New-Object System.Collections.Generic.List[string]
$script:DataMlDll     = New-Object System.Collections.Generic.List[string]
$script:DataApiServers = New-Object System.Collections.Generic.List[string]
$script:DataModelScan = $null                                                # {count; bytes; exts[]}

function Get-ProfileRoots {
    if ($null -ne $script:ProfileRoots) { return $script:ProfileRoots }

    $roots = New-Object System.Collections.Generic.List[string]
    if ($env:USERPROFILE) { $roots.Add($env:USERPROFILE) }

    # Real profile paths from the ProfileList - excludes the service accounts' pseudo profiles
    try {
        $profileList = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
        foreach ($entry in Get-ChildItem -Path $profileList -ErrorAction SilentlyContinue) {
            $path = (Get-ItemProperty -Path $entry.PSPath -ErrorAction SilentlyContinue).ProfileImagePath
            if ($path -and (Test-Path -Path $path)) { $roots.Add([string]$path) }
        }
    } catch {
        Write-Log ('  Warning: ProfileList could not be read ({0})' -f $_.Exception.Message)
    }

    # Fallback: the Users directory
    try {
        $usersDir = Join-Path $env:SystemDrive 'Users'
        foreach ($dir in Get-ChildItem -Path $usersDir -Directory -ErrorAction SilentlyContinue) {
            if ($dir.Name -in @('Public', 'Default', 'Default User', 'All Users')) { continue }
            $roots.Add($dir.FullName)
        }
    } catch { }

    $script:ProfileRoots = @($roots | Sort-Object -Unique)
    Write-Log ('  Inventory: {0} user profile(s)' -f $script:ProfileRoots.Count)
    $script:ProfileRoots
}

function Get-SoftwareInventory {
    if ($null -ne $script:SoftwareInventory) { return $script:SoftwareInventory }

    $keys = New-Object System.Collections.Generic.List[string]
    $keys.Add('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
    $keys.Add('HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')

    # Per-user installations: the script runs as SYSTEM, so HKCU is not the user's hive
    try {
        foreach ($hive in Get-ChildItem -Path 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue) {
            if ($hive.PSChildName -like '*_Classes') { continue }
            $keys.Add(('Registry::HKEY_USERS\{0}\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' -f $hive.PSChildName))
            $keys.Add(('Registry::HKEY_USERS\{0}\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' -f $hive.PSChildName))
        }
    } catch {
        Write-Log ('  Warning: user hives could not be enumerated ({0})' -f $_.Exception.Message)
    }

    $items = New-Object System.Collections.Generic.List[string]
    foreach ($key in $keys) {
        if (-not (Test-Path -Path $key)) { continue }
        foreach ($entry in Get-ChildItem -Path $key -ErrorAction SilentlyContinue) {
            $properties = $null
            try { $properties = Get-ItemProperty -Path $entry.PSPath -ErrorAction Stop } catch { continue }
            if (-not $properties.DisplayName) { continue }
            if ($properties.SystemComponent -eq 1) { continue }
            $items.Add([string]$properties.DisplayName)
        }
    }

    $script:SoftwareInventory = @($items | Sort-Object -Unique)
    Write-Log ('  Inventory: {0} installed software entries' -f $script:SoftwareInventory.Count)
    $script:SoftwareInventory
}

function Get-ServiceInventory {
    if ($null -ne $script:ServiceInventory) { return $script:ServiceInventory }

    try {
        $script:ServiceInventory = @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{ Name = $_.Name; DisplayName = $_.DisplayName; State = [string]$_.State }
        })
    } catch {
        Write-Log ('  Warning: Win32_Service not available ({0}), falling back to Get-Service' -f $_.Exception.Message)
        $script:ServiceInventory = @(Get-Service -ErrorAction SilentlyContinue | ForEach-Object {
            [pscustomobject]@{ Name = $_.Name; DisplayName = $_.DisplayName; State = [string]$_.Status }
        })
    }

    Write-Log ('  Inventory: {0} services' -f $script:ServiceInventory.Count)
    $script:ServiceInventory
}

function Get-ProcessInventory {
    if ($null -ne $script:ProcessInventory) { return $script:ProcessInventory }

    $script:ProcessInventory = @(Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject]@{ Name = $_.Name; Description = [string]$_.Description }
    } | Sort-Object -Property Name -Unique)
    Write-Log ('  Inventory: {0} running processes' -f $script:ProcessInventory.Count)
    $script:ProcessInventory
}

function Get-PortInventory {
    if ($null -ne $script:PortInventory) { return $script:PortInventory }

    $ports = New-Object System.Collections.Generic.List[int]
    if (Get-Command -Name Get-NetTCPConnection -ErrorAction SilentlyContinue) {
        try {
            foreach ($connection in Get-NetTCPConnection -State Listen -ErrorAction Stop) {
                $ports.Add([int]$connection.LocalPort)
            }
        } catch {
            Write-Log ('  Warning: Get-NetTCPConnection failed ({0})' -f $_.Exception.Message)
        }
    }
    if ($ports.Count -eq 0) {
        # Fallback for older systems: parse netstat
        foreach ($line in (& netstat.exe -an 2>$null)) {
            if ($line -match '^\s*TCP\s+\S+:(\d+)\s+\S+\s+LISTENING') { $ports.Add([int]$Matches[1]) }
        }
    }

    $script:PortInventory = @($ports | Sort-Object -Unique)
    Write-Log ('  Inventory: {0} listening TCP ports' -f $script:PortInventory.Count)
    $script:PortInventory
}

function Get-IdeExtensionInventory {
    if ($null -ne $script:IdeInventory) { return $script:IdeInventory }

    $names = New-Object System.Collections.Generic.List[string]
    foreach ($root in Get-ProfileRoots) {
        foreach ($rel in $IdeExtensionDirs) {
            $dir = Join-Path $root $rel
            if (-not (Test-Path -Path $dir)) { continue }
            foreach ($ext in Get-ChildItem -Path $dir -Directory -ErrorAction SilentlyContinue) {
                $names.Add($ext.Name.ToLowerInvariant())
            }
        }
        # JetBrains IDE plugins (IntelliJ, PyCharm, Rider, ...)
        $jetBrains = Join-Path $root 'AppData\Roaming\JetBrains'
        if (Test-Path -Path $jetBrains) {
            foreach ($plugin in Get-ChildItem -Path $jetBrains -Directory -Recurse -Depth 1 -Filter 'plugins' -ErrorAction SilentlyContinue) {
                foreach ($p in Get-ChildItem -Path $plugin.FullName -Directory -ErrorAction SilentlyContinue) {
                    $names.Add($p.Name.ToLowerInvariant())
                }
            }
        }
    }

    $script:IdeInventory = @($names | Sort-Object -Unique)
    Write-Log ('  Inventory: {0} IDE extension(s)' -f $script:IdeInventory.Count)
    $script:IdeInventory
}

function Get-EnvNameInventory {
    if ($null -ne $script:EnvNameInventory) { return $script:EnvNameInventory }

    $names = New-Object System.Collections.Generic.List[string]
    foreach ($scope in @('Machine', 'Process')) {
        try {
            foreach ($name in ([Environment]::GetEnvironmentVariables($scope)).Keys) { $names.Add([string]$name) }
        } catch { }
    }

    # Per-user variables live in the loaded user hives, not in SYSTEM's own environment
    try {
        foreach ($hive in Get-ChildItem -Path 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue) {
            if ($hive.PSChildName -like '*_Classes') { continue }
            foreach ($sub in @('Environment', 'Volatile Environment')) {
                $path = ('Registry::HKEY_USERS\{0}\{1}' -f $hive.PSChildName, $sub)
                if (-not (Test-Path -Path $path)) { continue }
                foreach ($name in (Get-Item -Path $path -ErrorAction SilentlyContinue).Property) { $names.Add([string]$name) }
            }
        }
    } catch {
        Write-Log ('  Warning: user environment hives could not be read ({0})' -f $_.Exception.Message)
    }

    $script:EnvNameInventory = @($names | Sort-Object -Unique)
    $script:EnvNameInventory
}

#endregion

#region Matching

# Case-insensitive substring match, '*' and '?' in the pattern turn it into a wildcard match
function Test-PatternMatch([string]$Value, [string]$Pattern) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    if ($Pattern.Contains('*') -or $Pattern.Contains('?')) { return $Value -like $Pattern }
    return $Value.IndexOf($Pattern, [StringComparison]::OrdinalIgnoreCase) -ge 0
}

function Find-Software([string]$Pattern) {
    foreach ($displayName in Get-SoftwareInventory) {
        if (Test-PatternMatch -Value $displayName -Pattern $Pattern) { return $displayName }
    }
    $null
}

function Find-NinjaService([string]$Pattern) {
    foreach ($service in Get-ServiceInventory) {
        if (-not ((Test-PatternMatch -Value $service.Name -Pattern $Pattern) -or
                  (Test-PatternMatch -Value $service.DisplayName -Pattern $Pattern))) { continue }
        if ($RequireServiceRunning -and $service.State -ne 'Running') { continue }
        if ($service.DisplayName) { return $service.DisplayName }
        return $service.Name
    }
    $null
}

function Find-NinjaProcess([string]$Pattern) {
    foreach ($process in Get-ProcessInventory) {
        if ((Test-PatternMatch -Value $process.Name -Pattern $Pattern) -or
            (Test-PatternMatch -Value $process.Description -Pattern $Pattern)) { return $process.Name }
    }
    $null
}

function Test-PortListening([int]$Port) {
    foreach ($listening in Get-PortInventory) {
        if ($listening -eq $Port) { return $true }
    }
    $false
}

function Find-IdeExtension([string]$Pattern) {
    foreach ($ext in Get-IdeExtensionInventory) {
        if (Test-PatternMatch -Value $ext -Pattern $Pattern) { return $ext }
    }
    $null
}

# A tool's config file / directory (e.g. '.claude') in any user profile is a strong usage signal
function Find-ConfigPath([string]$RelPath) {
    foreach ($root in Get-ProfileRoots) {
        if (Test-Path -Path (Join-Path $root $RelPath)) { return $true }
    }
    $false
}

# Get-Command against the SYSTEM PATH first, then the common per-user tool directories
function Find-Cli([string]$Name) {
    $command = Get-Command -Name $Name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($command) { return $command.Source }

    foreach ($root in Get-ProfileRoots) {
        foreach ($probe in $CliProbeDirs) {
            foreach ($ext in @('', '.exe', '.cmd', '.bat', '.ps1')) {
                $candidate = Join-Path $root (Join-Path $probe ($Name + $ext))
                # Join-Path resolves the wildcard in some probe dirs (Python\*\Scripts)
                foreach ($resolved in (Resolve-Path -Path $candidate -ErrorAction SilentlyContinue)) {
                    if (Test-Path -Path $resolved.Path -PathType Leaf) { return $resolved.Path }
                }
            }
        }
    }
    $null
}

#endregion

#region Detection

function Get-NamedDetections {
    param([hashtable]$Enabled)

    $results = New-Object System.Collections.Generic.List[string]
    foreach ($sig in $AiCatalog) {
        $evidence = New-Object System.Collections.Generic.List[string]

        if ($Enabled['software'] -and $sig.Software.Count) {
            foreach ($p in $sig.Software) { if (Find-Software $p) { $evidence.Add('installed'); break } }
        }
        if ($Enabled['process'] -and $sig.Process.Count) {
            foreach ($p in $sig.Process) {
                $hit = Find-NinjaProcess $p
                if ($hit) { $evidence.Add('running'); [void]$script:MatchedProcessNames.Add($hit); break }
            }
        }
        if ($Enabled['service'] -and $sig.Service.Count) {
            foreach ($p in $sig.Service) { if (Find-NinjaService $p) { $evidence.Add('service'); break } }
        }
        if ($Enabled['port'] -and $sig.Port.Count) {
            foreach ($port in $sig.Port) {
                if (Test-PortListening $port) { $evidence.Add('port ' + $port); [void]$script:MatchedPorts.Add($port) }
            }
        }
        if ($Enabled['ide'] -and $sig.Ide.Count) {
            foreach ($p in $sig.Ide) { if (Find-IdeExtension $p) { $evidence.Add('IDE plugin'); break } }
        }
        if ($Enabled['cli'] -and $sig.Cli.Count) {
            foreach ($p in $sig.Cli) { if (Find-Cli $p) { $evidence.Add('CLI'); break } }
        }
        if ($Enabled['config'] -and $sig.Config.Count) {
            foreach ($p in $sig.Config) { if (Find-ConfigPath $p) { $evidence.Add('config dir'); break } }
        }

        if ($evidence.Count -gt 0) {
            $line = '{0} ({1})' -f $sig.Name, ($evidence -join ', ')
            Write-Log ('  Detected: {0}' -f $line)
            $results.Add($line)
            # "active" = something is running now (a process or a listening port), not just installed
            $active = [bool](@($evidence | Where-Object { $_ -eq 'running' -or $_ -like 'port *' }).Count)
            $script:DataTools.Add([pscustomobject]@{ n = $sig.Name; e = @($evidence); a = $active })
        }
    }
    $results
}

function Get-ModelFileDetections {
    # label -> largest size seen across profiles
    $found = @{}
    foreach ($root in Get-ProfileRoots) {
        foreach ($spec in $ModelDirSpecs) {
            $dir = Join-Path $root $spec.Rel
            if (-not (Test-Path -Path $dir)) { continue }
            $size = 0
            try {
                $measure = Get-ChildItem -Path $dir -Recurse -File -Force -ErrorAction SilentlyContinue |
                    Measure-Object -Property Length -Sum
                if ($measure.Sum) { $size = [long]$measure.Sum }
            } catch { }
            if ($size -lt $MinModelBytes) { continue }
            if (-not $found.ContainsKey($spec.Label) -or $size -gt $found[$spec.Label]) {
                $found[$spec.Label] = $size
            }
        }
    }
    if ($found.Count -eq 0) { return $null }

    $script:DataModels = $found
    $parts = foreach ($label in ($found.Keys | Sort-Object)) { '{0} ({1})' -f $label, (Format-Size $found[$label]) }
    $line = 'Local AI models: ' + ($parts -join ', ')
    Write-Log ('  Detected: {0}' -f $line)
    $line
}

function Get-EnvKeyDetections {
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($name in Get-EnvNameInventory) {
        if ($name -match $EnvProviderPattern -and $name -match $EnvSecretPattern) { $names.Add($name) }
    }
    if ($names.Count -eq 0) { return $null }

    $unique = @($names | Sort-Object -Unique)
    foreach ($n in $unique) { $script:DataApiKeys.Add($n) }
    $line = 'AI API keys in environment: ' + ($unique -join ', ')
    Write-Log ('  Detected: {0}' -f $line)
    $line
}

# Heuristic: a process that has an ML inference runtime loaded is doing local AI, whatever it is
# called. Processes already named by the catalog are skipped so this only surfaces the unknowns.
function Get-MlDllDetections {
    $hits = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($proc in (Get-Process -ErrorAction SilentlyContinue)) {
        if ($script:MatchedProcessNames.Contains($proc.Name)) { continue }
        if ($hits.ContainsKey($proc.Name)) { continue }
        $modules = $null
        try { $modules = $proc.Modules } catch { continue }   # access denied / bitness mismatch
        if (-not $modules) { continue }
        foreach ($module in $modules) {
            $name = ([string]$module.ModuleName).ToLowerInvariant()
            foreach ($pattern in $MlDllPatterns) {
                if ($name.Contains($pattern)) { $hits[$proc.Name] = $pattern; break }
            }
            if ($hits.ContainsKey($proc.Name)) { break }
        }
    }
    if ($hits.Count -eq 0) { return $null }

    $parts = foreach ($name in ($hits.Keys | Sort-Object)) { '{0} ({1})' -f $name, $hits[$name] }
    foreach ($p in $parts) { $script:DataMlDll.Add($p) }
    $line = 'Possible local AI (ML runtime loaded): ' + ($parts -join ', ')
    Write-Log ('  Detected: {0}' -f $line)
    $line
}

# Heuristic: probe listening ports that are not already tied to a known tool, and only report a hit
# when the port answers like an LLM server. This fingerprints behaviour, so it needs no product name.
function Get-ApiProbeDetections {
    $results = New-Object System.Collections.Generic.List[string]
    $listening = Get-PortInventory
    foreach ($port in $ApiProbePorts) {
        if ($script:MatchedPorts.Contains($port)) { continue }
        if ($listening -notcontains $port) { continue }

        $kind = $null
        # Ollama-style API
        try {
            $tags = Invoke-RestMethod -Uri ('http://127.0.0.1:{0}/api/tags' -f $port) -TimeoutSec 2 -ErrorAction Stop
            if ($null -ne $tags -and ($tags.PSObject.Properties.Name -contains 'models')) { $kind = 'Ollama API' }
        } catch { }
        # OpenAI-compatible API
        if (-not $kind) {
            try {
                $models = Invoke-RestMethod -Uri ('http://127.0.0.1:{0}/v1/models' -f $port) -TimeoutSec 2 -ErrorAction Stop
                if ($null -ne $models -and (($models.object -eq 'list') -or ($models.PSObject.Properties.Name -contains 'data'))) {
                    $kind = 'OpenAI-compatible API'
                }
            } catch { }
        }
        if ($kind) {
            $line = 'Local LLM server ({0}, port {1})' -f $kind, $port
            Write-Log ('  Detected: {0}' -f $line)
            $results.Add($line)
            $script:DataApiServers.Add(('{0}, port {1}' -f $kind, $port))
        }
    }
    if ($results.Count -eq 0) { return $null }
    $results -join $Separator
}

# Heuristic: model weight files placed in the usual user data folders. Unambiguous ML extensions
# only, above a minimum size, so a stray tiny .pt does not trigger it.
function Get-ModelScanDetections {
    $count = 0
    [long]$total = 0
    $seenExt = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
    foreach ($root in Get-ProfileRoots) {
        foreach ($rel in $ModelScanRelDirs) {
            $dir = Join-Path $root $rel
            if (-not (Test-Path -Path $dir)) { continue }
            foreach ($file in (Get-ChildItem -Path $dir -Recurse -File -Force -Include $ModelExtensions -ErrorAction SilentlyContinue)) {
                if ($file.Length -lt $MinModelFileBytes) { continue }
                $count++
                $total += [long]$file.Length
                [void]$seenExt.Add($file.Extension.ToLowerInvariant())
            }
        }
    }
    if ($count -eq 0) { return $null }

    $sortedExts = @($seenExt | Sort-Object)
    $script:DataModelScan = [pscustomobject]@{ count = $count; bytes = $total; exts = $sortedExts }
    $exts = $sortedExts -join ', '
    $line = 'Local model files: {0} file(s), {1} ({2})' -f $count, (Format-Size $total), $exts
    Write-Log ('  Detected: {0}' -f $line)
    $line
}

# PEP 503 name normalisation: collapse runs of - _ . into a single '-' and lower-case
function ConvertTo-NormalizedName([string]$Name) {
    ($Name -replace '[-_.]+', '-').ToLowerInvariant()
}

# Vector 'pkg': AI SDKs installed via pip (any dist-info in a site-packages dir) or npm (global
# store). Vendor-agnostic - the same check finds the anthropic and the openai package.
function Get-PkgDetections {
    $found = New-Object System.Collections.Generic.List[string]

    # pip: match the normalised distribution name from every *.dist-info / *.egg-info folder
    $pipTargets = @{}
    foreach ($p in $PipPackages) { $pipTargets[(ConvertTo-NormalizedName $p)] = $p }
    $seenPip = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
    foreach ($root in Get-ProfileRoots) {
        foreach ($rel in $SitePackagesRelDirs) {
            foreach ($dir in (Resolve-Path -Path (Join-Path $root $rel) -ErrorAction SilentlyContinue)) {
                foreach ($meta in (Get-ChildItem -Path $dir.Path -Directory -ErrorAction SilentlyContinue |
                                   Where-Object { $_.Name -like '*.dist-info' -or $_.Name -like '*.egg-info' })) {
                    $base = $meta.Name -replace '\.(dist|egg)-info$', ''   # drop the metadata suffix
                    $distName = $base -replace '-\d.*$', ''                # drop the trailing -<version>
                    $norm = ConvertTo-NormalizedName $distName
                    if ($pipTargets.ContainsKey($norm) -and $seenPip.Add($norm)) {
                        $found.Add(('{0} (pip)' -f $pipTargets[$norm]))
                    }
                }
            }
        }
    }

    # npm: the global node_modules holds each package (scoped names map to nested folders)
    $seenNpm = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
    foreach ($root in Get-ProfileRoots) {
        $base = Join-Path $root $NpmGlobalRelDir
        if (-not (Test-Path -Path $base)) { continue }
        foreach ($pkg in $NpmPackages) {
            $pkgPath = Join-Path $base ($pkg -replace '/', '\')
            if ((Test-Path -Path $pkgPath) -and $seenNpm.Add($pkg)) { $found.Add(('{0} (npm)' -f $pkg)) }
        }
    }

    if ($found.Count -eq 0) { return $null }
    $unique = @($found | Sort-Object -Unique)
    foreach ($p in $unique) { $script:DataPackages.Add($p) }
    $line = 'AI SDKs installed: ' + ($unique -join ', ')
    Write-Log ('  Detected: {0}' -f $line)
    $line
}

#endregion

#region JSON (5.1-hard, no ConvertTo-Json)

# Built by hand so the output does not depend on Windows PowerShell 5.1 ConvertTo-Json behaviour
# (single-element arrays unwrapping to objects, default -Depth of 2, culture-dependent numbers).
# Arrays are always arrays, numbers are invariant, strings are escaped incl. non-ASCII as \uXXXX.

function ConvertTo-JsonString([string]$Text) {
    if ($null -eq $Text) { return '""' }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('"')
    foreach ($ch in $Text.ToCharArray()) {
        $code = [int]$ch
        switch ($ch) {
            '"' { [void]$sb.Append('\"'); continue }
            '\' { [void]$sb.Append('\\'); continue }
            "`b" { [void]$sb.Append('\b'); continue }
            "`f" { [void]$sb.Append('\f'); continue }
            "`n" { [void]$sb.Append('\n'); continue }
            "`r" { [void]$sb.Append('\r'); continue }
            "`t" { [void]$sb.Append('\t'); continue }
        }
        if ($code -lt 32 -or $code -gt 126) { [void]$sb.Append('\u'); [void]$sb.Append($code.ToString('x4')) }
        else { [void]$sb.Append($ch) }
    }
    [void]$sb.Append('"')
    $sb.ToString()
}

function ConvertTo-JsonStringArray($Items) {
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($item in $Items) { $parts.Add((ConvertTo-JsonString ([string]$item))) }
    '[' + ($parts -join ',') + ']'
}

function Format-JsonInt($Value) { ([long]$Value).ToString([Globalization.CultureInfo]::InvariantCulture) }

function New-AiDataJson {
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('{"v":1')
    [void]$sb.Append(',"host":' + (ConvertTo-JsonString ([string]$env:COMPUTERNAME)))
    [void]$sb.Append(',"at":' + (ConvertTo-JsonString ((Get-Date).ToUniversalTime().ToString('o'))))

    # tools: [{ "n": name, "e": [evidence], "a": active }]
    $toolParts = New-Object System.Collections.Generic.List[string]
    foreach ($tool in $script:DataTools) {
        $active = if ($tool.a) { 'true' } else { 'false' }
        $toolParts.Add('{"n":' + (ConvertTo-JsonString ([string]$tool.n)) +
            ',"e":' + (ConvertTo-JsonStringArray $tool.e) + ',"a":' + $active + '}')
    }
    [void]$sb.Append(',"tools":[' + ($toolParts -join ',') + ']')

    # models: [{ "label": label, "bytes": n }]
    $modelParts = New-Object System.Collections.Generic.List[string]
    foreach ($label in ($script:DataModels.Keys | Sort-Object)) {
        $modelParts.Add('{"label":' + (ConvertTo-JsonString ([string]$label)) +
            ',"bytes":' + (Format-JsonInt $script:DataModels[$label]) + '}')
    }
    [void]$sb.Append(',"models":[' + ($modelParts -join ',') + ']')

    # modelFiles: { "count": n, "bytes": n, "exts": [..] } or null
    if ($script:DataModelScan) {
        [void]$sb.Append(',"modelFiles":{"count":' + (Format-JsonInt $script:DataModelScan.count) +
            ',"bytes":' + (Format-JsonInt $script:DataModelScan.bytes) +
            ',"exts":' + (ConvertTo-JsonStringArray $script:DataModelScan.exts) + '}')
    }
    else {
        [void]$sb.Append(',"modelFiles":null')
    }

    [void]$sb.Append(',"apiKeys":' + (ConvertTo-JsonStringArray $script:DataApiKeys))
    [void]$sb.Append(',"packages":' + (ConvertTo-JsonStringArray $script:DataPackages))
    [void]$sb.Append(',"mldll":' + (ConvertTo-JsonStringArray $script:DataMlDll))
    [void]$sb.Append(',"apiServers":' + (ConvertTo-JsonStringArray $script:DataApiServers))
    [void]$sb.Append('}')
    $sb.ToString()
}

#endregion

#region Event log

# Event ID scheme (documented in the README - keep stable, SIEM / NinjaOne conditions build on it):
#   5000 Information  scan summary (every run)
#   5001 Warning      local LLM server detected (new)
#   5002 Warning      unidentified ML runtime loaded (new)
#   5003 Warning      AI API key present in environment (new)
#   5004 Information   named AI tool detected (new)
#   5010 Information   an AI signal from a previous run is no longer present (cleared)

function Test-Truthy([string]$Value) {
    if (-not $Value) { return $false }
    @('1', 'true', 'yes', 'on', 'enabled') -contains $Value.Trim().ToLowerInvariant()
}

# The current run's signals, each a stable key (for change detection) plus its event id/level/message
function Get-AiSignals {
    $signals = New-Object System.Collections.Generic.List[object]
    foreach ($tool in $script:DataTools) {
        $evidence = ''
        try { $evidence = (@($tool.e) -join ', ') } catch { }
        $signals.Add([pscustomobject]@{ key = "tool:$($tool.n)"; id = 5004; level = 'Information'; message = "AI tool detected: $($tool.n) ($evidence)" })
    }
    foreach ($server in $script:DataApiServers) {
        $signals.Add([pscustomobject]@{ key = "server:$server"; id = 5001; level = 'Warning'; message = "Local LLM server detected: $server" })
    }
    foreach ($runtime in $script:DataMlDll) {
        $signals.Add([pscustomobject]@{ key = "mldll:$runtime"; id = 5002; level = 'Warning'; message = "Unidentified ML runtime loaded: $runtime" })
    }
    foreach ($key in $script:DataApiKeys) {
        $signals.Add([pscustomobject]@{ key = "apikey:$key"; id = 5003; level = 'Warning'; message = "AI API key present in environment: $key" })
    }
    $signals
}

function Get-EventCache {
    if (-not (Test-Path -Path $EventCachePath)) { return @() }
    try { @(([IO.File]::ReadAllText($EventCachePath, [Text.Encoding]::UTF8) | ConvertFrom-Json)) }
    catch { @() }
}

function Save-EventCache($Keys) {
    try { [IO.File]::WriteAllText($EventCachePath, (ConvertTo-JsonStringArray $Keys), (New-Object Text.UTF8Encoding($false))) }
    catch { Write-Log ('  Warning: could not write event cache ({0})' -f $_.Exception.Message) }
}

# Creates the event source on first use (needs admin; the agent runs as SYSTEM). Returns $true if usable.
function Initialize-EventSource {
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
            [System.Diagnostics.EventLog]::CreateEventSource($EventSource, $EventLogName)
            Write-Log ('  Event source "{0}" created in the {1} log' -f $EventSource, $EventLogName)
        }
        $true
    }
    catch {
        Write-Log ('  Warning: event logging unavailable ({0}). Creating the source once needs admin rights.' -f $_.Exception.Message)
        $false
    }
}

function Write-AiEvent([int]$EventId, [string]$Level, [string]$Message) {
    try { Write-EventLog -LogName $EventLogName -Source $EventSource -EventId $EventId -EntryType $Level -Message $Message -ErrorAction Stop }
    catch { Write-Log ('  Warning: could not write event {0} ({1})' -f $EventId, $_.Exception.Message) }
}

# Emits the summary event, one event per NEW signal, and a cleared event per signal that disappeared.
# A local cache of the previous run's keys keeps a scheduled run from re-logging unchanged findings.
function Invoke-EventLogging([bool]$IsDryRun) {
    $signals = @(Get-AiSignals)
    $currentKeys = @($signals | ForEach-Object { $_.key })
    $previousKeys = @(Get-EventCache)

    $newSignals = @($signals | Where-Object { $previousKeys -notcontains $_.key })
    $clearedKeys = @($previousKeys | Where-Object { $currentKeys -notcontains $_ })

    $summary = 'AI scan on {0}: {1} tool(s), {2} local LLM server(s), {3} API key(s), {4} unidentified ML runtime(s). {5} new, {6} cleared since last run.' -f `
        $env:COMPUTERNAME, $script:DataTools.Count, $script:DataApiServers.Count, $script:DataApiKeys.Count, $script:DataMlDll.Count, $newSignals.Count, $clearedKeys.Count

    if ($IsDryRun) {
        Write-Log ('Dry run: would write event 5000 (summary) + {0} new + {1} cleared event(s)' -f $newSignals.Count, $clearedKeys.Count)
        return
    }

    Write-AiEvent 5000 'Information' $summary
    foreach ($signal in $newSignals) { Write-AiEvent $signal.id $signal.level $signal.message }
    foreach ($clearedKey in $clearedKeys) { Write-AiEvent 5010 'Information' ("AI signal no longer present: $clearedKey") }

    Save-EventCache $currentKeys
    Write-Log ('Event log: summary + {0} new + {1} cleared event(s) written (source "{2}")' -f $newSignals.Count, $clearedKeys.Count, $EventSource)
}

#endregion

#region Custom field

function Set-NinjaCustomField([string]$Name, [string]$Value) {
    $fieldValue = $Value
    if ([string]::IsNullOrEmpty($fieldValue)) { $fieldValue = $null }

    $hasPiped = [bool](Get-Command -Name 'Ninja-Property-Set-Piped' -ErrorAction SilentlyContinue)
    $hasDirect = [bool](Get-Command -Name 'Ninja-Property-Set' -ErrorAction SilentlyContinue)

    # Piped variant: the value is not parsed as a command line, so quotes and spaces are safe.
    # An empty value clears the field, and for that the direct variant with $null is the reliable one.
    if ($hasPiped -and $null -ne $fieldValue) {
        $fieldValue | Ninja-Property-Set-Piped $Name | Out-Null
        return 'Ninja-Property-Set-Piped'
    }
    if ($hasDirect) {
        Ninja-Property-Set $Name $fieldValue | Out-Null
        return 'Ninja-Property-Set'
    }
    if ($hasPiped) {
        $fieldValue | Ninja-Property-Set-Piped $Name | Out-Null
        return 'Ninja-Property-Set-Piped'
    }

    $cli = Join-Path $env:ProgramData 'NinjaRMMAgent\ninjarmm-cli.exe'
    if (Test-Path -Path $cli) {
        & $cli set $Name $fieldValue | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "ninjarmm-cli.exe returned exit code $LASTEXITCODE." }
        return 'ninjarmm-cli.exe'
    }

    throw 'No NinjaOne agent command found (Ninja-Property-Set / ninjarmm-cli.exe). Run the script through the NinjaOne agent or use -DryRun.'
}

#endregion

$AllVectors = @('software', 'process', 'service', 'port', 'artifact', 'ide', 'cli', 'config',
                'env', 'pkg', 'mldll', 'apiprobe', 'modelscan')

try {
    $CustomFieldName = "$CustomFieldName".Trim()
    if (-not $CustomFieldName) { throw "Script variable 'customFieldName' is required." }

    # Every vector is on unless listed in 'disabledVectors'
    $enabled = @{}
    foreach ($v in $AllVectors) { $enabled[$v] = $true }
    foreach ($raw in ($DisabledVectors -split '[,;\s]+')) {
        $v = $raw.Trim().ToLowerInvariant()
        if (-not $v) { continue }
        if ($AllVectors -contains $v) { $enabled[$v] = $false }
        else { Write-Log ('Warning: unknown vector "{0}" in disabledVectors, ignored' -f $v) }
    }
    $activeVectors = @($AllVectors | Where-Object { $enabled[$_] })
    Write-Log ('Device {0}: target field "{1}", active vectors: {2}' -f $env:COMPUTERNAME, $CustomFieldName, ($activeVectors -join ', '))

    $values = New-Object System.Collections.Generic.List[string]

    foreach ($line in (Get-NamedDetections -Enabled $enabled)) {
        if (-not $values.Contains($line)) { $values.Add($line) }
    }
    if ($enabled['artifact']) {
        $models = Get-ModelFileDetections
        if ($models) { $values.Add($models) }
    }
    if ($enabled['env']) {
        $keys = Get-EnvKeyDetections
        if ($keys) { $values.Add($keys) }
    }
    if ($enabled['pkg']) {
        $pkgs = Get-PkgDetections
        if ($pkgs) { $values.Add($pkgs) }
    }
    # Heuristic vectors run after the named pass so they can skip what the catalog already covered
    if ($enabled['mldll']) {
        $dlls = Get-MlDllDetections
        if ($dlls) { $values.Add($dlls) }
    }
    if ($enabled['apiprobe']) {
        foreach ($line in ((Get-ApiProbeDetections) -split '\r?\n')) {
            if ($line -and -not $values.Contains($line)) { $values.Add($line) }
        }
    }
    if ($enabled['modelscan']) {
        $found = Get-ModelScanDetections
        if ($found) { $values.Add($found) }
    }

    $fieldValue = $NoMatchValue
    if ($values.Count -gt 0) {
        $fieldValue = $values -join $Separator
        while ($fieldValue.Length -gt $MaxLength -and $values.Count -gt 1) {
            Write-Log ('Value longer than {0} characters, dropping "{1}"' -f $MaxLength, $values[$values.Count - 1])
            $values.RemoveAt($values.Count - 1)
            $fieldValue = $values -join $Separator
        }
        if ($fieldValue.Length -gt $MaxLength) { $fieldValue = $fieldValue.Substring(0, $MaxLength) }
    } else {
        Write-Log 'No AI tooling detected.'
    }

    # A multi-line value would break the log into several lines, so show it on one
    $logValue = $fieldValue -replace '\r?\n', ' | '

    # Machine-readable JSON of the same findings, for the central dashboard to aggregate.
    # Built by hand (see the JSON region) so it does not depend on 5.1 ConvertTo-Json behaviour.
    $DataFieldName = "$DataFieldName".Trim()
    $json = $null
    if ($DataFieldName) { $json = New-AiDataJson }

    $writeEvents = Test-Truthy $WriteEventLog

    if ($DryRun) {
        Write-Log ('Dry run: custom field "{0}" would be set to "{1}"' -f $CustomFieldName, $logValue)
        if ($DataFieldName) { Write-Log ('Dry run: data field "{0}" would be set to {1} characters of JSON' -f $DataFieldName, $json.Length) }
        if ($writeEvents) { Invoke-EventLogging $true }
        exit 0
    }

    $usedCommand = Set-NinjaCustomField -Name $CustomFieldName -Value $fieldValue
    Write-Log ('Custom field "{0}" set to "{1}" (via {2})' -f $CustomFieldName, $logValue, $usedCommand)

    if (Get-Command -Name 'Ninja-Property-Get' -ErrorAction SilentlyContinue) {
        $readBack = "$(Ninja-Property-Get $CustomFieldName)" -replace '\r?\n', ' | '
        Write-Log ('  Read back: "{0}"' -f $readBack)
    }

    if ($DataFieldName) {
        Set-NinjaCustomField -Name $DataFieldName -Value $json | Out-Null
        Write-Log ('Data field "{0}" set ({1} characters of JSON)' -f $DataFieldName, $json.Length)
    }

    if ($writeEvents -and (Initialize-EventSource)) { Invoke-EventLogging $false }

    exit 0
} catch {
    Write-Log ('ERROR: {0}' -f $_.Exception.Message)
    exit 1
}
