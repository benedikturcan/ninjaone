<#
.SYNOPSIS
    Builds a fleet-wide AI dashboard from the per-device JSON written by Set-AiDetectionTag.ps1 and
    writes it into the global WYSIWYG custom field "aiDashboard".

.DESCRIPTION
    Runs as a NinjaOne automation (Windows PowerShell 5.1) on ONE device, or locally. It is the
    central half of a two-component design:
        1. Set-AiDetectionTag.ps1 runs per device (agent, SYSTEM) and writes a compact JSON of its
           AI findings into a device custom field (default 'aiData').
        2. This script runs centrally, reads that field from EVERY device through the NinjaOne API,
           aggregates it, and renders one deep-analytical WYSIWYG dashboard.

    Data sources (official public API, client_credentials):
        GET   /v2/devices                         device id -> name
        GET   /v2/queries/custom-fields           the per-device AI JSON (paged via cursor)
        PATCH /v2/system/custom-fields            write the dashboard HTML

    The dashboard shows, across the whole fleet:
        - summary KPIs (devices scanned, devices with AI, tools seen, devices running AI now,
          devices with API keys, total local model storage),
        - every AI tool with how many devices have it, how many run it, and on WHICH devices,
        - a breakdown by category (local runtime / desktop app / coding assistant / CLI),
        - shadow-AI signals: local LLM servers and processes with an ML runtime loaded,
        - AI API keys by provider and AI SDKs (pip/npm) by package,
        - local model files by device.

    NinjaOne script variables (injected as environment variables, use these calculated names):
        clientId            API client ID (client_credentials, scopes: monitoring + management)
        clientSecret        API client secret
        region              NinjaOne region: eu (default), app, ca, oc, ...
        dataFieldName       Device field to read the AI JSON from (default 'aiData')
        dashboardFieldName  Global WYSIWYG field to write into (default 'aiDashboard')

    WYSIWYG fields only allow a small tag/style allowlist (no script, style, svg, img, strong, br):
    the dashboard is built from div/span/table, inline styles, background-bar charts and Font Awesome
    icons, exactly like Policy-Hierarchy-Report.ps1. Non-ASCII output is written as HTML entities.

    The source is kept ASCII-only on purpose: Windows PowerShell 5.1 reads BOM-less scripts as ANSI.
    Exit codes: 0 = dashboard written, 1 = error.

.EXAMPLE
    .\Set-AiDashboard.ps1 -ClientId '<id>' -ClientSecret '<secret>' -Region eu
#>
param(
    [string]$ClientId = $env:clientId,
    [string]$ClientSecret = $env:clientSecret,
    [string]$Region = $env:region,
    [string]$DataFieldName = $env:dataFieldName,
    [string]$DashboardFieldName = $env:dashboardFieldName
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

if (-not $ClientId) { $ClientId = $env:NINJA_CLIENT_ID }
if (-not $ClientSecret) { $ClientSecret = $env:NINJA_CLIENT_SECRET }
if (-not $Region) { $Region = if ($env:NINJA_REGION) { $env:NINJA_REGION } else { 'eu' } }
if (-not $DataFieldName) { $DataFieldName = 'aiData' }
if (-not $DashboardFieldName) { $DashboardFieldName = 'aiDashboard' }

$ApiUrl = "https://$Region.ninjarmm.com"
$Invariant = [Globalization.CultureInfo]::InvariantCulture
$script:DeviceNames = @{}   # deviceId -> name, filled by the bulk list and per-device lookups

#region HTTP

function Invoke-NinjaRequest {
    param(
        [Parameter(Mandatory)] [string]$Uri,
        [string]$Method = 'GET',
        [hashtable]$Headers = @{},
        $Body,
        [string]$ContentType
    )
    $params = @{ Uri = $Uri; Method = $Method; Headers = $Headers; UseBasicParsing = $true }
    if ($null -ne $Body) { $params.Body = $Body }
    if ($ContentType) { $params.ContentType = $ContentType }
    $response = Invoke-WebRequest @params
    [pscustomobject]@{
        StatusCode = [int]$response.StatusCode
        Text       = [Text.Encoding]::UTF8.GetString($response.RawContentStream.ToArray())
    }
}

function Get-AccessToken {
    $response = Invoke-NinjaRequest -Uri "$ApiUrl/ws/oauth/token" -Method POST -ContentType 'application/x-www-form-urlencoded' -Body @{
        grant_type    = 'client_credentials'
        client_id     = $ClientId
        client_secret = $ClientSecret
        # 'management' is required to write custom field values
        scope         = 'monitoring management'
    }
    ($response.Text | ConvertFrom-Json).access_token
}

function Invoke-NinjaApi {
    param([Parameter(Mandatory)] [string]$Endpoint)
    $response = Invoke-NinjaRequest -Uri "$ApiUrl$Endpoint" -Headers @{ Authorization = "Bearer $script:AccessToken"; Accept = 'application/json' }
    $response.Text | ConvertFrom-Json
}

function Set-GlobalCustomField {
    param([string]$FieldName, [string]$Html)
    $json = ConvertTo-Json -InputObject @{ $FieldName = @{ html = $Html } } -Depth 5 -Compress
    Invoke-NinjaRequest -Uri "$ApiUrl/v2/system/custom-fields" -Method PATCH `
        -Headers @{ Authorization = "Bearer $script:AccessToken" } `
        -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($json)) | Out-Null
}

#endregion

#region Data retrieval

function Get-DeviceName($Device) {
    if ($null -eq $Device) { return $null }
    if ($Device.displayName) { return "$($Device.displayName)" }
    if ($Device.systemName) { return "$($Device.systemName)" }
    if ($Device.dnsName) { return "$($Device.dnsName)" }
    if ($Device.netbiosName) { return "$($Device.netbiosName)" }
    $null
}

# Best-effort bulk name load. Handles the same shapes as the custom-field query (results / devices /
# bare array) and only stores real names, so anything it misses falls back to a per-device lookup.
function Get-AllDevices {
    $after = 0
    $count = 0
    while ($true) {
        $response = Invoke-NinjaApi ("/v2/devices?pageSize=1000&after={0}" -f $after)
        $batch = @()
        if ($null -eq $response) { $batch = @() }
        elseif ($response.PSObject.Properties['results']) { $batch = @($response.results) }
        elseif ($response.PSObject.Properties['devices']) { $batch = @($response.devices) }
        elseif ($response -is [System.Collections.IEnumerable] -and $response -isnot [string]) { $batch = @($response) }
        else { $batch = @($response) }
        if ($batch.Count -eq 0) { break }

        foreach ($device in $batch) {
            if ($null -eq $device -or -not $device.id) { continue }
            $name = Get-DeviceName $device
            if ($name) { $script:DeviceNames["$($device.id)"] = $name; $count++ }
        }

        if ($batch.Count -lt 1000) { break }
        $lastId = [int64]0
        $last = $batch | Select-Object -Last 1
        if ($last) { [void][int64]::TryParse("$($last.id)", [ref]$lastId) }
        if ($lastId -le $after) { break }
        $after = $lastId
    }
    $count
}

# Reliable per-device name (the pattern the Policy Hierarchy Report uses). Cached, and only called
# for devices that actually report AI, so it stays cheap even on a large fleet.
function Resolve-DeviceName([string]$Id) {
    if (-not $Id) { return 'Unknown device' }
    if ($script:DeviceNames.ContainsKey($Id)) { return $script:DeviceNames[$Id] }
    $name = $null
    try { $name = Get-DeviceName (Invoke-NinjaApi "/v2/device/$Id") } catch { }
    if (-not $name) { $name = "Device $Id" }
    $script:DeviceNames[$Id] = $name
    $name
}

# Reads one custom field across all devices, following the query cursor to the end.
# Logs the response shape on the first page and handles results / devices / bare-array shapes, so a
# 0-row result is diagnosable (usually the field lacks API-read permission or the name is wrong).
function Get-CustomFieldValues {
    param([string]$FieldName)
    $rows = New-Object System.Collections.Generic.List[object]
    $cursor = $null
    $first = $true
    do {
        $endpoint = "/v2/queries/custom-fields?fields=$FieldName"
        if ($cursor) { $endpoint += "&cursor=$cursor" }
        $response = Invoke-NinjaApi $endpoint

        if ($first) {
            $keys = if ($response) { ($response.PSObject.Properties.Name) -join ', ' } else { '(null)' }
            Write-Host "  query response fields: $keys"
            $first = $false
        }

        $items = @()
        if ($null -eq $response) { $items = @() }
        elseif ($response.PSObject.Properties['results']) { $items = @($response.results) }
        elseif ($response.PSObject.Properties['devices']) { $items = @($response.devices) }
        elseif ($response -is [System.Collections.IEnumerable] -and $response -isnot [string]) { $items = @($response) }
        else { $items = @($response) }
        foreach ($result in $items) { if ($null -ne $result) { $rows.Add($result) } }

        $cursor = if ($response -and $response.PSObject.Properties['cursor'] -and $response.cursor) { [string]$response.cursor.name } else { $null }
    } while ($cursor)
    $rows
}

# The query result shape varies a little between versions: value may be under .fields (object or
# array of {name,value}) or a direct property. This reads it whichever way it comes.
function Get-RowFieldValue($Row, [string]$Name) {
    if ($Row.PSObject.Properties['fields'] -and $Row.fields) {
        $fields = $Row.fields
        if ($fields -is [System.Management.Automation.PSCustomObject]) {
            $property = $fields.PSObject.Properties[$Name]
            if ($property) { return $property.Value }
        }
        foreach ($entry in @($fields)) {
            if ($entry.PSObject.Properties['name'] -and $entry.name -eq $Name) { return $entry.value }
        }
    }
    if ($Row.PSObject.Properties[$Name]) { return $Row.$Name }
    $null
}

function Get-RowDeviceId($Row) {
    foreach ($key in @('deviceId', 'nodeId', 'id')) {
        if ($Row.PSObject.Properties[$key] -and $Row.$key) { return [string]$Row.$key }
    }
    $null
}

# @($null).Count is 1 in PowerShell, and @() on a List[object] throws. This returns an empty array
# for null, enumerates any collection (List/array) safely, and wraps a single object as one element.
function ConvertTo-Array($Value) {
    if ($null -eq $Value) { return @() }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $out = New-Object System.Collections.Generic.List[object]
        foreach ($item in $Value) { $out.Add($item) }
        return $out.ToArray()
    }
    @($Value)
}

# Fallback for the human-readable tag field (e.g. "AI Tag"): turn its lines back into the same shape
# as the JSON, so the dashboard works even when only the human-readable field is populated / readable.
function ConvertFrom-AiTagText([string]$Text) {
    $tools = New-Object System.Collections.Generic.List[object]
    $apiKeys = New-Object System.Collections.Generic.List[string]
    $packages = New-Object System.Collections.Generic.List[string]
    $mldll = New-Object System.Collections.Generic.List[string]
    $apiServers = New-Object System.Collections.Generic.List[string]

    foreach ($line in ($Text -split '\r?\n')) {
        $l = $line.Trim()
        if (-not $l) { continue }
        if ($l -like 'AI API keys in environment:*') {
            foreach ($k in ($l.Substring($l.IndexOf(':') + 1) -split ',')) { $t = $k.Trim(); if ($t) { $apiKeys.Add($t) } }
            continue
        }
        if ($l -like 'AI SDKs installed:*') {
            foreach ($p in ($l.Substring($l.IndexOf(':') + 1) -split ',')) { $t = $p.Trim(); if ($t) { $packages.Add($t) } }
            continue
        }
        if ($l -like 'Possible local AI*:*') {
            foreach ($m in ($l.Substring($l.IndexOf(':') + 1) -split ',')) { $t = $m.Trim(); if ($t) { $mldll.Add($t) } }
            continue
        }
        if ($l -like 'Local LLM server*') { $apiServers.Add($l); continue }
        if ($l -like 'Local AI models:*' -or $l -like 'Local model files:*') { continue }  # no reliable byte count from text
        # Otherwise a tool line: "Name (evidence, evidence)"
        $name = $l; $evidence = ''
        $paren = $l.IndexOf(' (')
        if ($paren -gt 0 -and $l.EndsWith(')')) {
            $name = $l.Substring(0, $paren).Trim()
            $evidence = $l.Substring($paren + 2, $l.Length - $paren - 3)
        }
        if (-not $name) { continue }
        $active = ($evidence -match '(?i)\brunning\b') -or ($evidence -match '(?i)\bport\s+\d+')
        $tools.Add([pscustomobject]@{ n = $name; a = $active })
    }

    [pscustomobject]@{
        tools = $tools; apiKeys = $apiKeys; packages = $packages; mldll = $mldll
        apiServers = $apiServers; models = @(); modelFiles = $null; host = $null
    }
}

#endregion

#region Aggregation

# Tool name -> category, for the by-category breakdown. Unlisted tools fall into 'Other'.
$ToolCategory = @{
    'Ollama' = 'Local runtime'; 'LM Studio' = 'Local runtime'; 'GPT4All' = 'Local runtime'
    'Jan' = 'Local runtime'; 'AnythingLLM' = 'Local runtime'; 'Text Generation WebUI' = 'Local runtime'
    'llama.cpp server' = 'Local runtime'
    'ChatGPT Desktop' = 'Desktop app'; 'Claude Desktop' = 'Desktop app'; 'Microsoft Copilot' = 'Desktop app'
    'Perplexity' = 'Desktop app'
    'Cursor' = 'AI editor'; 'Windsurf' = 'AI editor'
    'GitHub Copilot' = 'Coding assistant'; 'Codeium' = 'Coding assistant'; 'Continue' = 'Coding assistant'
    'Tabnine' = 'Coding assistant'; 'Sourcegraph Cody' = 'Coding assistant'
    'Amazon Q / CodeWhisperer' = 'Coding assistant'; 'Supermaven' = 'Coding assistant'
    'Claude Code' = 'CLI'; 'Aider' = 'CLI'; 'llm (CLI)' = 'CLI'; 'ShellGPT' = 'CLI'
    'Gemini CLI' = 'CLI'; 'Hugging Face CLI' = 'CLI'
}
$CategoryOrder = @('Local runtime', 'Desktop app', 'AI editor', 'Coding assistant', 'CLI', 'Other')

function Get-ToolCategory([string]$Name) {
    if ($ToolCategory.ContainsKey($Name)) { return $ToolCategory[$Name] }
    'Other'
}

$ProviderPatterns = [ordered]@{
    'OpenAI' = 'OPENAI'; 'Azure OpenAI' = 'AZURE'; 'Anthropic' = 'ANTHROPIC|CLAUDE'; 'Google' = 'GEMINI|GOOGLE|VERTEX'
    'Mistral' = 'MISTRAL'; 'Groq' = 'GROQ'; 'Cohere' = 'COHERE'; 'Perplexity' = 'PERPLEXITY'
    'Hugging Face' = 'HUGGING|^HF'; 'xAI / Grok' = 'XAI|GROK'; 'DeepSeek' = 'DEEPSEEK'
    'Together' = 'TOGETHER'; 'Replicate' = 'REPLICATE'; 'OpenRouter' = 'OPENROUTER'; 'Ollama' = 'OLLAMA'
}

function Get-KeyProvider([string]$KeyName) {
    foreach ($provider in $ProviderPatterns.Keys) {
        if ($KeyName -match ('(?i)' + $ProviderPatterns[$provider])) { return $provider }
    }
    'Other'
}

#endregion

#region HTML

$MutedColor = '#94a3b8'
$ChipColors = @{
    success = @('#dcfce7', '#166534'); danger = @('#fee2e2', '#991b1b'); neutral = @('#e2e8f0', '#475569')
    warning = @('#fef9c3', '#854d0e'); info = @('#dbeafe', '#1e40af')
}
$CategoryColor = @{
    'Local runtime' = '#7c3aed'; 'Desktop app' = '#0891b2'; 'AI editor' = '#2563eb'
    'Coding assistant' = '#059669'; 'CLI' = '#d97706'; 'Other' = '#64748b'
}

function ConvertTo-HtmlText($Value) {
    ([string]$Value).Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;')
}

function Format-Size([double]$Bytes) {
    if ($Bytes -ge 1099511627776) { return ('{0:N1} TB' -f ($Bytes / 1099511627776)) }
    if ($Bytes -ge 1073741824) { return ('{0:N1} GB' -f ($Bytes / 1073741824)) }
    if ($Bytes -ge 1048576) { return ('{0:N0} MB' -f ($Bytes / 1048576)) }
    if ($Bytes -le 0) { return '0 MB' }
    return ('{0:N0} KB' -f ($Bytes / 1024))
}

function New-Chip([string]$Text, [string]$Variant = 'neutral', [string]$Margin = '0 0 0 6px') {
    '<span style="display:inline-block;margin:{0};padding:0 6px;border-radius:4px;font-size:10px;background-color:{1};color:{2};">{3}</span>' -f `
        $Margin, $ChipColors[$Variant][0], $ChipColors[$Variant][1], (ConvertTo-HtmlText $Text)
}

function New-InfoCard([string]$Variant, [string]$Icon, [string]$Title, [string]$Description) {
    '<div class="info-card {0}" style="margin-bottom:12px;"><i class="info-icon fa-solid {1}"></i><div class="info-text"><div class="info-title">{2}</div><div class="info-description">{3}</div></div></div>' -f `
        $Variant, $Icon, $Title, $Description
}

function New-FullWidthCard([string]$Title, [string]$Body) {
    '<div style="display:block;width:100%;margin-bottom:16px;"><div class="card flex-grow-1" style="width:100%;"><div class="card-title-box"><div class="card-title">{0}</div></div><div class="card-body">{1}</div></div></div>' -f $Title, $Body
}

function New-StatCard([string]$Value, [string]$Label) {
    '<div class="col"><div class="stat-card"><div class="stat-value">{0}</div><div class="stat-desc">{1}</div></div></div>' -f (ConvertTo-HtmlText $Value), (ConvertTo-HtmlText $Label)
}

# A horizontal proportion bar (WYSIWYG renders background colours, not border-top/bottom lines)
function New-Bar([int]$Value, [int]$Max, [string]$Color) {
    $pct = if ($Max -gt 0) { [Math]::Round(100.0 * $Value / $Max, [MidpointRounding]::AwayFromZero) } else { 0 }
    '<div style="background-color:#eef2f7;border-radius:4px;height:14px;width:100%;"><div style="width:{0}%;height:14px;border-radius:4px;background-color:{1};"></div></div>' -f $pct, $Color
}

# device deep link (best-effort URL; adjust the fragment if your console uses a different route)
function New-DeviceLink($Id, [string]$Name) {
    '<a href="{0}/#/deviceDashboard/{1}/overview" target="_blank" rel="noopener noreferrer">{2}</a>' -f $ApiUrl, $Id, (ConvertTo-HtmlText $Name)
}

function New-DeviceList($Devices, [int]$Limit = 15) {
    $sorted = @($Devices | Sort-Object { $_.name })
    $shown = @($sorted | Select-Object -First $Limit)
    $links = @($shown | ForEach-Object { New-DeviceLink $_.id $_.name })
    $html = ($links -join ', ')
    if ($sorted.Count -gt $Limit) { $html += ' <span style="color:{0};font-size:11px;">+{1} more</span>' -f $MutedColor, ($sorted.Count - $Limit) }
    $html
}

# One line per device with its detail (e.g. the exposed port / the loaded runtime) after the name
function New-DetailDeviceList($Devices) {
    $parts = foreach ($device in ($Devices | Sort-Object { $_.name })) {
        $detail = if ($device.detail) { ' <span style="color:{0};">- {1}</span>' -f $MutedColor, (ConvertTo-HtmlText $device.detail) } else { '' }
        '<div style="margin:2px 0;">' + (New-DeviceLink $device.id $device.name) + $detail + '</div>'
    }
    ($parts -join '')
}

# NinjaOne WYSIWYG blocks <img> and <svg>, so real product logos are impossible. Instead each tool
# gets a brand-coloured monogram badge (colour + 1-2 letters) - the closest the sanitizer allows.
$ToolBrand = @{
    'Claude Desktop' = @('#D97757', 'C'); 'Claude Code' = @('#D97757', 'CC')
    'ChatGPT Desktop' = @('#10A37F', 'GPT'); 'Microsoft Copilot' = @('#0A5AFF', 'Co')
    'Perplexity' = @('#20808D', 'Px'); 'GitHub Copilot' = @('#6E5494', 'GH')
    'Cursor' = @('#0B0B0B', 'Cu'); 'Windsurf' = @('#09B6A2', 'Ws')
    'Ollama' = @('#0B0B0B', 'Ol'); 'LM Studio' = @('#4F46E5', 'LM'); 'GPT4All' = @('#1F6FEB', 'G4')
    'Jan' = @('#2563EB', 'Jn'); 'AnythingLLM' = @('#6D28D9', 'AL')
    'Text Generation WebUI' = @('#DB2777', 'TG'); 'llama.cpp server' = @('#0EA5E9', 'Lc')
    'Codeium' = @('#09B6A2', 'Cd'); 'Continue' = @('#334155', 'Ct'); 'Tabnine' = @('#2B7A78', 'Tn')
    'Sourcegraph Cody' = @('#F94F82', 'Cy'); 'Amazon Q / CodeWhisperer' = @('#FF9900', 'Q')
    'Supermaven' = @('#8B5CF6', 'Sm'); 'Aider' = @('#22C55E', 'Ai'); 'llm (CLI)' = @('#0EA5E9', 'llm')
    'ShellGPT' = @('#16A34A', 'sg'); 'Gemini CLI' = @('#1A73E8', 'Ge'); 'Hugging Face CLI' = @('#FFAE1A', 'HF')
}

function Get-ToolBrand([string]$Name) {
    if ($ToolBrand.ContainsKey($Name)) { return $ToolBrand[$Name] }
    $category = Get-ToolCategory $Name
    $color = if ($CategoryColor.ContainsKey($category)) { $CategoryColor[$category] } else { '#64748b' }
    $mono = if ($Name.Length -ge 1) { $Name.Substring(0, 1).ToUpper() } else { '?' }
    @($color, $mono)
}

# One card per tool: brand badge, name + category, device/running chips, and the devices below.
function New-ToolCard($Tool) {
    $brand = Get-ToolBrand $Tool.Name
    $category = Get-ToolCategory $Tool.Name
    $badge = '<div style="width:36px;height:36px;min-width:36px;border-radius:9px;background-color:{0};color:#ffffff;font-size:13px;font-weight:bold;display:flex;align-items:center;justify-content:center;flex-shrink:0;text-align:center;">{1}</div>' -f $brand[0], (ConvertTo-HtmlText $brand[1])
    $deviceChip = New-Chip ("$($Tool.Hits) device" + $(if ($Tool.Hits -eq 1) { '' } else { 's' })) 'info' '0'
    $runningChip = if ($Tool.Active -gt 0) { New-Chip ("$($Tool.Active) running") 'danger' '0 0 0 6px' } else { New-Chip 'installed only' 'neutral' '0 0 0 6px' }
    '<div style="border:1px solid #e2e8f0;border-radius:10px;padding:12px;height:100%;box-sizing:border-box;">' +
    '<div style="display:flex;align-items:center;">' + $badge +
    ('<div style="margin-left:10px;"><div style="font-size:14px;font-weight:600;">{0}</div><div style="font-size:11px;color:{1};">{2}</div></div>' -f (ConvertTo-HtmlText $Tool.Name), $MutedColor, (ConvertTo-HtmlText $category)) +
    '</div>' +
    ('<div style="margin:8px 0 6px;">{0}{1}</div>' -f $deviceChip, $runningChip) +
    ('<div style="font-size:11px;color:{0};margin-bottom:2px;">Used on</div>' -f $MutedColor) +
    ('<div style="font-size:12px;line-height:1.7;">{0}</div>' -f (New-DeviceList $Tool.Devices 12)) +
    '</div>'
}

function New-DashboardHtml {
    param($Data)

    # --- KPI cards ---
    $modelSize = Format-Size $Data.totalModelBytes
    $stats = '<div class="row g-3" style="margin-bottom:16px;">' +
    (New-StatCard $Data.devicesScanned 'Devices scanned') +
    (New-StatCard $Data.devicesWithAi 'Devices with AI') +
    (New-StatCard $Data.distinctTools 'Distinct AI tools') +
    (New-StatCard $Data.devicesActive 'Running AI now') +
    (New-StatCard $Data.devicesWithKeys 'Devices with API keys') +
    (New-StatCard $modelSize 'Local model storage') +
    '</div>'

    # --- Tool cards: one card per tool, brand badge + the devices that use it below ---
    $cards = ''
    foreach ($tool in ($Data.tools | Sort-Object -Property @{ Expression = 'Hits'; Descending = $true }, @{ Expression = 'Name' })) {
        $cards += '<div class="col-12 col-md-6 col-xl-4" style="margin-bottom:12px;">' + (New-ToolCard $tool) + '</div>'
    }
    if ($cards) { $toolCards = '<div class="row g-3">' + $cards + '</div>' }
    else { $toolCards = New-InfoCard 'success' 'fa-circle-check' 'No named AI tools detected' 'No device reported a catalog AI tool.' }

    # --- By category ---
    $catMax = 0
    foreach ($c in $Data.categories.Values) { if ($c.Hits -gt $catMax) { $catMax = $c.Hits } }
    $catRows = ''
    foreach ($name in $CategoryOrder) {
        if (-not $Data.categories.ContainsKey($name)) { continue }
        $count = $Data.categories[$name].Hits
        $catRows += '<div style="display:flex;align-items:center;margin-bottom:6px;">' +
        ('<div style="width:130px;font-size:12px;">{0}</div>' -f (ConvertTo-HtmlText $name)) +
        ('<div style="width:34px;font-size:13px;">{0}</div>' -f $count) +
        ('<div style="flex-grow:1;">{0}</div>' -f (New-Bar $count $catMax $CategoryColor[$name])) +
        '</div>'
    }
    $categoryCard = if ($catRows) { $catRows } else { '<span style="color:{0};font-size:12px;">No categories.</span>' -f $MutedColor }

    # --- Shadow-AI signals: local LLM servers and ML runtimes loaded ---
    $shadow = ''
    # Note: do NOT wrap these List[object] in @(); @() on a List[object] throws "Argument types do
    # not match" in PowerShell. List objects have their own .Count and enumerate fine in pipelines.
    if ($Data.serverDevices.Count -gt 0) {
        $shadow += (New-InfoCard 'warning' 'fa-server' 'Local LLM servers responding' ('{0} device(s) expose an LLM API on localhost.' -f $Data.serverDevices.Count))
        $shadow += '<div style="font-size:12px;margin:0 0 12px;">{0}</div>' -f (New-DetailDeviceList $Data.serverDevices)
    }
    if ($Data.mldllDevices.Count -gt 0) {
        $shadow += (New-InfoCard 'warning' 'fa-microchip' 'ML runtime loaded (unidentified)' ('{0} device(s) run a process with an ML runtime that is not a named tool.' -f $Data.mldllDevices.Count))
        $shadow += '<div style="font-size:12px;margin:0 0 4px;">{0}</div>' -f (New-DetailDeviceList $Data.mldllDevices)
    }
    if (-not $shadow) { $shadow = New-InfoCard 'success' 'fa-circle-check' 'No unidentified local AI' 'No local LLM servers or unnamed ML runtimes were found.' }

    # --- API keys by provider ---
    $keyRows = ''
    foreach ($provider in ($Data.providers.Keys | Sort-Object { -$Data.providers[$_].Hits })) {
        $entry = $Data.providers[$provider]
        $keyRows += '<tr><td style="padding:5px 8px;font-size:13px;">{0}</td><td style="padding:5px 8px;">{1}</td><td style="padding:5px 8px;font-size:12px;">{2}</td></tr>' -f `
        (ConvertTo-HtmlText $provider), (New-Chip ("$($entry.Hits) device" + $(if ($entry.Hits -eq 1) { '' } else { 's' })) 'info' '0'), (New-DeviceList $entry.Devices)
    }
    $keyCard = if ($keyRows) {
        '<table style="width:100%;border-collapse:collapse;"><thead><tr><th style="text-align:left;padding:6px 8px;width:20%;">Provider</th><th style="text-align:left;padding:6px 8px;width:15%;">Devices</th><th style="text-align:left;padding:6px 8px;">On which devices</th></tr></thead><tbody>' + $keyRows + '</tbody></table>'
    }
    else { New-InfoCard 'success' 'fa-circle-check' 'No AI API keys found' 'No device has an AI provider key in its environment.' }

    # --- SDKs by package ---
    $pkgRows = ''
    foreach ($package in ($Data.packages.Keys | Sort-Object { -$Data.packages[$_].Hits }, { $_ })) {
        $entry = $Data.packages[$package]
        $pkgRows += '<tr><td style="padding:5px 8px;font-size:13px;font-family:monospace;">{0}</td><td style="padding:5px 8px;">{1}</td><td style="padding:5px 8px;font-size:12px;">{2}</td></tr>' -f `
        (ConvertTo-HtmlText $package), (New-Chip ("$($entry.Hits)") 'neutral' '0'), (New-DeviceList $entry.Devices)
    }
    $pkgCard = if ($pkgRows) {
        '<table style="width:100%;border-collapse:collapse;"><thead><tr><th style="text-align:left;padding:6px 8px;width:25%;">Package</th><th style="text-align:left;padding:6px 8px;width:10%;">Devices</th><th style="text-align:left;padding:6px 8px;">On which devices</th></tr></thead><tbody>' + $pkgRows + '</tbody></table>'
    }
    else { New-InfoCard 'success' 'fa-circle-check' 'No AI SDKs found' 'No device has an AI SDK installed via pip or npm.' }

    # --- Model storage by device ---
    $modelRows = ''
    foreach ($device in ($Data.modelDevices | Sort-Object { -$_.bytes } | Select-Object -First 25)) {
        $modelRows += '<tr><td style="padding:5px 8px;font-size:13px;">{0}</td><td style="padding:5px 8px;font-size:12px;">{1}</td></tr>' -f (New-DeviceLink $device.id $device.name), (Format-Size $device.bytes)
    }
    $modelCard = if ($modelRows) {
        ('<div style="font-size:12px;color:{0};margin-bottom:8px;">Total across the fleet: {1}</div>' -f $MutedColor, $modelSize) +
        '<table style="width:100%;border-collapse:collapse;"><thead><tr><th style="text-align:left;padding:6px 8px;">Device</th><th style="text-align:left;padding:6px 8px;width:20%;">Model storage</th></tr></thead><tbody>' + $modelRows + '</tbody></table>'
    }
    else { New-InfoCard 'success' 'fa-circle-check' 'No local model files' 'No device stores local model weight files.' }

    # --- Assemble ---
    '<div>' +
    (New-InfoCard '' 'fa-robot' 'AI Detection Dashboard' ("Generated $((Get-Date).ToString('dd.MM.yyyy HH:mm:ss')) from {0} device(s) reporting via '{1}'." -f $Data.devicesScanned, (ConvertTo-HtmlText $DataFieldName))) +
    $stats +
    (New-FullWidthCard '<i class="fa-solid fa-robot"></i>&nbsp;AI tools by device' $toolCards) +
    '<div class="row g-3">' +
    ('<div class="col-12 col-xl-6">{0}</div>' -f (New-FullWidthCard '<i class="fa-solid fa-layer-group"></i>&nbsp;By category' $categoryCard)) +
    ('<div class="col-12 col-xl-6">{0}</div>' -f (New-FullWidthCard '<i class="fa-solid fa-triangle-exclamation"></i>&nbsp;Shadow-AI signals' $shadow)) +
    '</div>' +
    (New-FullWidthCard '<i class="fa-solid fa-key"></i>&nbsp;AI API keys by provider' $keyCard) +
    (New-FullWidthCard '<i class="fa-solid fa-cube"></i>&nbsp;AI SDKs (pip / npm)' $pkgCard) +
    (New-FullWidthCard '<i class="fa-solid fa-hard-drive"></i>&nbsp;Local model storage by device' $modelCard) +
    '</div>'
}

#endregion

#region Main

try {
    $missing = @()
    if (-not $ClientId) { $missing += 'clientId' }
    if (-not $ClientSecret) { $missing += 'clientSecret' }
    if ($missing.Count -gt 0) { throw "Missing script variables: $($missing -join ', ')" }

    $script:AccessToken = Get-AccessToken

    Write-Host 'Loading devices...'
    $deviceCount = Get-AllDevices
    Write-Host "  $deviceCount device name(s) from bulk list (others resolved per device)"

    Write-Host "Loading custom field '$DataFieldName' across all devices..."
    $rows = Get-CustomFieldValues -FieldName $DataFieldName
    Write-Host "  $(@($rows).Count) rows returned"

    # Aggregate
    $tools = @{}          # name -> @{ Name; Count; Active; Devices=@() }
    $categories = @{}     # category -> @{ Count; Devices set (by id) }
    $providers = @{}      # provider -> @{ Count; Devices=@() }
    $packages = @{}       # package -> @{ Count; Devices=@() }
    $serverDevices = New-Object System.Collections.Generic.List[object]
    $mldllDevices = New-Object System.Collections.Generic.List[object]
    $modelDevices = New-Object System.Collections.Generic.List[object]
    $devicesScanned = 0; $devicesWithAi = 0; $devicesActive = 0; $devicesWithKeys = 0
    [double]$totalModelBytes = 0
    $categorySeen = @{}   # "category|deviceId" -> 1, so a device counts once per category

    $parseErrors = 0
    foreach ($row in $rows) {
        $raw = Get-RowFieldValue $row $DataFieldName
        if ($raw -is [string]) { $raw = $raw.Trim() }
        if (-not $raw) { continue }
        $data = $null
        # JSON from the aiData field, or the human-readable aiTag text as a fallback
        if ("$raw".StartsWith('{')) {
            try { $data = $raw | ConvertFrom-Json } catch { $parseErrors++; continue }
        }
        else {
            $data = ConvertFrom-AiTagText ([string]$raw)
        }
        if (-not $data) { continue }

        $deviceId = Get-RowDeviceId $row
        $name = Resolve-DeviceName $deviceId
        if ($data.host -and $name -eq "Device $deviceId") { $name = [string]$data.host }
        $device = [pscustomobject]@{ id = $deviceId; name = $name }
        $devicesScanned++

        $hasAi = $false; $isActive = $false

        foreach ($tool in (ConvertTo-Array $data.tools)) {
            $hasAi = $true
            $toolName = [string]$tool.n
            if (-not $tools.ContainsKey($toolName)) { $tools[$toolName] = @{ Name = $toolName; Hits = 0; Active = 0; Devices = New-Object System.Collections.Generic.List[object] } }
            $tools[$toolName].Hits++
            $tools[$toolName].Devices.Add($device)
            if ($tool.a) { $tools[$toolName].Active++; $isActive = $true }

            $category = Get-ToolCategory $toolName
            $catKey = "$category|$deviceId"
            if (-not $categories.ContainsKey($category)) { $categories[$category] = @{ Hits = 0 } }
            if (-not $categorySeen.ContainsKey($catKey)) { $categorySeen[$catKey] = 1; $categories[$category].Hits++ }
        }

        foreach ($key in (ConvertTo-Array $data.apiKeys)) {
            $hasAi = $true
            $provider = Get-KeyProvider ([string]$key)
            if (-not $providers.ContainsKey($provider)) { $providers[$provider] = @{ Hits = 0; Devices = New-Object System.Collections.Generic.List[object] } }
            # count each device once per provider
            if (-not ($providers[$provider].Devices | Where-Object { $_.id -eq $deviceId })) {
                $providers[$provider].Hits++
                $providers[$provider].Devices.Add($device)
            }
        }
        if ((ConvertTo-Array $data.apiKeys).Count -gt 0) { $devicesWithKeys++ }

        foreach ($package in (ConvertTo-Array $data.packages)) {
            $hasAi = $true
            $pkgName = [string]$package
            if (-not $packages.ContainsKey($pkgName)) { $packages[$pkgName] = @{ Hits = 0; Devices = New-Object System.Collections.Generic.List[object] } }
            $packages[$pkgName].Hits++
            $packages[$pkgName].Devices.Add($device)
        }

        $serverArr = ConvertTo-Array $data.apiServers
        if ($serverArr.Count -gt 0) {
            $hasAi = $true; $isActive = $true
            # detail e.g. "OpenAI-compatible API, port 8000" - strip the "Local LLM server (...)" wrapper from the text form
            $detail = (@($serverArr | ForEach-Object { ($_ -replace '^Local LLM server \(', '') -replace '\)\s*$', '' }) -join '; ')
            $serverDevices.Add([pscustomobject]@{ id = $deviceId; name = $name; detail = $detail })
        }
        $mldllArr = ConvertTo-Array $data.mldll
        if ($mldllArr.Count -gt 0) {
            $hasAi = $true
            $detail = (@($mldllArr | ForEach-Object { [string]$_ }) -join '; ')
            $mldllDevices.Add([pscustomobject]@{ id = $deviceId; name = $name; detail = $detail })
        }

        [double]$deviceBytes = 0
        foreach ($model in (ConvertTo-Array $data.models)) { $deviceBytes += [double]$model.bytes }
        if ($data.modelFiles -and $data.modelFiles.bytes) { $deviceBytes += [double]$data.modelFiles.bytes }
        if ($deviceBytes -gt 0) {
            $hasAi = $true
            $totalModelBytes += $deviceBytes
            $modelDevices.Add([pscustomobject]@{ id = $deviceId; name = $name; bytes = $deviceBytes })
        }

        if ($hasAi) { $devicesWithAi++ }
        if ($isActive) { $devicesActive++ }
    }

    $toolList = @($tools.Values | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Hits = $_.Hits; Active = $_.Active; Devices = $_.Devices } })

    $aggregate = [pscustomobject]@{
        devicesScanned  = $devicesScanned
        devicesWithAi   = $devicesWithAi
        devicesActive   = $devicesActive
        devicesWithKeys = $devicesWithKeys
        distinctTools   = $toolList.Count
        totalModelBytes = $totalModelBytes
        tools           = $toolList
        categories      = $categories
        providers       = $providers
        packages        = $packages
        serverDevices   = $serverDevices
        mldllDevices    = $mldllDevices
        modelDevices    = $modelDevices
    }

    Write-Host "Aggregated: $devicesWithAi of $devicesScanned devices with AI, $($toolList.Count) distinct tools ($parseErrors unparseable value(s))"

    if (@($rows).Count -eq 0) {
        Write-Host "HINT: 0 rows from /v2/queries/custom-fields for field '$DataFieldName'. Check that the field's"
        Write-Host "      machine name is exactly '$DataFieldName' and that its API permission is Read (or Read/Write)."
        Write-Host "      Global fields are not returned here; use a per-device (role) custom field."
    }
    elseif ($devicesScanned -eq 0) {
        Write-Host "HINT: rows returned but no value could be read for field '$DataFieldName'. The value may sit under a"
        Write-Host "      different property than expected - see 'query response fields' above."
    }

    $html = New-DashboardHtml -Data $aggregate
    Write-Host "Writing dashboard to global custom field `"$DashboardFieldName`" ($($html.Length) characters)..."
    Set-GlobalCustomField -FieldName $DashboardFieldName -Html $html
    Write-Host "Custom field `"$DashboardFieldName`" updated"
}
catch {
    Write-Host "ERROR: $($_.Exception.Message)"
    exit 1
}

#endregion
