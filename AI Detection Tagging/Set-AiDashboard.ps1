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

function Get-AllDevices {
    $devices = @{}
    $after = 0
    do {
        $batch = @(Invoke-NinjaApi ("/v2/devices?pageSize=1000&after={0}" -f $after))
        foreach ($device in $batch) {
            $name = if ($device.displayName) { $device.displayName } elseif ($device.systemName) { $device.systemName } else { "Device $($device.id)" }
            $devices[[string]$device.id] = $name
        }
        if ($batch.Count -gt 0) { $after = [int]$batch[$batch.Count - 1].id }
    } while ($batch.Count -eq 1000)
    $devices
}

# Reads one custom field across all devices, following the query cursor to the end
function Get-CustomFieldValues {
    param([string]$FieldName)
    $rows = New-Object System.Collections.Generic.List[object]
    $cursor = $null
    do {
        $endpoint = "/v2/queries/custom-fields?fields=$FieldName"
        if ($cursor) { $endpoint += "&cursor=$cursor" }
        $response = Invoke-NinjaApi $endpoint
        foreach ($result in @($response.results)) { $rows.Add($result) }
        $cursor = if ($response.PSObject.Properties['cursor'] -and $response.cursor) { [string]$response.cursor.name } else { $null }
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

# @($null).Count is 1 in PowerShell, so a missing JSON array would iterate once on $null.
# This returns an empty array for null and a real array otherwise.
function ConvertTo-Array($Value) {
    if ($null -eq $Value) { return @() }
    @($Value)
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

    # --- Tools across the fleet ---
    $maxCount = 0
    foreach ($tool in $Data.tools) { if ($tool.Hits -gt $maxCount) { $maxCount = $tool.Hits } }
    $toolRows = ''
    foreach ($tool in ($Data.tools | Sort-Object -Property @{ Expression = 'Hits'; Descending = $true }, @{ Expression = 'Name' })) {
        $category = Get-ToolCategory $tool.Name
        $activeChip = if ($tool.Active -gt 0) { New-Chip ("$($tool.Active) running") 'danger' '0' } else { New-Chip 'installed only' 'neutral' '0' }
        $toolRows += '<tr>' +
        ('<td style="padding:6px 8px;"><div style="font-size:13px;">{0}</div><div style="font-size:11px;color:{1};">{2}</div></td>' -f (ConvertTo-HtmlText $tool.Name), $MutedColor, (ConvertTo-HtmlText $category)) +
        ('<td style="padding:6px 8px;width:22%;"><div style="display:flex;align-items:center;"><span style="font-size:13px;width:28px;">{0}</span><div style="flex-grow:1;">{1}</div></div></td>' -f $tool.Hits, (New-Bar $tool.Hits $maxCount $CategoryColor[$category])) +
        ('<td style="padding:6px 8px;">{0}</td>' -f $activeChip) +
        ('<td style="padding:6px 8px;font-size:12px;">{0}</td>' -f (New-DeviceList $tool.Devices)) +
        '</tr>'
    }
    if ($toolRows) {
        $toolTable = '<table style="width:100%;border-collapse:collapse;"><thead><tr>' +
        '<th style="text-align:left;padding:6px 8px;width:22%;">Tool</th>' +
        '<th style="text-align:left;padding:6px 8px;width:22%;">Devices</th>' +
        '<th style="text-align:left;padding:6px 8px;width:12%;">Status</th>' +
        '<th style="text-align:left;padding:6px 8px;">On which devices</th>' +
        '</tr></thead><tbody>' + $toolRows + '</tbody></table>'
    }
    else {
        $toolTable = New-InfoCard 'success' 'fa-circle-check' 'No named AI tools detected' 'No device reported a catalog AI tool.'
    }

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
    if (@($Data.serverDevices).Count -gt 0) {
        $shadow += (New-InfoCard 'warning' 'fa-server' 'Local LLM servers responding' ('{0} device(s) expose an LLM API on localhost.' -f @($Data.serverDevices).Count))
        $shadow += '<div style="font-size:12px;margin:0 0 12px;">{0}</div>' -f (New-DeviceList $Data.serverDevices 30)
    }
    if (@($Data.mldllDevices).Count -gt 0) {
        $shadow += (New-InfoCard 'warning' 'fa-microchip' 'ML runtime loaded (unidentified)' ('{0} device(s) run a process with an ML runtime that is not a named tool.' -f @($Data.mldllDevices).Count))
        $shadow += '<div style="font-size:12px;margin:0 0 4px;">{0}</div>' -f (New-DeviceList $Data.mldllDevices 30)
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
    (New-FullWidthCard '<i class="fa-solid fa-list-check"></i>&nbsp;AI tools across the fleet' $toolTable) +
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
    $deviceNames = Get-AllDevices
    Write-Host "  $($deviceNames.Count) devices"

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

    foreach ($row in $rows) {
        $raw = Get-RowFieldValue $row $DataFieldName
        if (-not $raw) { continue }
        $data = $null
        try { $data = $raw | ConvertFrom-Json } catch { continue }
        if (-not $data) { continue }

        $deviceId = Get-RowDeviceId $row
        $name = if ($deviceId -and $deviceNames.ContainsKey($deviceId)) { $deviceNames[$deviceId] } elseif ($data.host) { [string]$data.host } else { "Device $deviceId" }
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

        if ((ConvertTo-Array $data.apiServers).Count -gt 0) { $hasAi = $true; $isActive = $true; $serverDevices.Add($device) }
        if ((ConvertTo-Array $data.mldll).Count -gt 0) { $hasAi = $true; $mldllDevices.Add($device) }

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

    Write-Host "Aggregated: $devicesWithAi of $devicesScanned devices with AI, $($toolList.Count) distinct tools"

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
