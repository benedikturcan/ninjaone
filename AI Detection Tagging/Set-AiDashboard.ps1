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
    [string]$DashboardFieldName = $env:dashboardFieldName,
    [string]$ActivitySourceName = $env:activitySourceName,
    [string]$ActivityConditionUid = $env:activityConditionUid,
    [string]$ActivityDays = $env:activityDays
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

if (-not $ClientId) { $ClientId = $env:NINJA_CLIENT_ID }
if (-not $ClientSecret) { $ClientSecret = $env:NINJA_CLIENT_SECRET }
if (-not $Region) { $Region = if ($env:NINJA_REGION) { $env:NINJA_REGION } else { 'eu' } }
if (-not $DataFieldName) { $DataFieldName = 'aiData' }
if (-not $DashboardFieldName) { $DashboardFieldName = 'aiDashboard' }
if (-not $ActivitySourceName) { $ActivitySourceName = 'NinjaAIDetection' }   # event source to match in activities
$ActivityLookbackDays = 30
if ($ActivityDays) { [void][int]::TryParse($ActivityDays, [ref]$ActivityLookbackDays) }

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

# Reads the AI-detection condition triggers from the NinjaOne activity feed (/v2/activities).
# Our events are CONDITION activities whose data.message.params.event_source is the agent's source
# ('NinjaAIDetection'). Each carries event_id, event_time and the message - exactly what we show.
function Get-AiActivities {
    param([string]$SourceName, [int]$Days, [string]$ConditionUid)
    $results = New-Object System.Collections.Generic.List[object]
    $cutoff = (Get-Date).ToUniversalTime().AddDays(-[math]::Abs($Days))
    $olderThan = $null
    $page = 0
    do {
        $endpoint = '/v2/activities?pageSize=200'
        if ($ConditionUid) { $endpoint += "&sourceConfigUid=$ConditionUid" }
        if ($olderThan) { $endpoint += "&olderThan=$olderThan" }

        $response = $null
        try { $response = Invoke-NinjaApi $endpoint }
        catch { Write-Host "  Warning: activities query failed ($($_.Exception.Message))"; break }

        $activities = @($response.activities)
        if ($page -eq 0) { Write-Host ("  activities response fields: " + (($response.PSObject.Properties.Name) -join ', ')) }
        if ($activities.Count -eq 0) { break }

        $minId = $null; $reachedCutoff = $false
        foreach ($activity in $activities) {
            if ($null -eq $minId -or [long]$activity.id -lt $minId) { $minId = [long]$activity.id }
            $when = $null
            try { $when = [DateTimeOffset]::FromUnixTimeSeconds([long]$activity.activityTime).UtcDateTime } catch { }
            if ($when -and $when -lt $cutoff) { $reachedCutoff = $true; continue }
            if ([string]$activity.activityType -ne 'CONDITION') { continue }

            $params = $activity.data.message.params
            $source = if ($params) { [string]$params.event_source } else { '' }
            if ($SourceName) {
                if ($source) { if ($source -ne $SourceName) { continue } }
                elseif (([string]$activity.message) -notmatch [regex]::Escape($SourceName)) { continue }
            }

            $eventId = if ($params -and $params.event_id) { [string]$params.event_id } else { [string]$activity.subject }
            $eventTime = if ($params -and $params.event_time) { [string]$params.event_time } elseif ($when) { $when.ToString('o') } else { '' }
            $eventMsg = if ($params -and $params.msg) { [string]$params.msg } else { [string]$activity.message }

            $results.Add([pscustomobject]@{
                deviceId = [string]$activity.deviceId
                name     = Resolve-DeviceName ([string]$activity.deviceId)
                eventId  = $eventId
                status   = [string]$activity.statusCode
                time     = $eventTime
                message  = $eventMsg
            })
        }

        $olderThan = $minId
        $page++
        if ($reachedCutoff) { break }
    } while ($activities.Count -eq 200 -and $page -lt 25)

    $results
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

# Parse a human-readable size like "230 MB" or "4.2 GB" (or "4,2 GB") back into bytes. The last
# separator is treated as the decimal point, so a thousands separator does not distort the value.
function ConvertFrom-SizeText([string]$Text) {
    $m = [regex]::Match($Text, '(?i)([0-9][0-9.,]*)\s*(TB|GB|MB|KB|B)\b')
    if (-not $m.Success) { return [long]0 }
    $raw = $m.Groups[1].Value -replace '[.,](?=.*[.,])', ''   # drop all separators except the last
    $num = 0.0
    [void][double]::TryParse(($raw -replace ',', '.'), [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$num)
    switch ($m.Groups[2].Value.ToUpperInvariant()) {
        'TB' { [long]($num * 1099511627776) }
        'GB' { [long]($num * 1073741824) }
        'MB' { [long]($num * 1048576) }
        'KB' { [long]($num * 1024) }
        default { [long]$num }
    }
}

# Fallback for the human-readable tag field (e.g. "AI Tag"): turn its lines back into the same shape
# as the JSON, so the dashboard works even when only the human-readable field is populated / readable.
function ConvertFrom-AiTagText([string]$Text) {
    $tools = New-Object System.Collections.Generic.List[object]
    $apiKeys = New-Object System.Collections.Generic.List[string]
    $packages = New-Object System.Collections.Generic.List[string]
    $mldll = New-Object System.Collections.Generic.List[string]
    $apiServers = New-Object System.Collections.Generic.List[string]
    $models = New-Object System.Collections.Generic.List[object]
    $modelFiles = $null

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
        # "Local AI models: Ollama models (4.2 GB), Hugging Face cache (11.8 GB)" - sum the sizes in parens
        if ($l -like 'Local AI models:*') {
            foreach ($mm in [regex]::Matches($l, '\(([^)]+)\)')) { $models.Add([pscustomobject]@{ label = ''; bytes = (ConvertFrom-SizeText $mm.Groups[1].Value) }) }
            continue
        }
        # "Local model files: 2 file(s), 230 MB (.gguf, .safetensors)"
        if ($l -like 'Local model files:*') {
            $count = 0; if ($l -match '(\d+)\s*file') { $count = [int]$Matches[1] }
            $exts = @()
            $mx = [regex]::Match($l, '\(([^)]*)\)\s*$')
            if ($mx.Success) { $exts = @(($mx.Groups[1].Value -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
            $modelFiles = [pscustomobject]@{ count = $count; bytes = (ConvertFrom-SizeText $l); exts = $exts }
            continue
        }
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
        apiServers = $apiServers; models = $models; modelFiles = $modelFiles; host = $null
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

# A small info icon with a native (title-attribute) tooltip - the WYSIWYG allows the title attribute
function New-InfoTip([string]$Text) {
    ' <i class="fa-solid fa-circle-info" style="font-size:12px;color:{0};cursor:help;" title="{1}"></i>' -f $MutedColor, (ConvertTo-HtmlText $Text)
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

function New-StatCard([string]$Value, [string]$Label, [string]$Tip = '') {
    $tipHtml = if ($Tip) { New-InfoTip $Tip } else { '' }
    '<div class="col"><div class="stat-card"><div class="stat-value">{0}</div><div class="stat-desc">{1}{2}</div></div></div>' -f (ConvertTo-HtmlText $Value), (ConvertTo-HtmlText $Label), $tipHtml
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

# Local time from an ISO event_time string (falls back to the raw string)
function Format-ActivityTime([string]$Iso) {
    try { return ([datetime]::Parse($Iso, $Invariant, [Globalization.DateTimeStyles]::RoundtripKind)).ToLocalTime().ToString('dd.MM.yyyy HH:mm:ss') }
    catch { return [string]$Iso }
}

# Table of the AI-detection condition triggers pulled from the NinjaOne activity feed. The 5000
# summary is a per-run heartbeat (it fires every scan, often all-zeros), so it is shown as a single
# "last scan" line rather than as rows - otherwise a "0 servers" summary sits next to a real
# "server detected" trigger and reads like a contradiction.
function New-ActivityTable($Activities, [int]$Days) {
    $all = @($Activities)
    $triggers = @($all | Where-Object { $_.eventId -ne '5000' })
    $summaries = @($all | Where-Object { $_.eventId -eq '5000' } | Sort-Object { $_.time } -Descending)

    $lastScanHtml = ''
    if ($summaries.Count -gt 0) {
        $lastScanHtml = '<div style="font-size:12px;color:{0};margin-bottom:8px;">Last scan summary: {1} &middot; {2}</div>' -f `
            $MutedColor, (ConvertTo-HtmlText (Format-ActivityTime $summaries[0].time)), (ConvertTo-HtmlText $summaries[0].message)
    }

    if ($triggers.Count -eq 0) {
        return $lastScanHtml + (New-InfoCard 'success' 'fa-circle-check' 'No AI detection triggers' ('No device triggered a detection (event 5001-5004) in the last {0} day(s). Per-run scan summaries are not listed here.' -f $Days))
    }

    $rows = ''
    foreach ($activity in ($triggers | Sort-Object { $_.time } -Descending | Select-Object -First 60)) {
        $variant = if (@('5001', '5002', '5003') -contains $activity.eventId) { 'danger' } elseif ($activity.eventId -eq '5010') { 'warning' } else { 'info' }
        $statusChip = if ($activity.status -and $activity.status -ne 'TRIGGERED') { New-Chip $activity.status 'neutral' '0 0 0 6px' } else { '' }
        $rows += '<tr>' +
        ('<td style="padding:5px 8px;font-size:13px;vertical-align:top;">{0}</td>' -f (New-DeviceLink $activity.deviceId $activity.name)) +
        ('<td style="padding:5px 8px;vertical-align:top;">{0}{1}</td>' -f (New-Chip $activity.eventId $variant '0'), $statusChip) +
        ('<td style="padding:5px 8px;font-size:12px;vertical-align:top;white-space:nowrap;">{0}</td>' -f (ConvertTo-HtmlText (Format-ActivityTime $activity.time))) +
        ('<td style="padding:5px 8px;font-size:12px;vertical-align:top;">{0}</td>' -f (ConvertTo-HtmlText $activity.message)) +
        '</tr>'
    }
    $lastScanHtml +
    ('<div style="font-size:12px;color:{0};margin-bottom:8px;">Detection triggers from the NinjaOne activity feed (last {1} days, newest first; per-run summaries excluded).</div>' -f $MutedColor, $Days) +
    '<table style="width:100%;border-collapse:collapse;"><thead><tr>' +
    '<th style="text-align:left;padding:6px 8px;width:22%;">Device</th>' +
    '<th style="text-align:left;padding:6px 8px;width:10%;">Event ID</th>' +
    '<th style="text-align:left;padding:6px 8px;width:16%;">Time</th>' +
    '<th style="text-align:left;padding:6px 8px;">Message</th>' +
    '</tr></thead><tbody>' + $rows + '</tbody></table>'
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
    (New-StatCard $Data.devicesScanned 'Devices scanned' 'Devices whose AI field the dashboard could read this run.') +
    (New-StatCard $Data.devicesWithAi 'Devices with AI' 'Devices where at least one AI signal was found (tool, API key, SDK, local server, model file or ML runtime).') +
    (New-StatCard $Data.distinctTools 'Distinct AI tools' 'Number of different named AI tools seen across the fleet.') +
    (New-StatCard $Data.devicesActive 'Running AI now' 'Devices with an AI process running or a local LLM server responding at scan time.') +
    (New-StatCard $Data.devicesWithKeys 'Devices with API keys' 'Devices with an AI provider API key in their environment. Only the variable name is read, never the value.') +
    (New-StatCard $modelSize 'Local model storage' 'Total size of local model files and known model directories across the fleet.') +
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
        # A table row renders reliably in WYSIWYG; the bar sits in the last (auto-width) cell
        $catRows += '<tr>' +
        ('<td style="width:150px;font-size:12px;padding:3px 8px 3px 0;vertical-align:middle;">{0}</td>' -f (ConvertTo-HtmlText $name)) +
        ('<td style="width:30px;font-size:13px;padding:3px 8px;vertical-align:middle;">{0}</td>' -f $count) +
        ('<td style="padding:3px 0;vertical-align:middle;">{0}</td>' -f (New-Bar $count $catMax $CategoryColor[$name])) +
        '</tr>'
    }
    $categoryCard = if ($catRows) { '<table style="width:100%;border-collapse:collapse;"><tbody>' + $catRows + '</tbody></table>' } else { '<span style="color:{0};font-size:12px;">No categories.</span>' -f $MutedColor }

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
        $detailParts = @()
        if ($device.files -gt 0) { $detailParts += ('{0} file(s)' -f $device.files) }
        if ($device.dirs -gt 0) { $detailParts += ('{0} model dir(s)' -f $device.dirs) }
        $extList = @($device.exts)
        $extText = if ($extList.Count -gt 0) { ' (' + ((@($extList | ForEach-Object { ConvertTo-HtmlText $_ })) -join ', ') + ')' } else { '' }
        $detail = ($detailParts -join ', ') + $extText
        $detailHtml = if ($detail.Trim()) { '<div style="font-size:11px;color:{0};">{1}</div>' -f $MutedColor, $detail } else { '' }
        $modelRows += '<tr><td style="padding:5px 8px;font-size:13px;vertical-align:top;">{0}</td><td style="padding:5px 8px;font-size:12px;vertical-align:top;">{1}{2}</td></tr>' -f (New-DeviceLink $device.id $device.name), (Format-Size $device.bytes), $detailHtml
    }
    $modelCard = if ($modelRows) {
        ('<div style="font-size:12px;color:{0};margin-bottom:8px;">Total across the fleet: {1}</div>' -f $MutedColor, $modelSize) +
        '<table style="width:100%;border-collapse:collapse;"><thead><tr><th style="text-align:left;padding:6px 8px;">Device</th><th style="text-align:left;padding:6px 8px;width:30%;">Model storage</th></tr></thead><tbody>' + $modelRows + '</tbody></table>'
    }
    else { New-InfoCard 'success' 'fa-circle-check' 'No local model files' 'No device stores local model weight files.' }

    # --- Condition activity from the NinjaOne activity feed ---
    $activityTable = New-ActivityTable $Data.activities $Data.activityDays

    # --- Assemble ---
    '<div>' +
    (New-InfoCard '' 'fa-robot' 'AI Detection Dashboard' ("Generated $((Get-Date).ToString('dd.MM.yyyy HH:mm:ss')) from {0} device(s) reporting via '{1}'." -f $Data.devicesScanned, (ConvertTo-HtmlText $DataFieldName))) +
    $stats +
    (New-FullWidthCard ('<i class="fa-solid fa-robot"></i>&nbsp;AI tools by device' + (New-InfoTip 'Named catalog AI tools found on the fleet, one card per tool. "running" = a process or local server is active now; "installed only" = present but not running.')) $toolCards) +
    '<div class="row g-3">' +
    ('<div class="col-12 col-xl-6">{0}</div>' -f (New-FullWidthCard ('<i class="fa-solid fa-layer-group"></i>&nbsp;By category' + (New-InfoTip 'Named catalog tools grouped by category (Local runtime, Desktop app, AI editor, Coding assistant, CLI), counting devices per category. Generic signals - unidentified servers, API keys, SDKs, model files - are not counted here; they have their own cards below.')) $categoryCard)) +
    ('<div class="col-12 col-xl-6">{0}</div>' -f (New-FullWidthCard ('<i class="fa-solid fa-triangle-exclamation"></i>&nbsp;Shadow-AI signals' + (New-InfoTip 'Unidentified local AI: a local LLM server responding on a port, or a process with an ML runtime (onnxruntime, torch, ...) loaded that is not a named catalog tool.')) $shadow)) +
    '</div>' +
    (New-FullWidthCard ('<i class="fa-solid fa-bell"></i>&nbsp;AI condition activity (NinjaOne)' + (New-InfoTip 'Condition triggers from the NinjaOne activity feed for event source NinjaAIDetection. The per-run scan summary (event 5000) is shown as a single "last scan" line, not as rows.')) $activityTable) +
    (New-FullWidthCard ('<i class="fa-solid fa-key"></i>&nbsp;AI API keys by provider' + (New-InfoTip 'Environment variables that look like an AI provider key, grouped by provider. Only the variable name is inspected - the secret value is never read.')) $keyCard) +
    (New-FullWidthCard ('<i class="fa-solid fa-cube"></i>&nbsp;AI SDKs (pip / npm)' + (New-InfoTip 'AI SDKs installed via pip (site-packages) or the global npm store, e.g. anthropic, openai, @anthropic-ai/sdk.')) $pkgCard) +
    (New-FullWidthCard ('<i class="fa-solid fa-hard-drive"></i>&nbsp;Local model storage by device' + (New-InfoTip 'Local model weight files (.gguf, .safetensors, .onnx, ...) and known model directories (Ollama, LM Studio, HF cache, ...), summed per device.')) $modelCard) +
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

    Write-Host "Loading AI condition activity (source '$ActivitySourceName', last $ActivityLookbackDays days)..."
    $activities = @(Get-AiActivities -SourceName $ActivitySourceName -Days $ActivityLookbackDays -ConditionUid $ActivityConditionUid)
    Write-Host "  $($activities.Count) matching activit(ies)"

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
        $dirCount = 0
        foreach ($model in (ConvertTo-Array $data.models)) { $deviceBytes += [double]$model.bytes; $dirCount++ }
        $fileCount = 0; $exts = @()
        if ($data.modelFiles) {
            if ($data.modelFiles.bytes) { $deviceBytes += [double]$data.modelFiles.bytes }
            if ($data.modelFiles.count) { $fileCount = [int]$data.modelFiles.count }
            $exts = @(ConvertTo-Array $data.modelFiles.exts)
        }
        if ($deviceBytes -gt 0) {
            $hasAi = $true
            $totalModelBytes += $deviceBytes
            $modelDevices.Add([pscustomobject]@{ id = $deviceId; name = $name; bytes = $deviceBytes; files = $fileCount; dirs = $dirCount; exts = $exts })
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
        activities      = $activities
        activityDays    = $ActivityLookbackDays
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
