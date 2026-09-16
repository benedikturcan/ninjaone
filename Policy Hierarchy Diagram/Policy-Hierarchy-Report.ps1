<#
.SYNOPSIS
    Writes a NinjaOne policy hierarchy report into the global WYSIWYG custom field "policyHierarchyReport".

.DESCRIPTION
    Runs as a NinjaOne automation script (Windows PowerShell 5.1) or locally.
    - Official API: policies, device policy overrides, custom field update
    - Private console API (/swb/...): child-policy overrides compared with the parent policy,
      authenticated with the rotating browser sessionKey cookie.
      If the sessionKey is missing or expired, the report shows the last successful result
      from a local cache together with its date.

    NinjaOne script variables (injected as environment variables, use these calculated names):
        sessionKey    sessionKey cookie of a logged-in NinjaOne web session
        clientId      API client ID (client_credentials, scopes: monitoring + management)
        clientSecret  API client secret
        region        NinjaOne region: eu (default), app, ca, oc, ...

    The source is kept ASCII-only on purpose: Windows PowerShell 5.1 reads BOM-less scripts as ANSI.
    Non-ASCII output characters are written as HTML entities.

.EXAMPLE
    .\Policy-Hierarchy-Report.ps1 -SessionKey '<sessionKey>' -ClientId '<clientId>' -ClientSecret '<clientSecret>'
#>
param(
    [string]$SessionKey = $env:sessionKey,
    [string]$ClientId = $env:clientId,
    [string]$ClientSecret = $env:clientSecret,
    [string]$Region = $env:region
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

if (-not $SessionKey) { $SessionKey = $env:NINJA_SESSION_KEY }
if (-not $ClientId) { $ClientId = $env:NINJA_CLIENT_ID }
if (-not $ClientSecret) { $ClientSecret = $env:NINJA_CLIENT_SECRET }
if (-not $Region) { $Region = if ($env:NINJA_REGION) { $env:NINJA_REGION } else { 'eu' } }

$ApiUrl = "https://$Region.ninjarmm.com"
$CustomFieldName = 'policyHierarchyReport'
$Invariant = [Globalization.CultureInfo]::InvariantCulture

# NinjaOne runs scripts from a temporary file, so the cache goes to the agent's data folder when available
$CacheDirectory = if ($env:NINJA_DATA_PATH) { $env:NINJA_DATA_PATH } elseif ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$CachePath = Join-Path $CacheDirectory 'policy-hierarchy-report-cache.json'

# Distinguishes "property does not exist" from a JSON null value
$script:Missing = New-Object Object

#region HTTP

function Invoke-NinjaRequest {
    param(
        [Parameter(Mandatory)] [string]$Uri,
        [string]$Method = 'GET',
        [hashtable]$Headers = @{},
        $Body,
        [string]$ContentType,
        $WebSession
    )
    $params = @{ Uri = $Uri; Method = $Method; Headers = $Headers; UseBasicParsing = $true }
    if ($null -ne $Body) { $params.Body = $Body }
    if ($ContentType) { $params.ContentType = $ContentType }
    if ($WebSession) { $params.WebSession = $WebSession }

    $response = Invoke-WebRequest @params
    # Decode explicitly as UTF-8: Windows PowerShell 5.1 would otherwise garble emojis in policy names
    [pscustomobject]@{
        StatusCode  = [int]$response.StatusCode
        ContentType = [string]$response.Headers['Content-Type']
        Text        = [Text.Encoding]::UTF8.GetString($response.RawContentStream.ToArray())
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
    # Arrays are emitted item by item, callers collect them with @()
    $parsed = $response.Text | ConvertFrom-Json
    $parsed
}

function Set-GlobalCustomField {
    param([string]$FieldName, [string]$Html)
    $json = ConvertTo-Json -InputObject @{ $FieldName = @{ html = $Html } } -Depth 5 -Compress
    Invoke-NinjaRequest -Uri "$ApiUrl/v2/system/custom-fields" -Method PATCH `
        -Headers @{ Authorization = "Bearer $script:AccessToken" } `
        -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($json)) | Out-Null
}

# Private NinjaOne console API, authenticated with the browser sessionKey cookie
function Invoke-ConsoleApi {
    param([Parameter(Mandatory)] [string]$Endpoint)
    if (-not $script:ConsoleSession) {
        $script:ConsoleSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        $script:ConsoleSession.Cookies.Add((New-Object System.Net.Cookie('sessionKey', $SessionKey, '/', "$Region.ninjarmm.com")))
    }
    $response = Invoke-NinjaRequest -Uri "$ApiUrl$Endpoint" -WebSession $script:ConsoleSession `
        -Headers @{ Accept = 'application/json'; 'X-Requested-With' = 'XMLHttpRequest' }
    # An expired session answers with the login page (HTML) instead of JSON
    if (-not $response.Text.TrimStart().StartsWith('{') -and -not $response.Text.TrimStart().StartsWith('[')) {
        throw "Console API returned no JSON: $Endpoint (sessionKey expired?)"
    }
    $response.Text | ConvertFrom-Json
}

#endregion

#region JSON helpers

function Test-JsonObject($Value) {
    ($null -ne $Value) -and ($Value -is [System.Management.Automation.PSCustomObject])
}

function Get-JsonProperty($Object, [string]$Name) {
    if (-not (Test-JsonObject $Object)) { return $script:Missing }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $script:Missing }
    , $property.Value
}

function Test-Missing($Value) { [object]::ReferenceEquals($Value, $script:Missing) }

function Test-HasInheritance($Value) {
    (Test-JsonObject $Value) -and ($null -ne $Value.PSObject.Properties['inheritance'])
}

function ConvertTo-CompareString($Value) {
    if (Test-Missing $Value) { return '<<missing>>' }
    if ($null -eq $Value) { return 'null' }
    ConvertTo-Json -InputObject $Value -Depth 50 -Compress
}

#endregion

#region Child-policy overrides

function Resolve-SectionName([string]$Key, $Value) {
    $shortKey = if ($Key.Length -gt 8) { $Key.Substring(0, 8) } else { $Key }
    if ($Value.conditionName) {
        $name = if ($Value.displayName) { $Value.displayName } else { $Value.conditionName }
        return "$name ($shortKey)"
    }
    if ($Value.actionsetScheduleName) { return "$($Value.actionsetScheduleName) ($shortKey)" }
    $Key
}

# Field-level differences between a child block and the same block of the parent.
# Nested blocks carrying their own inheritance flags are skipped, they are reported as separate overrides.
function Get-ValueDiff($Child, $Parent, [string]$Path = '') {
    if ((Test-JsonObject $Child) -and (Test-JsonObject $Parent)) {
        $keys = @($Child.PSObject.Properties.Name) + @($Parent.PSObject.Properties.Name) | Select-Object -Unique
        foreach ($key in $keys) {
            if ($key -eq 'inheritance') { continue }
            $childValue = Get-JsonProperty $Child $key
            $parentValue = Get-JsonProperty $Parent $key
            if ((Test-HasInheritance $childValue) -or (Test-HasInheritance $parentValue)) { continue }
            $subPath = if ($Path) { "$Path.$key" } else { $key }
            Get-ValueDiff $childValue $parentValue $subPath
        }
        return
    }
    if ((ConvertTo-CompareString $Child) -cne (ConvertTo-CompareString $Parent)) {
        # Plain assignments keep arrays intact ("= if (...) { $array }" would unroll them)
        $change = [ordered]@{ field = $Path; parentMissing = (Test-Missing $Parent); parentValue = $null; childMissing = (Test-Missing $Child); childValue = $null }
        if (-not $change.parentMissing) { $change.parentValue = $Parent }
        if (-not $change.childMissing) { $change.childValue = $Child }
        [pscustomobject]$change
    }
}

# Walks the child policy content (/swb/s4/policy/{id}) alongside the parent content
# (/swb/s6/policy/{id}/parent-content). Every block flagged as overridden or added in the child
# becomes one entry with its concrete field changes.
function Get-PolicyOverrides($Content, $ParentContent, [string[]]$Path = @()) {
    if (-not (Test-JsonObject $Content)) { return }
    foreach ($property in $Content.PSObject.Properties) {
        $key = $property.Name
        $value = $property.Value
        if ($key -eq 'inheritance' -or -not (Test-JsonObject $value)) { continue }

        $currentPath = @($Path) + @(Resolve-SectionName $key $value)
        $parentValue = Get-JsonProperty $ParentContent $key
        $inheritance = $value.PSObject.Properties['inheritance']

        if ($inheritance -and ($inheritance.Value.overridden -eq $true -or $inheritance.Value.inherited -eq $false)) {
            $addedInChild = Test-Missing $parentValue
            $changes = @()
            if (-not $addedInChild) { $changes = @(Get-ValueDiff $value $parentValue) }
            [pscustomobject]@{
                path         = $currentPath
                addedInChild = $addedInChild
                changes      = $changes
            }
        }

        Get-PolicyOverrides $value $(if (Test-Missing $parentValue) { $null } else { $parentValue }) $currentPath
    }
}

function Get-ChildPolicyOverrides($ChildPolicies) {
    foreach ($policy in $ChildPolicies) {
        $entry = [ordered]@{
            policyId       = $policy.id
            policyName     = $policy.name
            parentPolicyId = $policy.parentPolicyId
            nodeClass      = $policy.nodeClass
            overrides      = @()
            error          = $null
        }
        try {
            $data = Invoke-ConsoleApi "/swb/s4/policy/$($policy.id)"
            $parentContent = Invoke-ConsoleApi "/swb/s6/policy/$($policy.id)/parent-content"
            $entry.overrides = @(Get-PolicyOverrides $data.policy.content $parentContent)
        }
        catch {
            $entry.error = $_.Exception.Message
        }
        [pscustomobject]$entry
    }
}

function Read-OverridesCache {
    if (-not (Test-Path $CachePath)) { return $null }
    try { [IO.File]::ReadAllText($CachePath, [Text.Encoding]::UTF8) | ConvertFrom-Json }
    catch { $null }
}

# Loads child-policy overrides live and falls back to the cache when the sessionKey is missing or expired.
# Returns @{ Overrides; Status = @{ Source = live|cache|unavailable; FetchedAt; Reason } }
function Get-ChildOverridesWithFallback($ChildPolicies) {
    $cache = Read-OverridesCache

    $fromCache = {
        param([string]$Reason)
        Write-Host "WARNING: $Reason"
        if (-not $cache) {
            return @{ Overrides = @(); Status = @{ Source = 'unavailable'; FetchedAt = $null; Reason = $Reason } }
        }
        # Only keep entries for policies that are still child policies, with their current names
        $current = @{}
        foreach ($policy in $ChildPolicies) { $current[[string]$policy.id] = $policy }
        $entries = @($cache.childPolicyOverrides | Where-Object { $current.ContainsKey([string]$_.policyId) } | ForEach-Object {
                $_.policyName = $current[[string]$_.policyId].name
                $_.parentPolicyId = $current[[string]$_.policyId].parentPolicyId
                $_
            })
        Write-Host "Using cached child-policy overrides from $(Format-Timestamp $cache.fetchedAt)"
        @{ Overrides = $entries; Status = @{ Source = 'cache'; FetchedAt = $cache.fetchedAt; Reason = $Reason } }
    }

    if (-not $SessionKey) { return & $fromCache 'No sessionKey provided.' }
    if (@($ChildPolicies).Count -eq 0) {
        return @{ Overrides = @(); Status = @{ Source = 'live'; FetchedAt = (Get-Date).ToUniversalTime().ToString('o') } }
    }

    $results = @(Get-ChildPolicyOverrides $ChildPolicies)
    $failed = @($results | Where-Object { $_.error })
    if ($failed.Count -eq $results.Count) {
        return & $fromCache "The sessionKey is invalid or expired ($($failed[0].error))."
    }
    foreach ($item in $failed) { Write-Host "WARNING: child policy $($item.policyId) ($($item.policyName)) could not be loaded: $($item.error)" }

    # Failed single policies keep their last cached result instead of being overwritten with an error
    $cachedById = @{}
    if ($cache) { foreach ($item in @($cache.childPolicyOverrides)) { $cachedById[[string]$item.policyId] = $item } }
    $toCache = @($results | ForEach-Object {
            if ($_.error -and $cachedById.ContainsKey([string]$_.policyId)) { $cachedById[[string]$_.policyId] } elseif (-not $_.error) { $_ }
        })
    $fetchedAt = (Get-Date).ToUniversalTime().ToString('o')
    $cacheJson = ConvertTo-Json -InputObject @{ fetchedAt = $fetchedAt; childPolicyOverrides = $toCache } -Depth 50
    [IO.File]::WriteAllText($CachePath, $cacheJson, (New-Object Text.UTF8Encoding($false)))

    @{ Overrides = $results; Status = @{ Source = 'live'; FetchedAt = $fetchedAt } }
}

#endregion

#region Policies and devices

function Get-PolicyChain($PolicyId, [hashtable]$PolicyById) {
    $chain = New-Object System.Collections.ArrayList
    $current = $PolicyById[[string]$PolicyId]
    while ($current) {
        $chain.Insert(0, $current)
        $current = if ($current.parentPolicyId) { $PolicyById[[string]$current.parentPolicyId] } else { $null }
    }
    $chain
}

function Get-DeviceOverrideDetails($OverrideResults) {
    foreach ($entry in @($OverrideResults)) {
        try {
            $device = Invoke-NinjaApi "/v2/device/$($entry.deviceId)"
            $name = if ($device.displayName) { $device.displayName } elseif ($device.systemName) { $device.systemName } else { "Device $($entry.deviceId)" }
            [pscustomobject]@{ deviceId = $entry.deviceId; deviceName = $name; nodeClass = $device.nodeClass; policyId = $device.policyId; overrides = @($entry.overrides) }
        }
        catch {
            [pscustomobject]@{ deviceId = $entry.deviceId; deviceName = "Device $($entry.deviceId) (not reachable)"; nodeClass = 'UNKNOWN'; policyId = $null; overrides = @($entry.overrides) }
        }
    }
}

function New-PolicyTree($Policies) {
    $nodes = @{}
    foreach ($policy in $Policies) {
        $nodes[[string]$policy.id] = [pscustomobject]@{
            id               = $policy.id
            name             = $policy.name
            nodeClass        = $policy.nodeClass
            nodeClassDefault = [bool]$policy.nodeClassDefault
            parentPolicyId   = $policy.parentPolicyId
            children         = New-Object System.Collections.ArrayList
        }
    }
    $roots = New-Object System.Collections.ArrayList
    foreach ($policy in $Policies) {
        $node = $nodes[[string]$policy.id]
        if ($policy.parentPolicyId -and $nodes.ContainsKey([string]$policy.parentPolicyId)) {
            [void]$nodes[[string]$policy.parentPolicyId].children.Add($node)
        }
        else {
            [void]$roots.Add($node)
        }
    }
    $roots
}

#endregion

#region Report HTML
# NinjaOne WYSIWYG fields only allow a small tag/style allowlist (no svg, img, strong, br, script, style):
# the diagram is drawn with flex divs, borders and background bars and uses NinjaOne's card/stat-card/info-card classes.

$NodeClassInfo = [ordered]@{
    WINDOWS_WORKSTATION  = @('Windows Workstation', 'fa-solid fa-desktop')
    WINDOWS_SERVER       = @('Windows Server', 'fa-solid fa-server')
    MAC                  = @('macOS', 'fa-solid fa-laptop')
    MAC_SERVER           = @('macOS Server', 'fa-solid fa-server')
    APPLE_IOS            = @('iOS', 'fa-solid fa-mobile-screen')
    APPLE_IPADOS         = @('iPadOS', 'fa-solid fa-tablet-screen-button')
    LINUX_WORKSTATION    = @('Linux Workstation', 'fa-solid fa-desktop')
    LINUX_SERVER         = @('Linux Server', 'fa-solid fa-server')
    ANDROID              = @('Android', 'fa-solid fa-mobile-screen')
    AOSP                 = @('AOSP', 'fa-solid fa-mobile-screen')
    CHROMEOS             = @('ChromeOS', 'fa-solid fa-laptop')
    HYPERV_VMM_HOST      = @('Hyper-V Host', 'fa-solid fa-server')
    HYPERV_VMM_GUEST     = @('Hyper-V Guest', 'fa-solid fa-cube')
    VMWARE_VM_HOST       = @('VMware Host', 'fa-solid fa-server')
    VMWARE_VM_GUEST      = @('VMware Guest', 'fa-solid fa-cube')
    CLOUD_MONITOR_TARGET = @('Cloud Monitor', 'fa-solid fa-cloud')
    MANAGED_DEVICE       = @('Managed Device', 'fa-solid fa-plug')
    UNMANAGED_DEVICE     = @('Unmanaged Device', 'fa-solid fa-plug-circle-xmark')
}

# One report section per OS family, in this order; brand icons come from Font Awesome Free (fa-brands)
$OsFamilies = @(
    @{ Label = 'Windows'; Icon = 'fa-brands fa-windows'; Match = { param($nc) $nc -like 'WINDOWS_*' } }
    @{ Label = 'Apple'; Icon = 'fa-brands fa-apple'; Match = { param($nc) $nc -eq 'MAC' -or $nc -like 'MAC_*' -or $nc -like 'APPLE_*' } }
    @{ Label = 'Linux'; Icon = 'fa-brands fa-linux'; Match = { param($nc) $nc -like 'LINUX_*' } }
    @{ Label = 'Android'; Icon = 'fa-brands fa-android'; Match = { param($nc) $nc -eq 'ANDROID' -or $nc -eq 'AOSP' } }
    @{ Label = 'ChromeOS'; Icon = 'fa-brands fa-chrome'; Match = { param($nc) $nc -eq 'CHROMEOS' } }
    @{ Label = 'Virtualization'; Icon = 'fa-solid fa-cubes'; Match = { param($nc) $nc -like 'HYPERV_*' -or $nc -like 'VMWARE_*' } }
    @{ Label = 'Network (NMS)'; Icon = 'fa-solid fa-network-wired'; Match = { param($nc) $nc -like 'NMS*' } }
    @{ Label = 'Other'; Icon = 'fa-solid fa-ellipsis'; Match = { param($nc) $true } }
)

$AreaLabels = @{
    conditions              = 'Conditions'
    builtInConditions       = 'Built-in conditions'
    actionsetSchedules      = 'Scheduled automations'
    patchManagement         = 'OS patch management'
    softwarePatchManagement = 'Software patch management'
    antivirus               = 'Antivirus'
    monitors                = 'Monitors'
    backup                  = 'Backup'
    warrantyTracking        = 'Warranty tracking'
    mdmSettings             = 'MDM settings'
    browserManagement       = 'Browser management'
    ringDeployment          = 'Ring deployment'
    ninjaFlow               = 'NinjaFlow'
}

# HTML entities for the non-ASCII characters used in the report
$Sep = ' &rsaquo; '
$Dot = ' &middot; '

$LineColor = '#94a3b8'
$MutedColor = '#94a3b8'
$DepthColors = @('#6366f1', '#0891b2', '#7c3aed')
$ChipColors = @{ success = @('#dcfce7', '#166534'); danger = @('#fee2e2', '#991b1b'); neutral = @('#e2e8f0', '#475569') }
$StubWidth = 16
$ArrowWidth = 10

function ConvertTo-HtmlText($Value) {
    ([string]$Value).Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;')
}

function Format-Timestamp($Value) {
    $date = if ($Value -is [datetime]) { $Value } else { [datetime]::Parse([string]$Value, $Invariant, [Globalization.DateTimeStyles]::RoundtripKind) }
    $date.ToLocalTime().ToString('dd.MM.yyyy HH:mm:ss')
}

function Get-NodeClassLabel([string]$NodeClass) {
    if ($NodeClassInfo.Contains($NodeClass)) { return $NodeClassInfo[$NodeClass][0] }
    if (-not $NodeClass) { return 'Unknown' }
    $words = $NodeClass.Split('_') | ForEach-Object { $_.Substring(0, 1) + $_.Substring(1).ToLower() }
    ($words -join ' ') -replace '^Nms ', 'NMS '
}

function Get-NodeClassIcon([string]$NodeClass) {
    if ($NodeClassInfo.Contains($NodeClass)) { return $NodeClassInfo[$NodeClass][1] }
    if ($NodeClass -like 'NMS*') { 'fa-solid fa-ethernet' } else { 'fa-solid fa-circle-nodes' }
}

function Get-NodeClassOrder([string]$NodeClass) {
    $index = @($NodeClassInfo.Keys).IndexOf($NodeClass)
    if ($index -lt 0) { [int]::MaxValue } else { $index }
}

# camelCase keys become words, labels that are already names (conditions, schedules) stay as they are
function Format-Key([string]$Key) {
    if ($Key -cnotmatch '^[a-z][a-zA-Z0-9]*$') { return $Key }
    $words = ([regex]::Replace($Key, '([a-z0-9])([A-Z])', '$1 $2')).ToLower()
    $words.Substring(0, 1).ToUpper() + $words.Substring(1)
}

function Get-Plural([int]$Count) { if ($Count -eq 1) { "$Count policy" } else { "$Count policies" } }

function New-Chip([string]$Text, [string]$Variant = 'neutral', [string]$Margin = '0 0 0 6px') {
    '<span style="display:inline-block;margin:{0};padding:0 6px;border-radius:4px;font-size:10px;background-color:{1};color:{2};">{3}</span>' -f `
        $Margin, $ChipColors[$Variant][0], $ChipColors[$Variant][1], (ConvertTo-HtmlText $Text)
}

# Policy names open the policy editor in a new tab
function New-PolicyLink($Id, [string]$Name) {
    ('<a href="{0}/#/editor/policy/{1}" target="_blank" rel="noopener noreferrer">{2}</a>' -f $ApiUrl, $Id, (ConvertTo-HtmlText $Name)) +
    ('<i class="fa-solid fa-arrow-up-right-from-square" style="font-size:9px;color:{0};margin-left:4px;"></i>' -f $MutedColor)
}

function New-InfoCard([string]$Variant, [string]$Icon, [string]$Title, [string]$Description) {
    '<div class="info-card {0}" style="margin-bottom:12px;"><i class="info-icon fa-solid {1}"></i><div class="info-text"><div class="info-title">{2}</div><div class="info-description">{3}</div></div></div>' -f `
        $Variant, $Icon, $Title, $Description
}

# NinjaOne lays out sibling .card elements side by side; wrapping each one in its own
# full-width block forces one card per row so the diagrams keep the whole width.
function New-FullWidthCard([string]$Title, [string]$Body) {
    '<div style="display:block;width:100%;margin-bottom:16px;"><div class="card flex-grow-1" style="width:100%;"><div class="card-title-box"><div class="card-title">{0}</div></div><div class="card-body">{1}</div></div></div>' -f $Title, $Body
}

function New-Subheader([string]$Icon, [string]$Title, [string]$Meta) {
    $html = '<div style="display:flex;align-items:center;margin:4px 0 6px;padding:6px 10px;border-radius:6px;background-color:#f1f5f9;">' +
    ('<span style="display:inline-flex;align-items:center;justify-content:center;width:26px;height:26px;border-radius:6px;background-color:#e0e7ff;color:#4f46e5;font-size:13px;"><i class="{0}"></i></span>' -f $Icon) +
    ('<span style="font-size:15px;margin-left:10px;">{0}</span>' -f $Title)
    if ($Meta) { $html += '<span style="font-size:12px;color:{0};margin-left:8px;">{1}</span>' -f $MutedColor, $Meta }
    $html + '</div>'
}

function Get-SubtreeCount($Node) {
    $count = 1
    foreach ($child in $Node.children) { $count += Get-SubtreeCount $child }
    $count
}

function Get-TreeDepth($Node) {
    if ($Node.children.Count -eq 0) { return 1 }
    1 + (($Node.children | ForEach-Object { Get-TreeDepth $_ }) | Measure-Object -Maximum).Maximum
}

# Every changed field counts; an overridden block without value differences still counts once
function Get-ChangedSettingCount($ChildOverride) {
    $count = 0
    foreach ($override in @($ChildOverride.overrides)) { $count += [Math]::Max(@($override.changes | Where-Object { $_ }).Count, 1) }
    $count
}

function New-ReportHtml {
    param($Policies, $Tree, $DeviceOverrides, $ChildOverrides, [hashtable]$PolicyById, [hashtable]$ChildStatus)

    $deviceOverridesByPolicy = @{}
    foreach ($device in @($DeviceOverrides)) {
        if ($null -ne $device.policyId) { $deviceOverridesByPolicy[[string]$device.policyId] = 1 + [int]$deviceOverridesByPolicy[[string]$device.policyId] }
    }
    $childWithOverrides = @($ChildOverrides | Where-Object { @($_.overrides).Count -gt 0 } | Sort-Object policyName)
    $childOverrideByPolicy = @{}
    foreach ($child in $childWithOverrides) { $childOverrideByPolicy[[string]$child.policyId] = $child }
    $failedChildLoads = @($ChildOverrides | Where-Object { $_.error }).Count

    function New-PolicyTags($Policy) {
        $tags = ''
        if ($Policy.nodeClassDefault) { $tags += New-Chip 'Default' 'success' }
        $childOverride = $childOverrideByPolicy[[string]$Policy.id]
        if ($childOverride) {
            $changed = Get-ChangedSettingCount $childOverride
            $tags += New-Chip ("$changed changed setting" + $(if ($changed -eq 1) { '' } else { 's' })) 'danger'
        }
        $deviceCount = [int]$deviceOverridesByPolicy[[string]$Policy.id]
        if ($deviceCount -gt 0) { $tags += New-Chip ("$deviceCount device override" + $(if ($deviceCount -gt 1) { 's' } else { '' })) 'neutral' }
        $tags
    }

    # Horizontal tree (left to right) using the full width: at each level the card takes 100/remainingLevels %
    # of its container and the rest (flex-grow-1 with width 0, so long names never shrink the cards) holds the
    # next level. The column header uses the exact same nesting, so header labels and cards always line up.
    function Get-ColumnWidth([int]$Depth, [int]$Levels) { (100 / ($Levels - $Depth)).ToString('0.####', $Invariant) + '%' }

    function New-PolicyCard($Policy, [string]$Width, [string]$AccentColor) {
        ('<div style="width:{0};box-sizing:border-box;padding:6px 10px;border-width:1px;border-style:solid;border-color:#cbd5e1;border-left:4px solid {1};border-radius:6px;">' -f $Width, $AccentColor) +
        ('<div style="font-size:13px;word-break:break-word;">{0}</div>' -f (New-PolicyLink $Policy.id $Policy.name)) +
        ('<div style="font-size:11px;color:{0};">#{1}{2}</div>' -f $MutedColor, $Policy.id, (New-PolicyTags $Policy)) +
        '</div>'
    }

    # Card, a stub to the right, then the children stacked in the next column
    function New-Branch($Policy, [int]$Depth, [int]$Levels) {
        $children = @($Policy.children | Sort-Object name)
        $html = '<div class="flex-grow-1" style="width:0;display:flex;align-items:center;padding:4px 0;">' +
        (New-PolicyCard $Policy (Get-ColumnWidth $Depth $Levels) $DepthColors[[Math]::Min($Depth, 2)])
        if ($children.Count -gt 0) {
            # margin-top shifts the centered 2px stub down 1px so it lines up with the elbow bar, which starts at 50%
            $html += '<div style="width:{0}px;height:2px;margin-top:2px;background-color:{1};"></div>' -f $StubWidth, $LineColor
            $html += '<div class="flex-grow-1" style="width:0;">'
            for ($i = 0; $i -lt $children.Count; $i++) {
                $html += New-ChildRow $children[$i] ($Depth + 1) $Levels ($i -eq 0) ($i -eq $children.Count - 1)
            }
            $html += '</div>'
        }
        $html + '</div>'
    }

    # Elbow cell stretches to the row height; its halves draw the shared vertical line (first child: none above,
    # last child: none below), the 2px bar between them is the stub to the arrowhead.
    # Horizontal lines use background-color bars because NinjaOne does not render border-top/border-bottom here.
    function New-ChildRow($Child, [int]$Depth, [int]$Levels, [bool]$First, [bool]$Last) {
        $border = "border-left:2px solid $LineColor;"
        '<div style="display:flex;">' +
        ('<div style="width:{0}px;">' -f $StubWidth) +
        ('<div style="height:50%;{0}"></div>' -f $(if ($First) { '' } else { $border })) +
        ('<div style="height:2px;background-color:{0};"></div>' -f $LineColor) +
        ('<div style="height:50%;{0}"></div>' -f $(if ($Last) { '' } else { $border })) +
        '</div>' +
        ('<div style="width:{0}px;display:flex;align-items:center;"><i class="fa-solid fa-caret-right" style="color:{1};font-size:14px;"></i></div>' -f $ArrowWidth, $LineColor) +
        (New-Branch $Child $Depth $Levels) +
        '</div>'
    }

    function New-ColumnHeader([int]$Depth, [int]$Levels) {
        if ($Depth -ge $Levels) { return '' }
        $levelNames = @('Parent', 'Child', 'Child-Child')
        $label = "Level $($Depth + 1)" + $(if ($Depth -lt $levelNames.Count) { "$Dot$($levelNames[$Depth])" } else { '' })
        $html = ('<div style="width:{0};box-sizing:border-box;padding:0 0 0 4px;font-size:11px;color:{1};">' -f (Get-ColumnWidth $Depth $Levels), $MutedColor) +
        ('<span style="display:inline-block;width:8px;height:8px;background-color:{0};border-radius:2px;margin-right:4px;"></span>{1}</div>' -f $DepthColors[[Math]::Min($Depth, 2)], $label)
        if ($Depth + 1 -lt $Levels) {
            $html += '<div style="width:{0}px;text-align:center;"><i class="fa-solid fa-arrow-right" style="color:{1};font-size:11px;"></i></div>' -f ($StubWidth * 2 + $ArrowWidth), $LineColor
            $html += '<div class="flex-grow-1" style="width:0;display:flex;">{0}</div>' -f (New-ColumnHeader ($Depth + 1) $Levels)
        }
        '<div class="flex-grow-1" style="width:0;display:flex;align-items:center;">{0}</div>' -f $html
    }

    # Group root policies by node class
    $groups = @{}
    foreach ($root in @($Tree | Sort-Object name)) {
        $key = if ($root.nodeClass) { [string]$root.nodeClass } else { 'UNKNOWN' }
        if (-not $groups.ContainsKey($key)) { $groups[$key] = New-Object System.Collections.ArrayList }
        [void]$groups[$key].Add($root)
    }
    $groupList = @($groups.GetEnumerator() | ForEach-Object {
            $count = 0
            foreach ($root in $_.Value) { $count += Get-SubtreeCount $root }
            [pscustomobject]@{ NodeClass = $_.Key; Roots = @($_.Value); PolicyCount = $count }
        })

    # Every node class gets its own sub-section (e.g. macOS, iOS, iPadOS, macOS Server),
    # with its inheritance trees first and policies without inheritance as a row below.
    $familySections = ''
    $assigned = @{}
    foreach ($family in $OsFamilies) {
        $familyGroups = @($groupList | Where-Object { -not $assigned.ContainsKey($_.NodeClass) -and (& $family.Match $_.NodeClass) } |
            Sort-Object @{ Expression = { Get-NodeClassOrder $_.NodeClass } }, @{ Expression = { Get-NodeClassLabel $_.NodeClass } })
        if ($familyGroups.Count -eq 0) { continue }
        foreach ($group in $familyGroups) { $assigned[$group.NodeClass] = $true }

        $total = ($familyGroups | Measure-Object -Property PolicyCount -Sum).Sum
        $classSections = ''
        foreach ($group in $familyGroups) {
            $treeRoots = @($group.Roots | Where-Object { $_.children.Count -gt 0 })
            $standalone = @($group.Roots | Where-Object { $_.children.Count -eq 0 } | Sort-Object name)
            $meta = (Get-Plural $group.PolicyCount) + $(if ($treeRoots.Count -eq 0) { "$Dot" + 'no inheritance' } else { '' })

            $section = '<div style="margin-bottom:12px;">' + (New-Subheader (Get-NodeClassIcon $group.NodeClass) (ConvertTo-HtmlText (Get-NodeClassLabel $group.NodeClass)) $meta)
            if ($treeRoots.Count -gt 0) {
                $levels = ($treeRoots | ForEach-Object { Get-TreeDepth $_ } | Measure-Object -Maximum).Maximum
                $section += '<div style="display:flex;margin-top:8px;">{0}</div>' -f (New-ColumnHeader 0 $levels)
                foreach ($root in $treeRoots) { $section += '<div style="display:flex;">{0}</div>' -f (New-Branch $root 0 $levels) }
            }
            if ($standalone.Count -gt 0) {
                # Policies without parent or children: same card as in the trees (grey accent), laid out in a row
                $section += '<div class="row g-2" style="margin-top:4px;">'
                foreach ($policy in $standalone) { $section += '<div class="col-12 col-md-6 col-xl-4">{0}</div>' -f (New-PolicyCard $policy '100%' '#cbd5e1') }
                $section += '</div>'
            }
            $classSections += $section + '</div>'
        }

        $title = '<i class="{0}" style="font-size:18px;"></i>&nbsp;&nbsp;{1}<span style="font-size:12px;color:{2};margin-left:8px;">{3}</span>' -f $family.Icon, $family.Label, $MutedColor, (Get-Plural $total)
        $familySections += New-FullWidthCard $title $classSections
    }

    # Device overrides
    if (@($DeviceOverrides).Count -gt 0) {
        $deviceTable = '<table style="width:100%;border-collapse:collapse;"><thead><tr><th style="text-align:left;padding:6px 8px;">Device</th><th style="text-align:left;padding:6px 8px;">Policy</th><th style="text-align:left;padding:6px 8px;">Overridden sections</th></tr></thead><tbody>'
        foreach ($device in @($DeviceOverrides | Sort-Object deviceName)) {
            $chain = if ($null -ne $device.policyId -and $PolicyById.ContainsKey([string]$device.policyId)) {
                (@(Get-PolicyChain $device.policyId $PolicyById) | ForEach-Object { New-PolicyLink $_.id $_.name }) -join $Sep
            }
            else { 'No policy' }
            $sectionChips = (@($device.overrides) | ForEach-Object { New-Chip $_ 'neutral' '2px 4px 2px 0' }) -join ''
            $deviceTable += '<tr><td style="padding:6px 8px;"><div>{0}</div><div style="font-size:11px;color:{1};">{2}{3}#{4}</div></td><td style="padding:6px 8px;font-size:12px;">{5}</td><td style="padding:6px 8px;">{6}</td></tr>' -f `
                (ConvertTo-HtmlText $device.deviceName), $MutedColor, (ConvertTo-HtmlText (Get-NodeClassLabel $device.nodeClass)), $Dot, $device.deviceId, $chain, $sectionChips
        }
        $deviceTable += '</tbody></table>'
    }
    else {
        $deviceTable = New-InfoCard 'success' 'fa-circle-check' 'No device overrides' 'All devices follow their assigned policy.'
    }

    # Child-policy overrides: one block per child policy with a Parent -> Child value table
    function Format-OverrideValue($Value, [bool]$Missing, $Colors) {
        if ($Missing) { return '<span style="font-size:12px;color:{0};">not set</span>' -f $MutedColor }
        $raw = if ($Value -is [string]) { $Value } elseif ($null -eq $Value) { 'null' } else { ConvertTo-Json -InputObject $Value -Depth 50 -Compress }
        if ($raw.Length -gt 160) { $raw = $raw.Substring(0, 157) + '...' }
        '<span style="display:inline-block;padding:1px 6px;border-radius:4px;font-size:12px;font-family:monospace;word-break:break-word;background-color:{0};color:{1};">{2}</span>' -f `
            $Colors[0], $Colors[1], (ConvertTo-HtmlText $raw)
    }

    $cell = 'padding:6px 8px;vertical-align:top;'
    $childSection = ''
    $childDataDate = if ($ChildStatus.FetchedAt) { Format-Timestamp $ChildStatus.FetchedAt } else { $null }
    switch ($ChildStatus.Source) {
        'cache' {
            $childSection += New-InfoCard 'warning' 'fa-clock-rotate-left' "Child-policy overrides as of $childDataDate" `
                "$(ConvertTo-HtmlText $ChildStatus.Reason) Showing the data of the last run with a valid sessionKey."
        }
        'unavailable' {
            $childSection += New-InfoCard 'warning' 'fa-triangle-exclamation' 'Child-policy overrides unavailable' `
                "$(ConvertTo-HtmlText $ChildStatus.Reason) No earlier data found: run the script once with a valid sessionKey."
        }
        default {
            if ($failedChildLoads -gt 0) {
                $childSection += New-InfoCard 'warning' 'fa-triangle-exclamation' 'Child-policy overrides incomplete' `
                    "Could not load $failedChildLoads of $(@($ChildOverrides).Count) child policies from the NinjaOne console API."
            }
        }
    }

    foreach ($child in $childWithOverrides) {
        $rows = ''
        foreach ($override in @($child.overrides)) {
            $path = @($override.path)
            $area = [string]$path[0]
            $areaLabel = if ($AreaLabels.ContainsKey($area)) { $AreaLabels[$area] } else { Format-Key $area }
            $areaCell = '<td style="{0}font-size:12px;">{1}</td>' -f $cell, (ConvertTo-HtmlText $areaLabel)
            $itemLabel = if ($path.Count -gt 1) { ($path[1..($path.Count - 1)] | ForEach-Object { ConvertTo-HtmlText (Format-Key $_) }) -join $Sep } else { ConvertTo-HtmlText $areaLabel }
            $changes = @($override.changes | Where-Object { $_ })
            if ($changes.Count -eq 0) {
                $note = if ($override.addedInChild) { 'Added in child policy (not present in parent)' } else { 'Marked as overridden, values identical to parent' }
                $rows += '<tr>{0}<td style="{1}font-size:13px;">{2}</td><td style="{1}" colspan="2"><span style="font-size:12px;color:{3};">{4}</span></td></tr>' -f $areaCell, $cell, $itemLabel, $MutedColor, $note
                continue
            }
            foreach ($change in $changes) {
                $field = if ($change.field) {
                    '<div style="font-size:11px;color:{0};font-family:monospace;">{1}</div>' -f $MutedColor, ((([string]$change.field).Split('.') | ForEach-Object { ConvertTo-HtmlText (Format-Key $_) }) -join $Sep)
                }
                else { '' }
                $rows += '<tr>{0}<td style="{1}"><div style="font-size:13px;">{2}</div>{3}</td><td style="{1}">{4}</td><td style="{1}">{5}</td></tr>' -f `
                    $areaCell, $cell, $itemLabel, $field,
                (Format-OverrideValue $change.parentValue ([bool]$change.parentMissing) $ChipColors.danger),
                (Format-OverrideValue $change.childValue ([bool]$change.childMissing) $ChipColors.success)
            }
        }

        $parent = $PolicyById[[string]$child.parentPolicyId]
        $settingCount = Get-ChangedSettingCount $child
        $childSection += '<div style="margin-bottom:16px;">' +
        '<div style="display:flex;align-items:center;padding:6px 10px;border-radius:6px;background-color:#f1f5f9;">' +
        ('<span style="font-size:14px;">{0}</span>' -f (New-PolicyLink $child.policyId $child.policyName)) +
        ('<span style="font-size:12px;color:{0};margin:0 6px 0 10px;">inherits from</span>' -f $MutedColor) +
        ('<span style="font-size:12px;">{0}</span>' -f $(if ($parent) { New-PolicyLink $parent.id $parent.name } else { '&ndash;' })) +
        (New-Chip ("$settingCount changed setting" + $(if ($settingCount -eq 1) { '' } else { 's' })) 'danger' '0 0 0 10px') +
        '</div>' +
        '<table style="width:100%;border-collapse:collapse;margin-top:4px;"><thead><tr>' +
        '<th style="text-align:left;padding:6px 8px;width:16%;">Area</th>' +
        '<th style="text-align:left;padding:6px 8px;width:34%;">Setting</th>' +
        '<th style="text-align:left;padding:6px 8px;width:25%;">Parent value</th>' +
        '<th style="text-align:left;padding:6px 8px;width:25%;">Child value</th>' +
        "</tr></thead><tbody>$rows</tbody></table>" +
        '</div>'
    }
    if ($childWithOverrides.Count -eq 0 -and $ChildStatus.Source -ne 'unavailable' -and $failedChildLoads -eq 0) {
        $childSection += New-InfoCard 'success' 'fa-circle-check' 'No child-policy overrides' 'All child policies fully inherit from their parents.'
    }

    # Header and stats
    $maxDepth = if (@($Tree).Count -gt 0) { (@($Tree) | ForEach-Object { Get-TreeDepth $_ } | Measure-Object -Maximum).Maximum } else { 0 }
    $childStatValue = if ($ChildStatus.Source -eq 'unavailable') { 'n/a' } else { $childWithOverrides.Count }
    $childStatLabel = if ($ChildStatus.Source -eq 'cache') { "Child policies with overrides (as of $childDataDate)" } else { 'Child policies with overrides' }
    $statCard = '<div class="col"><div class="stat-card"><div class="stat-value">{0}</div><div class="stat-desc">{1}</div></div></div>'

    '<div>' +
    (New-InfoCard '' 'fa-sitemap' 'Policy Hierarchy' "Generated $((Get-Date).ToString('dd.MM.yyyy HH:mm:ss')) via API") +
    '<div class="row g-3" style="margin-bottom:16px;">' +
    ($statCard -f @($Policies).Count, 'Policies') +
    ($statCard -f @($Tree | Where-Object { $_.children.Count -gt 0 }).Count, 'Inheritance chains') +
    ($statCard -f $maxDepth, 'Max. depth') +
    ($statCard -f @($DeviceOverrides).Count, 'Devices with overrides') +
    ($statCard -f $childStatValue, $childStatLabel) +
    '</div>' +
    '<h2 style="font-size:16px;margin:8px 0 4px;">Inheritance diagram</h2>' +
    ('<div style="font-size:12px;color:{0};margin:0 0 12px;">Read left to right: arrows point from a policy to the policies that inherit from it.</div>' -f $MutedColor) +
    "<div style=`"display:block;width:100%;`">$familySections</div>" +
    '<h2 style="font-size:16px;margin:16px 0 8px;">Deviations</h2>' +
    '<div style="display:block;width:100%;">' +
    (New-FullWidthCard '<i class="fas fa-laptop-code"></i>&nbsp;Device overrides' $deviceTable) +
    (New-FullWidthCard '<i class="fas fa-code-branch"></i>&nbsp;Child-policy overrides' $childSection) +
    '</div>' +
    '</div>'
}

#endregion

#region Main

try {
    $missingSettings = @()
    if (-not $ClientId) { $missingSettings += 'clientId' }
    if (-not $ClientSecret) { $missingSettings += 'clientSecret' }
    if ($missingSettings.Count -gt 0) { throw "Missing script variables: $($missingSettings -join ', ')" }

    $script:AccessToken = Get-AccessToken

    Write-Host 'Loading policies...'
    $policies = @(Invoke-NinjaApi '/v2/policies')
    $policyById = @{}
    foreach ($policy in $policies) { $policyById[[string]$policy.id] = $policy }
    $tree = @(New-PolicyTree $policies)

    Write-Host 'Loading device policy overrides...'
    $overrideQuery = Invoke-NinjaApi '/v2/queries/policy-overrides'
    Write-Host "Loading details for $(@($overrideQuery.results).Count) devices..."
    $deviceOverrides = @(Get-DeviceOverrideDetails $overrideQuery.results)

    $childPolicies = @($policies | Where-Object { $_.parentPolicyId })
    Write-Host "Loading child-policy overrides for $($childPolicies.Count) child policies..."
    $childResult = Get-ChildOverridesWithFallback $childPolicies
    $withOverrides = @($childResult.Overrides | Where-Object { @($_.overrides).Count -gt 0 })
    Write-Host "Found $($withOverrides.Count) child policies with overrides ($($childResult.Status.Source))"

    $html = New-ReportHtml -Policies $policies -Tree $tree -DeviceOverrides $deviceOverrides -ChildOverrides @($childResult.Overrides) -PolicyById $policyById -ChildStatus $childResult.Status
    Write-Host "Writing report to global custom field `"$CustomFieldName`" ($($html.Length) characters)..."
    Set-GlobalCustomField -FieldName $CustomFieldName -Html $html
    Write-Host "Custom field `"$CustomFieldName`" updated"
}
catch {
    Write-Host "ERROR: $($_.Exception.Message)"
    exit 1
}

#endregion
