<#
.SYNOPSIS
    NinjaOne backup post-script: turns the backup bandwidth throttle of the device off again
    after the backup job, undoing Backup-Throttle-PreScript.ps1.

.DESCRIPTION
    Runs as a post-script of a NinjaOne backup plan (Windows PowerShell 5.1) or locally.
    POST /v2/backup/bandwidth-throttle for this device with enabled = false, so the next backup
    or any manual backup outside the pre-/post-script pair runs without the measured limit.

    Exit codes: 0 = throttle turned off, 1 = error.

    NinjaOne script variables (injected as environment variables, use these calculated names):
        clientId                 API client ID (client_credentials, scopes: monitoring + management)
        clientSecret             API client secret
        region                   NinjaOne region: eu (default), app, ca, oc, ...
        deviceId                 Device ID (default: NINJA_AGENT_NODE_ID provided by the agent)

    The source is kept ASCII-only on purpose: Windows PowerShell 5.1 reads BOM-less scripts as ANSI.

.EXAMPLE
    .\Backup-Throttle-PostScript.ps1 -ClientId '<clientId>' -ClientSecret '<clientSecret>' -DeviceId 123
#>
param(
    [string]$ClientId = $env:clientId,
    [string]$ClientSecret = $env:clientSecret,
    [string]$Region = $env:region,
    [string]$DeviceId = $env:deviceId
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

if (-not $ClientId) { $ClientId = $env:NINJA_CLIENT_ID }
if (-not $ClientSecret) { $ClientSecret = $env:NINJA_CLIENT_SECRET }
if (-not $Region) { $Region = if ($env:NINJA_REGION) { $env:NINJA_REGION } else { 'eu' } }
if (-not $DeviceId) { $DeviceId = $env:NINJA_AGENT_NODE_ID }

$ApiUrl = "https://$Region.ninjarmm.com"
$AllWeekDays = @('MONDAY', 'TUESDAY', 'WEDNESDAY', 'THURSDAY', 'FRIDAY', 'SATURDAY', 'SUNDAY')

# Write-Host instead of Write-Output: log lines inside functions must not end up in their return values
function Write-Log([string]$Message) {
    Write-Host ('[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss'), $Message)
}

#region NinjaOne API

# Status code and response body of a failed web request; Windows PowerShell 5.1 only shows the status line
function Get-HttpErrorDetail($ErrorRecord) {
    $detail = $ErrorRecord.Exception.Message
    # The web cmdlets already read the response stream and put the body into ErrorDetails
    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
        return "$detail Body: $($ErrorRecord.ErrorDetails.Message)"
    }
    $response = $ErrorRecord.Exception.Response
    if ($response) {
        try {
            $stream = $response.GetResponseStream()
            if ($stream.CanSeek) { $stream.Position = 0 }
            $reader = New-Object IO.StreamReader($stream)
            $body = $reader.ReadToEnd()
            $reader.Dispose()
            if ($body) { $detail = "$detail Body: $body" }
        }
        catch { }
    }
    $detail
}

function Get-AccessToken {
    try {
        $response = Invoke-RestMethod -Uri "$ApiUrl/ws/oauth/token" -Method POST -ContentType 'application/x-www-form-urlencoded' -UseBasicParsing -Body @{
            grant_type    = 'client_credentials'
            client_id     = $ClientId
            client_secret = $ClientSecret
            scope         = 'monitoring management'
        }
    }
    catch {
        throw "Authentication failed ($ApiUrl/ws/oauth/token): $(Get-HttpErrorDetail $_)"
    }
    $response.access_token
}

# The API answers {"result":"SUCCESS"} or {"result":"FAILURE"}; FAILURE comes with HTTP 500 and no reason
function Set-BandwidthThrottle([string]$Token, [hashtable]$Throttle) {
    $json = ConvertTo-Json -InputObject @{ deviceId = $script:ParsedDeviceId; bandwidthThrottle = $Throttle } -Depth 5 -Compress
    Write-Log "POST /v2/backup/bandwidth-throttle $json"
    try {
        # Same headers as the request sample in the NinjaOne API docs: no Accept header and a Content-Type without charset
        $response = Invoke-WebRequest -Uri "$ApiUrl/v2/backup/bandwidth-throttle" -Method POST -UseBasicParsing `
            -Headers @{ Authorization = "Bearer $Token" } `
            -ContentType 'application/json' -Body $json
        $text = [string]$response.Content
    }
    catch {
        $text = Get-HttpErrorDetail $_
        if ($text -notmatch 'FAILURE') { throw "POST /v2/backup/bandwidth-throttle failed: $text" }
    }
    Write-Log "  Response: $text"
    if ($text -match 'FAILURE') {
        throw ("NinjaOne rejected the bandwidth throttle for device $script:ParsedDeviceId (result FAILURE). " +
            'Most likely NinjaOne Backup is not enabled for this device: enable Backup for the device ' +
            '(policy / organization backup settings) and make sure a backup plan is assigned.')
    }
}

#endregion

try {
    if (-not $ClientId -or -not $ClientSecret) { throw "Script variables 'clientId' and 'clientSecret' are required." }
    $parsedDeviceId = 0
    if (-not [int]::TryParse("$DeviceId", [ref]$parsedDeviceId)) {
        throw "No device ID: NINJA_AGENT_NODE_ID is not set, pass the script variable 'deviceId'."
    }
    $script:ParsedDeviceId = $parsedDeviceId

    Write-Log "Device ${parsedDeviceId}: turning the backup bandwidth throttle off"
    $token = Get-AccessToken

    # Same payload shape as the pre-script (confirmed working); the limits are ignored while disabled
    Set-BandwidthThrottle $token @{
        enabled              = $false
        workHoursKbps        = 0
        nonWorkHoursKbps     = 0
        workHoursUserUnit    = 'KBPS'
        nonWorkHoursUserUnit = 'KBPS'
        workSchedule         = @{ startHour = 0; startMinute = 0; endHour = 23; endMinute = 59; weekDays = $AllWeekDays }
    }
    Write-Log 'Bandwidth throttle turned off.'
    exit 0
}
catch {
    Write-Log "ERROR: $($_.Exception.Message)"
    exit 1
}
