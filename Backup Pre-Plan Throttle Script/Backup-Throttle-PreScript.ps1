<#
.SYNOPSIS
    NinjaOne backup pre-script: measures the internet speed of the device and sets the
    backup bandwidth throttle to a percentage of the measured upload (or download) rate.

.DESCRIPTION
    Runs as a pre-script of a NinjaOne backup plan (Windows PowerShell 5.1) or locally.
    1. Speed test against speed.cloudflare.com (no external binary): several parallel streams
       for a fixed time window, the TCP ramp-up phase at the start is not counted.
    2. Throttle = measured rate (Kbps) * percentage / 100, never below minimumKbps.
    3. POST /v2/backup/bandwidth-throttle for this device via the official API. The throttle is
       meant for the job that is starting right now, so work and non-work hours get the same value
       and the work schedule covers the whole week: the limit applies regardless of the time of day.
    4. Waits applyDelaySeconds so the agent picks up the new setting before the backup job starts.
    The post-script Backup-Throttle-PostScript.ps1 turns the throttle off again after the backup.

    Bandwidth throttling in NinjaOne only applies to cloud backups, so upload is the default base.

    Exit codes: 0 = throttle set, 1 = error (speed test or API). Whether an error cancels the backup
    is controlled in the backup plan: "Cancel the backup job if the automation returns a failure code".

    NinjaOne script variables (injected as environment variables, use these calculated names):
        throttlePercent          Integer 1-100, share of the measured rate the backup may use (required)
        measureBase              upload (default) or download
        minimumKbps              Lower limit for the throttle in Kbps (default: 256)
        applyDelaySeconds        Wait after setting the throttle, before the backup starts (default: 60)
        testDurationSeconds      Measurement duration (default: 10)
        parallelStreams          Parallel connections (default: 4)
        clientId                 API client ID (client_credentials, scopes: monitoring + management)
        clientSecret             API client secret
        region                   NinjaOne region: eu (default), app, ca, oc, ...
        deviceId                 Device ID (default: NINJA_AGENT_NODE_ID provided by the agent)

    The source is kept ASCII-only on purpose: Windows PowerShell 5.1 reads BOM-less scripts as ANSI.

.EXAMPLE
    .\Backup-Throttle-PreScript.ps1 -ThrottlePercent 5 -ClientId '<clientId>' -ClientSecret '<clientSecret>' -DeviceId 123
#>
param(
    [string]$ThrottlePercent = $env:throttlePercent,
    [string]$MeasureBase = $env:measureBase,
    [string]$MinimumKbps = $env:minimumKbps,
    [string]$ApplyDelaySeconds = $env:applyDelaySeconds,
    [string]$TestDurationSeconds = $env:testDurationSeconds,
    [string]$ParallelStreams = $env:parallelStreams,
    [string]$ClientId = $env:clientId,
    [string]$ClientSecret = $env:clientSecret,
    [string]$Region = $env:region,
    [string]$DeviceId = $env:deviceId
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
# The default of 2 connections per host would cap the parallel streams
[Net.ServicePointManager]::DefaultConnectionLimit = 64
[Net.ServicePointManager]::Expect100Continue = $false

if (-not $ClientId) { $ClientId = $env:NINJA_CLIENT_ID }
if (-not $ClientSecret) { $ClientSecret = $env:NINJA_CLIENT_SECRET }
if (-not $Region) { $Region = if ($env:NINJA_REGION) { $env:NINJA_REGION } else { 'eu' } }
if (-not $DeviceId) { $DeviceId = $env:NINJA_AGENT_NODE_ID }

$ApiUrl = "https://$Region.ninjarmm.com"
$SpeedTestDownloadUrl = 'https://speed.cloudflare.com/__down?bytes=50000000'
$SpeedTestUploadUrl = 'https://speed.cloudflare.com/__up'
$UploadBytesPerRequest = 25MB
$WarmupSeconds = 2
$AllWeekDays = @('MONDAY', 'TUESDAY', 'WEDNESDAY', 'THURSDAY', 'FRIDAY', 'SATURDAY', 'SUNDAY')

# Write-Host instead of Write-Output: log lines inside functions must not end up in their return values
function Write-Log([string]$Message) {
    Write-Host ('[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss'), $Message)
}

#region Parameter validation

function Get-IntParameter([string]$Name, [string]$Value, [int]$Default, [int]$Min, [int]$Max, [switch]$Required) {
    if ([string]::IsNullOrWhiteSpace($Value)) {
        if ($Required) { throw "Script variable '$Name' is required." }
        return $Default
    }
    $parsed = 0
    if (-not [int]::TryParse($Value.Trim(), [ref]$parsed) -or $parsed -lt $Min -or $parsed -gt $Max) {
        throw "Script variable '$Name' must be an integer between $Min and $Max (value: '$Value')."
    }
    $parsed
}

#endregion

#region Speed test

# Runs in its own runspace per stream; adds the received bytes to $Counter[$Index] until the deadline
$DownloadWorker = {
    param([string]$Url, [long]$DeadlineTicks, [hashtable]$Counter, [int]$Index)
    $buffer = New-Object byte[] 65536
    while ([DateTime]::UtcNow.Ticks -lt $DeadlineTicks) {
        $request = $null
        try {
            $request = [Net.HttpWebRequest]::Create($Url)
            $request.Timeout = 15000
            $request.ReadWriteTimeout = 15000
            $request.UserAgent = 'NinjaOne-Backup-Throttle-PreScript'
            $response = $request.GetResponse()
            $stream = $response.GetResponseStream()
            while ([DateTime]::UtcNow.Ticks -lt $DeadlineTicks) {
                $read = $stream.Read($buffer, 0, $buffer.Length)
                if ($read -le 0) { break }
                $Counter[$Index] += $read
            }
        }
        catch {
            $Counter["error$Index"] = $_.Exception.Message
            Start-Sleep -Milliseconds 250
        }
        finally {
            # Abort instead of Close: Close would drain the remaining response body
            if ($request) { $request.Abort() }
        }
    }
}

# Sends random (incompressible) data; counts the bytes written to the unbuffered request stream
$UploadWorker = {
    param([string]$Url, [long]$DeadlineTicks, [hashtable]$Counter, [int]$Index, [long]$BytesPerRequest)
    $chunk = New-Object byte[] 65536
    (New-Object Random).NextBytes($chunk)
    while ([DateTime]::UtcNow.Ticks -lt $DeadlineTicks) {
        $request = $null
        try {
            $request = [Net.HttpWebRequest]::Create($Url)
            $request.Method = 'POST'
            $request.Timeout = 15000
            $request.ReadWriteTimeout = 15000
            $request.UserAgent = 'NinjaOne-Backup-Throttle-PreScript'
            $request.ContentType = 'application/octet-stream'
            $request.AllowWriteStreamBuffering = $false
            $request.ContentLength = $BytesPerRequest
            $stream = $request.GetRequestStream()
            $sent = 0L
            while ($sent -lt $BytesPerRequest -and [DateTime]::UtcNow.Ticks -lt $DeadlineTicks) {
                $count = [int][Math]::Min($chunk.Length, $BytesPerRequest - $sent)
                $stream.Write($chunk, 0, $count)
                $sent += $count
                $Counter[$Index] += $count
            }
            if ($sent -ge $BytesPerRequest) {
                $stream.Close()
                $request.GetResponse().Close()
                $request = $null
            }
        }
        catch {
            $Counter["error$Index"] = $_.Exception.Message
            Start-Sleep -Milliseconds 250
        }
        finally {
            if ($request) { $request.Abort() }
        }
    }
}

# Returns the steady-state throughput in Kbps (ramp-up phase excluded)
function Measure-Throughput {
    param(
        [ValidateSet('Download', 'Upload')] [string]$Direction,
        [int]$DurationSeconds,
        [int]$Streams
    )
    $counter = [hashtable]::Synchronized(@{})
    for ($i = 0; $i -lt $Streams; $i++) { $counter[$i] = 0L }

    $pool = [RunspaceFactory]::CreateRunspacePool(1, $Streams)
    $pool.Open()
    $start = [DateTime]::UtcNow
    $deadlineTicks = $start.AddSeconds($WarmupSeconds + $DurationSeconds).Ticks
    $jobs = for ($i = 0; $i -lt $Streams; $i++) {
        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $pool
        if ($Direction -eq 'Download') {
            [void]$ps.AddScript($DownloadWorker).AddArgument($SpeedTestDownloadUrl).AddArgument($deadlineTicks).AddArgument($counter).AddArgument($i)
        }
        else {
            [void]$ps.AddScript($UploadWorker).AddArgument($SpeedTestUploadUrl).AddArgument($deadlineTicks).AddArgument($counter).AddArgument($i).AddArgument([long]$UploadBytesPerRequest)
        }
        @{ PowerShell = $ps; Handle = $ps.BeginInvoke() }
    }

    $warmupBytes = $null
    $warmupTime = $null
    while ([DateTime]::UtcNow.Ticks -lt $deadlineTicks) {
        Start-Sleep -Milliseconds 100
        if ($null -eq $warmupBytes -and ([DateTime]::UtcNow - $start).TotalSeconds -ge $WarmupSeconds) {
            $warmupTime = [DateTime]::UtcNow
            $warmupBytes = Get-CounterTotal $counter $Streams
        }
    }
    $endTime = [DateTime]::UtcNow
    $endBytes = Get-CounterTotal $counter $Streams

    foreach ($job in $jobs) {
        # Workers stop by themselves after the deadline; wait for in-flight reads/writes
        [void]$job.Handle.AsyncWaitHandle.WaitOne(20000)
        $job.PowerShell.Dispose()
    }
    $pool.Close()
    $pool.Dispose()

    $errors = @($counter.Keys | Where-Object { "$_" -like 'error*' } | ForEach-Object { $counter[$_] } | Select-Object -Unique)
    foreach ($message in $errors) { Write-Log "  $Direction stream error: $message" }

    $seconds = ($endTime - $warmupTime).TotalSeconds
    if ($seconds -le 0 -or $endBytes -le $warmupBytes) {
        throw "$Direction speed test transferred no data (speed.cloudflare.com blocked?)."
    }
    [Math]::Round((($endBytes - $warmupBytes) * 8 / 1000) / $seconds)
}

function Get-CounterTotal([hashtable]$Counter, [int]$Streams) {
    $total = 0L
    for ($i = 0; $i -lt $Streams; $i++) { $total += [long]$Counter[$i] }
    $total
}

function Format-Rate([double]$Kbps) {
    if ($Kbps -ge 1000) { return ('{0:N2} Mbps' -f ($Kbps / 1000)) }
    '{0:N0} Kbps' -f $Kbps
}

#endregion

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
    $percent = Get-IntParameter 'throttlePercent' $ThrottlePercent 0 1 100 -Required
    $minimum = Get-IntParameter 'minimumKbps' $MinimumKbps 256 1 10000000
    $applyDelay = Get-IntParameter 'applyDelaySeconds' $ApplyDelaySeconds 60 0 1800
    $duration = Get-IntParameter 'testDurationSeconds' $TestDurationSeconds 10 3 60
    $streams = Get-IntParameter 'parallelStreams' $ParallelStreams 4 1 16
    $base = if ([string]::IsNullOrWhiteSpace($MeasureBase)) { 'upload' } else { $MeasureBase.Trim().ToLowerInvariant() }
    if ($base -notin @('upload', 'download')) { throw "Script variable 'measureBase' must be 'upload' or 'download' (value: '$MeasureBase')." }

    if (-not $ClientId -or -not $ClientSecret) { throw "Script variables 'clientId' and 'clientSecret' are required." }
    $parsedDeviceId = 0
    if (-not [int]::TryParse("$DeviceId", [ref]$parsedDeviceId)) {
        throw "No device ID: NINJA_AGENT_NODE_ID is not set, pass the script variable 'deviceId'."
    }
    $script:ParsedDeviceId = $parsedDeviceId

    Write-Log "Device $parsedDeviceId, base: $base, backup may use $percent % of it"

    # Only the relevant direction is measured to keep the backup start delay short
    Write-Log "Measuring $base speed ($duration s, $streams streams)..."
    $measuredKbps = Measure-Throughput -Direction $base -DurationSeconds $duration -Streams $streams
    Write-Log "Measured $base speed: $(Format-Rate $measuredKbps)"

    $throttleKbps = [int][Math]::Max($minimum, [Math]::Floor($measuredKbps * $percent / 100))
    Write-Log "Throttle: $(Format-Rate $throttleKbps)"

    $token = Get-AccessToken

    # The throttle is for the job starting now: same value in and outside work hours, whole week,
    # so the time of day of the backup does not matter
    Set-BandwidthThrottle $token @{
        enabled              = $true
        workHoursKbps        = $throttleKbps
        nonWorkHoursKbps     = $throttleKbps
        workHoursUserUnit    = 'KBPS'
        nonWorkHoursUserUnit = 'KBPS'
        workSchedule         = @{ startHour = 0; startMinute = 0; endHour = 23; endMinute = 59; weekDays = $AllWeekDays }
    }
    Write-Log "Bandwidth throttle set to $(Format-Rate $throttleKbps)."

    if ($applyDelay -gt 0) {
        Write-Log "Waiting $applyDelay s so the agent applies the throttle before the backup starts..."
        Start-Sleep -Seconds $applyDelay
    }
    Write-Log 'Done, backup can start.'
    exit 0
}
catch {
    Write-Log "ERROR: $($_.Exception.Message)"
    # Whether this cancels the backup is set in the backup plan ("Cancel the backup job if the automation returns a failure code")
    exit 1
}
