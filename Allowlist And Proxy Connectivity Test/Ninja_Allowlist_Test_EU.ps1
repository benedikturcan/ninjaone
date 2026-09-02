<#
.SYNOPSIS
    NinjaOne allowlist and connectivity test - EU region (eu-central-1),
    including proxy detection and per-URL proxy pass-through checks.

.DESCRIPTION
    Tests every endpoint listed in the NinjaOne Dojo allowlist articles
    (Global + EU region) for reachability - either directly, through the
    configured proxy, or both paths side by side.

    What is checked:
      - Proxy configuration of the NinjaOne agent (registry) and of NinjaOne
        Remote (NC_PROXY), including format and consistency validation
      - System proxy (WinINET / WinHTTP / PAC / environment variables)
      - DNS resolution (relevant in Direct mode)
      - Static-routing validation for NinjaOne Remote: resolved IPs of the
        nc-*-eu-central-1 hosts are compared against the documented static
        IPs and the legacy IPs being deprecated since 2026-03-31
      - TCP connect to every resolved IP (Direct mode)
      - HTTP CONNECT tunnel or SOCKS5 CONNECT per target (Proxy mode),
        including TLS-secured connections to HTTPS proxies
        -> shows per URL whether the proxy permits or actively blocks it
      - TLS 1.2 handshake with certificate inspection, also through the
        tunnel -> detects SSL inspection by both firewall and proxy
      - UDP path for NinjaOne Remote (Direct mode only, best effort)

.PARAMETER Mode
    Auto    - detect a proxy automatically; if found use Proxy, else Direct
    Direct  - test direct connections only
    Proxy   - test through the proxy only
    Both    - test both paths and compare them
    Default: Auto

.PARAMETER ProxyHost
    Specify the proxy manually instead of auto-detecting it.

.PARAMETER ProxyPort
    Port of the manually specified proxy.

.PARAMETER ProxyType
    Http, Https or Socks5. Default: Http
    Https means the connection TO the proxy itself is TLS-encrypted before
    the CONNECT request is sent.

.PARAMETER ProxyUser / .PARAMETER ProxyPassword
    Optional proxy authentication credentials. When the proxy is auto-detected
    from the agent registry, these OVERRIDE the registry credentials - useful
    because NinjaOne masks the registry password after the first successful
    agent login, so the stored value cannot be reused for testing.

.PARAMETER Timeout
    Timeout per connection attempt in milliseconds. Default: 5000

.PARAMETER AllShards
    Test all 40 WebSocket rendezvous shards instead of a sample.

.PARAMETER IncludeBackup / .PARAMETER IncludeCloudRdp
    Include these optional product areas in the test.

.PARAMETER IncludeIPv6
    Include AAAA records. Default: IPv4 only.

.PARAMETER SkipUdp
    Skip the UDP checks.

.PARAMETER ExportCsv
    Path for a CSV export of all individual results.

.EXAMPLE
    .\Ninja_Allowlist_Test_EU_V3.3.ps1
    Detects the proxy automatically and tests the appropriate path.

.EXAMPLE
    .\Ninja_Allowlist_Test_EU_V3.3.ps1 -Mode Both
    Compares direct vs. proxy - shows which path works where.

.EXAMPLE
    .\Ninja_Allowlist_Test_EU_V3.3.ps1 -ProxyHost 192.168.32.144 -ProxyPort 3128 -Mode Proxy

.NOTES
    Version : 3.3 (EU)
    Based on: Ninja Remote Connection test V2.6 / Allowlist test V3.1-EU
    Sources : NinjaOne Global Allowlist Information  (as of 2026-08-17)
              NinjaOne Allowlist: EU Region          (as of 2026-08-17)
              NinjaOne Agent: Configuration for Use Over a Proxy Server

    Exit code: 0 = no critical failures, 1 = at least one critical failure

    Changes vs. V3.2:
      - Fix 4: Registry proxy validation. The value types prescribed by the
        Dojo proxy article are now checked (ProxyHost = REG_SZ / String Value,
        ProxyPort = REG_DWORD), a set ProxyHost without ProxyPort is flagged
        as a critical misconfiguration, and the password masking NinjaOne
        applies after the first successful agent login is detected. Masked
        registry credentials are no longer silently reused: -ProxyUser /
        -ProxyPassword now override registry credentials even when the proxy
        host itself was auto-detected, and 407 responses carry an explicit
        hint pointing at the masked registry password instead of being
        misread as an allowlist problem.

    Changes vs. V3.1:
      - Fix 1: -ProxyType Https is now actually supported. The connection to
        the proxy is TLS-wrapped before CONNECT / GET is sent. Previously the
        script always spoke plaintext to the proxy and misreported failures
        against HTTPS proxies as allowlist problems.
      - Fix 3: Port 443 on HTTP-only targets (agent-app.ninjarmm.com,
        lockhart-grpc.ninjarmm.com) is no longer critical. The Dojo lists
        these as http:// only; a blocked 443 there is not an allowlist
        violation. 443 is still probed informationally.
      - Fix 6: Static-routing validation for NinjaOne Remote (EU). Resolved
        IPs of nc-1..nc-8-eu-central-1.ninjarmm.net are compared against the
        documented static IPs and the legacy IPs deprecated since 2026-03-31.
        A hit on a legacy IP raises a WARN with remediation advice - this is
        the check that matters most for customers using IP-only allowlisting.

    Changes vs. V2.6:
      - Fixed exit code logic ($Failed was set in the success branch)
      - Sockets are always released (finally block)
      - Added UDP 40000 (required since 2026-04-23)
      - TLS 1.2 handshake with certificate inspection -> detects SSL inspection
      - Full EU allowlist instead of only the 8 NinjaOne Remote hosts
      - Region fixed to EU, no interactive prompt
      - Proxy awareness: detection, validation and per-URL pass-through test
#>

[CmdletBinding()]
param (
    [ValidateSet('Auto', 'Direct', 'Proxy', 'Both')]
    [string] $Mode = 'Auto',

    [string] $ProxyHost,
    [int]    $ProxyPort,
    [ValidateSet('Http', 'Https', 'Socks5')]
    [string] $ProxyType = 'Http',
    [string] $ProxyUser,
    [string] $ProxyPassword,

    [int]    $Timeout = 5000,
    [switch] $AllShards,
    [switch] $IncludeBackup,
    [switch] $IncludeCloudRdp,
    [switch] $IncludeIPv6,
    [switch] $SkipUdp,
    [string] $ExportCsv
)

$ErrorActionPreference = 'Continue'
$ScriptVersion = '3.3-EU'
$AllowlistAsOf = '2026-08-17 (Global) / 2026-08-17 (EU)'
$IsWindowsOS   = ($env:OS -eq 'Windows_NT')

$Results = New-Object System.Collections.Generic.List[object]

function Add-Result {
    param(
        [string] $Category, [string] $Target, [string] $Address = '',
        [string] $Check,
        [ValidateSet('OK','FAIL','WARN','INFO')] [string] $Status,
        [string] $Path = '', [string] $Detail = '', [bool] $Critical = $true
    )
    $Results.Add([pscustomobject]@{
        Category = $Category; Target = $Target; Address = $Address
        Path = $Path; Check = $Check; Status = $Status
        Critical = $Critical; Detail = $Detail
    })
}

function Write-Line {
    param([string]$Status, [string]$Text)
    $color = switch ($Status) { 'OK' {'Green'} 'FAIL' {'Red'} 'WARN' {'Yellow'} default {'Gray'} }
    Write-Host ('[{0,-4}]' -f $Status) -ForegroundColor $color -NoNewline
    Write-Host " $Text"
}

function Write-Section {
    param([string]$Title)
    Write-Host ''
    Write-Host "--- $Title " -ForegroundColor White -NoNewline
    Write-Host ('-' * [Math]::Max(3, 56 - $Title.Length)) -ForegroundColor DarkGray
}

# ============================================================================
#  1. Target definitions - EU region
# ============================================================================

$Targets = New-Object System.Collections.Generic.List[object]

function Add-Target {
    param(
        [string]$Category, [string]$Name, [int[]]$TcpPorts, [int[]]$UdpPorts = @(),
        [int[]]$OptionalPorts = @(),
        [bool]$Tls = $true, [bool]$Critical = $true, [bool]$IsIp = $false, [string]$Note = ''
    )
    $Targets.Add([pscustomobject]@{
        Category = $Category; Name = $Name; TcpPorts = $TcpPorts; UdpPorts = $UdpPorts
        OptionalPorts = $OptionalPorts
        Tls = $Tls; Critical = $Critical; IsIp = $IsIp; Note = $Note
    })
}

# --- NinjaOne Remote (EU) ---------------------------------------------------
# TCP 443 = primary, TCP 7075 = fallback, UDP 40000 = required since 2026-04-23
foreach ($i in 1..8) {
    Add-Target -Category 'NinjaOne Remote' -Name "nc-$i-eu-central-1.ninjarmm.net" `
               -TcpPorts @(443, 7075) -UdpPorts @(40000)
}

# --- NinjaOne Remote static routing (EU) -------------------------------------
# Since 2026-03-31 NinjaOne Remote uses static IP load balancing. The EU Dojo
# article documents three static IPs per host plus the legacy IPs that entered
# deprecation on the same date (phase-out 60-90 days, propagation 30-90 days).
# Customers using IP-only allowlisting MUST have the static IPs permitted.
$RemoteStaticIps = @{
    'nc-1-eu-central-1.ninjarmm.net' = @{
        Static = @('63.177.135.24', '3.74.146.97',   '3.126.243.22')
        Legacy = @('18.156.147.147','18.198.84.37',  '35.156.79.105')
    }
    'nc-2-eu-central-1.ninjarmm.net' = @{
        Static = @('3.122.26.95',   '3.122.199.93',  '18.184.65.234')
        Legacy = @('18.158.11.238', '18.198.45.244', '3.73.72.38')
    }
    'nc-3-eu-central-1.ninjarmm.net' = @{
        Static = @('18.195.143.167','63.176.30.176', '18.153.243.224')
        Legacy = @('3.68.172.62',   '3.73.208.253',  '35.156.79.231')
    }
    'nc-4-eu-central-1.ninjarmm.net' = @{
        Static = @('3.72.181.243',  '3.77.25.109',   '18.197.183.60')
        Legacy = @('18.153.120.247','3.78.179.167',  '52.57.84.4')
    }
    'nc-5-eu-central-1.ninjarmm.net' = @{
        Static = @('52.28.27.128',  '52.29.189.82',  '3.124.254.175')
        Legacy = @('18.153.189.152','3.121.69.16',   '35.157.215.110')
    }
    'nc-6-eu-central-1.ninjarmm.net' = @{
        Static = @('3.72.216.6',    '18.196.91.56',  '63.177.143.248')
        Legacy = @('18.159.152.166','3.125.101.225', '3.126.178.43')
    }
    'nc-7-eu-central-1.ninjarmm.net' = @{
        Static = @('3.121.133.144', '3.124.86.116',  '18.156.59.221')
        Legacy = @('18.157.97.253', '3.126.210.185', '35.157.51.109')
    }
    'nc-8-eu-central-1.ninjarmm.net' = @{
        Static = @('52.59.164.144', '18.193.131.111','3.123.150.76')
        Legacy = @('18.157.126.13', '18.197.171.226','3.73.140.232')
    }
}

# --- WebSocket rendezvous points (EU) ---------------------------------------
Add-Target -Category 'WebSocket Rendezvous' -Name 'connect-eu-central.ninjarmm.com' -TcpPorts @(443)
$shardList = if ($AllShards) { 0..39 } else { @(0, 1, 2, 19, 20, 38, 39) }
foreach ($s in $shardList) {
    Add-Target -Category 'WebSocket Rendezvous' -Name "connect-eu-central-s$s.ninjarmm.com" -TcpPorts @(443)
}

# --- Agent and patcher (EU) -------------------------------------------------
'agent-eu-central.ninjarmm.com','fts-prod-frankfurt.ninjarmm.com',
'prod-bastrop-euc.ninjarmm.com','rtc-eu-central-1.ninjarmm.com',
'agent-tun-euc-0.ninjarmm.com' | ForEach-Object {
    Add-Target -Category 'Agent & Patcher (EU)' -Name $_ -TcpPorts @(443)
}

# --- File Explorer rendezvous points (EU) -----------------------------------
Add-Target -Category 'File Explorer' -Name 'fts-prod-london.ninjarmm.com' -TcpPorts @(443)

# --- NinjaOne MDM (EU) ------------------------------------------------------
'mdm-eu.ninjarmm.com','scep-eu.ninjarmm.com' | ForEach-Object {
    Add-Target -Category 'MDM (EU)' -Name $_ -TcpPorts @(443) -Critical $false `
               -Note 'only relevant when using NinjaOne MDM'
}

# --- Global agent / patcher URLs --------------------------------------------
'resources.ninjarmm.com','patching.ninjarmm.com','ninjauploads.s3.amazonaws.com',
'ninja-attachments-eu.s3.eu-central-1.amazonaws.com' | ForEach-Object {
    Add-Target -Category 'Global Agent/Patcher' -Name $_ -TcpPorts @(443)
}
# Dojo lists this URL as http:// only -> port 80 is the documented requirement.
# 443 is probed informationally but is NOT critical (Fix 3).
Add-Target -Category 'Global Agent/Patcher' -Name 'agent-app.ninjarmm.com' `
           -TcpPorts @(80, 443) -OptionalPorts @(443) -Tls $false `
           -Note 'Dojo lists http:// (port 80); 443 informational only'

# --- IP gateways (EU) -------------------------------------------------------
'18.184.54.189','52.29.101.132','18.195.227.137' | ForEach-Object {
    Add-Target -Category 'IP Gateways (EU)' -Name $_ -TcpPorts @(443) -Tls $false -IsIp $true
}

# --- Optional areas ---------------------------------------------------------
if ($IncludeBackup) {
    'ninja-backup-eucentral1.s3.eu-central-1.amazonaws.com',
    'ninja-backup-eunorth1.s3.eu-north-1.amazonaws.com',
    'ninja-backup-euwest1.s3.eu-west-1.amazonaws.com',
    'ninja-backup-euwest2.s3.eu-west-2.amazonaws.com',
    'ninja-backup-euwest3.s3.eu-west-3.amazonaws.com' | ForEach-Object {
        Add-Target -Category 'Device Backup (EU)' -Name $_ -TcpPorts @(443)
    }
    # Dojo lists this URL as http:// only -> 443 informational (Fix 3).
    Add-Target -Category 'Device Backup (EU)' -Name 'lockhart-grpc.ninjarmm.com' `
               -TcpPorts @(80, 443) -OptionalPorts @(443) -Tls $false `
               -Note 'Dojo lists http:// (port 80); 443 informational only'
}
if ($IncludeCloudRdp) {
    'agent-tun-euw2-0.ninjarmm.com','tun-eu-central-0.ninjarmm.com','tun-uk-0.ninjarmm.com' |
    ForEach-Object { Add-Target -Category 'Cloud RDP (EU)' -Name $_ -TcpPorts @(443) -Critical $false }
}

# ============================================================================
#  2. Proxy detection
# ============================================================================

function ConvertFrom-NcProxy {
    <#
      Parses the NC_PROXY value. Format per the Dojo article:
          [http(s)://]host:port:user:password
      Without a protocol prefix the proxy is treated as SOCKS5.
      Trailing colons are mandatory even when no credentials are used.
    #>
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

    $rx = '^(?:(?<scheme>https?)://)?(?<host>[^:/\s]+):(?<port>\d+)(?::(?<user>[^:]*))?(?::(?<pass>.*))?$'
    $m = [regex]::Match($Value.Trim(), $rx)
    if (-not $m.Success) {
        return [pscustomobject]@{ Valid = $false; Raw = $Value; Error = 'value cannot be parsed' }
    }

    $scheme = $m.Groups['scheme'].Value
    $type   = if ($scheme) { (Get-Culture).TextInfo.ToTitleCase($scheme) } else { 'Socks5' }

    # Dojo examples: "192.168.1.1:8080:user:" and "192.168.1.1:8080:" are both
    # valid, "192.168.1.1:8080" (no trailing colon) is not.
    $colonCount = ($Value -replace 'https?://', '').Split(':').Count - 1
    $trailingOk = $colonCount -ge 2

    return [pscustomobject]@{
        Valid      = $true
        Raw        = $Value
        Type       = $type
        Host       = $m.Groups['host'].Value
        Port       = [int]$m.Groups['port'].Value
        User       = $m.Groups['user'].Value
        Password   = $m.Groups['pass'].Value
        TrailingOk = $trailingOk
        Error      = ''
    }
}

function Get-NinjaProxyConfig {
    <# Reads every location where NinjaOne or Windows stores proxy settings. #>

    $cfg = [ordered]@{
        AgentProxy        = $null   # registry NinjaRMMAgent\Server
        AgentAutoDiscover = $null   # ProxyAutoDiscovery DWORD
        NcProxy           = $null   # NC_PROXY (NinjaOne Remote)
        NcProxyRaw        = $null
        WinInet           = $null   # HKCU Internet Settings
        WinInetPac        = $null   # AutoConfigURL
        WinHttp           = $null   # netsh winhttp
        EnvProxy          = $null   # HTTPS_PROXY / HTTP_PROXY
    }

    # --- NC_PROXY (readable as an env var on non-Windows too) ---------------
    $ncRaw = [System.Environment]::GetEnvironmentVariable('NC_PROXY', 'Machine')
    if (-not $ncRaw) { $ncRaw = $env:NC_PROXY }
    $cfg.NcProxyRaw = $ncRaw
    $cfg.NcProxy    = ConvertFrom-NcProxy -Value $ncRaw

    # --- Environment variables ----------------------------------------------
    $envProxy = $env:HTTPS_PROXY
    if (-not $envProxy) { $envProxy = $env:HTTP_PROXY }
    $cfg.EnvProxy = $envProxy

    if (-not $IsWindowsOS) { return $cfg }

    # --- NinjaOne agent registry --------------------------------------------
    $agentPaths = @(
        'HKLM:\SOFTWARE\WOW6432Node\NinjaRMM LLC\NinjaRMMAgent\Server',
        'HKLM:\SOFTWARE\Wow6432Node\NinjaRMM LLC\NinjaRMMAgent\Server',
        'HKLM:\SOFTWARE\NinjaRMM LLC\NinjaRMMAgent\Server'
    )
    foreach ($p in $agentPaths) {
        $k = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue
        if (-not $k) { continue }
        if ($null -ne $k.ProxyAutoDiscovery) { $cfg.AgentAutoDiscover = [int]$k.ProxyAutoDiscovery }
        if ($k.ProxyHost) {
            # Fix 4: validate the value types the Dojo proxy article prescribes
            # (ProxyHost = String Value / REG_SZ, ProxyPort = DWORD / REG_DWORD)
            # and detect the password masking NinjaOne applies after the first
            # successful agent login.
            $hostKind = $null; $portKind = $null
            try {
                $rk = Get-Item -Path $p -ErrorAction Stop
                try { $hostKind = [string]$rk.GetValueKind('ProxyHost') } catch { }
                try { $portKind = [string]$rk.GetValueKind('ProxyPort') } catch { }
            } catch { }

            $regUser = [string]$k.ProxyAuthName
            $regPass = [string]$k.ProxyAuthPassword
            # Dojo: "NinjaOne automatically hides the proxy password after the
            # first successful login." Detectable as: user set, but password
            # empty or an obviously masked placeholder.
            $masked = $false
            if ($regUser) {
                if ([string]::IsNullOrEmpty($regPass)) { $masked = $true }
                elseif ($regPass -match '^\*+$')       { $masked = $true }
            }

            $cfg.AgentProxy = [pscustomobject]@{
                Type = 'Http'
                Host = [string]$k.ProxyHost
                Port = if ($null -ne $k.ProxyPort) { [int]$k.ProxyPort } else { 0 }
                User = $regUser
                Password = $regPass
                HostKind = $hostKind
                PortKind = $portKind
                PortMissing = ($null -eq $k.ProxyPort)
                PasswordMasked = $masked
                RegPath = $p
            }
            break
        }
    }

    # --- WinINET (HKCU Internet Settings) -----------------------------------
    $ie = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
    if ($ie) {
        if ($ie.ProxyEnable -eq 1 -and $ie.ProxyServer) { $cfg.WinInet = [string]$ie.ProxyServer }
        if ($ie.AutoConfigURL) { $cfg.WinInetPac = [string]$ie.AutoConfigURL }
    }

    # --- WinHTTP -------------------------------------------------------------
    try {
        $netsh = & netsh winhttp show proxy 2>$null
        $line = ($netsh | Select-String -Pattern 'Proxyserver|Proxy Server' | Select-Object -First 1)
        if ($line -and $line -notmatch 'Direkt|Direct') {
            $cfg.WinHttp = ($line.ToString() -split ':', 2)[1].Trim()
        }
    } catch { }

    return $cfg
}

function Resolve-EffectiveProxy {
    <#
      Determines the proxy .NET would actually use for an HTTPS URL.
      Honours WinINET, PAC/WPAD and the bypass list.
    #>
    param([string]$SampleUrl = 'https://agent-eu-central.ninjarmm.com')
    try {
        $sys = [System.Net.WebRequest]::GetSystemWebProxy()
        $u   = [uri]$SampleUrl
        $p   = $sys.GetProxy($u)
        if ($p -and $p.AbsoluteUri -ne $u.AbsoluteUri) {
            return [pscustomobject]@{ Type = 'Http'; Host = $p.Host; Port = $p.Port; User = ''; Password = '' }
        }
    } catch { }
    return $null
}

# ============================================================================
#  3. Transports - direct, HTTP(S) CONNECT, SOCKS5
# ============================================================================

$KnownPublicCAs = @(
    'Amazon','DigiCert','Let''s Encrypt','ISRG','Sectigo','Comodo','GlobalSign',
    'GoDaddy','Starfield','Entrust','Thawte','VeriSign','Google Trust Services',
    'GTS ','Baltimore','Microsoft','Apple','Cloudflare','USERTrust','AAA Certificate'
)

function New-TcpClientWithTimeout {
    param([string]$Address, [int]$Port, [int]$TimeoutMs)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($Address, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            try { $client.Close() } catch { }
            throw "timed out after ${TimeoutMs}ms (packet dropped)"
        }
        $client.EndConnect($async) | Out-Null   # throws on RST / reject
        if (-not $client.Connected) { throw 'connection not established' }
        return $client
    } catch {
        try { $client.Close(); $client.Dispose() } catch { }
        throw
    }
}

function Get-ProxyBaseStream {
    <#
      Fix 1: Returns the stream over which proxy requests (CONNECT / GET) are
      sent. For ProxyType Https the TCP stream is wrapped in TLS towards the
      proxy itself BEFORE any request is sent - a real HTTPS proxy expects
      this and would otherwise drop or reject the plaintext CONNECT, which
      V3.1 misreported as an allowlist problem.

      The proxy certificate is not validated strictly (internal proxies often
      use internal CAs); an unexpected issuer is reported via the normal SSL
      inspection heuristics on the target TLS handshake instead.
    #>
    param($Client, $Proxy, [int]$TimeoutMs)

    $stream = $Client.GetStream()
    $stream.ReadTimeout  = $TimeoutMs
    $stream.WriteTimeout = $TimeoutMs

    if ($Proxy.Type -ne 'Https') { return $stream }

    $ssl = New-Object System.Net.Security.SslStream($stream, $false,
        [System.Net.Security.RemoteCertificateValidationCallback] {
            param($sndr, $certificate, $chain, $sslPolicyErrors) return $true
        })
    try {
        $ssl.AuthenticateAsClient($Proxy.Host, $null,
            [System.Security.Authentication.SslProtocols]::Tls12, $false)
    } catch {
        try { $ssl.Dispose() } catch { }
        throw "TLS handshake with the HTTPS proxy failed: $($_.Exception.Message)"
    }
    $ssl.ReadTimeout  = $TimeoutMs
    $ssl.WriteTimeout = $TimeoutMs
    return $ssl
}

function Read-Exact {
    param($Stream, [int]$Count)
    $buf = New-Object byte[] $Count
    $off = 0
    while ($off -lt $Count) {
        try {
            $n = $Stream.Read($buf, $off, $Count - $off)
        } catch [System.IO.IOException] {
            throw 'timed out - no or incomplete response from proxy (target not answering, or proxy dropping silently)'
        }
        if ($n -le 0) { throw 'connection closed by proxy' }
        $off += $n
    }
    return $buf
}

function Read-HttpHead {
    param($Stream, [int]$TimeoutMs)
    $Stream.ReadTimeout = $TimeoutMs
    $sb  = New-Object System.Text.StringBuilder
    $buf = New-Object byte[] 1
    $deadline = [datetime]::UtcNow.AddMilliseconds($TimeoutMs)
    while ([datetime]::UtcNow -lt $deadline) {
        try {
            $n = $Stream.Read($buf, 0, 1)
        } catch [System.IO.IOException] {
            break   # read timeout -> evaluate whatever arrived so far
        }
        if ($n -le 0) { break }
        [void]$sb.Append([char]$buf[0])
        if ($sb.Length -ge 4 -and $sb.ToString($sb.Length - 4, 4) -eq "`r`n`r`n") { break }
        if ($sb.Length -gt 16384) { break }
    }
    return $sb.ToString()
}

function Open-HttpProxyTunnel {
    <#
      Establishes an HTTP CONNECT tunnel to host:port through the proxy.
      For ProxyType Https the CONNECT is sent over a TLS connection to the
      proxy (Fix 1).
    #>
    param(
        [string]$TargetHost, [int]$TargetPort,
        $Proxy, [int]$TimeoutMs
    )

    $client = New-TcpClientWithTimeout -Address $Proxy.Host -Port $Proxy.Port -TimeoutMs $TimeoutMs
    try {
        $stream = Get-ProxyBaseStream -Client $client -Proxy $Proxy -TimeoutMs $TimeoutMs

        $req = "CONNECT ${TargetHost}:${TargetPort} HTTP/1.1`r`n"
        $req += "Host: ${TargetHost}:${TargetPort}`r`n"
        $req += "User-Agent: NinjaOne-Allowlist-Test/$ScriptVersion`r`n"
        $req += "Proxy-Connection: keep-alive`r`n"
        if ($Proxy.User) {
            $token = [Convert]::ToBase64String(
                [Text.Encoding]::ASCII.GetBytes("$($Proxy.User):$($Proxy.Password)"))
            $req += "Proxy-Authorization: Basic $token`r`n"
        }
        $req += "`r`n"

        $bytes = [Text.Encoding]::ASCII.GetBytes($req)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()

        $head = Read-HttpHead -Stream $stream -TimeoutMs $TimeoutMs
        if (-not $head) { throw 'no response from proxy to CONNECT' }

        $statusLine = ($head -split "`r`n")[0]
        $code = 0
        if ($statusLine -match '^HTTP/\d\.\d\s+(\d{3})') { $code = [int]$Matches[1] }

        if ($code -eq 200) {
            return [pscustomobject]@{ Client = $client; Stream = $stream; Code = $code; StatusLine = $statusLine }
        }

        try { $client.Close() } catch { }
        throw "proxy replied: $statusLine"
    } catch {
        try { $client.Close(); $client.Dispose() } catch { }
        throw
    }
}

function Open-Socks5Tunnel {
    <# Establishes a SOCKS5 CONNECT (RFC 1928) to host:port through the proxy. #>
    param([string]$TargetHost, [int]$TargetPort, $Proxy, [int]$TimeoutMs)

    $client = New-TcpClientWithTimeout -Address $Proxy.Host -Port $Proxy.Port -TimeoutMs $TimeoutMs
    try {
        $stream = $client.GetStream()
        $stream.ReadTimeout  = $TimeoutMs
        $stream.WriteTimeout = $TimeoutMs

        # --- Greeting -------------------------------------------------------
        $methods = if ($Proxy.User) { @(0x00, 0x02) } else { @(0x00) }
        $greet = @(0x05, $methods.Count) + $methods
        $stream.Write([byte[]]$greet, 0, $greet.Count)

        $resp = Read-Exact -Stream $stream -Count 2
        if ($resp[0] -ne 0x05) { throw 'not a SOCKS5 server (unexpected protocol version)' }
        if ($resp[1] -eq 0xFF) { throw 'SOCKS5: no acceptable authentication method' }

        # --- Username/password (RFC 1929) -----------------------------------
        if ($resp[1] -eq 0x02) {
            if (-not $Proxy.User) { throw 'SOCKS5 requires authentication but no credentials are configured' }
            $u = [Text.Encoding]::ASCII.GetBytes($Proxy.User)
            $p = [Text.Encoding]::ASCII.GetBytes([string]$Proxy.Password)
            $auth = @(0x01, $u.Length) + $u + @($p.Length) + $p
            $stream.Write([byte[]]$auth, 0, $auth.Count)
            $ar = Read-Exact -Stream $stream -Count 2
            if ($ar[1] -ne 0x00) { throw 'SOCKS5: authentication rejected' }
        }

        # --- CONNECT --------------------------------------------------------
        $hostBytes = [Text.Encoding]::ASCII.GetBytes($TargetHost)
        $reqBytes  = @(0x05, 0x01, 0x00, 0x03, $hostBytes.Length) + $hostBytes +
                     @([byte](($TargetPort -shr 8) -band 0xFF), [byte]($TargetPort -band 0xFF))
        $stream.Write([byte[]]$reqBytes, 0, $reqBytes.Count)

        $rep = Read-Exact -Stream $stream -Count 4
        if ($rep[1] -ne 0x00) {
            $reason = switch ($rep[1]) {
                0x01 { 'general SOCKS server failure' }
                0x02 { 'not allowed by ruleset (target blocked)' }
                0x03 { 'network unreachable' }
                0x04 { 'host unreachable' }
                0x05 { 'connection refused' }
                0x06 { 'TTL expired' }
                0x07 { 'command not supported' }
                0x08 { 'address type not supported' }
                default { 'code 0x{0:X2}' -f $rep[1] }
            }
            throw "SOCKS5 CONNECT rejected: $reason"
        }
        # consume the bound address
        switch ($rep[3]) {
            0x01 { $null = Read-Exact -Stream $stream -Count 6 }
            0x04 { $null = Read-Exact -Stream $stream -Count 18 }
            0x03 { $l = Read-Exact -Stream $stream -Count 1
                   $null = Read-Exact -Stream $stream -Count ([int]$l[0] + 2) }
        }

        return [pscustomobject]@{ Client = $client; Stream = $stream; Code = 200; StatusLine = 'SOCKS5 CONNECT ok' }
    } catch {
        try { $client.Close(); $client.Dispose() } catch { }
        throw
    }
}

function Test-TlsOnStream {
    <# Runs TLS 1.2 over an existing stream and evaluates the certificate. #>
    param($Stream, [string]$TargetHost)

    $script:CapturedCert   = $null
    $script:CapturedErrors = $null
    $ssl = $null
    try {
        $cb = [System.Net.Security.RemoteCertificateValidationCallback] {
            param($sndr, $certificate, $chain, $sslPolicyErrors)
            $script:CapturedCert   = $certificate
            $script:CapturedErrors = $sslPolicyErrors
            return $true   # deliberately always true so the certificate can be inspected
        }
        $ssl = New-Object System.Net.Security.SslStream($Stream, $false, $cb)
        $ssl.AuthenticateAsClient($TargetHost, $null,
            [System.Security.Authentication.SslProtocols]::Tls12, $false)

        $issuer = if ($script:CapturedCert) { $script:CapturedCert.Issuer } else { '(unknown)' }
        $known = $false
        foreach ($ca in $KnownPublicCAs) { if ($issuer -like "*$ca*") { $known = $true; break } }

        if (-not $known) {
            return [pscustomobject]@{ Status = 'WARN'
                Detail = "TLS ok, BUT unexpected issuer -> SSL inspection likely. Issuer: $issuer" }
        }
        if ($script:CapturedErrors -ne [System.Net.Security.SslPolicyErrors]::None) {
            return [pscustomobject]@{ Status = 'WARN'
                Detail = "TLS ok, but certificate warning: $($script:CapturedErrors). Issuer: $issuer" }
        }
        return [pscustomobject]@{ Status = 'OK'; Detail = "TLS 1.2, issuer: $issuer" }
    } catch {
        return [pscustomobject]@{ Status = 'FAIL'; Detail = "TLS handshake failed: $($_.Exception.Message)" }
    } finally {
        if ($ssl) { try { $ssl.Dispose() } catch { } }
    }
}

function Test-ProxyHttpGet {
    <#
      For plain HTTP targets (port 80). Shows whether the proxy permits the URL
      or blocks it with 403/407.

      HTTP proxy  : absolute-URI GET ("GET http://host/ HTTP/1.1").
      HTTPS proxy : same absolute-URI GET, but sent over TLS to the proxy
                    (Fix 1).
      SOCKS5      : SOCKS5 CONNECT to port 80 first, then an origin-form GET
                    through the tunnel - a SOCKS5 proxy does not understand the
                    absolute-URI form.
    #>
    param([string]$TargetHost, $Proxy, [int]$TimeoutMs)

    $client = $null
    $stream = $null
    try {
        if ($Proxy.Type -eq 'Socks5') {
            $tunnel = Open-Socks5Tunnel -TargetHost $TargetHost -TargetPort 80 -Proxy $Proxy -TimeoutMs $TimeoutMs
            $client = $tunnel.Client
            $stream = $tunnel.Stream
        } else {
            $client = New-TcpClientWithTimeout -Address $Proxy.Host -Port $Proxy.Port -TimeoutMs $TimeoutMs
            $stream = Get-ProxyBaseStream -Client $client -Proxy $Proxy -TimeoutMs $TimeoutMs
        }
    } catch {
        try { if ($client) { $client.Close(); $client.Dispose() } } catch { }
        return [pscustomobject]@{ Status = 'FAIL'; Detail = "proxy did not establish the connection: $($_.Exception.Message)" }
    }
    try {
        if ($Proxy.Type -eq 'Socks5') {
            $req = "GET / HTTP/1.1`r`nHost: $TargetHost`r`n"
        } else {
            $req = "GET http://$TargetHost/ HTTP/1.1`r`nHost: $TargetHost`r`n"
        }
        $req += "User-Agent: NinjaOne-Allowlist-Test/$ScriptVersion`r`nConnection: close`r`n"
        if ($Proxy.User -and $Proxy.Type -ne 'Socks5') {
            $token = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($Proxy.User):$($Proxy.Password)"))
            $req += "Proxy-Authorization: Basic $token`r`n"
        }
        $req += "`r`n"
        $b = [Text.Encoding]::ASCII.GetBytes($req)
        $stream.Write($b, 0, $b.Length); $stream.Flush()

        $head = Read-HttpHead -Stream $stream -TimeoutMs $TimeoutMs
        $statusLine = ($head -split "`r`n")[0]
        $code = 0
        if ($statusLine -match '^HTTP/\d\.\d\s+(\d{3})') { $code = [int]$Matches[1] }

        # Any well-formed HTTP response proves the path is open. The origin's own
        # status code is not the subject of this test - only 407 is unambiguously
        # the proxy's, and 403 is ambiguous (proxy policy or origin refusing GET /).
        switch ($code) {
            407     { return [pscustomobject]@{ Status = 'FAIL'; Detail = 'proxy requires authentication (407)' } }
            0       { return [pscustomobject]@{ Status = 'FAIL'; Detail = 'no valid HTTP response - path appears blocked' } }
            403     { return [pscustomobject]@{ Status = 'WARN'
                        Detail = '403 Forbidden - either the proxy blocks this URL or the origin refuses GET /. Check the proxy log to tell them apart.' } }
            default {
                if ($code -ge 500) { return [pscustomobject]@{ Status = 'WARN'; Detail = "proxy/upstream error: $statusLine" } }
                return [pscustomobject]@{ Status = 'OK'; Detail = "path is open ($statusLine)" }
            }
        }
    } catch {
        return [pscustomobject]@{ Status = 'FAIL'; Detail = $_.Exception.Message }
    } finally {
        try { $client.Close(); $client.Dispose() } catch { }
    }
}

function Test-UdpPath {
    <#
      UDP is connectionless - without a responder an "open" state cannot be
      proven. Only an active reject (ICMP unreachable) is detectable, so the
      result is INFO or WARN, never OK.
    #>
    param([string]$Address, [int]$Port)
    $udp = New-Object System.Net.Sockets.UdpClient
    try {
        $udp.Client.ReceiveTimeout = 1500
        $udp.Connect($Address, $Port)
        $payload = [Text.Encoding]::ASCII.GetBytes('ninja-allowlist-probe')
        $udp.Send($payload, $payload.Length) | Out-Null
        $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        try {
            $udp.Receive([ref]$remote) | Out-Null
            return [pscustomobject]@{ Status = 'INFO'; Detail = 'response received - path is open' }
        } catch [System.Net.Sockets.SocketException] {
            switch ($_.Exception.SocketErrorCode) {
                'TimedOut'        { return [pscustomobject]@{ Status = 'INFO'; Detail = 'no response (expected) - not verifiable, check the firewall rule manually' } }
                'ConnectionReset' { return [pscustomobject]@{ Status = 'INFO'; Detail = 'ICMP unreachable - normal for NinjaOne endpoints' } }
                default           { return [pscustomobject]@{ Status = 'WARN'; Detail = "UDP error: $($_.Exception.SocketErrorCode)" } }
            }
        }
    } catch {
        return [pscustomobject]@{ Status = 'WARN'; Detail = "UDP send error: $($_.Exception.Message)" }
    } finally {
        try { $udp.Close(); $udp.Dispose() } catch { }
    }
}

function Resolve-NinjaHost {
    param([string]$Name)
    $ips = @()
    if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) {
        try {
            $types = if ($IncludeIPv6) { @('A','AAAA') } else { @('A') }
            foreach ($t in $types) {
                $r = Resolve-DnsName -Name $Name -Type $t -ErrorAction Stop
                $ips += ($r | Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress)
            }
        } catch { }
    }
    if (-not $ips -or $ips.Count -eq 0) {
        $entry = [System.Net.Dns]::GetHostEntry($Name)
        $ips = $entry.AddressList | ForEach-Object {
            if ($IncludeIPv6 -or $_.AddressFamily -eq 'InterNetwork') { $_.IPAddressToString }
        }
    }
    return ($ips | Where-Object { $_ } | Select-Object -Unique)
}

function Test-RemoteStaticIp {
    <#
      Fix 6: Validates resolved IPs of the NinjaOne Remote hosts against the
      static IPs documented in the EU allowlist article and against the legacy
      IPs whose deprecation started on 2026-03-31 (phase-out 60-90 days).

      This is the decisive check for environments using IP-only allowlisting:
      - Static IP  -> OK   (this IP must be in the firewall allowlist)
      - Legacy IP  -> WARN (still resolving to a range being retired; the
                            static IPs must be permitted NOW or Remote breaks
                            once the legacy range is switched off)
      - Unknown IP -> WARN (neither list matches; the Dojo article may have
                            been updated - re-check the EU allowlist)
      Only IPv4 is compared; the article documents IPv4 addresses only.
    #>
    param([string]$HostName, [string[]]$ResolvedIps)

    if (-not $RemoteStaticIps.ContainsKey($HostName)) { return }
    $known = $RemoteStaticIps[$HostName]

    foreach ($ip in ($ResolvedIps | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' })) {
        if ($known.Static -contains $ip) {
            Write-Line 'OK' "$HostName [$ip] is a documented static IP (post-2026-03-31 range)"
            Add-Result -Category 'NinjaOne Remote' -Target $HostName -Address $ip -Path 'Direct' `
                       -Check 'Static IP' -Status 'OK' -Critical $false `
                       -Detail 'resolved IP matches the documented static range - ensure it is permitted when allowlisting by IP'
        } elseif ($known.Legacy -contains $ip) {
            Write-Line 'WARN' "$HostName [$ip] resolves to a LEGACY IP (deprecation started 2026-03-31). If you allowlist by IP, add the static IPs now: $($known.Static -join ', ')"
            Add-Result -Category 'NinjaOne Remote' -Target $HostName -Address $ip -Path 'Direct' `
                       -Check 'Static IP' -Status 'WARN' -Critical $false `
                       -Detail "legacy IP - being phased out; required static IPs: $($known.Static -join ', ')"
        } else {
            Write-Line 'WARN' "$HostName [$ip] is neither in the documented static nor in the legacy IP list - the EU allowlist article may have changed, re-check it"
            Add-Result -Category 'NinjaOne Remote' -Target $HostName -Address $ip -Path 'Direct' `
                       -Check 'Static IP' -Status 'WARN' -Critical $false `
                       -Detail 'IP unknown to allowlist data as of 2026-08-17 - verify against the current Dojo article'
        }
    }
}

# ============================================================================
#  4. Header and proxy analysis
# ============================================================================

Write-Host ''
Write-Host '===============================================================' -ForegroundColor Cyan
Write-Host ' NinjaOne Allowlist Test  -  EU region (eu-central-1)'          -ForegroundColor Cyan
Write-Host " Script version : $ScriptVersion"                               -ForegroundColor Cyan
Write-Host " Allowlist as of: $AllowlistAsOf"                               -ForegroundColor Cyan
Write-Host " Host           : $env:COMPUTERNAME   $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor Cyan
Write-Host '===============================================================' -ForegroundColor Cyan

$cfg = Get-NinjaProxyConfig

Write-Section 'Proxy configuration'

# --- Agent proxy ------------------------------------------------------------
if ($cfg.AgentProxy) {
    $ap = $cfg.AgentProxy
    Write-Line 'INFO' "NinjaOne agent (registry): $($ap.Host):$($ap.Port)$(if ($ap.User) { " (user: $($ap.User))" })"
    Add-Result -Category 'Proxy configuration' -Target 'Agent registry' -Check 'Configuration' `
               -Status 'INFO' -Detail "$($ap.Host):$($ap.Port) from $($ap.RegPath)"

    # --- Fix 4: registry validation per the Dojo proxy article ---------------
    if ($ap.HostKind -and $ap.HostKind -ne 'String') {
        Write-Line 'WARN' "Registry: ProxyHost has value type $($ap.HostKind) - the Dojo article requires a String Value (REG_SZ)."
        Add-Result -Category 'Proxy configuration' -Target 'Agent registry' -Check 'ProxyHost type' -Status 'WARN' `
                   -Detail "value kind $($ap.HostKind) instead of REG_SZ - agent may not read the proxy correctly" -Critical $false
    }
    if ($ap.PortMissing) {
        Write-Line 'FAIL' 'Registry: ProxyHost is set but ProxyPort is missing - the agent cannot use this proxy. Add ProxyPort as DWORD (32-bit) per the Dojo article.'
        Add-Result -Category 'Proxy configuration' -Target 'Agent registry' -Check 'ProxyPort present' -Status 'FAIL' `
                   -Detail 'ProxyHost without ProxyPort - incomplete proxy configuration'
    } elseif ($ap.PortKind -and $ap.PortKind -ne 'DWord') {
        Write-Line 'WARN' "Registry: ProxyPort has value type $($ap.PortKind) - the Dojo article requires a DWORD (32-bit)."
        Add-Result -Category 'Proxy configuration' -Target 'Agent registry' -Check 'ProxyPort type' -Status 'WARN' `
                   -Detail "value kind $($ap.PortKind) instead of REG_DWORD - agent may not read the proxy correctly" -Critical $false
    }
    if ($ap.PasswordMasked) {
        Write-Line 'WARN' 'Registry: ProxyAuthName is set but the password looks masked. Per the Dojo article, NinjaOne hides the proxy password after the first successful login - the registry value cannot be reused for testing. Pass -ProxyUser/-ProxyPassword for authenticated proxy tests.'
        Add-Result -Category 'Proxy configuration' -Target 'Agent registry' -Check 'ProxyAuthPassword' -Status 'WARN' `
                   -Detail 'password masked by NinjaOne after first successful login - supply -ProxyUser/-ProxyPassword for tests' -Critical $false
    }
} else {
    Write-Line 'INFO' 'NinjaOne agent (registry): no proxy configured'
    Add-Result -Category 'Proxy configuration' -Target 'Agent registry' -Check 'Configuration' `
               -Status 'INFO' -Detail 'no ProxyHost value set'
}

if ($null -ne $cfg.AgentAutoDiscover) {
    $s = if ($cfg.AgentAutoDiscover -eq 1) { 'enabled' } else { 'disabled (0)' }
    Write-Line 'INFO' "Agent proxy auto-discovery: $s"
    Add-Result -Category 'Proxy configuration' -Target 'ProxyAutoDiscovery' -Check 'Configuration' `
               -Status 'INFO' -Detail $s
}

# --- NC_PROXY ---------------------------------------------------------------
if ($cfg.NcProxyRaw) {
    if (-not $cfg.NcProxy.Valid) {
        Write-Line 'FAIL' "NC_PROXY is set but invalid: '$($cfg.NcProxyRaw)'"
        Add-Result -Category 'Proxy configuration' -Target 'NC_PROXY' -Check 'Format' -Status 'FAIL' `
                   -Detail "value '$($cfg.NcProxyRaw)' does not match host:port:user:password"
    } else {
        $nc = $cfg.NcProxy
        Write-Line 'INFO' "NinjaOne Remote (NC_PROXY): $($nc.Type) $($nc.Host):$($nc.Port)"
        Add-Result -Category 'Proxy configuration' -Target 'NC_PROXY' -Check 'Configuration' `
                   -Status 'INFO' -Detail "$($nc.Type) $($nc.Host):$($nc.Port)"
        if (-not $nc.TrailingOk) {
            Write-Line 'WARN' "NC_PROXY: trailing colons are missing. The Dojo article requires them even without credentials (e.g. '$($nc.Host):$($nc.Port)::')"
            Add-Result -Category 'Proxy configuration' -Target 'NC_PROXY' -Check 'Format' -Status 'WARN' `
                       -Detail 'trailing colons missing'
        }
        if ($nc.Type -eq 'Socks5') {
            Write-Line 'INFO' 'NC_PROXY has no protocol prefix -> interpreted as SOCKS5. Prefix with http:// or https:// for an HTTP(S) proxy.'
        }
        if ($nc.Type -eq 'Http') {
            Write-Line 'WARN' 'NC_PROXY uses HTTP. The Dojo article explicitly recommends HTTPS.'
            Add-Result -Category 'Proxy configuration' -Target 'NC_PROXY' -Check 'Protocol' -Status 'WARN' `
                       -Detail 'HTTP instead of HTTPS - Dojo recommends HTTPS' -Critical $false
        }
    }
} else {
    Write-Line 'INFO' 'NinjaOne Remote (NC_PROXY): not set'
}

# --- System proxy -----------------------------------------------------------
if ($cfg.WinInet)    { Write-Line 'INFO' "Windows/WinINET proxy: $($cfg.WinInet)" }
if ($cfg.WinInetPac) { Write-Line 'INFO' "PAC file (AutoConfigURL): $($cfg.WinInetPac)" }
if ($cfg.WinHttp)    { Write-Line 'INFO' "WinHTTP proxy: $($cfg.WinHttp)" }
if ($cfg.EnvProxy)   { Write-Line 'INFO' "Environment variable HTTP(S)_PROXY: $($cfg.EnvProxy)" }

$effective = Resolve-EffectiveProxy
if ($effective) {
    Write-Line 'INFO' "Effective system proxy for ninjarmm.com: $($effective.Host):$($effective.Port)"
}

# --- Consistency checks -----------------------------------------------------
if ($cfg.AgentProxy -and -not $cfg.NcProxyRaw) {
    Write-Line 'WARN' 'The agent uses a proxy but NC_PROXY is not set -> NinjaOne Remote will not use the proxy.'
    Add-Result -Category 'Proxy configuration' -Target 'Consistency' -Check 'Agent vs. NC_PROXY' -Status 'WARN' `
               -Detail 'agent proxy configured, NC_PROXY missing - Remote sessions will not go through the proxy'
}
if ($cfg.AgentProxy -and $cfg.NcProxy -and $cfg.NcProxy.Valid -and
    $cfg.NcProxy.Host -ne $cfg.AgentProxy.Host) {
    Write-Line 'WARN' "Agent proxy ($($cfg.AgentProxy.Host)) and NC_PROXY ($($cfg.NcProxy.Host)) point to different servers."
    Add-Result -Category 'Proxy configuration' -Target 'Consistency' -Check 'Agent vs. NC_PROXY' -Status 'WARN' `
               -Detail 'different proxy hosts configured'
}
if (-not $cfg.AgentProxy -and $cfg.AgentAutoDiscover -ne 1 -and ($cfg.WinInet -or $cfg.WinInetPac)) {
    Write-Line 'WARN' 'Windows uses a proxy but the agent has neither a proxy entry nor ProxyAutoDiscovery=1.'
    Add-Result -Category 'Proxy configuration' -Target 'Consistency' -Check 'System vs. Agent' -Status 'WARN' `
               -Detail 'set ProxyAutoDiscovery=1 or configure ProxyHost/ProxyPort'
}

# ============================================================================
#  5. Determine the test mode
# ============================================================================

# Proxy selection order: parameter > agent registry > NC_PROXY > system proxy
$testProxy = $null
if ($ProxyHost) {
    $testProxy = [pscustomobject]@{ Type = $ProxyType; Host = $ProxyHost; Port = $ProxyPort
                                    User = $ProxyUser; Password = $ProxyPassword
                                    PasswordMasked = $false; Source = 'parameter' }
} elseif ($cfg.AgentProxy) {
    # Fix 4: -ProxyUser/-ProxyPassword override the registry credentials,
    # because NinjaOne masks the stored password after the first login.
    $useUser = if ($ProxyUser) { $ProxyUser } else { $cfg.AgentProxy.User }
    $usePass = if ($ProxyUser) { $ProxyPassword } else { $cfg.AgentProxy.Password }
    $useMask = if ($ProxyUser) { $false } else { [bool]$cfg.AgentProxy.PasswordMasked }
    $testProxy = [pscustomobject]@{ Type = 'Http'; Host = $cfg.AgentProxy.Host; Port = $cfg.AgentProxy.Port
                                    User = $useUser; Password = $usePass
                                    PasswordMasked = $useMask
                                    Source = 'NinjaOne agent registry' }
} elseif ($cfg.NcProxy -and $cfg.NcProxy.Valid) {
    $testProxy = [pscustomobject]@{ Type = $cfg.NcProxy.Type; Host = $cfg.NcProxy.Host; Port = $cfg.NcProxy.Port
                                    User = $cfg.NcProxy.User; Password = $cfg.NcProxy.Password
                                    PasswordMasked = $false; Source = 'NC_PROXY' }
} elseif ($effective) {
    $testProxy = [pscustomobject]@{ Type = 'Http'; Host = $effective.Host; Port = $effective.Port
                                    User = ''; Password = ''
                                    PasswordMasked = $false; Source = 'system proxy' }
}

$paths = @()
switch ($Mode) {
    'Direct' { $paths = @('Direct') }
    'Proxy'  { $paths = @('Proxy')  }
    'Both'   { $paths = @('Direct', 'Proxy') }
    'Auto'   { $paths = if ($testProxy) { @('Proxy') } else { @('Direct') } }
}

if ($paths -contains 'Proxy') {
    if (-not $testProxy) {
        Write-Line 'FAIL' 'Proxy mode requested but no proxy was detected or specified. Use -ProxyHost / -ProxyPort.'
        $paths = @($paths | Where-Object { $_ -ne 'Proxy' })
    } elseif (-not $testProxy.Port -or $testProxy.Port -le 0) {
        Write-Line 'FAIL' "Proxy $($testProxy.Host) has no valid port. Skipping the proxy test."
        $paths = @($paths | Where-Object { $_ -ne 'Proxy' })
    }
}
if ($paths.Count -eq 0) { $paths = @('Direct') }

Write-Host ''
Write-Line 'INFO' "Test mode: $($paths -join ' + ')"
$maskedCredHint = ''
if ($paths -contains 'Proxy') {
    Write-Line 'INFO' "Proxy in use: $($testProxy.Type) $($testProxy.Host):$($testProxy.Port)  (source: $($testProxy.Source))"

    # Fix 4: warn up front when testing with masked registry credentials
    if ($testProxy.PasswordMasked) {
        $maskedCredHint = ' NOTE: the registry password is masked by NinjaOne after the first successful agent login - pass -ProxyUser/-ProxyPassword for authenticated tests.'
        Write-Line 'WARN' "Proxy credentials come from the agent registry, but the stored password looks masked. If the proxy enforces authentication, expect 407 responses - these are NOT allowlist problems.$maskedCredHint"
        Add-Result -Category 'Proxy configuration' -Target "$($testProxy.Host):$($testProxy.Port)" `
                   -Check 'Credentials' -Status 'WARN' -Critical $false `
                   -Detail 'masked registry password in use - 407 results are credential-related, not allowlist-related'
    }

    # Reachability of the proxy itself (TCP; for Https additionally TLS)
    try {
        $c = New-TcpClientWithTimeout -Address $testProxy.Host -Port $testProxy.Port -TimeoutMs $Timeout
        try {
            if ($testProxy.Type -eq 'Https') {
                $null = Get-ProxyBaseStream -Client $c -Proxy $testProxy -TimeoutMs $Timeout
                Write-Line 'OK' "Proxy $($testProxy.Host):$($testProxy.Port) is reachable (TLS handshake to proxy ok)"
            } else {
                Write-Line 'OK' "Proxy $($testProxy.Host):$($testProxy.Port) is reachable"
            }
        } finally {
            try { $c.Close(); $c.Dispose() } catch { }
        }
        Add-Result -Category 'Proxy configuration' -Target "$($testProxy.Host):$($testProxy.Port)" `
                   -Check 'Proxy reachable' -Status 'OK'
    } catch {
        Write-Line 'FAIL' "Proxy $($testProxy.Host):$($testProxy.Port) is unreachable: $($_.Exception.Message)"
        Add-Result -Category 'Proxy configuration' -Target "$($testProxy.Host):$($testProxy.Port)" `
                   -Check 'Proxy reachable' -Status 'FAIL' -Detail $_.Exception.Message
        Write-Host ''
        Write-Host ' Aborting: proxy tests are meaningless without a reachable proxy.' -ForegroundColor Red
        if ($paths -notcontains 'Direct') { exit 1 }
        $paths = @('Direct')
    }
}

# ============================================================================
#  6. Tests
# ============================================================================

$i = 0
$total = $Targets.Count * $paths.Count
$lastKey = ''

foreach ($path in $paths) {
    Write-Host ''
    Write-Host "===============  Path: $path  ===============" -ForegroundColor Magenta

    foreach ($t in $Targets) {
        $i++
        Write-Progress -Activity "NinjaOne allowlist test (EU) - $path" `
                       -Status "$($t.Category) - $($t.Name)" `
                       -PercentComplete ([int](($i / $total) * 100))

        $key = "$path|$($t.Category)"
        if ($key -ne $lastKey) { Write-Section $t.Category; $lastKey = $key }

        # ------------------------------------------------------------------
        #  DIRECT
        # ------------------------------------------------------------------
        if ($path -eq 'Direct') {

            $ips = @()
            if ($t.IsIp) {
                $ips = @($t.Name)
            } else {
                try {
                    $ips = @(Resolve-NinjaHost -Name $t.Name)
                    if ($ips.Count -eq 0) { throw 'no A records returned' }
                    Add-Result -Category $t.Category -Target $t.Name -Check 'DNS' -Status 'OK' `
                               -Path $path -Detail ($ips -join ', ') -Critical $t.Critical
                } catch {
                    Write-Line 'FAIL' "$($t.Name) - DNS resolution failed: $($_.Exception.Message)"
                    Add-Result -Category $t.Category -Target $t.Name -Check 'DNS' -Status 'FAIL' `
                               -Path $path -Detail $_.Exception.Message -Critical $t.Critical
                    continue
                }
            }

            # Fix 6: static-routing validation for the NinjaOne Remote hosts
            if (-not $t.IsIp) { Test-RemoteStaticIp -HostName $t.Name -ResolvedIps $ips }

            foreach ($ip in $ips) {
                foreach ($port in $t.TcpPorts) {
                    # Port 7075 is only a fallback for 443 per the Dojo article,
                    # and ports marked optional (Fix 3: 443 on http://-only
                    # targets) are informational -> neither is critical.
                    $portCritical = $t.Critical -and ($port -ne 7075) -and
                                    ($t.OptionalPorts -notcontains $port)
                    $open = $false
                    try {
                        $c = New-TcpClientWithTimeout -Address $ip -Port $port -TimeoutMs $Timeout
                        $c.Close(); $open = $true
                    } catch { $open = $false }

                    if ($open) {
                        Write-Line 'OK' "$($t.Name) [$ip] TCP/$port open"
                        Add-Result -Category $t.Category -Target $t.Name -Address $ip -Path $path `
                                   -Check "TCP/$port" -Status 'OK' -Critical $portCritical
                    } else {
                        $status = if ($portCritical) { 'FAIL' } else { 'WARN' }
                        $hint = if ($port -eq 7075) { ' (fallback port, not critical)' }
                                elseif ($t.OptionalPorts -contains $port) { ' (informational - Dojo documents this target as http:// only)' }
                                else { '' }
                        Write-Line $status "$($t.Name) [$ip] TCP/$port blocked or unreachable$hint"
                        Add-Result -Category $t.Category -Target $t.Name -Address $ip -Path $path `
                                   -Check "TCP/$port" -Status $status -Critical $portCritical `
                                   -Detail "no connection within ${Timeout}ms$hint"
                    }
                }
            }

            if ($t.Tls -and -not $t.IsIp -and ($t.TcpPorts -contains 443)) {
                try {
                    $c = New-TcpClientWithTimeout -Address $t.Name -Port 443 -TimeoutMs $Timeout
                    $tls = Test-TlsOnStream -Stream $c.GetStream() -TargetHost $t.Name
                    $c.Close()
                } catch {
                    $tls = [pscustomobject]@{ Status = 'FAIL'; Detail = $_.Exception.Message }
                }
                Write-Line $tls.Status "$($t.Name) TLS - $($tls.Detail)"
                Add-Result -Category $t.Category -Target $t.Name -Check 'TLS/443' -Path $path `
                           -Status $tls.Status -Detail $tls.Detail -Critical $t.Critical
            }

            if (-not $SkipUdp -and $t.UdpPorts.Count -gt 0 -and $ips.Count -gt 0) {
                foreach ($uport in $t.UdpPorts) {
                    $u = Test-UdpPath -Address $ips[0] -Port $uport
                    Write-Line $u.Status "$($t.Name) [$($ips[0])] UDP/$uport - $($u.Detail)"
                    Add-Result -Category $t.Category -Target $t.Name -Address $ips[0] -Path $path `
                               -Check "UDP/$uport" -Status $u.Status -Detail $u.Detail -Critical $false
                }
            }
            continue
        }

        # ------------------------------------------------------------------
        #  PROXY
        # ------------------------------------------------------------------

        # IP gateways are infrastructure, not HTTP targets -> n/a in proxy mode
        if ($t.IsIp) {
            Write-Line 'INFO' "$($t.Name) - IP gateway, not testable through a proxy (use -Mode Both to test it directly)"
            Add-Result -Category $t.Category -Target $t.Name -Check 'n/a' -Status 'INFO' -Path $path `
                       -Detail 'an IP gateway cannot be addressed through an HTTP proxy' -Critical $false
            continue
        }

        foreach ($port in $t.TcpPorts) {

            # Port 80 -> plain GET through the proxy instead of CONNECT
            if ($port -eq 80) {
                $r = Test-ProxyHttpGet -TargetHost $t.Name -Proxy $testProxy -TimeoutMs $Timeout
                if ($maskedCredHint -and $r.Detail -match '\b407\b') { $r.Detail += $maskedCredHint }
                Write-Line $r.Status "$($t.Name) HTTP/80 via proxy - $($r.Detail)"
                Add-Result -Category $t.Category -Target $t.Name -Check 'HTTP/80 via proxy' -Path $path `
                           -Status $r.Status -Detail $r.Detail -Critical $t.Critical
                continue
            }

            $portCritical = $t.Critical -and ($port -ne 7075) -and
                            ($t.OptionalPorts -notcontains $port)
            $tunnel = $null
            try {
                if ($testProxy.Type -eq 'Socks5') {
                    $tunnel = Open-Socks5Tunnel -TargetHost $t.Name -TargetPort $port -Proxy $testProxy -TimeoutMs $Timeout
                } else {
                    $tunnel = Open-HttpProxyTunnel -TargetHost $t.Name -TargetPort $port -Proxy $testProxy -TimeoutMs $Timeout
                }
            } catch {
                $msg = $_.Exception.Message
                $status = if ($portCritical) { 'FAIL' } else { 'WARN' }
                $hint = ''
                if ($port -eq 7075) {
                    # A failure on 7075 is expected here, not an allowlist problem
                    $hint = if ($testProxy.Type -eq 'Socks5') {
                        ' | 7075 is only used when 443 fails, and the endpoint answers on it on demand. Make sure the firewall permits 7075 outbound.'
                    } else {
                        ' | HTTP proxies usually permit CONNECT on 443 only. Use SOCKS5 for the Remote fallback, or open 7075 directly on the firewall.'
                    }
                } elseif ($t.OptionalPorts -contains $port) {
                    $hint = ' | informational - Dojo documents this target as http:// only'
                } else {
                    if ($msg -match '\b407\b') {
                        $hint += ' | The proxy requires authentication - supply credentials.'
                        if ($maskedCredHint) { $hint += $maskedCredHint }
                    }
                    if ($msg -match '\b403\b') { $hint += ' | The proxy actively blocks this URL - add it to the proxy allowlist.' }
                    if ($msg -match '\b502\b|\b504\b') { $hint += ' | The proxy itself cannot reach the target - check the upstream firewall.' }
                }

                Write-Line $status "$($t.Name):$port via proxy - $msg$hint"
                Add-Result -Category $t.Category -Target $t.Name -Check "CONNECT/$port" -Path $path `
                           -Status $status -Detail "$msg$hint" -Critical $portCritical
                continue
            }

            try {
                Write-Line 'OK' "$($t.Name):$port - proxy permits ($($tunnel.StatusLine))"
                Add-Result -Category $t.Category -Target $t.Name -Check "CONNECT/$port" -Path $path `
                           -Status 'OK' -Detail $tunnel.StatusLine -Critical $portCritical

                # TLS through the tunnel -> detects SSL inspection by the proxy
                if ($t.Tls -and $port -eq 443) {
                    $tls = Test-TlsOnStream -Stream $tunnel.Stream -TargetHost $t.Name
                    Write-Line $tls.Status "$($t.Name) TLS in tunnel - $($tls.Detail)"
                    Add-Result -Category $t.Category -Target $t.Name -Check 'TLS/443 (tunnel)' -Path $path `
                               -Status $tls.Status -Detail $tls.Detail -Critical $t.Critical
                }
            } finally {
                try { $tunnel.Client.Close(); $tunnel.Client.Dispose() } catch { }
            }
        }

        if (-not $SkipUdp -and $t.UdpPorts.Count -gt 0) {
            Add-Result -Category $t.Category -Target $t.Name -Check 'UDP/40000' -Path $path `
                       -Status 'INFO' -Critical $false `
                       -Detail 'UDP does not traverse HTTP/HTTPS proxies - a separate firewall rule is required'
        }
    }
}

Write-Progress -Activity 'NinjaOne allowlist test (EU)' -Completed

# ============================================================================
#  7. Summary
# ============================================================================

$fails = @($Results | Where-Object { $_.Status -eq 'FAIL' })
$warns = @($Results | Where-Object { $_.Status -eq 'WARN' })
$oks   = @($Results | Where-Object { $_.Status -eq 'OK'   })
$criticalFails = @($fails | Where-Object { $_.Critical })

Write-Host ''
Write-Host '===============================================================' -ForegroundColor Cyan
Write-Host ' Summary' -ForegroundColor Cyan
Write-Host '===============================================================' -ForegroundColor Cyan
Write-Host ("  Passed   : {0}" -f $oks.Count)   -ForegroundColor Green
Write-Host ("  Warnings : {0}" -f $warns.Count) -ForegroundColor Yellow
Write-Host ("  Failures : {0}  (critical: {1})" -f $fails.Count, $criticalFails.Count) -ForegroundColor Red

if ($paths.Count -gt 1) {
    Write-Host ''
    Write-Host '  Path comparison:' -ForegroundColor White
    foreach ($p in $paths) {
        $pf = @($fails | Where-Object { $_.Path -eq $p -and $_.Critical }).Count
        $po = @($oks   | Where-Object { $_.Path -eq $p }).Count
        Write-Host ("    {0,-7} : {1} passed / {2} critical failures" -f $p, $po, $pf)
    }
    $directOk = @($oks | Where-Object { $_.Path -eq 'Direct' }).Count
    $proxyOk  = @($oks | Where-Object { $_.Path -eq 'Proxy'  }).Count
    if ($proxyOk -gt 0 -and $directOk -eq 0) {
        Write-Host '    -> Only the proxy path works. Direct connections are blocked (expected in proxy environments).' -ForegroundColor Gray
    } elseif ($directOk -gt 0 -and $proxyOk -eq 0) {
        Write-Host '    -> Only direct connections work. The proxy does not let NinjaOne through.' -ForegroundColor Gray
    }
}

Write-Host ''
if ($criticalFails.Count -gt 0) {
    Write-Host ' Critical failures:' -ForegroundColor Red
    $criticalFails | Group-Object Target | ForEach-Object {
        $checks = (($_.Group | Select-Object -ExpandProperty Check -Unique) -join ', ')
        Write-Host ("   - {0}  ({1})" -f $_.Name, $checks) -ForegroundColor Red
    }
    Write-Host ''
}

# --- Static routing advisory (Fix 6) -----------------------------------------
$legacyHits  = @($Results | Where-Object { $_.Check -eq 'Static IP' -and $_.Status -eq 'WARN' -and $_.Detail -like 'legacy IP*' })
$unknownHits = @($Results | Where-Object { $_.Check -eq 'Static IP' -and $_.Status -eq 'WARN' -and $_.Detail -like 'IP unknown*' })
if ($legacyHits.Count -gt 0) {
    Write-Host ' NinjaOne Remote static routing - action required for IP allowlisting:' -ForegroundColor Yellow
    Write-Host '   The hosts below still resolve to legacy IPs whose deprecation started' -ForegroundColor Yellow
    Write-Host '   on 2026-03-31 (phase-out 60-90 days). If your firewall allowlists by'  -ForegroundColor Yellow
    Write-Host '   IP address, add the documented static IPs NOW - once the legacy range' -ForegroundColor Yellow
    Write-Host '   is switched off, NinjaOne Remote sessions will fail. If you allowlist' -ForegroundColor Yellow
    Write-Host '   by URL (*.ninjarmm.net), no action is needed.'                          -ForegroundColor Yellow
    $legacyHits | ForEach-Object {
        Write-Host ("   - {0} [{1}]" -f $_.Target, $_.Address) -ForegroundColor Yellow
    }
    Write-Host ''
}
if ($unknownHits.Count -gt 0) {
    Write-Host ' NinjaOne Remote - undocumented IPs resolved:' -ForegroundColor Yellow
    Write-Host '   The IPs below match neither the static nor the legacy list from the'   -ForegroundColor Yellow
    Write-Host '   EU allowlist article (data as of 2026-08-17). Re-check the current'    -ForegroundColor Yellow
    Write-Host '   Dojo article - the documented ranges may have changed.'                -ForegroundColor Yellow
    $unknownHits | ForEach-Object {
        Write-Host ("   - {0} [{1}]" -f $_.Target, $_.Address) -ForegroundColor Yellow
    }
    Write-Host ''
}

$inspection = @($Results | Where-Object { $_.Detail -like '*SSL inspection*' })
if ($inspection.Count -gt 0) {
    Write-Host ' SSL inspection notice:' -ForegroundColor Yellow
    Write-Host '   Unexpected certificate issuer on the hosts below. Per the Dojo article,' -ForegroundColor Yellow
    Write-Host '   NinjaOne URLs must be excluded from SSL inspection policies - otherwise'  -ForegroundColor Yellow
    Write-Host '   NinjaOne Remote breaks.'                                                  -ForegroundColor Yellow
    $inspection | Select-Object -ExpandProperty Target -Unique |
        ForEach-Object { Write-Host ("   - {0}" -f $_) -ForegroundColor Yellow }
    Write-Host ''
}

$cfgIssues = @($Results | Where-Object { $_.Category -eq 'Proxy configuration' -and $_.Status -in @('WARN','FAIL') })
if ($cfgIssues.Count -gt 0) {
    Write-Host ' Proxy configuration - action required:' -ForegroundColor Yellow
    $cfgIssues | ForEach-Object { Write-Host ("   - {0}: {1}" -f $_.Target, $_.Detail) -ForegroundColor Yellow }
    Write-Host ''
}

Write-Host ' Not automatically verifiable (check manually):'                                      -ForegroundColor Gray
Write-Host '   - UDP 57075-57200 (optional, P2P player <-> streamer)'                             -ForegroundColor Gray
Write-Host '   - UDP 20201 (localhost loopback)'                                                  -ForegroundColor Gray
Write-Host '   - Wildcards: *.ninjarmm.com, *.ninjarmm.net, *.rmmservice.eu, *.ingest.sentry.io'  -ForegroundColor Gray
Write-Host '   - cloudfront.net, Windows/macOS/Linux patch sources'                               -ForegroundColor Gray
Write-Host '   - Mail server 198.37.154.203 (inbound notifications)'                              -ForegroundColor Gray
Write-Host '   - Code signing: NinjaOne LLC, thumbprint 5f4f53c903859c0bdefd456789d9c517f9f68c06' -ForegroundColor Gray
if ($paths -notcontains 'Direct') {
    Write-Host '   - Static-IP validation for NinjaOne Remote (only runs in Direct/Both mode,'    -ForegroundColor Gray
    Write-Host '     because in Proxy mode the proxy performs the DNS resolution)'                -ForegroundColor Gray
}
if ($cfg.WinInetPac) {
    Write-Host "   - PAC file $($cfg.WinInetPac) - review its rules for ninjarmm.com/.net manually" -ForegroundColor Gray
}
Write-Host ''

if (-not $AllShards) {
    Write-Host ' Note: only a sample of the 40 WebSocket shards was tested. Full scan: -AllShards' -ForegroundColor Gray
    Write-Host ''
}

if ($ExportCsv) {
    try {
        $Results | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8
        Write-Host " CSV report saved: $ExportCsv" -ForegroundColor Cyan
        Write-Host ''
    } catch { Write-Warning "CSV export failed: $($_.Exception.Message)" }
}

Write-Host ' NinjaOne allowlist test (EU) complete.' -ForegroundColor Cyan
Write-Host ''

# Exit code: 1 only on critical failures (V2.6 had this logic inverted)
if ($criticalFails.Count -gt 0) { exit 1 } else { exit 0 }
