# NinjaOne Allowlist & Proxy Connectivity Test (EU)

Check in one run whether a Windows device can reach every NinjaOne endpoint in the EU region, directly or through a proxy. The script also checks whether the agent service is healthy and whether the device has internet access at all.

---

## TL;DR

- One PowerShell script: [`Ninja_Allowlist_Test_EU.ps1`](Ninja_Allowlist_Test_EU.ps1).
- Tests every endpoint from the NinjaOne Dojo allowlist articles (**Global + EU region**, as of 2026-08-17).
- Detects the proxy automatically (agent registry, `NC_PROXY`, WinINET, PAC, WinHTTP, environment variables) and tests **per URL** whether the proxy lets it through.
- Detects **SSL inspection**, **legacy NinjaOne Remote IPs** and **broken proxy registry values**.
- Checks the **`NinjaRMMAgent` service** (not installed / stopped / running) and starts or restarts it.
- Checks **internet access**: an adapter being up (LAN/WLAN) does not mean the device has internet.
- Exit code `0` = no critical failures, `1` = at least one critical failure.

---

## When to use it

| Situation | What the test tells you |
|---|---|
| Agent shows offline in NinjaOne | Is the service running, does the device have internet, which endpoint is blocked? |
| Rolling out NinjaOne at a new customer | Does the firewall/proxy permit everything **before** the agent is installed? |
| NinjaOne Remote does not connect | Are TCP 443/7075 and UDP 40000 open, are the static Remote IPs permitted, is SSL inspection active? |
| Customer uses a proxy | Does the proxy permit each URL, or does it block with 403/407? Is the agent proxy configured correctly? |
| Firewall allowlists by IP | Do the NinjaOne Remote hosts still resolve to legacy IPs that are being retired? |
| "LAN/WLAN is connected, but nothing works" | Gateway, ping, DNS and TCP/443 show whether the device actually reaches the internet. |

---

## What is checked

The script runs these steps in order:

### 1. NinjaOne agent service (`NinjaRMMAgent`)

| Service state | Action | Result |
|---|---|---|
| Not found | none | **Agent is not installed.** Reported as FAIL, but not critical: the allowlist results still apply to a later installation. |
| Stopped | started immediately | OK if it is still running 5 seconds after start, otherwise FAIL (crash loop) |
| Running | **restarted after the tests** | OK / FAIL after the restart |
| Disabled | none | FAIL with the command to re-enable it |

- Starting or restarting requires **administrator or SYSTEM** rights. Without them you get a warning only.
- If the script runs **through NinjaOne** (or as SYSTEM), a direct restart would kill the script before its output is uploaded. In that case the restart runs **90 seconds later** through a one-time scheduled task (`NinjaOne-AllowlistTest-AgentRestart`), which deletes itself afterwards.
- `-NoServiceRestart` only reports the service state and does not touch the service.

### 2. Network and internet connectivity

1. **Active adapters** (LAN/WLAN) with IP address and default gateway
2. **Ping to the default gateway**
3. **Ping to public resolvers** `1.1.1.1`, `8.8.8.8`, `9.9.9.9` (by IP, independent of DNS)
4. **DNS resolution** of `www.msftconnecttest.com`
5. **Direct TCP/443** to `1.1.1.1` / `8.8.8.8`, only when ping fails (many networks filter ICMP)

| Verdict | Meaning |
|---|---|
| **OK** | Ping or TCP/443 works: the device has internet. |
| **WARN – proxy only** | No direct internet, but a proxy is configured. The proxy tests decide. |
| **FAIL – no internet** | Adapter is up, but the internet is not reachable. The allowlist failures are then most likely a **consequence** of this; the summary says so. |

### 3. Proxy configuration

- **Agent registry** `HKLM\SOFTWARE\WOW6432Node\NinjaRMM LLC\NinjaRMMAgent\Server`
  - `ProxyHost` must be **REG_SZ**, `ProxyPort` must be **REG_DWORD**
  - `ProxyHost` without `ProxyPort` = critical misconfiguration
  - Detects the password that NinjaOne masks after the first successful login
- **`NC_PROXY`** (NinjaOne Remote): format `[http(s)://]host:port:user:password`, trailing colons, HTTP vs. HTTPS
- **System proxy**: WinINET, PAC file, WinHTTP, `HTTP(S)_PROXY`
- **Consistency**: agent proxy without `NC_PROXY`, different proxy hosts, system proxy without agent proxy

### 4. Endpoint tests

| Area | Endpoints | Ports |
|---|---|---|
| NinjaOne Remote | `nc-1` … `nc-8-eu-central-1.ninjarmm.net` | TCP 443, TCP 7075 (fallback), UDP 40000 |
| WebSocket rendezvous | `connect-eu-central.ninjarmm.com`, shards `s0`–`s39` (sample by default) | TCP 443 |
| Agent & patcher (EU) | `agent-eu-central`, `fts-prod-frankfurt`, `prod-bastrop-euc`, `rtc-eu-central-1`, `agent-tun-euc-0` | TCP 443 |
| File Explorer | `fts-prod-london.ninjarmm.com` | TCP 443 |
| MDM (EU) *(not critical)* | `mdm-eu`, `scep-eu` | TCP 443 |
| Global agent/patcher | `resources`, `patching`, S3 buckets, `agent-app.ninjarmm.com` (HTTP) | TCP 443 / 80 |
| IP gateways (EU) | `18.184.54.189`, `52.29.101.132`, `18.195.227.137` | TCP 443 |
| Device Backup *(optional)* | EU S3 buckets, `lockhart-grpc` | TCP 443 / 80 |
| Cloud RDP *(optional)* | `agent-tun-euw2-0`, `tun-eu-central-0`, `tun-uk-0` | TCP 443 |

Per endpoint, depending on the path:

- **Direct:** DNS → TCP connect to every resolved IP → TLS 1.2 handshake with certificate check → UDP (best effort)
- **Proxy:** HTTP CONNECT or SOCKS5 CONNECT per URL → TLS through the tunnel. For HTTPS proxies the connection to the proxy itself is TLS-encrypted.
- **NinjaOne Remote static IPs** (Direct only): resolved IPs are compared with the documented static IPs and with the legacy IPs being retired since 2026-03-31.

---

## Requirements

- Windows PowerShell **5.1** or PowerShell **7+**
- Windows 10 / 11 or Windows Server 2016+ (the service check and scheduled task need Windows)
- **Administrator or SYSTEM** rights for the service start/restart (everything else also works without them)
- No modules, no internet downloads, no NinjaOne API access

---

## Usage

### Option A: Run manually on the device

Use this when the agent is offline or not installed yet: then you cannot run the script through NinjaOne.

1. Copy [`Ninja_Allowlist_Test_EU.ps1`](Ninja_Allowlist_Test_EU.ps1) to the device, for example to `C:\Temp`.
2. Open **PowerShell as administrator**.
3. Allow the script for this session only and run it:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

```powershell
C:\Temp\Ninja_Allowlist_Test_EU.ps1
```

4. Optional: save the results as CSV for the customer or the firewall team:

```powershell
C:\Temp\Ninja_Allowlist_Test_EU.ps1 -ExportCsv C:\Temp\ninja-allowlist.csv
```

> **Tip:** When run manually in the user's session, the WinINET/PAC proxy of the **logged-in user** is detected. That is useful if the customer's browser uses a proxy.

### Option B: Run through NinjaOne

1. **Administration → Library → Automation → Add → New Script**.
2. Name: `NinjaOne Allowlist Test (EU)`.
3. Language **PowerShell**, operating system **Windows**, architecture **All**, run as **System**.
4. Paste the content of [`Ninja_Allowlist_Test_EU.ps1`](Ninja_Allowlist_Test_EU.ps1).
5. Open the device → **Run** → pick the script. Enter parameters (see below) in the **Parameters** field if needed, for example:

```
-Mode Both -AllShards
```

6. Check the output in the activity log of the device.

Things to know when running through NinjaOne:

- The script runs as **SYSTEM**. HKCU settings (WinINET, PAC) belong to the SYSTEM account, **not** to the logged-in user.
- The agent restart is deferred by **90 seconds**, so the device is briefly offline shortly after the script finishes. That is expected.
- If the script has critical failures, it exits with code `1` and NinjaOne marks the run as **failed**.
- Use `-NoServiceRestart` if you only want the report without restarting the agent.

---

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `-Mode` | `Auto` | `Auto` = use the proxy if one is detected, otherwise direct. `Direct`, `Proxy`, or `Both` (compare both paths). |
| `-ProxyHost` | – | Set the proxy manually instead of detecting it. |
| `-ProxyPort` | – | Port of the manual proxy. |
| `-ProxyType` | `Http` | `Http`, `Https` (TLS to the proxy) or `Socks5`. |
| `-ProxyUser` / `-ProxyPassword` | – | Proxy credentials. Override the (masked) registry credentials. |
| `-Timeout` | `5000` | Timeout per connection attempt in ms. |
| `-AllShards` | off | Test all 40 WebSocket shards instead of a sample. |
| `-IncludeBackup` | off | Also test the Device Backup endpoints. |
| `-IncludeCloudRdp` | off | Also test the Cloud RDP endpoints. |
| `-IncludeIPv6` | off | Also test AAAA records. |
| `-SkipUdp` | off | Skip the UDP checks. |
| `-ExportCsv` | – | Path for a CSV export of all results. |
| `-NoServiceRestart` | off | Only report the agent service state, do not start/restart it. |

### Examples

Standard test, proxy detected automatically:
```powershell
.\Ninja_Allowlist_Test_EU.ps1
```

Compare the direct path and the proxy path:
```powershell
.\Ninja_Allowlist_Test_EU.ps1 -Mode Both
```

Test a specific proxy with credentials:
```powershell
.\Ninja_Allowlist_Test_EU.ps1 -Mode Proxy -ProxyHost 192.168.32.144 -ProxyPort 3128 -ProxyUser svc-ninja -ProxyPassword '********'
```

Full test including backup, all shards and CSV, without touching the agent:
```powershell
.\Ninja_Allowlist_Test_EU.ps1 -AllShards -IncludeBackup -NoServiceRestart -ExportCsv C:\Temp\ninja.csv
```

---

## Reading the output

Every line starts with a status:

| Status | Meaning |
|---|---|
| `[OK  ]` | Check passed. |
| `[FAIL]` | Check failed. **Critical** failures cause exit code `1`. |
| `[WARN]` | Worth a look, but not blocking (e.g. fallback port 7075, SSL inspection, legacy IP). |
| `[INFO]` | Information only (configuration, UDP results, adapters). |

Example excerpt:
```
--- NinjaOne agent service ------------------------------------
[INFO] Service 'NinjaRMMAgent' found - status: Running, start type: Automatic
[INFO] Service 'NinjaRMMAgent' is running -> it will be restarted after the connectivity tests

--- Network and internet connectivity -------------------------
[INFO] LAN  'Ethernet' (Intel(R) Ethernet Connection) - IP: 192.168.1.20, gateway: 192.168.1.1
[OK  ] Default gateway 192.168.1.1 answers ping (1 ms)
[OK  ] Ping 1.1.1.1 ok (18 ms)
[OK  ] DNS resolution of www.msftconnecttest.com ok (13.107.4.52)
[OK  ] The device has internet access
```

At the end, the **summary** shows:

- number of passed checks, warnings and (critical) failures
- path comparison for `-Mode Both`
- list of critical failures per endpoint
- notes on missing internet, the agent service, legacy Remote IPs, SSL inspection and proxy configuration
- items that cannot be verified automatically (e.g. UDP 57075–57200, wildcards, patch sources)

---

## Troubleshooting

| Result | Cause | What to do |
|---|---|---|
| `Service 'NinjaRMMAgent' not found` | Agent not installed | Install the agent. The allowlist results still tell you if the network is ready. |
| Service is started but stops again | Agent crashes or cannot start | Check the Windows event log and `C:\ProgramData\NinjaRMMAgent\logs`, reinstall the agent if needed. |
| `Not running elevated` | PowerShell not started as admin | Start PowerShell as administrator or run it through NinjaOne as System. |
| `no internet` | Uplink, gateway, firewall or captive portal | Fix the network first; the allowlist failures are a result of this. |
| `DNS resolves (internal resolver), but the internet is not reachable` | Internal DNS works, outbound traffic is blocked | Check the default route and firewall; a proxy may be required. |
| `DNS resolution failed` for NinjaOne hosts | DNS filter or split DNS | Allow `*.ninjarmm.com` / `*.ninjarmm.net` in the DNS filter. |
| `TCP/443 blocked or unreachable` | Firewall drops the connection | Add the endpoint to the firewall allowlist. |
| `unexpected issuer -> SSL inspection likely` | Firewall/proxy intercepts TLS | Exclude NinjaOne URLs from SSL inspection. |
| `resolves to a LEGACY IP` | IP-based allowlist with old Remote IPs | Add the documented static IPs; not needed if you allowlist by URL. |
| `proxy replied: ... 407` | Proxy requires authentication | Pass `-ProxyUser` / `-ProxyPassword` (the registry password is masked). |
| `proxy replied: ... 403` | Proxy blocks the URL | Add the URL to the proxy allowlist. |
| `proxy replied: ... 502/504` | Proxy cannot reach the target | Check the upstream firewall behind the proxy. |
| `CONNECT/7075` fails via HTTP proxy | HTTP proxies usually permit CONNECT on 443 only | Expected. Open 7075 directly on the firewall or use SOCKS5. |
| `ProxyHost is set but ProxyPort is missing` | Incomplete agent proxy registry | Add `ProxyPort` as **DWORD (32-bit)**. |
| `agent uses a proxy but NC_PROXY is not set` | NinjaOne Remote ignores the proxy | Set `NC_PROXY` as a system environment variable. |
| `Aborting: proxy tests are meaningless without a reachable proxy` | Proxy host/port wrong or blocked | Check the proxy address, or use `-Mode Both` to also test direct. |

---

## Limitations

- **UDP** cannot be proven open without a responder. UDP results are only `INFO`/`WARN`, never `OK`.
- **Static IP validation** only runs in `Direct`/`Both` mode, because in proxy mode the proxy resolves DNS.
- **IP gateways** cannot be tested through an HTTP proxy.
- **PAC files** are detected but not evaluated per URL; review their rules for `ninjarmm.com` / `ninjarmm.net` manually.
- Wildcards (`*.ninjarmm.com`, `*.ninjarmm.net`, `*.rmmservice.eu`, `*.ingest.sentry.io`), CloudFront and OS patch sources are not tested.
- The internet check uses public resolvers (Cloudflare, Google, Quad9). Networks that block all of them **and** have no proxy are reported as having no internet.
- The endpoint list reflects the Dojo articles **as of 2026-08-17**. Check the current articles if results do not match.

---

## Sources

- NinjaOne Dojo: *Global Allowlist Information*
- NinjaOne Dojo: *Allowlist: EU Region*
- NinjaOne Dojo: *NinjaOne Agent: Configuration for Use Over a Proxy Server*

---

## Version

Current version: **3.4-EU**. The full change history is in the header of the script (`.NOTES`).
