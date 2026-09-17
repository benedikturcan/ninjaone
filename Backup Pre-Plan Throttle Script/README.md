# NinjaOne Backup Pre-/Post-Script: Dynamic Bandwidth Throttle

Measure the internet speed of a device right before a backup starts, set the NinjaOne backup bandwidth throttle to a percentage of the measured rate, and turn the throttle off again after the backup.

---

## TL;DR

- Two PowerShell scripts for a backup plan:
  - [`Backup-Throttle-PreScript.ps1`](Backup-Throttle-PreScript.ps1): speed test and throttle **before** the backup.
  - [`Backup-Throttle-PostScript.ps1`](Backup-Throttle-PostScript.ps1): throttle **off** after the backup.
- Speed test against `speed.cloudflare.com` with parallel streams; no binary to download or install.
- Throttle = measured **upload** rate x `throttlePercent` / 100 (e.g. 150 Mbps upload, `throttlePercent = 20` -> 30 Mbps = 30000 Kbps).
- Sets the throttle via `POST /v2/backup/bandwidth-throttle` for the device the script runs on.
- Waits `applyDelaySeconds` (default 60 s) so the agent applies the throttle **to the job that is starting now**.
- Exit code `1` on errors. Whether that cancels the backup is set in the backup plan (see below).
- **NinjaOne Backup must be enabled for the device**, otherwise the API rejects the throttle.

---

## How it works

### Pre-script

1. **Speed test** of one direction (upload by default, since throttling only applies to cloud backups). The first 2 seconds (TCP ramp-up) are not counted, then the average over `testDurationSeconds` is used.
2. **Calculation:** measured rate x `throttlePercent` / 100, never below `minimumKbps`.
3. **API call** `POST /v2/backup/bandwidth-throttle` with `enabled = true`. The script runs right before the job, so no time window is needed: work and non-work hours get the same value, and the work schedule covers the whole week (00:00-23:59, Monday-Sunday).
4. **Wait** `applyDelaySeconds`, then exit `0` and the backup starts.

Example output:
```
[07:54:52] Device 7, base: upload, backup may use 20 % of it
[07:54:52] Measuring upload speed (10 s, 4 streams)...
[07:55:04] Measured upload speed: 152.19 Mbps
[07:55:04] Throttle: 30.44 Mbps
[07:55:05] POST /v2/backup/bandwidth-throttle {"bandwidthThrottle":{...},"deviceId":7}
[07:55:05]   Response: {"result":"SUCCESS"}
[07:55:05] Bandwidth throttle set to 30.44 Mbps.
[07:55:05] Waiting 60 s so the agent applies the throttle before the backup starts...
[07:56:05] Done, backup can start.
```

### Post-script

`POST /v2/backup/bandwidth-throttle` with `enabled = false`: the next backup (or a manual backup outside the plan) runs without the measured limit.

---

## Setup

### Step 1: Create an API client app
1. Go to **Administration → Apps → API → Client App IDs** and add a new client app.
2. Application platform: **API Services (machine-to-machine)**.
3. Allowed scopes: **Monitoring** and **Management**.
4. Allowed grant types: **Client credentials**.
5. Save and copy the **Client ID** and **Client Secret**.

The client app belongs to the instance it was created on: an app from `app.ninjarmm.com` does not exist on `eu.ninjarmm.com` (`Client app not exist`).

### Step 2: Add both scripts
1. **Administration → Library → Automation → Add → New Script**.
2. Names: `Backup Pre-Plan Throttle` and `Backup Post-Plan Throttle Reset`.
3. Language **PowerShell**, operating system **Windows**, architecture **All**, run as **System**.
4. Paste the content of [`Backup-Throttle-PreScript.ps1`](Backup-Throttle-PreScript.ps1) or [`Backup-Throttle-PostScript.ps1`](Backup-Throttle-PostScript.ps1).
   Copy from the file in a local editor (Ctrl+A, Ctrl+C) into the emptied NinjaOne editor. Check that the script ends with `exit 1` and `}`: a partial paste causes parser errors such as `Missing closing '}'` or `Unexpected token '}'`.

### Step 3: Add script variables
The **calculated name** must match (case does not matter). Leave the **Parameters** field empty. Backup pre-/post-scripts run without a run dialog, so the values must be set as **default values** in the script.

**Pre-script:**

| Name / calculated name | Type | Mandatory | Default value | Purpose |
|---|---|---|---|---|
| `throttlePercent` | Integer | Yes | e.g. `20` | Share (1-100) of the measured rate the backup may use |
| `clientId` | String/Text | Yes | your Client ID | API authentication |
| `clientSecret` | String/Text | Yes | your Client Secret | API authentication |
| `region` | String/Text | No | `eu` | Your NinjaOne region (`eu`, `app`, `ca`, `oc`, ...) |
| `measureBase` | Drop-down | No | `upload` | `upload` or `download` |
| `minimumKbps` | Integer | No | `256` | Lower limit of the throttle |
| `applyDelaySeconds` | Integer | No | `60` | Wait before the backup starts (0-1800) |
| `testDurationSeconds` | Integer | No | `10` | Measurement time (3-60) |
| `parallelStreams` | Integer | No | `4` | Parallel connections (1-16) |

**Post-script:** only `clientId`, `clientSecret` and optionally `region`.

### Step 4: Backup plan

**Pre plan automations** -> *Run script before backup job* -> **Add** `Backup Pre-Plan Throttle`.

| Checkbox "Cancel the backup job if the automation returns a failure code" | Behavior on error (speed test blocked, API error, backup not enabled) |
|---|---|
| enabled | Backup is cancelled, no backup runs without the calculated throttle |
| disabled | Backup runs with the previous throttle of the device |

**Post plan automations** -> add `Backup Post-Plan Throttle Reset`.

---

## Errors

| Log message | Cause | Fix |
|---|---|---|
| `NinjaOne rejected the bandwidth throttle for device N (result FAILURE). Most likely NinjaOne Backup is not enabled for this device` | The API answers HTTP 500 with `{"result":"FAILURE"}` and no reason. Seen when Backup is not enabled for the device. | Enable NinjaOne Backup for the device and assign a backup plan. |
| `Authentication failed (...): ... Client app not exist` | Wrong Client ID, or the app was created on another instance/region | Copy the Client ID from the console of the right instance, check `region`. |
| `Script variable 'throttlePercent' is required.` | Variable missing, no default value, or calculated name differs | Check the script variables. |
| `No device ID: NINJA_AGENT_NODE_ID is not set` | Running outside NinjaOne | Pass `-DeviceId`. |
| `Upload speed test transferred no data (speed.cloudflare.com blocked?)` | Firewall/proxy blocks the speed test | Allow `speed.cloudflare.com` (HTTPS/443). |
| `Missing closing '}'` / `Unexpected token '}'` | Script was not pasted completely | Paste the full file again (see Step 2). |

---

## Local test

Outside NinjaOne the variables are passed as parameters; `deviceId` is required there because `NINJA_AGENT_NODE_ID` only exists in NinjaOne runs:

```powershell
.\Backup-Throttle-PreScript.ps1 -ThrottlePercent 20 -ClientId '<clientId>' -ClientSecret '<clientSecret>' -DeviceId 123
.\Backup-Throttle-PostScript.ps1 -ClientId '<clientId>' -ClientSecret '<clientSecret>' -DeviceId 123
```

---

## Notes

- **Default values of script variables are visible** to everyone who can edit the script, including `clientSecret`. Use a dedicated API client, restrict who can edit the script and rotate the secret regularly.
- **Payload format:** `workHoursUserUnit = KBPS` and weekdays `MONDAY` ... `SUNDAY` are confirmed working; the API documentation lists no allowed values. The limit is always sent in Kbps.
- **The API cannot read the current throttle:** `GET /v2/device/{id}` does not return it. The post-script therefore turns the throttle off instead of restoring a previous value, and any throttle or work schedule set manually on the device is replaced.
- **Duration:** about 12 seconds of speed test, API calls and `applyDelaySeconds` before the backup starts.
- **Measured rate = currently free bandwidth.** Other traffic during the test lowers the result.
- **Timing:** the API only confirms the value on the server, not on the agent. Check in the first backup job details whether the transfer rate matches the throttle; if not, raise `applyDelaySeconds`.
