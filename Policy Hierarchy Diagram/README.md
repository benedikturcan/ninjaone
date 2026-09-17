# Policy Hierarchy Report for NinjaOne

Visualize your complete policy inheritance and every policy override in a single NinjaOne custom field, generated automatically by a PowerShell automation script.

---

## TL;DR

- One PowerShell script that runs as a regular NinjaOne automation.
- It writes an interactive-looking report into a **global WYSIWYG custom field** (`policyHierarchyReport`).
- The report shows:
  - **which policy inherits from which** (left-to-right diagram per OS and node class),
  - **which devices override their policy**,
  - **which settings a child policy overrides from its parent, including the parent value and the child value.**
- Every policy name links directly to the policy editor.

---

## Why this report?

Policy inheritance in NinjaOne is powerful: a parent policy defines the baseline, child policies (for example service packages or customer-specific policies) inherit it and change only what they need. With a growing number of policies this quickly becomes hard to follow:

| Problem in daily work | How the report helps |
|---|---|
| "Which policy is the parent of this one?" requires opening every policy. | One diagram per node class shows the full chain Parent → Child → Child-Child. |
| Overridden settings are only visible inside each child policy, section by section. | One table per child policy lists every overridden setting with **parent value → child value**. |
| Nobody notices when a child policy silently deviates from the standard. | Overrides are counted and flagged directly on the policy in the diagram. |
| Device-level policy overrides are scattered across devices. | All devices with overrides are listed with their policy chain and overridden sections. |
| Onboarding new technicians to the policy structure takes time. | The report is the documentation, always up to date after each run. |
| Audits and customer reviews need proof of the configured standard. | The report can be shown or exported as the current state of all policies. |

### Benefits at a glance

- **Transparency:** the whole policy structure on one page instead of dozens of clicks.
- **Faster troubleshooting:** see immediately whether a behavior comes from the parent or from an override.
- **Standardization:** deviations from your baseline become visible and can be reviewed.
- **Always current:** run it on demand or on a schedule; no manual documentation.
- **No extra tooling:** runs inside NinjaOne, output lives inside NinjaOne.

---

## User stories

> **As a technician**, I want to see which parent policy a device's policy inherits from, so that I know where to change a setting without breaking other customers.

> **As a technician**, I want to see exactly which settings a child policy overrides and what the original parent value was, so that I can troubleshoot unexpected alerts, patching or reboot behavior quickly.

> **As a team lead**, I want an overview of all policies that deviate from our standard packages, so that I can review and clean up unplanned changes.

> **As a service owner**, I want our Basic / Silver / Gold packages documented automatically, so that the documentation never gets out of date.

> **As a new team member**, I want a visual map of our policy structure, so that I understand the setup without opening every policy.

> **As an auditor or customer success manager**, I want a current snapshot of policy configuration and deviations, so that I can use it in reviews and audits.

---

## What the report contains

### 1. Summary
Total policies, inheritance chains, maximum depth, devices with overrides and child policies with overrides.

### 2. Inheritance diagram
- One section per OS family (Windows, Apple, Linux, Android, ChromeOS, Virtualization, Network, Other).
- Inside each family one sub-section per node class (for example *Windows Workstation*, *Windows Server*, *macOS*, *iOS*).
- Read left to right: **Level 1 · Parent → Level 2 · Child → Level 3 · Child-Child**.
- Chips on each policy: `Default`, `x changed settings`, `x device overrides`.
- Policies without inheritance are listed as cards below the diagram of their node class.
- Every policy name opens the policy editor in a new tab.

### 3. Deviations
- **Device overrides:** device, full policy chain, overridden sections.
- **Child-policy overrides:** one block per child policy with the columns **Area · Setting · Parent value · Child value**.

---

## How it works

```
NinjaOne automation (PowerShell 5.1)
|
|-- Official Public API (client credentials)
|     GET   /v2/policies                        all policies and their parents
|     GET   /v2/queries/policy-overrides         devices with policy overrides
|     GET   /v2/device/{id}                     device details
|     PATCH /v2/system/custom-fields             write the report
|
|-- NinjaOne console API (browser sessionKey)
|     GET   /swb/s4/policy/{id}                 child policy incl. "overridden" flags
|     GET   /swb/s6/policy/{id}/parent-content  parent values for comparison
|
'-- Local cache (NINJA_DATA_PATH)
      last successful child-policy override result
```

The official API does not expose which settings a child policy overrides. This information is only available through the console API that the NinjaOne web interface uses itself, authenticated with the `sessionKey` cookie of a logged-in technician.

**If the sessionKey is missing or expired, the script still runs.** Policies, diagram and device overrides are always updated. The child-policy override section then shows the data of the last successful run, clearly marked with its date.

---

## Requirements

### NinjaOne

| Requirement | Details |
|---|---|
| API client app | Grant type **Client credentials**, scopes **Monitoring** and **Management** (Management is required to write custom field values). |
| Global custom field | Type **WYSIWYG**, name **`policyHierarchyReport`**, API permission **Write** (or Read/Write). |
| Automation script | PowerShell script in the automation library (see setup). |
| Device to run on | Any Windows device with the NinjaOne agent and outbound HTTPS to your NinjaOne region (for example `eu.ninjarmm.com`). |
| Technician account | Needed only to obtain the `sessionKey` for child-policy overrides; the account must be able to view policies. |

### Technical

- Windows PowerShell 5.1 (default on Windows 10/11 and Windows Server 2016+).
- TLS 1.2 (enabled by the script).
- No additional modules or software.

---

## Setup

### Step 1: Create an API client app
1. Go to **Administration → Apps → API → Client App IDs** and add a new client app.
2. Application platform: **API Services (machine-to-machine)**.
3. Allowed scopes: **Monitoring** and **Management**.
4. Allowed grant types: **Client credentials**.
5. Save and copy the **Client ID** and **Client Secret**.

### Step 2: Create the custom field
1. Create a new **global** custom field.
2. Label: `Policy Hierarchy Report`, name: **`policyHierarchyReport`**, type: **WYSIWYG**.
3. Permissions: Technician **Read Only**, Automations **None**, API **Write** (or Read/Write).
4. Optional: enable **Expand large value on render**; the report is larger than 10,000 characters and is collapsed by default otherwise.

### Step 3: Add the script
1. **Administration → Library → Automation → Add → New Script**.
2. Name: `Policy Hierarchy Report`.
3. Language **PowerShell**, operating system **Windows**, architecture **All**, run as **System**.
4. Paste the content of [`Policy-Hierarchy-Report.ps1`](Policy-Hierarchy-Report.ps1).

### Step 4: Add script variables
Add the following variables of type **String/Text**. The **calculated name** must match (case does not matter).

| Name / calculated name | Mandatory | Default value | Purpose |
|---|---|---|---|
| `sessionKey` | No | *(empty)* | Browser sessionKey for child-policy overrides. Enter it when running the script. |
| `clientId` | Yes | your Client ID | API authentication |
| `clientSecret` | Yes | your Client Secret | API authentication |
| `region` | No | `eu` | Your NinjaOne region (`eu`, `app`, `ca`, `oc`, ...) |

Leave the **Parameters** field empty.

### Step 5: Get the sessionKey
1. Log in to NinjaOne in your browser.
2. Open the developer tools (**F12**) → **Application** (Chrome/Edge) or **Storage** (Firefox) → **Cookies** → your NinjaOne URL.
3. Copy the value of the cookie **`sessionKey`**.

The sessionKey changes regularly. Treat it like a password (see security notes).

### Step 6: Run the script
1. Open any Windows device → **Run** → **Policy Hierarchy Report**.
2. Paste the current `sessionKey` and run.
3. Open the custom field `policyHierarchyReport` to see the report.

Example output:
```
Loading policies...
Loading device policy overrides...
Loading details for 1 devices...
Loading child-policy overrides for 17 child policies...
Found 2 child policies with overrides (live)
Writing report to global custom field "policyHierarchyReport" (90056 characters)...
Custom field "policyHierarchyReport" updated
```

### Optional: Schedule it
Create a scheduled task (for example daily) that runs the script on one device. Scheduled runs usually have no current sessionKey: they refresh the diagram and device overrides, while child-policy overrides are shown from the last run with a valid sessionKey.

---

## Behavior of the sessionKey fallback

| Situation | Result |
|---|---|
| Valid sessionKey | Child-policy overrides loaded live and saved to the cache. |
| Expired or invalid sessionKey, cache available | Report shows cached child-policy overrides with the date of the last successful run and the reason. |
| No sessionKey, no cache | Report shows "Child-policy overrides unavailable". |
| Client ID or secret missing | Script stops with `ERROR: Missing script variables` and exit code 1; the custom field is not changed. |

The cache is stored in the NinjaOne agent data folder (`NINJA_DATA_PATH`, usually `C:\ProgramData\NinjaRMMAgent`) as `policy-hierarchy-report-cache.json`. Always run the script on the same device to use the cache.

---

## Security notes

- **The sessionKey is an active login session** of the technician who copied it. Anyone who has it can act as this technician in the web interface until the session ends. Never store it permanently, never share it, and log out of the browser session if it was exposed.
- **Default values of script variables are visible** to everyone who can edit the script. Consider leaving `clientSecret` empty and entering it at runtime, and restrict who can edit the script.
- **Use a dedicated API client** for this report and rotate the client secret regularly.
- The script only **reads** policies and devices and **writes one custom field**. It never changes policies or devices.

---

## Limitations

- **Console API is not officially supported.** The `/swb/...` endpoints are used by the NinjaOne web interface and may change without notice. The official API parts keep working even if they do.
- **WYSIWYG restrictions:** no JavaScript, no SVG, no collapsible sections inside the field; the diagram is built from HTML and inline styles only. Maximum field size is 200,000 characters.
- **Brand icons** (Windows, Apple, Linux, Android, Chrome) rely on Font Awesome brand icons in NinjaOne.
- **Values are shown raw** as stored by NinjaOne (for example `waitMinutes: 300` together with `unitOfTime: HOURS`).
- **Device overrides** show the overridden sections, not the individual values.

---

## Troubleshooting

| Message / symptom | Cause | Fix |
|---|---|---|
| `ERROR: Missing script variables: clientId, clientSecret` | Variables missing or calculated name differs | Check the calculated names of the script variables. |
| `ERROR: ... (400) Bad Request` on token | Wrong client ID/secret or scope not allowed | Verify the API client has **Monitoring** and **Management** and grant type **Client credentials**. |
| `ERROR: ... (403) Forbidden` when writing | Custom field has no API write permission | Set API permission of `policyHierarchyReport` to **Write**. |
| `WARNING: The sessionKey is invalid or expired (401 Unauthorized)` | sessionKey expired | Copy a fresh sessionKey from the browser and run again. |
| `Child-policy overrides unavailable` | No valid sessionKey yet on this device | Run once with a valid sessionKey on the same device. |
| Report appears collapsed | Field larger than 10,000 characters | Enable **Expand large value on render** on the custom field. |
| Icons missing | Font Awesome brand icons not available | Cosmetic only; the report is still complete. |

---

## FAQ

**Does the script change any policy?**
No. It only reads data and writes the report into one custom field.

**Why is a browser sessionKey needed?**
The public API does not provide policy override details. Without a sessionKey the report still works, only the child-policy override values come from the last successful run.

**Can I run it on a server?**
Yes, on any Windows device with the NinjaOne agent and internet access. The data is tenant-wide, independent of the device.

**Which NinjaOne regions are supported?**
All regions; set the `region` variable (for example `eu`, `app`, `ca`, `oc`).

---

## Roadmap ideas

- Device count per policy and detection of unused policies.
- Organizations assigned to each policy.
- "Changed since last run" section and alerting on new overrides.
- Reading credentials from a secure custom field.
- Splitting the report into several fields (one per OS family) for collapsible sections.

---

## Download

Source code: [github.com/benedikturcan/ninjaone](https://github.com/benedikturcan/ninjaone/tree/main/Policy%20Hierarchy%20Diagram)

*Feedback and ideas are welcome.*
