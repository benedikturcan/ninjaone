# Install-WingetMachine.ps1

Installs one or more Winget packages in machine scope. Designed to run as a NinjaOne
automation under the SYSTEM account, but works in any elevated context. Current
version: **1.4.4**.

## Prerequisites

- Windows 10/11 (x64 or ARM64), Windows PowerShell 5.1 or PowerShell 7
- Elevated execution (SYSTEM or administrator) – enforced by the script
- A functional winget (App Installer >= approx. 1.4) on the endpoint
  - The script locates winget even under SYSTEM (scans `%ProgramFiles%\WindowsApps`)
    and probes every candidate with `winget --version` before using it
  - The script does **not** repair winget itself (deliberate design decision, see below)
- Windows Server 2022: winget does not ship with it and is not officially supported
  by Microsoft. It can be retrofitted (see Troubleshooting), but for servers a direct
  vendor installer is usually the more robust choice.

## NinjaOne setup

Create the script as a PowerShell automation, run **as System**. Success is evaluated
via the exit code (0 = success, 1 = failure).

Create three script variables and map them as dynamic script variables. The names
must match exactly (the script reads them via `$env:`):

| Variable        | Type           | Required | Description |
|-----------------|----------------|----------|-------------|
| `wingetId`      | Text           | yes      | Winget package ID, comma-separated for multiple packages. Example: `Microsoft.PowerShell` or `Microsoft.PowerShell,7zip.7zip`. Allowed characters: letters, digits, `. + _ -` |
| `wingetVersion` | Text           | no       | Exact version(s), comma-separated. When set, the count must match the number of IDs. Empty = latest version |
| `architecture`  | Text/Dropdown  | no       | Forced target architecture: `x64`, `x86`, or `arm64`. Empty = device architecture is detected automatically (recommended default) |

## Parameters (optional, without script variables)

| Parameter                | Default | Description |
|--------------------------|---------|-------------|
| `-Id`                    | `$env:wingetId` | Package ID(s) |
| `-Version`               | `$env:wingetVersion` | Version(s) |
| `-Architecture`          | `$env:architecture` | Target architecture |
| `-LogPath`               | auto    | Log file path; default: `%TEMP%\winget-install-<Id>-<timestamp>.log` (under SYSTEM: `C:\Windows\Temp`) |
| `-ShowTimeoutSeconds`    | 120     | Timeout for `winget show` (scope check) |
| `-InstallTimeoutSeconds` | 1800    | Timeout for `winget install`; on timeout the whole process tree is terminated |

## Behavior

1. Elevation check, winget discovery including a functional probe
2. Per package: validation of Id/Version, `winget show` for the machine-scope check
   (if parsing fails, e.g. due to localized winget output, the installation is still
   attempted and logged as `Indeterminate`)
3. `winget install --scope machine --silent`; "already installed" is detected via
   winget exit codes and counts as success (`AlreadyInstalled`)
4. Copies the matching Start Menu shortcut to the Public Desktop
   (token matching against the package ID; nothing is copied if nothing matches)
5. Per-package summary in the log, exit code 0/1

Exit codes: **0** = all packages succeeded (including AlreadyInstalled),
**1** = at least one package failed or a fatal error occurred.

## Troubleshooting (known failure patterns)

**`winget candidate failed startup probe ... 0xC0000135`**
The App Installer on the device is broken or only partially installed
(STATUS_DLL_NOT_FOUND, typically missing VCLibs/UI.Xaml dependencies).
The script discards the candidate and tries older version folders. If no working
one exists, it aborts. Run the repair once, elevated:

```powershell
Install-Module Microsoft.WinGet.Client -Force
Repair-WinGetPackageManager -AllUsers -Force -Latest
```

**`winget is not available or not functional on this device`**
No functional winget found. Same repair as above. The script deliberately does not
repair on its own: `Add-AppxPackage` is blocked by Windows under SYSTEM (0x80073CF9),
and installing modules as a side effect of an install script is undesirable. The
repair belongs in a separate remediation script.

**`Wrapped installer reported its own exit code: <n>`**
winget itself ran fine; the vendor's installer failed. The code is vendor-specific
(example Citrix Workspace: 4xxxx codes, documented in Citrix CTX695019). Check the
vendor's installer logs.

**ARM64 devices**
If the winget manifest does not offer an ARM64 installer, winget downloads the x64
installer (emulation). Some installers (e.g. Citrix Workspace) fail in that case.
Check upfront with `winget show <Id>` (inspect the installer blocks); if needed,
deploy the vendor's native ARM64 installer separately.

**Inconsistent results on existing devices**
Manually installed legacy versions are sometimes recognized by winget under a
different ID (example: old Citrix installations as `CitrixOnlinePluginPackWeb`).
winget may then install "on top" instead of reporting `AlreadyInstalled`.

## Log file

In addition to the NinjaOne output, the script writes to
`C:\Windows\Temp\winget-install-<Id>-<timestamp>.log` (under SYSTEM).
Format: `yyyy-MM-dd HH:mm:ss [Level] Message`. Errors additionally go to
stderr and appear red in NinjaOne.

## Changelog

See the header comment in `Install-WingetMachine.ps1`.

## Disclaimer

Provided AS IS, without warranty of any kind. Use at your own risk.
