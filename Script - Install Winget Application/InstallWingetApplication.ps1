<#
.SYNOPSIS
[Version 1.4.0] Installs one or more Winget packages in machine scope under SYSTEM.
Change Log:
- 1.4.4: Removed all auto-bootstrap logic (Add-AppxPackage is denied under SYSTEM,
         module installs are out of scope). If winget is missing or broken the script
         fails fast with remediation guidance.
- 1.4.2: winget discovery now probes each candidate with 'winget --version' and falls
         back to the next one. Fixes endpoints where the newest WindowsApps folder is a
         staged/broken App Installer that crashes with 0xC0000135 (STATUS_DLL_NOT_FOUND).
- 1.4.1: Fixed empty exit codes from Start-Process -PassThru (PS 5.1 requires caching
         the process handle before exit, otherwise .ExitCode is $null). Added null-safe
         exit code reporting.
- 1.4.0: QA rework:
         * Fixed output-stream contamination (Write-Log no longer pollutes function return values).
         * Deterministic exit codes: exit 1 on any package failure or fatal error.
         * Locale-independent handling: scope-check parse failures no longer block installs;
           "already installed" detected via winget exit codes (0x8A150061 / 0x8A15002B) first.
         * Device architecture detected from PROCESSOR_ARCHITECTURE(/W6432); the 'architecture'
           input is now the *requested* target architecture and is passed to winget install.
         * Hardened bootstrap (TLS 1.2, -UseBasicParsing, try/catch, temp cleanup, clear guidance).
         * Proper argument quoting for Start-Process + input validation of Id/Version (injection safe).
         * Install runs with a timeout; timeouts kill the whole process tree (taskkill /T).
         * winget discovery works under SYSTEM and PowerShell 7 (WindowsApps scan, Appx fallback).
         * Shortcut copy uses token matching only - no more "copy whatever changed last" fallback.
         * Elevation check, guarded file logging, temp file cleanup, PSSA-friendly verbs,
           removed dead code and automatic-variable shadowing, special-folder APIs for paths.
- 1.3.1: Removed pinning workflow and clarified NinjaOne custom field inputs.
- 1.3.0: Optional exact-version install + installed-version pinning with end summary.
- 1.2.0: Copy Start Menu shortcut to Public Desktop after install.
- 1.1.1: Standardized warning output to [Warning].
- 1.1.0: Single-file packaging.
Example output:
2026-09-22 12:00:00 [Info] Starting winget machine install for Ids=Microsoft.PowerShell
2026-09-22 12:00:00 [Info] LogPath=C:\Windows\Temp\winget-install-Microsoft.PowerShell-20260922-120000.log

.DESCRIPTION
Ensures winget is available, validates machine scope support where possible, and installs
with RMM-friendly logging to stdout/stderr and a temp log file. When used in NinjaOne,
configure custom fields for `wingetId` (comma-separated for multiple packages),
`wingetVersion` (optional, comma-separated, must match Id count), and `architecture`
(optional target architecture: x64/x86/arm64) and map them to dynamic script variables.

Exit codes: 0 = all packages succeeded; 1 = at least one package failed or a fatal error occurred.

.NOTES
Compatibility: Windows PowerShell 5.1 and PowerShell 7. Designed to run as SYSTEM.
Requires winget >= 1.4 on the endpoint for --disable-interactivity; SYSTEM support
requires a reasonably current App Installer.
Provided AS IS, without warranty of any kind, express or implied, including
merchantability, fitness for a particular purpose, or noninfringement. Use at
your own risk. The author shall not be liable for any claim, damages, or other
liability arising from, out of, or in connection with the script or its use.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$Id = $env:wingetId,

    [Parameter(Mandatory = $false)]
    [string]$Version = $env:wingetVersion,

    [Parameter(Mandatory = $false)]
    [string]$LogPath,

    [Parameter(Mandatory = $false)]
    [string]$Architecture = $env:architecture,

    [Parameter(Mandatory = $false)]
    [int]$ShowTimeoutSeconds = 120,

    [Parameter(Mandatory = $false)]
    [int]$InstallTimeoutSeconds = 1800
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

# Locale-independent winget result codes (subset)
$script:WingetExitPackageAlreadyInstalled = -1978335135  # 0x8A150061 APPINSTALLER_CLI_ERROR_PACKAGE_ALREADY_INSTALLED
$script:WingetExitNoApplicableUpgrade     = -1978335189  # 0x8A15002B APPINSTALLER_CLI_ERROR_UPDATE_NOT_APPLICABLE
$script:WingetExitNoPackageFound          = -1978335212  # 0x8A150014 APPINSTALLER_CLI_ERROR_NO_APPLICATIONS_FOUND

$script:LogPath = $null

function Write-Log {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Info', 'Warning', 'Error')][string]$Level,
        [Parameter(Mandatory = $true)][string]$Message
    )

    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"

    # Write-Host / WriteErrorLine keep the success output stream clean so that
    # function return values are never contaminated by log lines.
    if ($Level -eq 'Error') {
        $Host.UI.WriteErrorLine($line)
    } else {
        Write-Host $line
    }

    if ($script:LogPath) {
        try {
            Add-Content -Path $script:LogPath -Value $line -ErrorAction Stop
        } catch {
            # Never let file logging take the whole script down.
        }
    }
}

function Test-IsElevated {
    $identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function ConvertTo-NormalizedArchitecture {
    param([Parameter(Mandatory = $false)][string]$Architecture)

    if ([string]::IsNullOrWhiteSpace($Architecture)) { return $null }
    $value = $Architecture.Trim().ToLowerInvariant()

    switch ($value) {
        'amd64'   { return 'x64' }
        'x64'     { return 'x64' }
        'x86'     { return 'x86' }
        'x32'     { return 'x86' }
        'i386'    { return 'x86' }
        'arm64'   { return 'arm64' }
        'aarch64' { return 'arm64' }
        default   { return $value }
    }
}

function Get-DeviceArchitecture {
    # PROCESSOR_ARCHITEW6432 is only set inside 32-bit processes on a 64-bit OS.
    $arch = $env:PROCESSOR_ARCHITEW6432
    if ([string]::IsNullOrWhiteSpace($arch)) { $arch = $env:PROCESSOR_ARCHITECTURE }

    $normalized = ConvertTo-NormalizedArchitecture -Architecture $arch
    if (-not $normalized) { $normalized = 'x64' }
    return $normalized
}

function ConvertTo-ProcessArgumentString {
    # Quotes arguments correctly for Start-Process -ArgumentList (single string).
    param([Parameter(Mandatory = $true)][string[]]$ArgumentList)

    $escaped = foreach ($arg in $ArgumentList) {
        $value = [string]$arg
        if ($value.Length -eq 0 -or $value -match '[\s"]') {
            '"' + ($value -replace '(\\*)"', '$1$1\"') + '"'
        } else {
            $value
        }
    }

    return ($escaped -join ' ')
}

function Get-WingetOutputTail {
    param(
        [Parameter(Mandatory = $false)][string]$Output,
        [Parameter(Mandatory = $false)][int]$MaxLines = 6
    )

    if ([string]::IsNullOrWhiteSpace($Output)) { return '' }

    $lines = $Output -split "\r?\n"
    $filtered = @(foreach ($line in $lines) {
        $trimmed = $line.Trim()
        if (-not $trimmed) { continue }
        if ($trimmed -match '\b(KB|MB|GB)\b\s*/\s*[\d\.]+') { continue }
        if ($trimmed -match '^[\s\-\|\\/]+$') { continue }
        $trimmed
    })

    if ($filtered.Count -eq 0) { return '' }

    return (($filtered | Select-Object -Last $MaxLines) -join "`n")
}

function Invoke-WingetProcess {
    # Runs winget with a hard timeout. On timeout the whole process tree is killed
    # so that spawned child installers (msiexec etc.) do not linger.
    param(
        [Parameter(Mandatory = $true)][string]$WingetPath,
        [Parameter(Mandatory = $true)][string[]]$ArgumentList,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )

    $token  = [guid]::NewGuid().ToString('N')
    $tmpOut = Join-Path -Path $env:TEMP -ChildPath "winget-$token.out.log"
    $tmpErr = Join-Path -Path $env:TEMP -ChildPath "winget-$token.err.log"
    $argString = ConvertTo-ProcessArgumentString -ArgumentList $ArgumentList

    try {
        $process = Start-Process -FilePath $WingetPath -ArgumentList $argString -NoNewWindow -PassThru `
            -RedirectStandardOutput $tmpOut -RedirectStandardError $tmpErr

        # PS 5.1 quirk: without touching .Handle before the process exits,
        # .ExitCode is $null afterwards (Start-Process -PassThru).
        $null = $process.Handle

        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            try {
                Start-Process -FilePath (Join-Path -Path $env:SystemRoot -ChildPath 'System32\taskkill.exe') `
                    -ArgumentList "/PID $($process.Id) /T /F" -NoNewWindow -Wait -ErrorAction Stop
            } catch {
                try { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue } catch { }
            }
            return [pscustomobject]@{
                Output   = "Timed out after $TimeoutSeconds seconds"
                ExitCode = 124
                TimedOut = $true
            }
        }

        # Second WaitForExit() (without timeout) ensures redirected output is fully flushed.
        $process.WaitForExit()

        $stdout = ''
        if (Test-Path -Path $tmpOut) {
            $content = Get-Content -Path $tmpOut -Raw -ErrorAction SilentlyContinue
            if ($content) { $stdout = $content }
        }
        if (Test-Path -Path $tmpErr) {
            $errContent = Get-Content -Path $tmpErr -Raw -ErrorAction SilentlyContinue
            if ($errContent -and $errContent.Trim().Length -gt 0) {
                $stdout = $stdout + "`n" + $errContent
            }
        }

        # Belt and braces: with the handle cached this should never be null,
        # but never let a null exit code masquerade as anything meaningful.
        $exitCode = $process.ExitCode
        if ($null -eq $exitCode) { $exitCode = -1 }

        return [pscustomobject]@{
            Output   = $stdout
            ExitCode = $exitCode
            TimedOut = $false
        }
    } finally {
        Remove-Item -Path $tmpOut, $tmpErr -Force -ErrorAction SilentlyContinue
    }
}

function ConvertTo-WingetPackageInfo {
    # NOTE: winget show output is localized to the OS display language. On non-English
    # systems the keywords below will not match; callers must treat an empty installer
    # list as "indeterminate", never as "machine scope unsupported".
    param([Parameter(Mandatory = $true)][object]$Output)

    $text = if ($Output -is [array]) { $Output -join "`n" } else { [string]$Output }
    $lines = $text -split "\r?\n"
    $installers = @()
    $current = $null

    foreach ($line in $lines) {
        if ($line -match '^\s*Installer:\s*$') {
            if ($current) { $installers += [pscustomobject]$current }
            $current = @{}
            continue
        }

        if ($null -ne $current -and $line -match '^\s*([^:]+):\s*(.+)$') {
            $key   = $Matches[1].Trim().ToLowerInvariant()
            $value = $Matches[2].Trim()

            switch ($key) {
                'scope'                  { $current['Scope'] = $value }
                'installer architecture' { $current['Architecture'] = $value }
                'architecture'           { $current['Architecture'] = $value }
            }
        }
    }

    if ($current) { $installers += [pscustomobject]$current }

    if ($installers.Count -eq 0) {
        $regexOptions = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor `
                        [System.Text.RegularExpressions.RegexOptions]::Multiline
        $scopeMatches = [regex]::Matches($text, '^\s*Scope:\s*(\S+)\s*$', $regexOptions)
        foreach ($scopeMatch in $scopeMatches) {
            $installers += [pscustomobject]@{ Scope = $scopeMatch.Groups[1].Value }
        }
    }

    return [pscustomobject]@{ Installers = $installers }
}

function Test-WingetExecutable {
    # A staged or broken App Installer folder launches winget.exe but crashes it
    # immediately with 0xC0000135 (STATUS_DLL_NOT_FOUND). Probe before committing.
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        $probe = Invoke-WingetProcess -WingetPath $Path -ArgumentList @('--version') -TimeoutSeconds 30
        if ($probe.TimedOut -or $probe.ExitCode -ne 0) {
            $hexCode = '0x{0:X8}' -f ($probe.ExitCode -band 0xFFFFFFFF)
            Write-Log -Level Warning -Message "winget candidate failed startup probe (exit code $($probe.ExitCode) / $hexCode): $Path"
            return $false
        }
        return $true
    } catch {
        Write-Log -Level Warning -Message "winget candidate probe failed: $Path ($_)"
        return $false
    }
}

function Get-WingetPath {
    $candidates = New-Object System.Collections.Generic.List[string]

    $cmd = Get-Command -Name 'winget.exe' -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source) { $candidates.Add($cmd.Source) }

    # Under SYSTEM winget is usually not on PATH -> scan WindowsApps directly.
    # This also works on PowerShell 7, where the Appx module is unreliable.
    # Collect ALL version folders (newest first); a newer folder can be broken
    # while an older one still works.
    $appsRoot = Join-Path -Path $env:ProgramFiles -ChildPath 'WindowsApps'
    if (Test-Path -Path $appsRoot) {
        $dirs = @(Get-ChildItem -Path $appsRoot -Directory -Filter 'Microsoft.DesktopAppInstaller_*' -ErrorAction SilentlyContinue)
        $sorted = @($dirs | ForEach-Object {
            $parsedVersion = $null
            if ($_.Name -match '_(\d+(?:\.\d+){1,3})_') {
                try { $parsedVersion = [version]$Matches[1] } catch { $parsedVersion = $null }
            }
            [pscustomobject]@{ Directory = $_; Version = $parsedVersion }
        } | Sort-Object -Property Version -Descending)

        foreach ($entry in $sorted) {
            $candidate = Join-Path -Path $entry.Directory.FullName -ChildPath 'winget.exe'
            if (Test-Path -Path $candidate) { $candidates.Add($candidate) }
        }
    }

    # Fallback: Appx query (reliable on Windows PowerShell only).
    if ($PSVersionTable.PSEdition -ne 'Core') {
        try {
            $apps = Get-AppxPackage -AllUsers -Name 'Microsoft.DesktopAppInstaller' -ErrorAction Stop
            foreach ($app in @($apps | Where-Object { $_.InstallLocation } | Sort-Object -Property Version -Descending)) {
                $candidate = Join-Path -Path $app.InstallLocation -ChildPath 'winget.exe'
                if (Test-Path -Path $candidate) { $candidates.Add($candidate) }
            }
        } catch {
            Write-Log -Level Warning -Message "Get-AppxPackage lookup failed: $_"
        }
    }

    foreach ($candidate in @($candidates | Select-Object -Unique)) {
        if (Test-WingetExecutable -Path $candidate) { return $candidate }
    }

    return $null
}

function Initialize-Winget {
    $path = Get-WingetPath
    if ($path) { return $path }

    # No auto-bootstrap: Add-AppxPackage is denied under SYSTEM (0x80073CF9) and
    # installing PSGallery modules is out of scope for an install script.
    # Repairing winget is a separate remediation task.
    throw ('winget is not available or not functional on this device. Remediation (run once, elevated): ' +
           'Install-Module Microsoft.WinGet.Client -Force; Repair-WinGetPackageManager -AllUsers -Force -Latest')
}

function Get-WingetPackageInfo {
    param(
        [Parameter(Mandatory = $true)][string]$WingetPath,
        [Parameter(Mandatory = $true)][string]$PackageId,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )

    Write-Log -Level Info -Message "Running winget show for Id=$PackageId"
    $showStart = Get-Date
    $result = Invoke-WingetProcess -WingetPath $WingetPath -ArgumentList @(
        'show', '--id', $PackageId, '--source', 'winget',
        '--accept-source-agreements', '--disable-interactivity'
    ) -TimeoutSeconds $TimeoutSeconds
    $elapsed = New-TimeSpan -Start $showStart -End (Get-Date)
    Write-Log -Level Info -Message "Completed winget show (elapsed $([math]::Round($elapsed.TotalSeconds, 1))s, exit code $($result.ExitCode))"

    if ($result.TimedOut) {
        Write-Log -Level Warning -Message 'winget show timed out; skipping machine scope check'
        return [pscustomobject]@{ Installers = @(); SkipScopeCheck = $true }
    }

    if ($result.ExitCode -eq $script:WingetExitNoPackageFound) {
        throw "Package Id=$PackageId not found in source 'winget' (exit code 0x8A150014)"
    }

    if ($result.ExitCode -ne 0) {
        $tail = Get-WingetOutputTail -Output ([string]$result.Output)
        Write-Log -Level Warning -Message "winget show returned exit code $($result.ExitCode); skipping machine scope check. Output: $tail"
        return [pscustomobject]@{ Installers = @(); SkipScopeCheck = $true }
    }

    return ConvertTo-WingetPackageInfo -Output $result.Output
}

function Get-PerPackageOptionMap {
    param(
        [Parameter(Mandatory = $true)][string[]]$Ids,
        [Parameter(Mandatory = $false)][string]$RawValue,
        [Parameter(Mandatory = $true)][string]$OptionName
    )

    $map = @{}
    if ([string]::IsNullOrWhiteSpace($RawValue)) { return $map }

    $values = @($RawValue -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($values.Count -eq 0) { return $map }

    if ($values.Count -ne $Ids.Count) {
        throw "$OptionName count ($($values.Count)) must match Id count ($($Ids.Count))"
    }

    for ($i = 0; $i -lt $Ids.Count; $i++) {
        $map[$Ids[$i]] = $values[$i]
    }

    return $map
}

function Get-InstallersForArchitecture {
    param(
        [Parameter(Mandatory = $true)][object]$PkgInfo,
        [Parameter(Mandatory = $true)][string]$Architecture
    )

    $normalizedArch = ConvertTo-NormalizedArchitecture -Architecture $Architecture
    $installers = @()

    foreach ($installer in @($PkgInfo.Installers)) {
        $installerArch = ConvertTo-NormalizedArchitecture -Architecture $installer.Architecture
        if (-not $installerArch -or $installerArch -eq $normalizedArch) {
            $installers += $installer
        }
    }

    return $installers
}

function Test-MachineScopeForArchitecture {
    param(
        [Parameter(Mandatory = $true)][object]$PkgInfo,
        [Parameter(Mandatory = $true)][string]$Architecture
    )

    if (-not $PkgInfo -or @($PkgInfo.Installers).Count -eq 0) { return $false }

    $matching = @(Get-InstallersForArchitecture -PkgInfo $PkgInfo -Architecture $Architecture)
    if ($matching.Count -eq 0) { return $false }

    $scopes = @($matching |
        Where-Object { $_.Scope } |
        ForEach-Object { $_.Scope.ToString().ToLowerInvariant() })

    if ($scopes -contains 'machine') { return $true }
    # Assumption: installers without a declared scope may still support machine scope.
    if ($scopes.Count -eq 0) { return $true }

    return (@($scopes | Where-Object { $_ -ne 'user' }).Count -gt 0)
}

function Install-WingetPackage {
    param(
        [Parameter(Mandatory = $true)][string]$WingetPath,
        [Parameter(Mandatory = $true)][string]$PackageId,
        [Parameter(Mandatory = $false)][string]$PackageVersion,
        [Parameter(Mandatory = $false)][string]$RequestedArchitecture,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )

    $argsList = @(
        'install', '--id', $PackageId, '--source', 'winget', '--scope', 'machine',
        '--silent', '--accept-package-agreements', '--accept-source-agreements',
        '--disable-interactivity'
    )

    if (-not [string]::IsNullOrWhiteSpace($PackageVersion)) {
        Write-Log -Level Info -Message "Running winget install for Id=$PackageId Version=$PackageVersion"
        $argsList += @('--version', $PackageVersion)
    } else {
        Write-Log -Level Info -Message "Running winget install for Id=$PackageId"
    }

    if (-not [string]::IsNullOrWhiteSpace($RequestedArchitecture)) {
        $argsList += @('--architecture', $RequestedArchitecture)
    }

    $result = Invoke-WingetProcess -WingetPath $WingetPath -ArgumentList $argsList -TimeoutSeconds $TimeoutSeconds

    if ($result.TimedOut) {
        throw "winget install timed out after $TimeoutSeconds seconds for Id=$PackageId"
    }

    if ($result.ExitCode -eq 0) {
        Write-Log -Level Info -Message 'Install completed successfully'
        return [pscustomobject]@{ Status = 'Installed' }
    }

    $rawOutput = [string]$result.Output
    $tail = Get-WingetOutputTail -Output $rawOutput
    if ([string]::IsNullOrWhiteSpace($tail)) { $tail = $rawOutput }
    $hexCode = '0x{0:X8}' -f ($result.ExitCode -band 0xFFFFFFFF)

    # Surface the wrapped installer's own exit code (e.g. Citrix 40041) when winget reports it.
    if ($rawOutput -match 'Installer failed with exit code:\s*(-?\d+)') {
        Write-Log -Level Warning -Message "Wrapped installer reported its own exit code: $($Matches[1]) (vendor-specific, look it up in the vendor's documentation)"
    }

    # Exit-code based detection first (locale-independent); English text match as fallback only.
    $alreadyInstalled =
        ($result.ExitCode -eq $script:WingetExitPackageAlreadyInstalled) -or
        ($result.ExitCode -eq $script:WingetExitNoApplicableUpgrade) -or
        ($tail -match '(?i)already installed') -or
        ($tail -match '(?i)no available upgrade found') -or
        ($tail -match '(?i)no newer package versions are available')

    if ($alreadyInstalled) {
        Write-Log -Level Warning -Message "winget install indicates already installed or no applicable upgrade for Id=$PackageId (exit code $hexCode)"
        return [pscustomobject]@{ Status = 'AlreadyInstalled' }
    }

    Write-Log -Level Error -Message "winget install failed (exit code $($result.ExitCode) / $hexCode): $tail"
    throw "winget install failed for Id=$PackageId (exit code $hexCode)"
}

function Get-StartMenuShortcuts {
    $path = [Environment]::GetFolderPath('CommonPrograms')
    if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path -Path $path)) { return @() }
    return @(Get-ChildItem -Path $path -Filter '*.lnk' -Recurse -ErrorAction SilentlyContinue)
}

function Find-PackageShortcut {
    param(
        [Parameter(Mandatory = $false)][object[]]$Shortcuts,
        [Parameter(Mandatory = $true)][string]$PackageId,
        [Parameter(Mandatory = $true)][datetime]$InstallStart
    )

    if (-not $Shortcuts -or @($Shortcuts).Count -eq 0) { return $null }

    $graceStart = $InstallStart.AddMinutes(-2)
    $recent = @($Shortcuts | Where-Object { $_.LastWriteTime -ge $graceStart })
    if ($recent.Count -eq 0) { return $null }

    # Token-based matching: 'Microsoft.PowerShell' matches a shortcut named 'PowerShell 7 (x64)'.
    $tokens = @($PackageId -split '[._\-\s]+' |
        Where-Object { $_.Length -ge 3 } |
        ForEach-Object { $_.ToLowerInvariant() })
    if ($tokens.Count -eq 0) { $tokens = @($PackageId.ToLowerInvariant()) }

    $nameMatches = @(foreach ($shortcut in $recent) {
        $baseName = $shortcut.BaseName.ToLowerInvariant()
        foreach ($token in $tokens) {
            if ($baseName.Contains($token)) { $shortcut; break }
        }
    })

    if ($nameMatches.Count -gt 0) {
        return ($nameMatches | Sort-Object -Property LastWriteTime -Descending | Select-Object -First 1)
    }

    # Deliberately no fallback to arbitrary recently changed shortcuts: with parallel
    # installs/updates that would copy unrelated shortcuts to every desktop.
    return $null
}

function Copy-PublicDesktopShortcut {
    param(
        [Parameter(Mandatory = $true)][string]$PackageId,
        [Parameter(Mandatory = $true)][datetime]$InstallStart
    )

    $publicDesktop = [Environment]::GetFolderPath('CommonDesktopDirectory')
    if ([string]::IsNullOrWhiteSpace($publicDesktop) -or -not (Test-Path -Path $publicDesktop)) {
        Write-Log -Level Warning -Message "Public Desktop not found at '$publicDesktop'"
        return [pscustomobject]@{ Status = 'PublicDesktopMissing' }
    }

    $shortcuts = Get-StartMenuShortcuts
    if (@($shortcuts).Count -eq 0) {
        Write-Log -Level Warning -Message 'No Start Menu shortcuts found to copy'
        return [pscustomobject]@{ Status = 'NoStartMenuShortcuts' }
    }

    $match = Find-PackageShortcut -Shortcuts $shortcuts -PackageId $PackageId -InstallStart $InstallStart
    if (-not $match) {
        Write-Log -Level Warning -Message "No suitable Start Menu shortcut found for Id=$PackageId"
        return [pscustomobject]@{ Status = 'NotFound' }
    }

    $dest = Join-Path -Path $publicDesktop -ChildPath $match.Name
    if (Test-Path -Path $dest) {
        Write-Log -Level Info -Message "Public Desktop shortcut already exists: $dest"
        return [pscustomobject]@{ Status = 'AlreadyExists' }
    }

    try {
        Copy-Item -Path $match.FullName -Destination $dest -Force -ErrorAction Stop
        Write-Log -Level Info -Message "Copied shortcut to Public Desktop: $dest"
        return [pscustomobject]@{ Status = 'Copied' }
    } catch {
        Write-Log -Level Warning -Message "Failed to copy shortcut to Public Desktop: $_"
        return [pscustomobject]@{ Status = 'CopyFailed' }
    }
}

function Format-SummaryValue {
    param([Parameter(Mandatory = $false)][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return 'n/a' }
    return $Value
}

function Write-ExecutionSummary {
    param(
        [Parameter(Mandatory = $true)][object[]]$Results,
        [Parameter(Mandatory = $true)][int]$SuccessCount,
        [Parameter(Mandatory = $true)][int]$FailureCount
    )

    Write-Log -Level Info -Message "Completed. Successes=$SuccessCount Failures=$FailureCount"

    foreach ($result in $Results) {
        $requestedVersion = if ([string]::IsNullOrWhiteSpace($result.RequestedVersion)) { 'latest' } else { $result.RequestedVersion }

        $message = "Summary Id=$($result.Id); RequestedVersion=$requestedVersion; " +
                   "ScopeCheck=$(Format-SummaryValue -Value $result.ScopeCheck); " +
                   "Install=$(Format-SummaryValue -Value $result.InstallStatus); " +
                   "Shortcut=$(Format-SummaryValue -Value $result.ShortcutStatus)"
        if (-not [string]::IsNullOrWhiteSpace($result.Error)) {
            $message = "$message; Error=$($result.Error)"
        }

        Write-Log -Level Info -Message $message
    }
}

function Invoke-WingetMachineInstall {
    param(
        [Parameter(Mandatory = $false)][string]$Id,
        [Parameter(Mandatory = $false)][string]$Version,
        [Parameter(Mandatory = $false)][string]$LogPath,
        [Parameter(Mandatory = $false)][string]$RequestedArchitecture,
        [Parameter(Mandatory = $true)][int]$ShowTimeoutSeconds,
        [Parameter(Mandatory = $true)][int]$InstallTimeoutSeconds
    )

    $ids = @(($Id -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($ids.Count -eq 0) {
        throw "No package IDs provided. Set the 'wingetId' custom field or the -Id parameter."
    }

    if ([string]::IsNullOrWhiteSpace($LogPath)) {
        $safeId = ($ids -join '_') -replace '[^a-zA-Z0-9._-]', '_'
        if ($safeId.Length -gt 60) { $safeId = $safeId.Substring(0, 60) }
        $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $LogPath = Join-Path -Path $env:TEMP -ChildPath "winget-install-$safeId-$timestamp.log"
    }
    $script:LogPath = $LogPath

    $versionMap = Get-PerPackageOptionMap -Ids $ids -RawValue $Version -OptionName 'Version'

    Write-Log -Level Info -Message "Starting winget machine install for Ids=$($ids -join ', ')"
    Write-Log -Level Info -Message "LogPath=$LogPath"
    Write-Log -Level Info -Message "OS=$([System.Environment]::OSVersion.VersionString)"
    Write-Log -Level Info -Message "PowerShell=$($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"
    Write-Log -Level Info -Message "User=$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"

    if (-not (Test-IsElevated)) {
        throw 'Machine scope installs require an elevated context (SYSTEM or administrator)'
    }

    $wingetPath = Initialize-Winget
    Write-Log -Level Info -Message "Using winget at $wingetPath"

    $deviceArch = Get-DeviceArchitecture
    Write-Log -Level Info -Message "Device architecture: $deviceArch"

    $explicitArch = ConvertTo-NormalizedArchitecture -Architecture $RequestedArchitecture
    $scopeArch = if ($explicitArch) { $explicitArch } else { $deviceArch }
    if ($explicitArch) {
        Write-Log -Level Info -Message "Requested target architecture: $explicitArch"
    }

    $successCount = 0
    $failureCount = 0
    $results = @()

    foreach ($pkgId in $ids) {
        $requestedVersion = ''
        if ($versionMap.ContainsKey($pkgId)) { $requestedVersion = $versionMap[$pkgId] }

        $result = [ordered]@{
            Id               = $pkgId
            RequestedVersion = $requestedVersion
            ScopeCheck       = 'Pending'
            InstallStatus    = 'NotAttempted'
            ShortcutStatus   = 'NotAttempted'
            Error            = ''
        }

        Write-Log -Level Info -Message "Processing Id=$pkgId"

        try {
            # Ids/versions come from RMM custom fields: validate before they reach a command line.
            if ($pkgId -notmatch '^[A-Za-z0-9][A-Za-z0-9.+_\-]*$') {
                throw "Invalid package Id format: '$pkgId'"
            }
            if ($requestedVersion -and $requestedVersion -notmatch '^[A-Za-z0-9][A-Za-z0-9.+_\-]*$') {
                throw "Invalid version format: '$requestedVersion'"
            }

            $installStart = Get-Date
            $pkg = Get-WingetPackageInfo -WingetPath $wingetPath -PackageId $pkgId -TimeoutSeconds $ShowTimeoutSeconds

            if ($pkg.SkipScopeCheck -eq $true) {
                Write-Log -Level Warning -Message "Skipping machine scope check for Id=$pkgId"
                $result.ScopeCheck = 'Skipped'
            } elseif (@($pkg.Installers).Count -eq 0) {
                # winget show output is localized; an unparseable result must not block the install.
                Write-Log -Level Warning -Message 'Could not parse installer metadata (possibly localized winget output); proceeding without scope validation'
                $result.ScopeCheck = 'Indeterminate'
            } else {
                $archInstallers = @(Get-InstallersForArchitecture -PkgInfo $pkg -Architecture $scopeArch)
                Write-Log -Level Info -Message "Matching installers for ${scopeArch}: $($archInstallers.Count)"
                if (-not (Test-MachineScopeForArchitecture -PkgInfo $pkg -Architecture $scopeArch)) {
                    $result.ScopeCheck = 'Rejected'
                    throw "Machine scope not supported for Id=$pkgId on architecture $scopeArch"
                }
                $result.ScopeCheck = 'Validated'
                Write-Log -Level Info -Message 'Machine scope supported, starting install'
            }

            $installResult = Install-WingetPackage -WingetPath $wingetPath -PackageId $pkgId `
                -PackageVersion $requestedVersion -RequestedArchitecture $explicitArch `
                -TimeoutSeconds $InstallTimeoutSeconds
            $result.InstallStatus = $installResult.Status

            $shortcutResult = Copy-PublicDesktopShortcut -PackageId $pkgId -InstallStart $installStart
            $result.ShortcutStatus = $shortcutResult.Status

            Write-Log -Level Info -Message "Id=$pkgId completed successfully"
            $successCount += 1
        } catch {
            $failureCount += 1
            $result.Error = $_.ToString()
            if ($result.InstallStatus -eq 'NotAttempted') {
                $result.InstallStatus = 'Failed'
            }
            Write-Log -Level Error -Message "Id=$pkgId failed: $_"
        }

        $results += [pscustomobject]$result
    }

    Write-ExecutionSummary -Results $results -SuccessCount $successCount -FailureCount $failureCount

    return [pscustomobject]@{
        SuccessCount = $successCount
        FailureCount = $failureCount
    }
}

# ---------------------------------------------------------------------------
# Entry point with deterministic exit codes for RMM evaluation.
# ---------------------------------------------------------------------------
$script:ExitCode = 0
try {
    $summary = Invoke-WingetMachineInstall -Id $Id -Version $Version -LogPath $LogPath `
        -RequestedArchitecture $Architecture -ShowTimeoutSeconds $ShowTimeoutSeconds `
        -InstallTimeoutSeconds $InstallTimeoutSeconds

    if ($summary.FailureCount -gt 0) {
        Write-Log -Level Error -Message "One or more package installs failed (Failures=$($summary.FailureCount))"
        $script:ExitCode = 1
    }
} catch {
    Write-Log -Level Error -Message "Fatal error: $_"
    $script:ExitCode = 1
}

exit $script:ExitCode
