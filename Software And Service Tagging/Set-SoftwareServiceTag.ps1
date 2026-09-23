<#
.SYNOPSIS
    NinjaOne software and service tagging: checks a device for installed software, services, running
    processes or listening TCP ports and writes the result into a text custom field.

.DESCRIPTION
    Runs as a NinjaOne automation (Windows PowerShell 5.1) or locally for testing.
    1. What to look for comes from the script variable 'checks', one rule per line or separated by ';'.
       Rule syntax: [type:]pattern[=text]   (type: software, service, process, port, any)
    2. Every rule is evaluated against the local inventory:
         software  installed software from the uninstall registry keys (HKLM 32/64 bit + all user hives)
         service   Windows services, matched on service name and display name
         process   running processes, matched on process name and file description
         port      listening TCP ports (numeric pattern)
         any       software, then service, then process; the first hit wins (default)
    3. Every rule that matches produces one text: either the text after '=' or the default sentence
       for that type, e.g. "Has Veeam installed" or "Has service VeeamBackupSvc".
    4. All texts are joined and written into the custom field 'customFieldName' via Ninja-Property-Set.

    Installed software is read from the registry on purpose. Win32_Product (Get-WmiObject Win32_Product)
    would trigger an MSI reconfiguration of every installed package and is far too slow and invasive.

    NinjaOne script variables (injected as environment variables, use these calculated names):
        customFieldName   Name of the target custom field (required, must be writable by scripts)
        checks            The rules, one per line or separated by ';' (required)

    Everything else is a constant in the "Defaults" block below - change it there if needed.
    -DryRun only logs the value instead of writing it; it can be passed in the NinjaOne
    "Script parameters" field of a run or schedule.

    Exit codes: 0 = custom field written, 1 = error.

    The source is kept ASCII-only on purpose: Windows PowerShell 5.1 reads BOM-less scripts as ANSI.

.EXAMPLE
    .\Set-SoftwareServiceTag.ps1 -CustomFieldName softwareTag -Checks 'Veeam'
    Veeam found -> custom field 'softwareTag' = "Has Veeam installed"

.EXAMPLE
    .\Set-SoftwareServiceTag.ps1 -CustomFieldName softwareTag -Checks 'service:VeeamBackupSvc=Backup Server; service:NTDS=Domain Controller' -DryRun
    Custom field 'softwareTag' would be set to "Backup Server, Domain Controller"
#>
param(
    [string]$CustomFieldName = $env:customFieldName,
    [string]$Checks = $env:checks,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

#region Defaults

# Deliberately constants and not script variables: these are set once for the whole environment.
$SoftwareText = 'Has {0} installed'      # {0} = the pattern of the rule
$ServiceText = 'Has service {0}'
$ProcessText = 'Has {0} running'
$PortText = 'Listening on port {0}'
# Multi-line custom field: one match per line. Single-line text field: use ', ' and 255 instead.
$Separator = "`r`n"                      # joins several matches
$NoMatchValue = ''                       # written when nothing matches, empty clears the field
$MaxLength = 10000                       # length limit of the custom field (single-line text: 255)
$RequireServiceRunning = $false          # $true: a service only counts while it is running

#endregion

# Write-Host instead of Write-Output: log lines inside functions must not end up in their return values
function Write-Log([string]$Message) {
    Write-Host ('[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss'), $Message)
}

#region Inventory

$script:SoftwareInventory = $null
$script:ServiceInventory = $null
$script:ProcessInventory = $null
$script:PortInventory = $null

function Get-SoftwareInventory {
    if ($null -ne $script:SoftwareInventory) { return $script:SoftwareInventory }

    $keys = New-Object System.Collections.Generic.List[string]
    $keys.Add('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
    $keys.Add('HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')

    # Per-user installations: the script runs as SYSTEM, so HKCU is not the user's hive
    try {
        foreach ($hive in Get-ChildItem -Path 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue) {
            if ($hive.PSChildName -like '*_Classes') { continue }
            $keys.Add(('Registry::HKEY_USERS\{0}\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' -f $hive.PSChildName))
            $keys.Add(('Registry::HKEY_USERS\{0}\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' -f $hive.PSChildName))
        }
    } catch {
        Write-Log ('  Warning: user hives could not be enumerated ({0})' -f $_.Exception.Message)
    }

    $items = New-Object System.Collections.Generic.List[string]
    foreach ($key in $keys) {
        if (-not (Test-Path -Path $key)) { continue }
        foreach ($entry in Get-ChildItem -Path $key -ErrorAction SilentlyContinue) {
            $properties = $null
            try { $properties = Get-ItemProperty -Path $entry.PSPath -ErrorAction Stop } catch { continue }
            if (-not $properties.DisplayName) { continue }
            if ($properties.SystemComponent -eq 1) { continue }
            $items.Add([string]$properties.DisplayName)
        }
    }

    $script:SoftwareInventory = @($items | Sort-Object -Unique)
    Write-Log ('  Inventory: {0} installed software entries' -f $script:SoftwareInventory.Count)
    $script:SoftwareInventory
}

function Get-ServiceInventory {
    if ($null -ne $script:ServiceInventory) { return $script:ServiceInventory }

    try {
        $script:ServiceInventory = @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{ Name = $_.Name; DisplayName = $_.DisplayName; State = [string]$_.State }
        })
    } catch {
        Write-Log ('  Warning: Win32_Service not available ({0}), falling back to Get-Service' -f $_.Exception.Message)
        $script:ServiceInventory = @(Get-Service -ErrorAction SilentlyContinue | ForEach-Object {
            [pscustomobject]@{ Name = $_.Name; DisplayName = $_.DisplayName; State = [string]$_.Status }
        })
    }

    Write-Log ('  Inventory: {0} services' -f $script:ServiceInventory.Count)
    $script:ServiceInventory
}

function Get-ProcessInventory {
    if ($null -ne $script:ProcessInventory) { return $script:ProcessInventory }

    $script:ProcessInventory = @(Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject]@{ Name = $_.Name; Description = [string]$_.Description }
    } | Sort-Object -Property Name -Unique)
    Write-Log ('  Inventory: {0} running processes' -f $script:ProcessInventory.Count)
    $script:ProcessInventory
}

function Get-PortInventory {
    if ($null -ne $script:PortInventory) { return $script:PortInventory }

    $ports = New-Object System.Collections.Generic.List[int]
    if (Get-Command -Name Get-NetTCPConnection -ErrorAction SilentlyContinue) {
        try {
            foreach ($connection in Get-NetTCPConnection -State Listen -ErrorAction Stop) {
                $ports.Add([int]$connection.LocalPort)
            }
        } catch {
            Write-Log ('  Warning: Get-NetTCPConnection failed ({0})' -f $_.Exception.Message)
        }
    }
    if ($ports.Count -eq 0) {
        # Fallback for older systems: parse netstat
        foreach ($line in (& netstat.exe -an 2>$null)) {
            if ($line -match '^\s*TCP\s+\S+:(\d+)\s+\S+\s+LISTENING') { $ports.Add([int]$Matches[1]) }
        }
    }

    $script:PortInventory = @($ports | Sort-Object -Unique)
    Write-Log ('  Inventory: {0} listening TCP ports' -f $script:PortInventory.Count)
    $script:PortInventory
}

#endregion

#region Matching

# Case-insensitive substring match, '*' and '?' in the pattern turn it into a wildcard match
function Test-PatternMatch([string]$Value, [string]$Pattern) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    if ($Pattern.Contains('*') -or $Pattern.Contains('?')) { return $Value -like $Pattern }
    return $Value.IndexOf($Pattern, [StringComparison]::OrdinalIgnoreCase) -ge 0
}

function Find-Software([string]$Pattern) {
    foreach ($displayName in Get-SoftwareInventory) {
        if (Test-PatternMatch -Value $displayName -Pattern $Pattern) { return $displayName }
    }
    $null
}

function Find-NinjaService([string]$Pattern) {
    foreach ($service in Get-ServiceInventory) {
        if (-not ((Test-PatternMatch -Value $service.Name -Pattern $Pattern) -or
                  (Test-PatternMatch -Value $service.DisplayName -Pattern $Pattern))) { continue }
        if ($RequireServiceRunning -and $service.State -ne 'Running') {
            Write-Log ('  Service "{0}" found but not running (state: {1})' -f $service.DisplayName, $service.State)
            continue
        }
        if ($service.DisplayName) { return $service.DisplayName }
        return $service.Name
    }
    $null
}

function Find-NinjaProcess([string]$Pattern) {
    foreach ($process in Get-ProcessInventory) {
        if ((Test-PatternMatch -Value $process.Name -Pattern $Pattern) -or
            (Test-PatternMatch -Value $process.Description -Pattern $Pattern)) { return $process.Name }
    }
    $null
}

function Find-Port([string]$Pattern) {
    $port = 0
    if (-not [int]::TryParse($Pattern.Trim(), [ref]$port)) {
        throw "Rule 'port:$Pattern' needs a numeric port number."
    }
    foreach ($listening in Get-PortInventory) {
        if ($listening -eq $port) { return [string]$port }
    }
    $null
}

#endregion

#region Rules

$KnownTypes = @('software', 'service', 'process', 'port', 'any')

function ConvertTo-RuleList([string]$Text) {
    $rules = New-Object System.Collections.Generic.List[object]
    foreach ($raw in ($Text -split '[;\r\n]+')) {
        $line = $raw.Trim()
        if (-not $line) { continue }
        if ($line.StartsWith('#')) { continue }

        $type = 'any'
        $colon = $line.IndexOf(':')
        if ($colon -gt 0) {
            $prefix = $line.Substring(0, $colon).Trim().ToLowerInvariant()
            if ($KnownTypes -contains $prefix) {
                $type = $prefix
                $line = $line.Substring($colon + 1).Trim()
            }
        }

        $text = ''
        $equals = $line.IndexOf('=')
        if ($equals -ge 0) {
            $text = $line.Substring($equals + 1).Trim().Trim('"').Trim("'").Trim()
            $line = $line.Substring(0, $equals).Trim()
        }

        $pattern = $line.Trim('"').Trim("'").Trim()
        if (-not $pattern) { continue }

        $rules.Add([pscustomobject]@{ Type = $type; Pattern = $pattern; Text = $text })
    }
    $rules
}

#endregion

#region Custom field

function Set-NinjaCustomField([string]$Name, [string]$Value) {
    $fieldValue = $Value
    if ([string]::IsNullOrEmpty($fieldValue)) { $fieldValue = $null }

    $hasPiped = [bool](Get-Command -Name 'Ninja-Property-Set-Piped' -ErrorAction SilentlyContinue)
    $hasDirect = [bool](Get-Command -Name 'Ninja-Property-Set' -ErrorAction SilentlyContinue)

    # Piped variant: the value is not parsed as a command line, so quotes and spaces are safe.
    # An empty value clears the field, and for that the direct variant with $null is the reliable one.
    if ($hasPiped -and $null -ne $fieldValue) {
        $fieldValue | Ninja-Property-Set-Piped $Name | Out-Null
        return 'Ninja-Property-Set-Piped'
    }
    if ($hasDirect) {
        Ninja-Property-Set $Name $fieldValue | Out-Null
        return 'Ninja-Property-Set'
    }
    if ($hasPiped) {
        $fieldValue | Ninja-Property-Set-Piped $Name | Out-Null
        return 'Ninja-Property-Set-Piped'
    }

    $cli = Join-Path $env:ProgramData 'NinjaRMMAgent\ninjarmm-cli.exe'
    if (Test-Path -Path $cli) {
        & $cli set $Name $fieldValue | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "ninjarmm-cli.exe returned exit code $LASTEXITCODE." }
        return 'ninjarmm-cli.exe'
    }

    throw 'No NinjaOne agent command found (Ninja-Property-Set / ninjarmm-cli.exe). Run the script through the NinjaOne agent or use -DryRun.'
}

#endregion

try {
    $CustomFieldName = "$CustomFieldName".Trim()
    if (-not $CustomFieldName) { throw "Script variable 'customFieldName' is required." }
    if ([string]::IsNullOrWhiteSpace($Checks)) { throw "Script variable 'checks' is required." }

    $rules = @(ConvertTo-RuleList -Text $Checks)
    if ($rules.Count -eq 0) { throw "Script variable 'checks' does not contain a usable rule." }

    Write-Log ('Device {0}: {1} rule(s), target field: {2}' -f $env:COMPUTERNAME, $rules.Count, $CustomFieldName)

    $values = New-Object System.Collections.Generic.List[string]
    foreach ($rule in $rules) {
        Write-Log ('Rule [{0}] "{1}"' -f $rule.Type, $rule.Pattern)

        $detected = $null
        $matchedType = $rule.Type
        switch ($rule.Type) {
            'software' { $detected = Find-Software $rule.Pattern }
            'service'  { $detected = Find-NinjaService $rule.Pattern }
            'process'  { $detected = Find-NinjaProcess $rule.Pattern }
            'port'     { $detected = Find-Port $rule.Pattern }
            default {
                # any: software first, it carries the most readable product name
                $detected = Find-Software $rule.Pattern
                if ($detected) { $matchedType = 'software' }
                if (-not $detected) {
                    $detected = Find-NinjaService $rule.Pattern
                    if ($detected) { $matchedType = 'service' }
                }
                if (-not $detected) {
                    $detected = Find-NinjaProcess $rule.Pattern
                    if ($detected) { $matchedType = 'process' }
                }
            }
        }

        if (-not $detected) {
            Write-Log '  No match'
            continue
        }

        $value = $rule.Text
        if (-not $value) {
            $template = switch ($matchedType) {
                'service' { $ServiceText }
                'process' { $ProcessText }
                'port'    { $PortText }
                default   { $SoftwareText }
            }
            $value = $template.Replace('{0}', $rule.Pattern)
        }

        Write-Log ('  Match ({0}): {1} -> "{2}"' -f $matchedType, $detected, $value)
        if (-not $values.Contains($value)) { $values.Add($value) }
    }

    $fieldValue = $NoMatchValue
    if ($values.Count -gt 0) {
        $fieldValue = $values -join $Separator
        while ($fieldValue.Length -gt $MaxLength -and $values.Count -gt 1) {
            Write-Log ('Value longer than {0} characters, dropping "{1}"' -f $MaxLength, $values[$values.Count - 1])
            $values.RemoveAt($values.Count - 1)
            $fieldValue = $values -join $Separator
        }
        if ($fieldValue.Length -gt $MaxLength) {
            Write-Log ('Value longer than {0} characters, truncating' -f $MaxLength)
            $fieldValue = $fieldValue.Substring(0, $MaxLength)
        }
    } else {
        Write-Log 'No rule matched.'
    }

    # A multi-line value would break the log into several lines, so show it on one
    $logValue = $fieldValue -replace '\r?\n', ' | '

    if ($DryRun) {
        Write-Log ('Dry run: custom field "{0}" would be set to "{1}"' -f $CustomFieldName, $logValue)
        exit 0
    }

    $usedCommand = Set-NinjaCustomField -Name $CustomFieldName -Value $fieldValue
    Write-Log ('Custom field "{0}" set to "{1}" (via {2})' -f $CustomFieldName, $logValue, $usedCommand)

    if (Get-Command -Name 'Ninja-Property-Get' -ErrorAction SilentlyContinue) {
        $readBack = "$(Ninja-Property-Get $CustomFieldName)" -replace '\r?\n', ' | '
        Write-Log ('  Read back: "{0}"' -f $readBack)
    }

    exit 0
} catch {
    Write-Log ('ERROR: {0}' -f $_.Exception.Message)
    exit 1
}
