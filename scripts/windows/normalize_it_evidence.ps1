[CmdletBinding()]
param(
    # Folder containing one or more raw Sysmon CSV files.
    [Parameter(Mandatory)]
    [string]$InputDirectory,

    # Output must be inside derived\, never raw\.
    [Parameter(Mandatory)]
    [string]$OutputDir,

    [Parameter(Mandatory)]
    [ValidatePattern('^run-\d{3,}$')]
    [string]$RunId,

    [Parameter(Mandatory)]
    [ValidateSet("baseline", "attack")]
    [string]$Label
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Refuse to alter existing derived results silently.
if (Test-Path (Join-Path -Path $OutputDir -ChildPath "sysmon_normalized.csv")) {
    throw "Normalized sysmon output already exists"
}
if (Test-Path (Join-Path -Path $OutputDir -ChildPath "powershell_normalized.csv")) {
    throw "Normalized powershell output already exists"
}
if (Test-Path (Join-Path -Path $OutputDir -ChildPath "rdp_normalized.csv")) {
    throw "Normalized RDP attribution output already exists"
}

$SysmonCsv = Join-Path -Path $OutputDir -ChildPath "sysmon_normalized.csv"
$PowerShellOutputCsv = Join-Path $OutputDir "powershell_normalized.csv"
$RdpOutputCsv = Join-Path $OutputDir "rdp_normalized.csv"
New-Item $OutputDir -ItemType Directory -Force | Out-Null

# Extract one named value from the multiline Sysmon Message field.
# Example: "Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
function Get-SysmonField {
    param(
        [string]$Message,
        [string]$FieldName
    )

    $Pattern = "(?m)^" +
        [regex]::Escape($FieldName) +
        ":\s*(.*)$"

    $Match = [regex]::Match($Message, $Pattern)

    if ($Match.Success) {
        return $Match.Groups[1].Value.Trim()
    }

    return $null
}

# Find raw Sysmon CSV exports beneath the supplied directory.
$InputFiles = @(
    Get-ChildItem $InputDirectory -Recurse -File -Filter "*Sysmon*.csv"
)

if ($InputFiles.Count -eq 0) {
    throw "No Sysmon CSV files found in: $InputDirectory"
}

$NormalizedRows = foreach ($File in $InputFiles) {
    $RawRowNumber = 0

    foreach ($Event in Import-Csv $File.FullName) {
        $RawRowNumber++

        # Only normalize process-creation events.
        if ($Event.Id -ne "1") {
            continue
        }

        # Convert Windows timestamp into consistent UTC format.
        try {
            $TimestampUtc = (
                [datetime]$Event.TimeCreated
            ).ToUniversalTime().ToString("o")
        }
        catch {
            $TimestampUtc = $Event.TimeCreated
        }

        [PSCustomObject]@{
            timestamp_utc     = $TimestampUtc
            host              = $Event.MachineName
            user              = Get-SysmonField $Event.Message "User"
            event_id          = $Event.Id
            provider          = "Microsoft-Windows-Sysmon"
            process_image     = Get-SysmonField $Event.Message "Image"
            process_id        = Get-SysmonField $Event.Message "ProcessId"
            parent_image      = Get-SysmonField $Event.Message "ParentImage"
            parent_process_id = Get-SysmonField $Event.Message "ParentProcessId"
            command_line      = Get-SysmonField $Event.Message "CommandLine"
            run_id            = $RunId
            label             = $Label
            raw_file          = $File.FullName
            raw_row           = $RawRowNumber
        }
    }
}

if (@($NormalizedRows).Count -eq 0) {
    throw "No Sysmon Event ID 1 records were found."
}

# Normalize response-enrichment evidence separately from detection telemetry.
function Convert-ToUtcText {
    param([string]$TimeText)

    if (-not $TimeText) {
        return $null
    }

    try {
        return ([datetime]$TimeText).ToUniversalTime().ToString("o")
    }
    catch {
        return $TimeText
    }
}

function Test-AttributionIp {
    param([string]$AddressText)

    if (-not $AddressText -or $AddressText -eq "-") {
        return $false
    }

    $ParsedAddress = $null
    if (-not [System.Net.IPAddress]::TryParse($AddressText, [ref]$ParsedAddress)) {
        return $false
    }

    if ([System.Net.IPAddress]::IsLoopback($ParsedAddress)) {
        return $false
    }

    return $AddressText -notin "0.0.0.0", "::"
}

$NormalizedRdp = @(
    # Best real-time source: active client connection to local RDP port 3389.
    foreach ($File in Get-ChildItem $InputDirectory -Recurse -File `
        -Filter "00-rdp-connections.csv") {
        $RowNumber = 0
        foreach ($Row in Import-Csv $File.FullName) {
            $RowNumber++
            $SourceIp = $Row.RemoteAddress

            [PSCustomObject]@{
                timestamp_utc      = Convert-ToUtcText $Row.captured_utc
                host               = $Row.host
                user               = $Row.user
                domain             = $null
                source_ip          = $SourceIp
                source_port        = $Row.RemotePort
                local_ip           = $Row.LocalAddress
                local_port         = $Row.LocalPort
                logon_type         = "active_rdp_tcp"
                event_id           = $null
                provider           = "Get-NetTCPConnection"
                attribution_source = "active_tcp_connection"
                source_ip_valid    = Test-AttributionIp $SourceIp
                run_id             = $RunId
                label              = $Label
                raw_file           = $File.FullName
                raw_row            = $RowNumber
            }
        }
    }

    # Historical fallback: Security 4624 Logon Type 10.
    foreach ($File in Get-ChildItem $InputDirectory -Recurse -File `
        -Filter "EventLog_Security_4624_RDP.csv") {
        $RowNumber = 0
        foreach ($Row in Import-Csv $File.FullName) {
            $RowNumber++
            $SourceIp = $Row.IpAddress

            [PSCustomObject]@{
                timestamp_utc      = Convert-ToUtcText $Row.TimeCreated
                host               = $Row.MachineName
                user               = $Row.TargetUserName
                domain             = $Row.TargetDomainName
                source_ip          = $SourceIp
                source_port        = $Row.IpPort
                local_ip           = $null
                local_port         = "3389"
                logon_type         = $Row.LogonType
                event_id           = $Row.Id
                provider           = $Row.ProviderName
                attribution_source = "security_4624"
                source_ip_valid    = Test-AttributionIp $SourceIp
                run_id             = $RunId
                label              = $Label
                raw_file           = $File.FullName
                raw_row            = $RowNumber
            }
        }
    }

    # Optional fallback: Terminal Services Event 1149.
    foreach ($File in Get-ChildItem $InputDirectory -Recurse -File `
        -Filter "*TerminalServices-RemoteConnectionManager_Operational.csv") {
        $RowNumber = 0
        foreach ($Row in Import-Csv $File.FullName) {
            $RowNumber++
            $SourceIp = $Row.IpAddress

            [PSCustomObject]@{
                timestamp_utc      = Convert-ToUtcText $Row.TimeCreated
                host               = $Row.MachineName
                user               = $Row.TargetUserName
                domain             = $Row.TargetDomainName
                source_ip          = $SourceIp
                source_port        = $null
                local_ip           = $null
                local_port         = "3389"
                logon_type         = "rdp_authentication"
                event_id           = $Row.Id
                provider           = $Row.ProviderName
                attribution_source = "terminal_services_1149"
                source_ip_valid    = Test-AttributionIp $SourceIp
                run_id             = $RunId
                label              = $Label
                raw_file           = $File.FullName
                raw_row            = $RowNumber
            }
        }
    }
)

if ($NormalizedRdp.Count -gt 0) {
    $NormalizedRdp |
        Export-Csv $RdpOutputCsv -NoTypeInformation -Encoding UTF8

    $ValidSources = @(
        $NormalizedRdp |
            Where-Object { $_.source_ip_valid -eq $true } |
            Select-Object -ExpandProperty source_ip -Unique
    )

    Write-Host "Normalized $($NormalizedRdp.Count) RDP attribution records."
    if ($ValidSources.Count -gt 0) {
        Write-Host "Observed RDP source IP(s): $($ValidSources -join ', ')"
    }
    else {
        Write-Warning "RDP evidence was present, but no usable source IP was found."
    }
}
else {
    Write-Warning "No RDP attribution evidence was available to normalize."
}

# Create derived folder and save normalized rows.
New-Item (Split-Path $SysmonCsv -Parent) `
    -ItemType Directory -Force | Out-Null

$NormalizedRows | Export-Csv `
    -Path $SysmonCsv `
    -NoTypeInformation `
    -Encoding UTF8

Write-Host "Normalized $(@($NormalizedRows).Count) process events."
Write-Host "Saved: $SysmonCsv"

# Normalize Powershell Events

$PowerShellFiles = @(
    Get-ChildItem $InputDirectory -Recurse -File `
        -Filter "EventLog_Microsoft-Windows-PowerShell_Operational.csv"
)

if ($PowerShellFiles.Count -eq 0) {
    Write-Warning "No PowerShell Operational CSV was found."
}
else {
    $NormalizedPowerShell = foreach ($File in $PowerShellFiles) {
        $RowNumber = 0

        foreach ($Event in Import-Csv $File.FullName) {
            $RowNumber++

            # Only retain useful pipeline and script-block events.
            if ($Event.Id -notin "4103", "4104") {
                continue
            }

            try {
                $TimestampUtc = (
                    [datetime]$Event.TimeCreated
                ).ToUniversalTime().ToString("o")
            }
            catch {
                $TimestampUtc = $Event.TimeCreated
            }

            # These fields might not exist in older event exports.
            $User = if ($Event.PSObject.Properties["UserId"]) {
                $Event.UserId
            }
            else {
                $null
            }

            $RecordId = if ($Event.PSObject.Properties["RecordId"]) {
                $Event.RecordId
            }
            else {
                $null
            }

            # Keep the command content on one physical CSV line.
            $ScriptContent = $Event.Message

            if ($ScriptContent) {
                $ScriptContent = $ScriptContent -replace "`r?`n", "\n"
            }

            $EventType = if ($Event.Id -eq "4104") {
                "script_block"
            }
            else {
                "module_pipeline"
            }

            [PSCustomObject]@{
                timestamp_utc = $TimestampUtc
                host          = $Event.MachineName
                user          = $User
                event_id      = $Event.Id
                provider      = "Microsoft-Windows-PowerShell"
                event_type    = $EventType
                script_text   = $ScriptContent
                record_id     = $RecordId
                run_id        = $RunId
                label         = $Label
                raw_file      = $File.FullName
                raw_row       = $RowNumber
            }
        }
    }

    if (@($NormalizedPowerShell).Count -eq 0) {
        Write-Warning "PowerShell CSV found, but it contained no 4103 or 4104 events."
    }
    else {
        $NormalizedPowerShell |
            Export-Csv `
                -Path $PowerShellOutputCsv `
                -NoTypeInformation `
                -Encoding UTF8

        Write-Host (
            "Normalized $(@($NormalizedPowerShell).Count) PowerShell events."
        )

        Write-Host "Saved: $PowerShellOutputCsv"
    }
}