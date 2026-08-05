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

$SysmonCsv = Join-Path -Path $OutputDir -ChildPath "sysmon_normalized.csv"
$PowerShellOutputCsv = Join-Path $OutputDir "powershell_normalized.csv"

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

            [PSCustomObject]@{
                timestamp_utc = $TimestampUtc
                host          = $Event.MachineName
                user          = $User
                event_id      = $Event.Id
                provider      = "Microsoft-Windows-PowerShell"
                event_type    = if ($Event.Id -eq "4104") {
                                    "script_block"
                                }
                                else {
                                    "module_pipeline"
                                }
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