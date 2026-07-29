<#
Runs the controlled Modbus write and records a ground-truth timeline entry. Validates OT results

Run from PowerShell:
.\run_ot_action.ps1 -BaselinePath "Z:\Evidence\baseline\normalized\modbus-baseline-....json"
#>

param(
    # This makes you deliberately select the exact clean-state baseline that
    # modbus_restore.py will later use to restore Conpot.
    [Parameter(Mandatory = $true)]
    [string]$BaselinePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# $PSScriptRoot is the folder containing this .ps1 file: ...\ot\
# This avoids hard-coding Z:\ or C:\ for the project files.
$ScriptDirectory = $PSScriptRoot
$ProjectRoot = Split-Path -Path $ScriptDirectory -Parent

# TODO 1:
# Make paths to:
#   config\lab.json
#   ot\modbus_write.py
$ConfigPath = Join-Path -Path $ProjectRoot -ChildPath "config\lab.json"
$ModbusWriteScript = Join-Path -Path $ProjectRoot -ChildPath "ot\modbus_write.py"

# TODO 2:
# Read lab.json into $Config.
# Hint: Get-Content -Raw reads the whole JSON file;
# ConvertFrom-Json turns it into a PowerShell object.
$Config = Get-Content -Raw -Path $ConfigPath
$Config = ConvertFrom-Json $Config

# TODO 3:
# Build the full timeline CSV path from these lab.json fields:
# $Config.evidence.windows_root
# $Config.evidence.timeline_relative_path
$TimelinePath = Join-Path -Path $Config.evidence.windows_root -ChildPath $Config.evidence.timeline_relative_path

# Confirm the chosen baseline exists before recording an action or opening
# a Modbus connection.
if (-not (Test-Path -LiteralPath $BaselinePath -PathType Leaf)) {
    throw "Baseline file not found: $BaselinePath"
}

# TODO 4:
# Create the folder that will contain $TimelinePath if it does not exist.
# Hint: Split-Path $TimelinePath -Parent, then New-Item -ItemType Directory.
$Prepath = Split-Path -Path $TimelinePath -Parent
New-Item -Path $Prepath -ItemType Directory -Force | Out-Null

function Add-TimelineEvent {
    param(
        [string]$Phase,
        [string]$Status,
        [string]$Details
    )

    # A timestamp in UTC makes this easy to compare with your Python JSON,
    # Sysmon events, Conpot logs, and PCAP timestamps.
    $event = [PSCustomObject]@{
        timestamp_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        phase         = $Phase
        status        = $Status
        details       = $Details
        baseline_file = $BaselinePath
    }

    # TODO 5:
    # If $TimelinePath does not yet exist, create it with Export-Csv.
    # Otherwise append the new row with Export-Csv -Append.
    if(Test-Path -LiteralPath $TimelinePath) {
        $event | Export-Csv -Path $TimelinePath -NoTypeInformation -Append
    } else {
        $event | Export-Csv -Path $TimelinePath -NoTypeInformation
    }
}

Write-Host "Baseline: $BaselinePath"
Write-Host "Action: controlled Conpot coil write"
Write-Host "Timeline: $TimelinePath"

# Record that the launcher was intentionally started before calling Python.
Add-TimelineEvent -Phase "modbus_write" -Status "STARTED" `
    -Details "Launching modbus_write.py."

try {
    # The Python script retains its own WRITE confirmation gate.
    # The '&' runs the py command; $LASTEXITCODE is its exit status.
    & py $ModbusWriteScript $BaselinePath

    if ($LASTEXITCODE -ne 0) {
        throw "modbus_write.py exited with code $LASTEXITCODE."
    }

    Add-TimelineEvent -Phase "modbus_write" -Status "COMPLETED" `
        -Details "Write script finished successfully."

    Write-Host "OT action completed. Running modbus_restore.py."

    # Path to the restoration script. It receives the same exact baseline file
    # because that file contains the original coil value to restore.
    $ModbusRestoreScript = Join-Path $ScriptDirectory "modbus_restore.py"

    # Do not restore automatically. This gives you time to capture/log the attack
    # state before returning the Conpot coil to its clean baseline value.
    $RestoreChoice = Read-Host "Type RESTORE to run modbus_restore.py now"

    if ($RestoreChoice -eq "RESTORE") {
        Add-TimelineEvent -Phase "modbus_restore" -Status "STARTED" `
            -Details "Launching modbus_restore.py."

        # Pass the exact same baseline path used for the write.
        & py $ModbusRestoreScript $BaselinePath

        if ($LASTEXITCODE -ne 0) {
            throw "modbus_restore.py exited with code $LASTEXITCODE."
        }

        Add-TimelineEvent -Phase "modbus_restook, so now how should re" -Status "COMPLETED" `
            -Details "Restore script finished successfully."

        Write-Host "Conpot coil restored to its baseline value."
    }
    else {
        Add-TimelineEvent -Phase "modbus_restore" -Status "SKIPPED" `
            -Details "Restore was not requested by the operator."

        Write-Host "Restore skipped. Run modbus_restore.py later with the same baseline."
    }
}
catch {
    Add-TimelineEvent -Phase "modbus_write" -Status "FAILED" `
        -Details $_.Exception.Message

    throw
}