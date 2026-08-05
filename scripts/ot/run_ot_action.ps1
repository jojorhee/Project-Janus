<#
Runs one complete OT evidence sequence:
pre-write state -> write -> verify -> restore -> verify.

Usage:
    .\run_ot_action.ps1 -RunId run-001
#>

param(
    [Parameter(Mandatory)]
    [ValidatePattern('^run-\d{3,}$')]
    [string]$RunId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path $PSScriptRoot -Parent
$Config = Get-Content (Join-Path $ProjectRoot "config\lab.json") -Raw |
    ConvertFrom-Json

$RunRoot = Join-Path $Config.evidence.windows_root `
    "$($Config.evidence.ot_folder)\$($Config.evidence.runs_folder)\$RunId"
$RawRoot = Join-Path $RunRoot $Config.evidence.raw_folder
$ActionLog = Join-Path $RawRoot "run_ot_action.csv"
$Transcript = Join-Path $RawRoot "powershell-transcript.txt"

foreach ($Folder in @(
    $RawRoot,
    (Join-Path $RunRoot $Config.evidence.metadata_folder),
    (Join-Path $RunRoot $Config.evidence.screenshots_folder),
    (Join-Path $RunRoot $Config.evidence.derived_folder)
)) {
    New-Item $Folder -ItemType Directory -Force | Out-Null
}

if ((Test-Path $ActionLog) -or (Test-Path $Transcript)) {
    throw "Run evidence already exists. Use a new run ID."
}

function Add-RunEvent {
    param([string]$Phase, [string]$Status, [string]$Details)

    $Event = [PSCustomObject]@{
        timestamp_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        run_id        = $RunId
        phase         = $Phase
        status        = $Status
        details       = $Details
    }
    $Event | Export-Csv $ActionLog -NoTypeInformation -Append
}

function Invoke-OtStep {
    param([string]$Phase, [string]$Script, [string[]]$Arguments)

    Add-RunEvent $Phase "STARTED" "Launching $Script"
    try {
        & py (Join-Path $PSScriptRoot $Script) @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "$Script exited with code $LASTEXITCODE."
        }
        Add-RunEvent $Phase "COMPLETED" "$Script completed successfully."
    }
    catch {
        Add-RunEvent $Phase "FAILED" $_.Exception.Message
        throw
    }
}

function New-RunNotes {
    param(
        # Start time is recorded before any Modbus scripts execute.
        [Parameter(Mandatory)]
        [datetime]$StartTime
    )

    # Capture end time only after all five OT steps succeed.
    $EndTime = Get-Date
    $Duration = New-TimeSpan -Start $StartTime -End $EndTime
    $TimeZone = Get-TimeZone

    # Build run-001\metadata\run_notes.txt using existing run variables.
    $MetadataRoot = Join-Path $RunRoot $Config.evidence.metadata_folder
    $NotesPath = Join-Path $MetadataRoot "run_notes.txt"

    New-Item $MetadataRoot -ItemType Directory -Force | Out-Null

    # Protect evidence from accidental replacement.
    if (Test-Path $NotesPath) {
        throw "Run notes already exist: $NotesPath"
    }

    # Load evidence created by the five Python steps.
    $PreWritePath = Join-Path $RawRoot "01-pre-write-state.json"
    $WritePath = Join-Path $RawRoot "02-write-result.json"
    $PostWritePath = Join-Path $RawRoot "03-post-write-verification.json"
    $RestorePath = Join-Path $RawRoot "04-restore-result.json"
    $PostRestorePath = Join-Path $RawRoot "05-post-restore-verification.json"

    # Ensure every required JSON exists before creating notes.
    foreach ($Path in @(
        $PreWritePath,
        $WritePath,
        $PostWritePath,
        $RestorePath,
        $PostRestorePath
    )) {
        if (-not (Test-Path $Path -PathType Leaf)) {
            throw "Cannot create run notes; evidence is missing: $Path"
        }
    }

    # Convert JSON evidence into PowerShell objects.
    $PreWrite = Get-Content $PreWritePath -Raw | ConvertFrom-Json
    $Write = Get-Content $WritePath -Raw | ConvertFrom-Json
    $PostWrite = Get-Content $PostWritePath -Raw | ConvertFrom-Json
    $Restore = Get-Content $RestorePath -Raw | ConvertFrom-Json
    $PostRestore = Get-Content $PostRestorePath -Raw | ConvertFrom-Json

    # Get configured coil address and its dynamic JSON property.
    $Coil = [string]$Config.modbus.allowed_coils[0]
    $InitialValue = $PreWrite.coils.PSObject.Properties[$Coil].Value
    $FinalValue = $PostRestore.coils.PSObject.Properties[$Coil].Value

    # Predict PCAP filename from run ID:
    # run-001 becomes ot_run_001.pcap.
    $PcapName = "ot_$($RunId.Replace('-', '_')).pcap"

    # PCAP packet count and frame number remain manual because tcpdump runs
    # on Linux and the PowerShell script cannot inspect that file yet.
    $Notes = @"
Project Janus - OT Run Notes

Run ID: $RunId
Date: $($StartTime.ToString("yyyy-MM-dd"))
Timezone: $($TimeZone.Id)
Start time: $($StartTime.ToString("HH:mm:ss"))
End time: $($EndTime.ToString("HH:mm:ss"))
Duration: $($Duration.ToString())

Source system: $($Config.hosts.windows_client.hostname) ($($Config.hosts.windows_client.ip))
Target system: $($Config.hosts.conpot.hostname) ($($Config.hosts.conpot.ip):$($Config.hosts.conpot.modbus_port))
Modbus unit ID: $($Config.modbus.unit_id)

PCAP file: $PcapName
Packets captured: PENDING MANUAL ENTRY
Write-request frame: PENDING MANUAL ENTRY

Action results:
- Pre-write coil $Coil value: $InitialValue
- Requested attack value: $($Write.requested_value)
- Write read-back verified: $($Write.verified)
- Independent post-write verified: $($PostWrite.verified)
- Restore operation verified: $($Restore.verified)
- Independent post-restore verified: $($PostRestore.verified)
- Final coil $Coil value: $FinalValue

Evidence:
- Five JSON state/result files and matching logs
- PowerShell transcript
- run_ot_action.csv
- Conpot log and PCAP must be copied from Linux

Outcome: Clean OT sequence completed successfully and coil $Coil was restored.
"@

    # Write completed notes into this run's metadata folder.
    $Notes | Set-Content -Path $NotesPath -Encoding UTF8

    Write-Host "Run notes created: $NotesPath"
}

$RunStart = Get-Date
$TranscriptStarted = $false
try {
    Start-Transcript -Path $Transcript | Out-Null
    $TranscriptStarted = $true

    Invoke-OtStep -Phase "pre_write" `
        -Script "modbus_baseline.py" -Arguments @($RunId, "pre-write")
    Invoke-OtStep -Phase "write" `
        -Script "modbus_write.py" -Arguments @($RunId)
    Invoke-OtStep -Phase "verify_write" `
        -Script "modbus_baseline.py" -Arguments @($RunId, "post-write")
    Invoke-OtStep -Phase "restore" `
        -Script "modbus_restore.py" -Arguments @($RunId)
    Invoke-OtStep -Phase "verify_restore" `
        -Script "modbus_baseline.py" -Arguments @($RunId, "post-restore")

    New-RunNotes -StartTime $RunStart
    Write-Host "OT run completed: $RunRoot"
}
finally {
    if ($TranscriptStarted) {
        Stop-Transcript | Out-Null
    }
}