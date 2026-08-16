<#
Runs one complete, numbered Project Janus IT evidence capture.

Usage:
    .\run_it_vector.ps1 -RunId run-999
#>

[CmdletBinding()]
param(
    # Explicit run ID prevents confusing automatic numbering.
    [Parameter(Mandatory)]
    [ValidatePattern('^run-\d{3,}$')]
    [string]$RunId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# -------------------------
# 1. Build evidence paths
# -------------------------

$EvidenceRoot = "C:\CyberRangers\evidence\it\runs"
$RunRoot = Join-Path $EvidenceRoot $RunId

$RawRoot = Join-Path $RunRoot "raw"
$ClientRoot = Join-Path $RawRoot "windows-client"
$DiscoveryRoot = Join-Path $ClientRoot "discovery"
$DcRoot = Join-Path $RawRoot "domain-controller"
$MetadataRoot = Join-Path $RunRoot "metadata"
$ScreenshotsRoot = Join-Path $RunRoot "screenshots"
$DerivedRoot = Join-Path $RunRoot "derived"

# Refuse to reuse a run directory.
if (Test-Path $RunRoot) {
    throw "Run already exists: $RunRoot"
}

foreach ($Folder in @(
    $DiscoveryRoot,
    $DcRoot,
    $MetadataRoot,
    $ScreenshotsRoot,
    $DerivedRoot
)) {
    New-Item $Folder -ItemType Directory -Force | Out-Null
}

$ActionLog = Join-Path $ClientRoot "run_it_vector.csv"
$TranscriptPath = Join-Path $ClientRoot "powershell-transcript.txt"

# -------------------------
# 2. Define script paths
# -------------------------

$DiscoveryScript = Join-Path $PSScriptRoot "win_discovery.ps1"
$DcAccessScript = Join-Path $PSScriptRoot "test_dc_access.ps1"
$ExportScript = Join-Path $PSScriptRoot "export_win_events.ps1"
$CleanupScript = Join-Path $PSScriptRoot "cleanup.ps1"
$NormalizeScript = Join-Path $PSScriptRoot "normalize_it_evidence.ps1"
$JsonNormalizer = Join-Path $PSScriptRoot "normalize_windows.py"
$WindowsSchema = Join-Path `
    $PSScriptRoot `
    "..\ai\specifications\it_schema.json"

$NetlogonWiper = "\\purplelab.local\netlogon\simulated_wiper.ps1"
$TargetDirectory = "C:\WiperTest"
$WiperEvidence = Join-Path $ClientRoot "04-wiper-result.json"

# Fail before starting if a required local script is missing.
foreach ($Script in @(
    $DiscoveryScript,
    $DcAccessScript,
    $ExportScript,
    $CleanupScript,
    $NormalizeScript,
    $JsonNormalizer,
    $WindowsSchema
)) {
    if (-not (Test-Path $Script -PathType Leaf)) {
        throw "Required script missing: $Script"
    }
}

$PythonCommand = Get-Command python -ErrorAction SilentlyContinue
if (-not $PythonCommand) {
    throw "Python was not found in PATH. Install Python before running this script."
}

$PythonExe = $PythonCommand.Source
& $PythonExe -c "import jsonschema" 2>$null
if ($LASTEXITCODE -ne 0) {
    throw "Python package 'jsonschema' is missing. Run: python -m pip install jsonschema"
}

# -------------------------
# 3. Evidence helper functions
# -------------------------

function Add-RunEvent {
    param(
        [string]$Phase,
        [string]$Status,
        [string]$Details
    )

    $Event = [PSCustomObject]@{
        timestamp_utc = (
            Get-Date
        ).ToUniversalTime().ToString("o")
        run_id = $RunId
        phase = $Phase
        status = $Status
        details = $Details
    }

    $Event | Export-Csv `
        -Path $ActionLog `
        -NoTypeInformation `
        -Append
}

function Invoke-EvidenceStep {
    param(
        [string]$Phase,
        [scriptblock]$Action
    )

    Add-RunEvent $Phase "STARTED" "Step started."

    try {
        # Save any useful object returned by the child script.
        $Result = & $Action

        Add-RunEvent $Phase "COMPLETED" "Step completed successfully."
        return $Result
    }
    catch {
        Add-RunEvent $Phase "FAILED" $_.Exception.Message
        throw
    }
}

function Export-FileInventory {
    param(
        [string]$OutputPath
    )

    # Hash files before or after the wipe.
    # The marker is included so restoration can also be proven.
    $Inventory = foreach (
        $File in Get-ChildItem $TargetDirectory -File -Recurse -Force
    ) {
        [PSCustomObject]@{
            collected_utc = (
                Get-Date
            ).ToUniversalTime().ToString("o")
            path = $File.FullName
            size_bytes = $File.Length
            last_write_utc = $File.LastWriteTimeUtc.ToString("o")
            sha256 = (
                Get-FileHash $File.FullName -Algorithm SHA256
            ).Hash
        }
    }

    $Inventory | Export-Csv `
        -Path $OutputPath `
        -NoTypeInformation
}

# -------------------------
# 4. Prepare run state
# -------------------------

$RunStarted = Get-Date
$AttributionStart = $RunStarted.AddMinutes(-15)
$RunEnded = $null
$AttackStart = $null
$AttackEnd = $null
$RdpSourceIps = @()
$ProposedBlockMinutes = 15

$RunStatus = "FAILED"
$CleanupStatus = "NOT_RUN"
$FailureMessage = $null
$TranscriptStarted = $false

try {
    Start-Transcript -Path $TranscriptPath | Out-Null
    $TranscriptStarted = $true

    Add-RunEvent "run" "STARTED" "IT evidence run started."

    # Warn instead of forcing elevation.
    $Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = [System.Security.Principal.WindowsPrincipal]::new($Identity)
    $IsAdministrator = $Principal.IsInRole(
        [System.Security.Principal.WindowsBuiltInRole]::Administrator
    )

    if (-not $IsAdministrator) {
        Write-Warning (
            "PowerShell is not elevated. Event-log access may fail. " +
            "The attack scripts will still be attempted."
        )
    }

    # Capture current RDP/session context.
    & quser.exe 2>&1 |
        Set-Content (Join-Path $ClientRoot "00-rdp-session.txt")

    # Capture the live RDP TCP peer without assuming or hardcoding Kali's IP.
    # This is response enrichment only; it is not part of detection logic.
    try {
        $RdpConnections = @(
            Get-NetTCPConnection -LocalPort 3389 -State Established `
                -ErrorAction Stop
        )
    }
    catch {
        $RdpConnections = @()
        Write-Warning "Unable to inspect active RDP connections: $($_.Exception.Message)"
    }

    if ($RdpConnections.Count -gt 0) {
        $RdpCapturedUtc = (Get-Date).ToUniversalTime().ToString("o")
        $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $RdpConnectionPath = Join-Path $ClientRoot "00-rdp-connections.csv"

        $RdpConnections |
            ForEach-Object {
                [PSCustomObject]@{
                    captured_utc = $RdpCapturedUtc
                    host          = $env:COMPUTERNAME
                    user          = $CurrentUser
                    State         = $_.State
                    LocalAddress  = $_.LocalAddress
                    LocalPort     = $_.LocalPort
                    RemoteAddress = $_.RemoteAddress
                    RemotePort    = $_.RemotePort
                    OwningProcess = $_.OwningProcess
                }
            } |
            Export-Csv $RdpConnectionPath -NoTypeInformation -Encoding UTF8

        $RdpSourceIps = @(
            $RdpConnections |
                Select-Object -ExpandProperty RemoteAddress -Unique
        )

        Add-RunEvent "rdp_attribution" "CAPTURED" `
            "Observed active RDP source(s): $($RdpSourceIps -join ', ')"
    }
    else {
        Write-Warning "No active RDP TCP source was observed; attribution may remain unresolved."
        Add-RunEvent "rdp_attribution" "UNRESOLVED" `
            "No established connection to local TCP port 3389 was observed."
    }

    # Record target files before attack activity.
    Export-FileInventory `
        -OutputPath (Join-Path $ClientRoot "01-pre-wipe-files.csv")

    # Exact event-export window starts here.
    $AttackStart = Get-Date

    # -------------------------
    # 5. Run discovery
    # -------------------------

    $Discovery = Invoke-EvidenceStep -Phase "discovery" -Action {
        & $DiscoveryScript `
            -RunId $RunId `
            -OutputDirectory $DiscoveryRoot
    }

    # -------------------------
    # 6. Prove DC access and stage payload
    # -------------------------

    Invoke-EvidenceStep -Phase "dc_netlogon" -Action {
        & $DcAccessScript `
            -RunId $RunId `
            -DomainControllerEvidencePath $Discovery.RunDirectory `
            -OutputDirectory $DcRoot
    }

    if (-not (Test-Path $NetlogonWiper -PathType Leaf)) {
        throw "Netlogon wiper was not staged: $NetlogonWiper"
    }

    # -------------------------
    # 7. Launch separate wiper process
    # -------------------------

    Invoke-EvidenceStep -Phase "wiper" -Action {
        # This launches a distinct powershell.exe process.
        # Sysmon should record its parent, command line, user, and image.
        Write-Output "Hello!"
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& '\\purplelab.local\netlogon\simulated_wiper.ps1' -TargetDirectory 'C:\WiperTest'"

        if ($LASTEXITCODE -ne 0) {
            throw "Wiper process exited with code $LASTEXITCODE."
        }
    }

    # End attack window immediately after wiper completion.
    $AttackEnd = Get-Date

    Export-FileInventory `
        -OutputPath (Join-Path $ClientRoot "05-post-wipe-files.csv")

    # Allow Sysmon a few seconds to finish writing events.
    Start-Sleep -Seconds 3

    # -------------------------
    # 8. Export exact event window
    # -------------------------

    Invoke-EvidenceStep -Phase "event_export" -Action {
        & $ExportScript `
            -StartTime $AttackStart `
            -EndTime $AttackEnd `
            -AttributionStartTime $AttributionStart `
            -OutputDirectory $ClientRoot
    }

    $SysmonCsv = Join-Path `
        $ClientRoot `
        "EventLog_Microsoft-Windows-Sysmon_Operational.csv"

    if (-not (Test-Path $SysmonCsv -PathType Leaf)) {
        throw "Required Sysmon CSV was not created."
    }

    # Clean-run requirement: Sysmon must show the wiper PowerShell process.
    $WiperProcessEvents = @(
        Import-Csv $SysmonCsv |
            Where-Object {
                $_.Id -eq "1" -and
                $_.Message -match "simulated_wiper\.ps1"
            }
    )

    if ($WiperProcessEvents.Count -eq 0) {
        throw "No Sysmon Event ID 1 found for simulated_wiper.ps1."
    }

    Add-RunEvent `
        "evidence_validation" `
        "COMPLETED" `
        "Found $($WiperProcessEvents.Count) matching Sysmon process event(s)."

    $RunStatus = "EVIDENCE_CAPTURED"

    # -------------------------
    # 9. Require cleanup approval
    # -------------------------

    $CleanupChoice = Read-Host (
        "Evidence captured. Verify files, then type CLEANUP to restore lab"
    )

    if ($CleanupChoice -eq "CLEANUP") {
        Invoke-EvidenceStep -Phase "cleanup" -Action {
            & $CleanupScript `
                -RunId $RunId `
                -OutputDirectory $ClientRoot
        }

        $CleanupStatus = "COMPLETED"
        $RunStatus = "COMPLETED"
    }
    else {
        $CleanupStatus = "SKIPPED"
        $RunStatus = "EVIDENCE_CAPTURED_CLEANUP_SKIPPED"

        Add-RunEvent `
            "cleanup" `
            "SKIPPED" `
            "Operator did not approve cleanup."
    }

    Add-RunEvent "run" $RunStatus "IT evidence run finished."
}
catch {
    $FailureMessage = $_.Exception.Message
    $RunStatus = "FAILED"

    Add-RunEvent "run" "FAILED" $FailureMessage
}
finally {
    $RunEnded = Get-Date

    # Transcript must stop before hashing, or its hash would immediately change.
    if ($TranscriptStarted) {
        Stop-Transcript | Out-Null
    }

    # -------------------------
    # 10. Generate run notes
    # -------------------------

    $AttackStartText = if ($AttackStart) {
        $AttackStart.ToUniversalTime().ToString("o")
    }
    else {
        "not-recorded"
    }

    $AttackEndText = if ($AttackEnd) {
        $AttackEnd.ToUniversalTime().ToString("o")
    }
    else {
        "not-recorded"
    }

    $RdpSourceText = if ($RdpSourceIps.Count -gt 0) {
        $RdpSourceIps -join ", "
    }
    else {
        "unresolved"
    }

    $Notes = @"
Project Janus - IT Run Notes

Run ID: $RunId
Run status: $RunStatus
Cleanup status: $CleanupStatus

Run started UTC: $($RunStarted.ToUniversalTime().ToString("o"))
Run ended UTC: $($RunEnded.ToUniversalTime().ToString("o"))
Attack started UTC: $AttackStartText
Attack ended UTC: $AttackEndText
RDP attribution window UTC: $($AttributionStart.ToUniversalTime().ToString("o")) to $AttackEndText
Observed active RDP source IP(s): $RdpSourceText

Initiating host: $env:COMPUTERNAME
Initiating user: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
Target directory: $TargetDirectory
Netlogon payload: $NetlogonWiper

Required behavior:
- Local domain discovery
- WinRM access to domain controller
- Payload transfer through Netlogon
- Separate powershell.exe wiper process
- Local disposable-file deletion
- Exact-time Sysmon and PowerShell event export
- RDP source attribution from active TCP, Security 4624, or optional Event 1149
- Lab cleanup after operator approval

Safe response candidate:
- Alert and preserve evidence
- If attribution is valid, request analyst approval for a temporary
  ${ProposedBlockMinutes}-minute pfSense source-IP block
- Never block a hardcoded address or act when attribution is unresolved

Failure: $FailureMessage
"@

    $Notes | Set-Content `
        (Join-Path $MetadataRoot "run_notes.txt") `
        -Encoding UTF8

    # -------------------------
    # 11. Hash all raw evidence
    # -------------------------

    $HashLines = foreach (
        $File in Get-ChildItem $RawRoot -File -Recurse | Sort-Object FullName
    ) {
        $Hash = Get-FileHash $File.FullName -Algorithm SHA256

        # Store a path relative to run root.
        $RelativePath = $File.FullName.Substring($RunRoot.Length)
        $RelativePath = $RelativePath.TrimStart("\")

        "$($Hash.Hash)  $RelativePath"
    }

    $HashLines | Set-Content `
        (Join-Path $MetadataRoot "file_hashes.sha256") `
        -Encoding ASCII
}

# Normalize and validate captured IT telemetry
# ===========================================================================
# Raw evidence remains unchanged. The PowerShell normalizer first creates flat
# CSV derivatives. The Python adapter then converts them to schema-valid JSONL.

$NormalizeParameters = @{
    InputDirectory = $RawRoot
    OutputDir       = $DerivedRoot
    RunId           = $RunId
    Label           = "attack"
}

$SysmonNormalized = Join-Path $DerivedRoot "sysmon_normalized.csv"
$PowerShellNormalized = Join-Path $DerivedRoot "powershell_normalized.csv"
$RdpNormalized = Join-Path $DerivedRoot "rdp_normalized.csv"
$WindowsJsonl = Join-Path $DerivedRoot "windows_events.jsonl"

Write-Host "`nNormalizing Windows events to CSV..." -ForegroundColor Cyan

$NormalizationFailure = $null

try {
    & $NormalizeScript @NormalizeParameters

    foreach ($NormalizedCsv in @(
        $SysmonNormalized,
        $PowerShellNormalized,
        $RdpNormalized
    )) {
        if (-not (Test-Path $NormalizedCsv -PathType Leaf)) {
            throw "Expected normalized CSV was not created: $NormalizedCsv"
        }
    }

    Write-Host "Converting normalized CSVs to validated JSONL..." `
        -ForegroundColor Cyan

    & $PythonExe $JsonNormalizer `
        --sysmon $SysmonNormalized `
        --powershell $PowerShellNormalized `
        --rdp $RdpNormalized `
        --schema $WindowsSchema `
        --output $WindowsJsonl

    if ($LASTEXITCODE -ne 0) {
        throw "Windows JSON normalization failed with exit code $LASTEXITCODE."
    }

    if (-not (Test-Path $WindowsJsonl -PathType Leaf)) {
        throw "JSON normalizer did not create: $WindowsJsonl"
    }

    Write-Host "IT CSV and JSONL normalization completed." `
        -ForegroundColor Green
}
catch {
    # Normalization failure does not erase or invalidate raw evidence.
    $NormalizationFailure = $_.Exception.Message
    Write-Warning "Raw evidence was captured, but normalization failed:"
    Write-Warning $NormalizationFailure
}

if ($FailureMessage) {
    throw $FailureMessage
}

if ($NormalizationFailure) {
    throw $NormalizationFailure
}

Write-Host "IT evidence run completed: $RunRoot"