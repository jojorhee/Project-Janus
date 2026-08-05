<#
Finalizes an OT run after the Linux PCAP has been stopped and copied into raw\.

Usage:
    .\finalize_ot_run.ps1 -RunId run-001
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^run-\d{3,}$')]
    [string]$RunId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Build the same paths used by run_ot_action.ps1.
$ProjectRoot = Split-Path $PSScriptRoot -Parent
$ConfigPath = Join-Path $ProjectRoot "config\lab.json"
if (-not (Test-Path $ConfigPath -PathType Leaf)) {
    throw "Configuration file not found: $ConfigPath"
}

$Config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
$RunRoot = Join-Path $Config.evidence.windows_root `
    "$($Config.evidence.ot_folder)\$($Config.evidence.runs_folder)\$RunId"
$RawRoot = Join-Path $RunRoot $Config.evidence.raw_folder
$DerivedRoot = Join-Path $RunRoot $Config.evidence.derived_folder
$MetadataRoot = Join-Path $RunRoot $Config.evidence.metadata_folder

$PcapName = "ot_$($RunId.Replace('-', '_')).pcap"
$PcapPath = Join-Path $RawRoot $PcapName
$NotesPath = Join-Path $MetadataRoot "run_notes.txt"
$NormalizedCsv = Join-Path $DerivedRoot "modbus_normalized.csv"
$HashPath = Join-Path $MetadataRoot "file_hashes.sha256"
$Normalizer = Join-Path $PSScriptRoot "normalize_ot_evidence.ps1"
$Tshark = "C:\Program Files\Wireshark\tshark.exe"

# Fail before changing evidence if anything required is unavailable.
foreach ($RequiredFile in @($PcapPath, $NotesPath, $Normalizer, $Tshark)) {
    if (-not (Test-Path $RequiredFile -PathType Leaf)) {
        throw "Required file not found: $RequiredFile"
    }
}
foreach ($NewFile in @($NormalizedCsv, $HashPath)) {
    if (Test-Path $NewFile) {
        throw "Finalized output already exists: $NewFile"
    }
}

$Notes = Get-Content $NotesPath -Raw
if ($Notes -notmatch '(?m)^Packets captured:' -or
    $Notes -notmatch '(?m)^Write-request frame(?:\(s\))?:') {
    throw "Run notes do not contain the expected PCAP placeholders."
}

# Count every frame in the completed PCAP.
$Frames = @(& $Tshark -r $PcapPath -T fields -e frame.number)
if ($LASTEXITCODE -ne 0 -or $Frames.Count -eq 0) {
    throw "TShark could not read packets from: $PcapPath"
}

# Validate that the PCAP contains at least one client write request.
$WriteFilter = 'tcp.dstport == 502 && ' +
    '(modbus.func_code == 5 || modbus.func_code == 15)'
$WriteFrames = @(
    & $Tshark -r $PcapPath -Y $WriteFilter -T fields -e frame.number |
        Where-Object { $_ }
)
if ($LASTEXITCODE -ne 0) {
    throw "TShark could not inspect Modbus writes in: $PcapPath"
}
if ($WriteFrames.Count -eq 0) {
    throw "No Modbus write-request frames were found."
}

# Normalize Modbus packets into derived\.
& $Normalizer `
    -PcapPath $PcapPath `
    -OutputDirectory $DerivedRoot `
    -RunId $RunId `
    -Label "attack"

if (-not (Test-Path $NormalizedCsv -PathType Leaf)) {
    throw "Normalizer did not create: $NormalizedCsv"
}

# Replace the pending values without rewriting the rest of the notes.
$WriteFrameText = $WriteFrames -join ", "
$Notes = $Notes -replace '(?m)^Packets captured:.*$', `
    "Packets captured: $($Frames.Count)"
$Notes = $Notes -replace '(?m)^Write-request frame(?:\(s\))?:.*$', `
    "Write-request frame(s): $WriteFrameText"
$Notes | Set-Content $NotesPath -Encoding UTF8

# Hash the final run, excluding the manifest that is being created.
$HashLines = foreach (
    $File in Get-ChildItem $RunRoot -File -Recurse |
        Where-Object FullName -ne $HashPath |
        Sort-Object FullName
) {
    $Hash = Get-FileHash $File.FullName -Algorithm SHA256
    $RelativePath = $File.FullName.Substring($RunRoot.Length).TrimStart("\")
    "$($Hash.Hash)  $RelativePath"
}
$HashLines | Set-Content $HashPath -Encoding ASCII

Write-Host "OT run finalized: $RunRoot" -ForegroundColor Green
Write-Host "Packets: $($Frames.Count) | Write request frame(s): $WriteFrameText"