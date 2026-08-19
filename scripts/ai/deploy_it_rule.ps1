param(
    [string]$CandidateRule = "Z:\ai\candidates\generation-001\it_rule.json",
    [string]$Validator = "Z:\ai\validate_it_rules.py",
    [string]$BaselineEvents = "Z:\evidence\normalized\it\baseline_win_events_1.jsonl",
    [string]$DeploymentRoot = "C:\CyberRangers\rules\it"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ActiveDir = Join-Path $DeploymentRoot "active"
$BackupDir = Join-Path $DeploymentRoot "backups"
$LogDir = "C:\CyberRangers\deployment_logs\it"
$ActiveRule = Join-Path $ActiveDir "it_rule.json"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$TemporaryRule = Join-Path $ActiveDir "it_rule.$Timestamp.tmp"

New-Item -ItemType Directory -Force -Path $ActiveDir, $BackupDir, $LogDir |
    Out-Null

# Reject the candidate if baseline validation fails.
$ValidationLog = Join-Path $LogDir "predeployment_$Timestamp.log"

$ValidationOutput = & py $Validator `
    --mode baseline `
    --rule_file $CandidateRule `
    --event_file $BaselineEvents 2>&1

$ValidationExit = $LASTEXITCODE
$ValidationOutput | Tee-Object -FilePath $ValidationLog

if ($ValidationExit -ne 0) {
    throw "Candidate validation failed. Deployment cancelled."
}

$CandidateHash = (Get-FileHash $CandidateRule -Algorithm SHA256).Hash

# Stage and verify a complete temporary copy.
Copy-Item -LiteralPath $CandidateRule -Destination $TemporaryRule
$TemporaryHash = (Get-FileHash $TemporaryRule -Algorithm SHA256).Hash

if ($TemporaryHash -ne $CandidateHash) {
    Remove-Item $TemporaryRule
    throw "Temporary-file hash does not match the candidate."
}

# Preserve the currently active rule, if one exists.
$BackupRule = $null

if (Test-Path $ActiveRule) {
    $BackupRule = Join-Path $BackupDir "it_rule_$Timestamp.json"
    Copy-Item -LiteralPath $ActiveRule -Destination $BackupRule

    Move-Item -LiteralPath $TemporaryRule -Destination $ActiveRule -Force
}
else {
    Move-Item -LiteralPath $TemporaryRule -Destination $ActiveRule -Force
}

$ActiveHash = (Get-FileHash $ActiveRule -Algorithm SHA256).Hash

if ($ActiveHash -ne $CandidateHash) {
    throw "Active-rule hash verification failed."
}

$Record = [ordered]@{
    timestamp       = (Get-Date).ToString("o")
    status          = "deployed"
    candidate       = $CandidateRule
    active_rule     = $ActiveRule
    backup_rule     = $BackupRule
    sha256          = $ActiveHash
    validation_log  = $ValidationLog
}

$Record |
    ConvertTo-Json |
    Set-Content (Join-Path $LogDir "deployment_$Timestamp.json")

Write-Host "Deployment successful."
Write-Host "Active rule: $ActiveRule"
Write-Host "SHA-256: $ActiveHash"