param(
    [string]$DeploymentRoot = "C:\CyberRangers\rules\it",
    [string]$Validator = "Z:\ai\validate_it_rules.py",
    [string]$BaselineEvents = "Z:\evidence\normalized\it\baseline_win_events_1.jsonl"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ActiveRule = Join-Path $DeploymentRoot "active\it_rule.json"
$BackupDir = Join-Path $DeploymentRoot "backups"
$LogDir = "C:\CyberRangers\deployment_logs\it"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

$BackupRule = Get-ChildItem $BackupDir -Filter "it_rule_*.json" |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if (-not $BackupRule) {
    throw "No IT-rule backup exists."
}

# Prove that the backup still passes baseline validation.
$ValidationOutput = & py $Validator `
    --mode baseline `
    --rule_file $BackupRule.FullName `
    --event_file $BaselineEvents 2>&1

$ValidationExit = $LASTEXITCODE
$ValidationOutput |
    Tee-Object (Join-Path $LogDir "rollback_validation_$Timestamp.log")

if ($ValidationExit -ne 0) {
    throw "Backup validation failed. Rollback cancelled."
}

# Preserve the rule being replaced.
$PreRollback = Join-Path $BackupDir "pre_rollback_$Timestamp.json"
Copy-Item $ActiveRule $PreRollback

# Stage the backup beside the active file.
$TemporaryRule = Join-Path `
    (Split-Path $ActiveRule) `
    "rollback_$Timestamp.tmp"

Copy-Item $BackupRule.FullName $TemporaryRule

$BackupHash = (Get-FileHash $BackupRule.FullName -Algorithm SHA256).Hash
$TemporaryHash = (Get-FileHash $TemporaryRule -Algorithm SHA256).Hash

if ($BackupHash -ne $TemporaryHash) {
    Remove-Item $TemporaryRule
    throw "Rollback staging hash mismatch."
}

# Atomically replace the active rule.
 Move-Item -LiteralPath $TemporaryRule -Destination $ActiveRule -Force

$ActiveHash = (Get-FileHash $ActiveRule -Algorithm SHA256).Hash

if ($ActiveHash -ne $BackupHash) {
    throw "Restored active-rule hash does not match the backup."
}

[ordered]@{
    timestamp          = (Get-Date).ToString("o")
    status             = "rollback_successful"
    restored_backup    = $BackupRule.FullName
    replaced_rule_copy = $PreRollback
    active_rule        = $ActiveRule
    sha256             = $ActiveHash
} |
    ConvertTo-Json |
    Set-Content (Join-Path $LogDir "rollback_$Timestamp.json")

Write-Host "Rollback successful."
Write-Host "Restored: $($BackupRule.FullName)"
Write-Host "Active SHA-256: $ActiveHash"