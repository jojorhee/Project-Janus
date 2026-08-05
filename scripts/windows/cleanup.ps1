[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^run-\d{3,}$')]
    [string]$RunId,

    # run-001\raw\windows-client
    [Parameter(Mandatory)]
    [string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Fixed lab paths prevent this cleanup script from affecting unintended files.
$BackupPath = 'C:\WiperTest-Backup'
$TargetPath = 'C:\WiperTest'
$NetlogonPayloadPath = '\\purplelab\netlogon\simulated_wiper.ps1'

New-Item $OutputDirectory -ItemType Directory -Force | Out-Null

$EvidencePath = Join-Path $OutputDirectory "06-cleanup-result.json"

if (Test-Path $EvidencePath) {
    throw "Cleanup evidence already exists. Use a new run ID."
}

$Result = [ordered]@{
    run_id                    = $RunId
    started_utc              = (Get-Date).ToUniversalTime().ToString("o")
    hostname                 = $env:COMPUTERNAME
    backup_path              = $BackupPath
    target_path              = $TargetPath
    restored_item_count      = 0
    target_restored          = $false
    netlogon_payload_path    = $NetlogonPayloadPath
    netlogon_payload_removed = $false
    error                    = $null
}

try {
    # Do not create or modify the target unless the known backup exists.
    if (-not (Test-Path -LiteralPath $BackupPath -PathType Container)) {
        throw "Backup directory not found: $BackupPath"
    }

    # Recreate the safe test directory if the wiper removed it.
    if (-not (Test-Path -LiteralPath $TargetPath -PathType Container)) {
        New-Item -ItemType Directory -Path $TargetPath -Force | Out-Null
    }

    # Copy every backup item, including hidden marker files and subdirectories.
    $BackupItems = Get-ChildItem -LiteralPath $BackupPath -Force
    foreach ($Item in $BackupItems) {
        Copy-Item -LiteralPath $Item.FullName `
            -Destination $TargetPath `
            -Recurse `
            -Force
    }

    Write-Host "Restored $($BackupItems.Count) backup item(s) to $TargetPath"

    $Result.restored_item_count = $BackupItems.Count
    $Result.target_restored = Test-Path `
        (Join-Path $TargetPath ".wiper-lab-approved") `
        -PathType Leaf

    # Remove only the named simulated payload from NETLOGON.
    if (Test-Path -LiteralPath $NetlogonPayloadPath -PathType Leaf) {
        Remove-Item -LiteralPath $NetlogonPayloadPath -Force
        Write-Host "Removed NETLOGON payload: $NetlogonPayloadPath"
        $Result.netlogon_payload_removed = $true
    }
    else {
        Write-Warning "NETLOGON payload was already absent: $NetlogonPayloadPath"
        $Result.netlogon_payload_removed = $true
    }

    Write-Host 'Cleanup completed successfully.'
}
catch {
    throw "Cleanup failed: $($_.Exception.Message)"
} finally {
    # Preserve cleanup evidence on both success and failure.
    $Result.completed_utc = (
        Get-Date
    ).ToUniversalTime().ToString("o")

    $Result | ConvertTo-Json -Depth 4 |
        Set-Content $EvidencePath -Encoding UTF8
}