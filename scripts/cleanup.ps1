[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Fixed lab paths prevent this cleanup script from affecting unintended files.
$BackupPath = 'C:\WiperTest-Backup'
$TargetPath = 'C:\WiperTest'
$NetlogonPayloadPath = '\\purplelab\netlogon\simulated_wiper.ps1'

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

    # Remove only the named simulated payload from NETLOGON.
    if (Test-Path -LiteralPath $NetlogonPayloadPath -PathType Leaf) {
        Remove-Item -LiteralPath $NetlogonPayloadPath -Force
        Write-Host "Removed NETLOGON payload: $NetlogonPayloadPath"
    }
    else {
        Write-Warning "NETLOGON payload was already absent: $NetlogonPayloadPath"
    }

    Write-Host 'Cleanup completed successfully.'
}
catch {
    Write-Error "Cleanup failed: $($_.Exception.Message)"
    exit 1
}