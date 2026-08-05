[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$TargetDirectory,

    [Parameter(Mandatory)]
    [string]$EvidencePath
)

$markerName = '.wiper-lab-approved'
#$markerText = 'CLEANUP_APPROVED'

$target = (Resolve-Path -LiteralPath $TargetDirectory).Path
$marker = Join-Path $target $markerName

# Refuse dangerous targets such as C:\
if ($target -eq [System.IO.Path]::GetPathRoot($target)) {
    throw 'Refusing to clean a drive root.'
}

# Marker must exist directly inside the target directory.
if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) {
    throw "Required marker not found: $marker"
}

# This is a lil simple, but lets spice thangs up! We can record the start time of the wipe,
# Create a record for each targeted file, create a deletion manifest, and save evidence
<#Get-ChildItem -LiteralPath $target -File -Recurse |
    Where-Object FullName -ne $marker |
    Remove-Item -Force -WhatIf:$WhatIfPreference#>
$StartedUtc = (Get-Date).ToUniversalTIme()
$Files = @(
    Get-ChildItem -LiteralPath $target -File -Recurse | Where-Object FullName -ne $marker
)

$FileResults = foreach ($File in $Files) {
    $Hash = (Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash
    $Status = "skipped"

    try {
        # Supports -WhatIf while allowing normal deletion during real runs.
        if ($PSCmdlet.ShouldProcess($File.FullName, "Delete approved test file")) {
            Remove-Item -LiteralPath $File.FullName -Force
            $Status = "deleted"
        }
        elseif ($WhatIfPreference) {
            $Status = "whatif"
        }
    }
    catch {
        $Status = "failed: $($_.Exception.Message)"
    }

    [PSCustomObject]@{
        path            = $File.FullName
        size_bytes      = $File.Length
        sha256_before   = $Hash
        action_status   = $Status
    }
}

$FailedFiles = @(
    $FileResults | Where-Object action_status -Like "failed:*"
)

# Create a structured deletion manifest.
$Result = [ordered]@{
    started_utc    = $StartedUtc.ToString("o")
    completed_utc  = (Get-Date).ToUniversalTime().ToString("o")
    hostname       = $env:COMPUTERNAME
    user           = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    target         = $target
    marker         = $marker
    whatif         = [bool]$WhatIfPreference
    targeted_count = $Files.Count
    deleted_count  = @($FileResults | Where-Object action_status -eq "deleted").Count
    failed_count   = $FailedFiles.Count
    files          = $FileResults
}

# Save evidence outside the directory being wiped.
New-Item (Split-Path $EvidencePath -Parent) `
    -ItemType Directory -Force | Out-Null

$Result | ConvertTo-Json -Depth 5 |
    Set-Content -LiteralPath $EvidencePath -Encoding UTF8

Write-Host "Wiper evidence saved: $EvidencePath"

if ($FailedFiles.Count -gt 0) {
    throw "$($FailedFiles.Count) approved test file(s) could not be deleted."
}