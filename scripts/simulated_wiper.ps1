[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$TargetDirectory
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

Get-ChildItem -LiteralPath $target -File -Recurse |
    Where-Object FullName -ne $marker |
    Remove-Item -Force -WhatIf:$WhatIfPreference

Write-Host "Cleanup completed: $target"