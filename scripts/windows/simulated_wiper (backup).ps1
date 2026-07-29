<#
    Project Janus — safe, non-destructive Sandworm wiper simulation.

    Configuration comes from lab.json > windows:
      wiper_search_root, wiper_approved_root, wiper_approval_marker,
      wiper_target_manifest, payload_staging_path

    The per-run manifest contains directory entries, for example:
    {
      "directories": [
        { "relative_directory": "documents", "action": "replace" }
      ]
    }

    Default behavior is a dry run. Add -Execute only after reviewing output.
    This script never deletes files or directories.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$ConfigPath,

    [switch]$Execute
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# The marker file must contain this exact single line.
<#$ExpectedMarkerContent = 'JANUS_WIPER_LAB_APPROVED'
$QuarantineName = '_janus_quarantine'
$ReplacementText = 'JANUS LAB: safe simulated wipe replacement.`r`n'#>

function Get-CanonicalPath {
    param([Parameter(Mandatory)][string]$Path)
    [System.IO.Path]::GetFullPath($Path)
}

function Test-IsChildPath {
    param(
        [Parameter(Mandatory)][string]$ChildPath,
        [Parameter(Mandatory)][string]$ParentPath
    )

    $child = (Get-CanonicalPath $ChildPath).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    $parent = (Get-CanonicalPath $ParentPath).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    $comparison = if ($env:OS -eq 'Windows_NT') { [System.StringComparison]::OrdinalIgnoreCase } else { [System.StringComparison]::Ordinal }

    return $child.StartsWith($parent + [System.IO.Path]::DirectorySeparatorChar, $comparison)
}

function Test-IsReparsePoint {
    param([Parameter(Mandatory)][System.IO.FileSystemInfo]$Item)
    return [bool]($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)
}

function Write-Audit {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "[$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))] $Message"
}

function Get-SafeFilesUnderDirectory {
    param(
        [Parameter(Mandatory)][string]$DirectoryPath,
        [Parameter(Mandatory)][string]$ApprovedRoot,
        [Parameter(Mandatory)][string]$QuarantineRoot,
        [Parameter(Mandatory)][string]$MarkerPath
    )

    $pending = [System.Collections.Generic.Stack[string]]::new()
    $pending.Push($DirectoryPath)

    while ($pending.Count -gt 0) {
        $currentDirectory = $pending.Pop()
        foreach ($item in @(Get-ChildItem -LiteralPath $currentDirectory -Force)) {
            if (Test-IsReparsePoint $item) {
                Write-Audit "SKIP reparse point: $($item.FullName)"
                continue
            }

            $itemPath = Get-CanonicalPath $item.FullName
            if ($itemPath -eq $MarkerPath -or
                (Test-IsChildPath $itemPath $QuarantineRoot) -or
                -not (Test-IsChildPath $itemPath $ApprovedRoot)) {
                continue
            }

            if ($item.PSIsContainer) { $pending.Push($itemPath) }
            else { $itemPath }
        }
    }
}

$configFullPath = Get-CanonicalPath $ConfigPath
$config = Get-Content -LiteralPath $configFullPath -Raw | ConvertFrom-Json
if ($null -eq $config.windows) { throw "lab.json is missing the 'windows' object." }

foreach ($name in @('wiper_search_root', 'wiper_approved_root', 'wiper_approval_marker')) {
    if ([string]::IsNullOrWhiteSpace([string]$config.windows.$name)) {
        throw "lab.json is missing windows.$name"
    }
}

$markerName = [string]$config.windows.wiper_approval_marker

$searchRoot = Get-CanonicalPath ([string]$config.windows.wiper_search_root)
$approvedRoot = Get-CanonicalPath ([string]$config.windows.wiper_approved_root)
$markerName = [string]$config.windows.wiper_approval_marker
#$manifestPath = Get-CanonicalPath ([string]$config.windows.wiper_target_manifest)
#$stagingPath = Get-CanonicalPath ([string]$config.windows.payload_staging_path)
$scriptPath = Get-CanonicalPath $PSCommandPath

if (-not (Test-Path -LiteralPath $searchRoot -PathType Container)) { throw "wiper_search_root does not exist: $searchRoot" }
if (-not (Test-Path -LiteralPath $approvedRoot -PathType Container)) { throw "wiper_approved_root does not exist: $approvedRoot" }
if (-not (Test-IsChildPath $approvedRoot $searchRoot)) { throw 'wiper_approved_root must be inside wiper_search_root.' }
#if (-not (Test-IsChildPath $scriptPath $stagingPath)) { throw "This script must be run from payload_staging_path: $stagingPath" }
if ([System.IO.Path]::IsPathRooted($markerName) -or $markerName -match '[\\/]') { throw 'wiper_approval_marker must be a file name, not a path.' }

<#$markerPath = Join-Path $approvedRoot $markerName
if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) { throw "Approval marker is missing: $markerPath" }
if ((Get-Item -LiteralPath $markerPath -Force | ForEach-Object { Test-IsReparsePoint $_ })) { throw 'Approval marker cannot be a reparse point.' }
if ((Get-Content -LiteralPath $markerPath -Raw).Trim() -cne $ExpectedMarkerContent) { throw 'Approval marker content does not match the expected lab marker.' }#>

<#if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw "Target manifest is missing: $manifestPath" }
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($null -eq $manifest.directories -or @($manifest.directories).Count -eq 0) { throw "Manifest must contain a non-empty 'directories' array." }#>

$quarantineRoot = Join-Path $approvedRoot $QuarantineName
foreach ($entry in @($manifest.directories)) {
    foreach ($field in @('relative_directory', 'action')) {
        if ([string]::IsNullOrWhiteSpace([string]$entry.$field)) { throw "A directory entry is missing '$field'." }
    }

    $relativeDirectory = [string]$entry.relative_directory
    $action = [string]$entry.action
    if ($action -notin @('rename', 'quarantine', 'replace')) { throw "Unsupported action '$action'." }
    if ([System.IO.Path]::IsPathRooted($relativeDirectory) -or $relativeDirectory -match '(^|[\\/])\.\.([\\/]|$)') { throw "Unsafe manifest path: $relativeDirectory" }

    $targetDirectory = Get-CanonicalPath (Join-Path $approvedRoot $relativeDirectory)
    if ($targetDirectory -eq $approvedRoot) { throw 'The manifest may not target the WiperTest root.' }
    if (-not (Test-IsChildPath $targetDirectory $approvedRoot) -or (Test-IsChildPath $targetDirectory $quarantineRoot)) { throw "Target directory is outside the permitted scope: $relativeDirectory" }
    if (-not (Test-Path -LiteralPath $targetDirectory -PathType Container)) { throw "Target directory does not exist: $targetDirectory" }
    if (Test-IsReparsePoint (Get-Item -LiteralPath $targetDirectory -Force)) { throw "Target directory cannot be a reparse point: $targetDirectory" }

    foreach ($targetPath in @(Get-SafeFilesUnderDirectory -DirectoryPath $targetDirectory -ApprovedRoot $approvedRoot -QuarantineRoot $quarantineRoot -MarkerPath $markerPath)) {
        $file = Get-Item -LiteralPath $targetPath -Force
        $display = "$($action.ToUpperInvariant()): $targetPath"
        if (-not $Execute) { Write-Audit "DRY RUN $display"; continue }

        if ($action -eq 'rename') {
            $newName = "$($file.Name).janus-simulated-wiped"
            Write-Audit $display
            Rename-Item -LiteralPath $file.FullName -NewName $newName
        }
        elseif ($action -eq 'quarantine') {
            $relativeFile = $targetPath.Substring($approvedRoot.Length).TrimStart('\\', '/')
            $destination = Join-Path $quarantineRoot $relativeFile
            $destinationParent = Split-Path -Parent $destination
            if (-not (Test-Path -LiteralPath $destinationParent)) { New-Item -ItemType Directory -Path $destinationParent -Force | Out-Null }
            if (Test-Path -LiteralPath $destination) { throw "Refusing to overwrite existing quarantine file: $destination" }
            Write-Audit $display
            Move-Item -LiteralPath $file.FullName -Destination $destination
        }
        else {
            Write-Audit $display
            Set-Content -LiteralPath $file.FullName -Value $ReplacementText -NoNewline
        }
    }
}

if ($Execute) {
    Write-Audit 'Simulation complete.'
}
else {
    Write-Audit 'Dry run complete. Review output; use -Execute to apply.'
}