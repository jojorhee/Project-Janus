<# Pseudocode for discovering target directory for "wiping"
Load lab.json
Read windows settings

Search wiper_search_root for the marker file
Verify exactly one marker was found
Verify its folder equals wiper_approved_root

Take a human-chosen subdirectory, such as "documents"
Verify it exists inside wiper_approved_root
Refuse if it is the root itself

Write wiper-target-manifest.json:
    directories:
      - relative_directory: documents
        action: replace
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ConfigPath,

    # Example: documents
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$RelativeTargetDirectory,

    [ValidateSet('rename', 'quarantine', 'replace')]
    [string]$Action = 'replace'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-IsChildPath {
    param(
        [Parameter(Mandatory)][string]$ChildPath,
        [Parameter(Mandatory)][string]$ParentPath
    )

    $childFull = [System.IO.Path]::GetFullPath($ChildPath).TrimEnd('\')
    $parentFull = [System.IO.Path]::GetFullPath($ParentPath).TrimEnd('\')

    return $childFull.StartsWith(
        $parentFull + '\',
        [System.StringComparison]::OrdinalIgnoreCase
    )
}

if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
    throw "Config file was not found: $ConfigPath"
}

$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json

if ($null -eq $config.windows) {
    throw "lab.json is missing the 'windows' object."
}

$windows = $config.windows

foreach ($required in @(
    'wiper_search_root',
    'wiper_approved_root',
    'wiper_approval_marker',
    'wiper_target_manifest'
)) {
    if ([string]::IsNullOrWhiteSpace([string]$windows.$required)) {
        throw "lab.json is missing windows.$required"
    }
}

$searchRoot = (Resolve-Path -LiteralPath $windows.wiper_search_root).Path
$approvedRoot = (Resolve-Path -LiteralPath $windows.wiper_approved_root).Path
$markerFileName = [string]$windows.wiper_approval_marker
$manifestPath = (Resolve-Path -LiteralPath $windows.wiper_target_manifest)


$markers = @(
    Get-ChildItem -LiteralPath $searchRoot -Filter $markerFileName -File -Force -Recurse |
        Where-Object {
            -not ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint)
        }
)

if ($markers.Count -ne 1) {
    throw "Expected exactly one '$markerFileName' under $searchRoot; found $($markers.Count)."
}

$discoveredRoot = $markers[0].Directory.FullName

if ($discoveredRoot -ne $approvedRoot) {
    throw "Marker was found in an unapproved folder: $discoveredRoot"
}

Write-Host "Approved wiper folder discovered: $discoveredRoot"

# TODO:
# Reject an absolute $RelativeTargetDirectory.
# 2. Join it to $approvedRoot.
# 3. Confirm it exists and is a directory.
# 4. Confirm it is inside $approvedRoot.
# 5. Refuse if it equals $approvedRoot itself.
if ([System.IO.Path]::IsPathRooted($RelativeTargetDirectory)) {
    throw "RelativeTargetDirectory must not be an absolute path."
}

$approvedFullPath = [System.IO.Path]::GetFullPath($approvedRoot).TrimEnd('\')
$joinedPath = [System.IO.Path]::GetFullPath(
    (Join-Path -Path $approvedFullPath -ChildPath $RelativeTargetDirectory)
).TrimEnd('\')
if($joinedPath eq $approvedRoot) {
    throw "Error: target directory cannot be the same as approved root directory"
}
if (-not (Test-Path -LiteralPath $joinedPath -PathType Container)) {
    throw "Target directory does not exist: $joinedPath"
}
if(not Test-Path -Path $joinedPath) {
    if(not ($joinedPath eq Container)) {
        throw "$joinedPath " + " is not a directory"
    } else {
        New-Item -Path $joinedPath -ItemType Directory
    }
}  



$manifestParent = Split-Path -Path $manifestPath -Parent

if (-not (Test-Path -LiteralPath $manifestParent -PathType Container)) {
    throw "Manifest parent directory does not exist: $manifestParent"
}

$manifest = [ordered]@{
    schema_version = 1
    generated_utc  = (Get-Date).ToUniversalTime().ToString('o')

    directories = @(
        [ordered]@{
            relative_directory = $RelativeTargetDirectory.Trim('\', '/')
            action             = $Action
        }
    )
}

$manifest | ConvertTo-Json -Depth 10 |
    Set-Content -LiteralPath $manifestPath -Encoding UTF8