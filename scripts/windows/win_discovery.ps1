<#
.SYNOPSIS
    Collects a small set of read-only Windows and domain discovery evidence.

.EXAMPLE
    .\win_discovery.ps1 -OutputDirectory C:\ProjectJanus\evidence\attack\it
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory,

    [Parameter(Mandatory)]
    [ValidatePattern('^run-\d{3,}$')]
    [string]$RunId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-EvidenceJson {
    param(
        [Parameter(Mandatory)][object]$Data,
        [Parameter(Mandatory)][string]$Path
    )

    $Data | ConvertTo-Json -Depth 6 |
        Set-Content -LiteralPath $Path -Encoding utf8
}

# Create one unique directory for this discovery run.
if (-not (Test-Path -LiteralPath $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}

if (-not (Test-Path -LiteralPath $OutputDirectory -PathType Container)) {
    throw "OutputDirectory must be a directory: $OutputDirectory"
}

$evidenceParent = (Resolve-Path -LiteralPath $OutputDirectory).Path
$startedUtc = (Get-Date).ToUniversalTime()


<#$safeHostName = $env:COMPUTERNAME -replace '[^a-zA-Z0-9._-]', '_'
$runId = 'windows-discovery_{0}_{1}' -f `
$safeHostName, $startedUtc.ToString('yyyyMMddTHHmmssfffZ')
$runDirectory = Join-Path $evidenceParent $runId
New-Item -ItemType Directory -Path $runDirectory -ErrorAction Stop | Out-Null#>
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$runDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path

$metadataPath = Join-Path $runDirectory "00_run-metadata.json"
if(Test-Path $metadataPath) {
    throw "Discovery evidence already exists. Use a new run ID"
}

# Record basic run context.
$metadata = [ordered]@{
    project        = 'Project Janus'
    script         = 'win_discovery.ps1'
    run_id         = $RunId
    started_utc    = $startedUtc.ToString('o')
    collector_host = $env:COMPUTERNAME
    collector_user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    run_directory  = $runDirectory
    mode           = 'local_read_only_discovery'
}

Write-EvidenceJson -Data $metadata `
    -Path $metadataPath

# Collect only the host/domain facts useful to this IT scenario.
$computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
$operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem

$domainInfo = [ordered]@{
    collected_utc = (Get-Date).ToUniversalTime().ToString('o')
    computer_name = $computerSystem.Name
    os_name        = $operatingSystem.Caption
    os_version     = $operatingSystem.Version
    part_of_domain = $computerSystem.PartOfDomain
    domain         = $computerSystem.Domain
    domain_role    = $computerSystem.DomainRole
}

Write-EvidenceJson -Data $domainInfo `
    -Path (Join-Path $runDirectory '01_domain.json')

# Record the current identity and whether it already has local admin rights.
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [System.Security.Principal.WindowsPrincipal]::new($identity)

$privilegeInfo = [ordered]@{
    collected_utc  = (Get-Date).ToUniversalTime().ToString('o')
    current_user   = $identity.Name
    is_administrator = $principal.IsInRole(
        [System.Security.Principal.WindowsBuiltInRole]::Administrator
    )
    security_groups = @(
        whoami.exe /groups /fo csv 2>$null | ConvertFrom-Csv
    )
}

Write-EvidenceJson -Data $privilegeInfo `
    -Path (Join-Path $runDirectory '02_privileges.json')

$serverFqdn = $null

# Find the domain controller and save its FQDN for test_dc_access.ps1.
if ($computerSystem.PartOfDomain) {
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
        $domainController = $domain.FindDomainController()
        $serverFqdn = $domainController.Name

        $domainControllerInfo = [ordered]@{
            collected_utc = (Get-Date).ToUniversalTime().ToString('o')
            domain        = $domain.Name
            dc_name       = $domainController.Name
            dc_ip_address = $domainController.IPAddress
            dc_site       = $domainController.SiteName
            reachable     = $true
        }
    }
    catch {
        $domainControllerInfo = [ordered]@{
            collected_utc = (Get-Date).ToUniversalTime().ToString('o')
            reachable     = $false
            error         = $_.Exception.Message
        }
    }
}
else {
    $domainControllerInfo = [ordered]@{
        collected_utc = (Get-Date).ToUniversalTime().ToString('o')
        reachable     = $false
        reason        = 'Host is not joined to a domain.'
    }
}

Write-EvidenceJson -Data $domainControllerInfo `
    -Path (Join-Path $runDirectory '03_domain-controller.json')

Write-Host "Discovery complete: $runDirectory"

# Returning the directory makes it easy to pass into test_dc_access.ps1.
[PSCustomObject]@{
    RunDirectory =  $runDirectory
    ServerFqdn   = $serverFqdn
}