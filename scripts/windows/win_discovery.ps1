<#
.SYNOPSIS
    Project Janus: local, read-only Windows discovery evidence collector.

.DESCRIPTION
    This first build creates an isolated evidence folder and records run metadata.
    Discovery collectors will be added below in small, reviewable sections.

    It makes no discovery-system configuration changes. The only write operations
    create the user-approved evidence directory and files inside it.
#>

[CmdletBinding()]
param(
    # Approved parent directory for this run's evidence.
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertTo-SafePathName {
    param([Parameter(Mandatory)][string]$Value)

    # Keep the run-folder name valid even if a hostname contains unusual characters.
    return ($Value -replace '[^a-zA-Z0-9._-]', '_')
}

function Write-EvidenceJson {
    param(
        [Parameter(Mandatory)][object]$Data,
        [Parameter(Mandatory)][string]$Path
    )

    $Data | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Path -Encoding utf8
}

# 1) Resolve the caller-approved evidence parent. Create it only when needed.
if (-not (Test-Path -LiteralPath $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}

if (-not (Test-Path -LiteralPath $OutputDirectory -PathType Container)) {
    throw "OutputDirectory must be a directory: $OutputDirectory"
}

$evidenceParent = (Resolve-Path -LiteralPath $OutputDirectory).Path

# 2) Give this run a unique, readable identifier.
$runStartedUtc = (Get-Date).ToUniversalTime()
$hostName = ConvertTo-SafePathName -Value $env:COMPUTERNAME
$runId = 'windows-discovery_{0}_{1}' -f $hostName, $runStartedUtc.ToString('yyyyMMddTHHmmssZ')
$runDirectory = Join-Path $evidenceParent $runId

if (Test-Path -LiteralPath $runDirectory) {
    throw "Evidence run directory already exists: $runDirectory"
}

New-Item -ItemType Directory -Path $runDirectory -ErrorAction Stop | Out-Null

# 3) Record enough context to connect later files to this exact run.
$runMetadata = [ordered]@{
    project = 'Project Janus'
    script = '01_windows_discovery.ps1'
    run_id = $runId
    started_utc = $runStartedUtc.ToString('o')
    collector_host = $env:COMPUTERNAME
    collector_user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    evidence_parent = $evidenceParent
    run_directory = $runDirectory
    mode = 'local_read_only_discovery'
}

$metadataPath = Join-Path $runDirectory '00_run-metadata.json'
Write-EvidenceJson -Data $runMetadata -Path $metadataPath

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertTo-SafePathName {
    param([Parameter(Mandatory)][string]$Value)

    # Keep the run-folder name valid even if a hostname contains unusual characters.
    return ($Value -replace '[^a-zA-Z0-9._-]', '_')
}

function Write-EvidenceJson {
    param(
        [Parameter(Mandatory)][object]$Data,
        [Parameter(Mandatory)][string]$Path
    )

    $Data | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Path -Encoding utf8
}

# 1) Resolve the caller-approved evidence parent. Create it only when needed.
if (-not (Test-Path -LiteralPath $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}

if (-not (Test-Path -LiteralPath $OutputDirectory -PathType Container)) {
    throw "OutputDirectory must be a directory: $OutputDirectory"
}

$evidenceParent = (Resolve-Path -LiteralPath $OutputDirectory).Path

# 2) Give this run a unique, readable identifier.
$runStartedUtc = (Get-Date).ToUniversalTime()
$hostName = ConvertTo-SafePathName -Value $env:COMPUTERNAME
$runId = 'windows-discovery_{0}_{1}' -f $hostName, $runStartedUtc.ToString('yyyyMMddTHHmmssZ')
$runDirectory = Join-Path $evidenceParent $runId
$attempt = 1

while (Test-Path -LiteralPath $runDirectory) {
    $runId = 'windows-discovery_{0}_{1}_{2}' -f `
        $hostName, `
        $runStartedUtc.ToString('yyyyMMddTHHmmssZ'), `
        $attempt

    $runDirectory = Join-Path $evidenceParent $runId
    $attempt++
}

New-Item -ItemType Directory -Path $runDirectory -ErrorAction Stop | Out-Null
# 3) Record enough context to connect later files to this exact run.
$runMetadata = [ordered]@{
    project = 'Project Janus'
    script = 'windows_discovery.ps1'
    run_id = $runId
    started_utc = $runStartedUtc.ToString('o')
    collector_host = $env:COMPUTERNAME
    collector_user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    evidence_parent = $evidenceParent
    run_directory = $runDirectory
    mode = 'local_read_only_discovery'
}

$metadataPath = Join-Path $runDirectory '00_run-metadata.json'
Write-EvidenceJson -Data $runMetadata -Path $metadataPath



# Privileges
$currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$currentPrincipal = [System.Security.Principal.WindowsPrincipal]::new($currentIdentity)

$privileges = [ordered]@{
    collected_utc = (Get-Date).ToUniversalTime().ToString('o')
    is_administrator = $currentPrincipal.IsInRole(
        [System.Security.Principal.WindowsBuiltInRole]::Administrator
    )
    token_privileges = @(
        whoami.exe /priv /fo csv 2>$null | ConvertFrom-Csv
    )
    security_groups = @(
        whoami.exe /groups /fo csv 2>$null | ConvertFrom-Csv
    )
}

Write-EvidenceJson -Data $privileges -Path (Join-Path $runDirectory '03_privileges.json')


# Domain
$computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem

$domainInfo = [ordered]@{
    collected_utc = (Get-Date).ToUniversalTime().ToString('o')
    part_of_domain = $computerSystem.PartOfDomain
    domain = $computerSystem.Domain
    domain_role = $computerSystem.DomainRole
    computer_name = $computerSystem.Name
}

Write-EvidenceJson -Data $domainInfo -Path (Join-Path $runDirectory '04_domain.json')


# Domain Controller
$domainControllerInfo = $null

if ($computerSystem.PartOfDomain) {
    try {
        $adDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
        $domainController = $adDomain.FindDomainController()

        $domainControllerInfo = [ordered]@{
            collected_utc = (Get-Date).ToUniversalTime().ToString('o')
            domain = $adDomain.Name
            dc_name = $domainController.Name
            dc_ip_address = $domainController.IPAddress
            dc_site = $domainController.SiteName
            reachable = $true
        }
    }
    catch {
        $domainControllerInfo = [ordered]@{
            collected_utc = (Get-Date).ToUniversalTime().ToString('o')
            reachable = $false
            error = $_.Exception.Message
        }
    }
}
else {
    $domainControllerInfo = [ordered]@{
        collected_utc = (Get-Date).ToUniversalTime().ToString('o')
        reachable = $false
        reason = 'Host is not joined to a domain.'
    }
}

Write-EvidenceJson -Data $domainControllerInfo -Path (Join-Path $runDirectory '05_domain-controller.json')


# Network Interfaces
$interfaces = foreach ($adapter in Get-NetAdapter -IncludeHidden) {
    $ipAddresses = @(
        Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue |
            Select-Object IPAddress, AddressFamily, PrefixLength, AddressState
    )

    $dnsServers = @(
        Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue |
            ForEach-Object { $_.ServerAddresses }
    )

    [ordered]@{
        name = $adapter.Name
        interface_index = $adapter.ifIndex
        status = $adapter.Status.ToString()
        mac_address = $adapter.MacAddress
        link_speed = $adapter.LinkSpeed
        ip_addresses = $ipAddresses
        dns_servers = $dnsServers
    }
}

Write-EvidenceJson -Data @(
    [ordered]@{
        collected_utc = (Get-Date).ToUniversalTime().ToString('o')
        interfaces = $interfaces
    }
) -Path (Join-Path $runDirectory '06_interfaces.json')


# Routes
$routes = Get-NetRoute -ErrorAction SilentlyContinue |
    Sort-Object AddressFamily, DestinationPrefix, RouteMetric |
    Select-Object `
        DestinationPrefix,
        NextHop,
        InterfaceAlias,
        InterfaceIndex,
        AddressFamily,
        RouteMetric,
        State,
        Protocol

Write-EvidenceJson -Data @(
    [ordered]@{
        collected_utc = (Get-Date).ToUniversalTime().ToString('o')
        routes = @($routes)
    }
) -Path (Join-Path $runDirectory '07_routes.json')


# Processes
$processes = Get-CimInstance -ClassName Win32_Process |
    Sort-Object ProcessId |
    Select-Object `
        ProcessId,
        ParentProcessId,
        Name,
        ExecutablePath,
        CommandLine,
        CreationDate

Write-EvidenceJson -Data @(
    [ordered]@{
        collected_utc = (Get-Date).ToUniversalTime().ToString('o')
        processes = @($processes)
    }
) -Path (Join-Path $runDirectory '08_processes.json')


# Services
$services = Get-CimInstance -ClassName Win32_Service |
    Sort-Object Name |
    Select-Object `
        Name,
        DisplayName,
        State,
        StartMode,
        StartName,
        ProcessId,
        PathName

Write-EvidenceJson -Data @(
    [ordered]@{
        collected_utc = (Get-Date).ToUniversalTime().ToString('o')
        services = @($services)
    }
) -Path (Join-Path $runDirectory '09_services.json')


# TODO (your practice): collect SMB shares into 10_shares.json.
$shares = Get-SmbShare | ForEach-Object { Get-SmbShareAccess -InputObject $_ }


Write-EvidenceJson -Data @(
    [ordered]@{
        collected_utc = (Get-Date).ToUniversalTime().ToString('o')
        shares = @($shares)
    }
) -Path (Join-Path $runDirectory '10_shares.json')

# TODO (your practice): collect network connections into 11_connections.json.
function ConvertTo-ConnectionAddress {
    param([string]$Address)

    switch ($Address) {
        '::'        { 'any-ipv6' }
        '::1'       { 'loopback-ipv6' }
        '0.0.0.0'   { 'any-ipv4' }
        '127.0.0.1' { 'loopback-ipv4' }
        default     { $Address }
    }
}

$connections = Get-NetTCPConnection -ErrorAction SilentlyContinue |
    Sort-Object State, LocalAddress, LocalPort |
    ForEach-Object {
        $isListener = $_.State -in @('Listen', 'Bound')

        [ordered]@{
            protocol       = 'TCP'
            state          = $_.State.ToString()
            local_address  = ConvertTo-ConnectionAddress $_.LocalAddress
            local_port     = $_.LocalPort
            remote_address = if ($isListener) { $null } else {
                ConvertTo-ConnectionAddress $_.RemoteAddress
            }
            remote_port    = if ($isListener) { $null } else {
                $_.RemotePort
            }
            owning_pid     = $_.OwningProcess
        }
    }

Write-EvidenceJson -Data @(
    [ordered]@{
        collected_utc = (Get-Date).ToUniversalTime().ToString('o')
        connections = @($connections)
    }
) -Path (Join-Path $runDirectory '11_connections.json')

<#$summaryPath = Join-Path $runDirectory '00_summary.txt'
@(
    'Project Janus - Windows Discovery Evidence'
    "Run ID: $runId"
    "Started (UTC): $($runMetadata.started_utc)"
    "Host: $($runMetadata.collector_host)"
    "User: $($runMetadata.collector_user)"
    'Status: Evidence folder initialized; collectors not yet added.'
) | Set-Content -LiteralPath $summaryPath -Encoding utf8#>

Write-Host "Evidence folder initialized: $runDirectory"