[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$DomainControllerEvidencePath,

    [Parameter(Mandatory)]
    [string]$OutputDirectory = $DomainControllerEvidencePath,

    [Parameter(Mandatory)]
    [ValidatePattern('^run-\d{3,}$')]
    [string]$RunId
)

<#$DomainControllerEvidencePath = (Get-ChildItem -Path $DomainControllerEvidencePath -Directory | Sort-Object CreationTime -Descending | 
Select-Object -First 1).FullName#>
# $DomainControllerEvidencePath = Join-Path -Path $DomainControllerEvidencePath -ChildPath "03_domain-controller.json"
$ErrorActionPreference = 'Stop'

New-Item $OutputDirectory -ItemType Directory -Force | Out-Null

$DiscoveryPath = Join-Path `
    $DomainControllerEvidencePath "03_domain-controller.json"

$EvidencePath = Join-Path `
    $OutputDirectory "03-dc-netlogon-proof.json"

if (-not (Test-Path $DiscoveryPath -PathType Leaf)) {
    throw "Domain-controller discovery evidence missing: $DiscoveryPath"
}

if (Test-Path $EvidencePath) {
    throw "DC evidence already exists. Use a new run ID."
}

$ServerFqdn = (
    Get-Content $DiscoveryPath -Raw | ConvertFrom-Json
).dc_name


$RemotePayloadPath = "C:\CyberRangers\payload\simulated_wiper.ps1"
$NetlogonDestination = "\\purplelab.local\NETLOGON\simulated_wiper.ps1"

# Start with failure-safe values. These will be updated as each step succeeds.
$Result = [ordered]@{
    run_id                    = $RunId
    started_utc              = (Get-Date).ToUniversalTime().ToString("o")
    initiating_host          = $env:COMPUTERNAME
    initiating_user          = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    target_fqdn              = $ServerFqdn
    winrm_reachable          = $false
    remote_access            = $null
    remote_payload_path      = $RemotePayloadPath
    remote_payload_sha256    = $null
    netlogon_destination     = $NetlogonDestination
    netlogon_payload_sha256  = $null
    copy_verified            = $false
    error                    = $null
}

# $Session = null

try {
    Test-WSMan -ComputerName $ServerFqdn | Out-Null
    $Result.winrm_reachable = $true

    $Credential = Get-Credential `
        -UserName "PURPLELAB\Administrator" `
        -Message "Enter approved DC lab credentials."

    $Session = New-PSSession `
        -ComputerName $ServerFqdn `
        -Credential $Credential

    # Record remote hostname, user, domain, DC role
    $Result.remote_access = Invoke-Command -Session $Session -ScriptBlock {
        $Computer = Get-CimInstance Win32_ComputerSystem

        [PSCustomObject]@{
            collected_utc    = (Get-Date).ToUniversalTime().ToString('o')
            remote_hostname  = $env:COMPUTERNAME
            remote_user      = whoami.exe
            domain           = $computer.Domain
            domain_role      = $computer.DomainRole
            is_domain_dc     = $computer.DomainRole -in @(4, 5)
        }
    }

    # Hash source payload while it is still on the DC.
    $SourceHash = Invoke-Command `
        -Session $Session `
        -ArgumentList $RemotePayloadPath `
        -ScriptBlock {
            param($Path)

            if (-not (Test-Path $Path -PathType Leaf)) {
                throw "Remote payload missing: $Path"
            }

            (Get-FileHash $Path -Algorithm SHA256).Hash
        }

    $Result.remote_payload_sha256 = $SourceHash

    Copy-Item `
        -FromSession $Session `
        -Path $RemotePayloadPath `
        -Destination $NetlogonDestination `
        -Force

    if (-not (Test-Path $NetlogonDestination -PathType Leaf)) {
        throw "Payload was not found in Netlogon after copy."
    }

    # Hash destination and prove it matches the server source.
    $DestinationHash = (
        Get-FileHash $NetlogonDestination -Algorithm SHA256
    ).Hash

    $Result.netlogon_payload_sha256 = $DestinationHash
    $Result.copy_verified = $SourceHash -eq $DestinationHash

    if (-not $Result.copy_verified) {
        throw "Source and Netlogon payload hashes do not match."
    }
} catch {
    throw $_Exception.Message
} finally {
    if($Session) {
        Remove-PSSession $Session
    }

    $Result.completed_utc = (Get-Date).ToUniversalTime().ToString("o")

    $Result | ConvertTo-Json -Depth 6 |
    Set-Content -LiteralPath $EvidencePath -Encoding utf8
}