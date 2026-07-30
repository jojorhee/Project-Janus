[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$DomainControllerEvidencePath,
    #[Parameter(Mandatory)]
    [string]$OutputDirectory = $DomainControllerEvidencePath
)

<#$DomainControllerEvidencePath = (Get-ChildItem -Path $DomainControllerEvidencePath -Directory | Sort-Object CreationTime -Descending | 
Select-Object -First 1).FullName#>
$DomainControllerEvidencePath = Join-Path -Path $DomainControllerEvidencePath -ChildPath "05_domain-controller.json"
$ErrorActionPreference = 'Stop'


$ServerFqdn = (
    Get-Content $DomainControllerEvidencePath -Raw | ConvertFrom-Json
).dc_name


$credential = Get-Credential -UserName 'PURPLELAB\Administrator' `
    -Message 'Enter the approved Windows Server/DC lab credentials.'

# Confirms that WinRM is reachable before attempting remote commands.
Test-WSMan -ComputerName $ServerFqdn | Out-Null

# Runs harmless identity checks on the DC.
$accessProof = Invoke-Command `
    -ComputerName $ServerFqdn `
    -Credential $credential `
    -ScriptBlock {
        $computer = Get-CimInstance Win32_ComputerSystem

        [PSCustomObject]@{
            collected_utc    = (Get-Date).ToUniversalTime().ToString('o')
            remote_hostname  = $env:COMPUTERNAME
            remote_user      = whoami.exe
            domain           = $computer.Domain
            domain_role      = $computer.DomainRole
            is_domain_dc     = $computer.DomainRole -in @(4, 5)
        }
    }

$result = [ordered]@{
    target_fqdn    = $ServerFqdn
    winrm_reachable = $true
    remote_access  = $accessProof
}

$proofPath = Join-Path $OutputDirectory 'dc-access-proof.json'
$result | ConvertTo-Json -Depth 4 |
    Set-Content -LiteralPath $proofPath -Encoding utf8

Write-Host "DC access test passed: $proofPath"

#Copy-Item -Path "C:\CyberRangers\payload\simulated_wiper.ps1" -Destination "\\purplelab.local\NETLOGON" -FromSession (New-PSSession -ComputerName $ServerFqdn -Credential ($Credential))
#Enter-PSSession -ComputerName $ServerFqdn -Credential ($credential)
$Session = New-PSSession -ComputerName $ServerFqdn -Credential ($credential)

Copy-Item -Path "C:\CyberRangers\payload\simulated_wiper.ps1" -Destination "\\purplelab.local\NETLOGON" -FromSession $Session

Remove-PSSession $Session