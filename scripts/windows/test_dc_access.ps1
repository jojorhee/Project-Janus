[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$DomainControllerEvidencePath
    [Parameter(Mandatory)]
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $DomainControllerEvidencePath -PathType Leaf)) {
    throw "Target directory does not exist: $DomainControllerEvidencePath"
}
if(!((Get-Item $DomainControllerEvidencePath).Extension -eq ".json")) {
    throw "Error: " + $DomainControllerEvidencePath + " is not a json file!"
}

$data = Get-Content -Path $DomainControllerEvidencePath -Raw | ConvertFrom-Json
$ServerFqdn = $data.dc_name


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

$accessProof | ConvertTo-Json |
    Set-Content -Path (Join-Path $OutputDirectory 'dc-access-proof.json') -Encoding UTF8

Enter-PSSession -ComputerName $ServerFqdn -Credential ($credential)