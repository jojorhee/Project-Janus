# Run this script in an elevated PowerShell window on the Domain Controller.
# The GPO startup script registers a Scheduled Task on targeted clients.
# The task then runs the payload every minute as SYSTEM.

<#
.SYNOPSIS
    Deploys a user-supplied PowerShell payload to lab clients through a GPO
    and recurring scheduled task.

.EXAMPLE
    .\Deploy-LabPayload.ps1 `
        -TargetOU 'OU=Purple-Team-Lab,DC=lab,DC=example,DC=com' `
        -PayloadPath 'C:\LabPayloads\SandwormSimulation.ps1' `
        -IntervalMinutes 15

.NOTES
    Use only in an isolated, authorized lab environment.
#>

[CmdletBinding()]
param(
    #[Parameter(Mandatory)]
    #[ValidatePattern('^OU=')]
    [string]$TargetOU='OU=Test-Clients,DC=purplelab,DC=local',

    [string]$GpoName = 'LAB - Scheduled PowerShell Payload',

    [string]$TaskName = 'Janus-Payload',

    [ValidateRange(1, 1440)]
    [int]$IntervalMinutes = 15,

    [switch]$Remove
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory
Import-Module GroupPolicy

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------

$Domain        = Get-ADDomain
$DnsDomain     = $Domain.DNSRoot
$NetlogonPath  = "\\$DnsDomain\NETLOGON"

$PayloadPath="C:\CyberRangers\payload\simulated_wiper.ps1"
<#if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) {
      throw "Payload file does not exist: $_"
}

if ([IO.Path]::GetExtension($_) -ne '.ps1') {
      throw 'PayloadPath must reference a .ps1 file.'
}#>

$PackageName   = 'Janus-Payload'
$PayloadName   = "$PackageName-Payload.ps1"
$BootstrapName = "$PackageName-Bootstrap.ps1"

$PayloadUNC    = Join-Path $NetlogonPath $PayloadName
$BootstrapUNC  = Join-Path $NetlogonPath $BootstrapName

$LocalRoot     = 'C:\ProgramData\PurpleTeam\LabPayload'
$LocalPayload  = Join-Path $LocalRoot 'Payload.ps1'

$RunKey        = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Run'
$RunValueName  = 'PurpleTeamLabPayloadBootstrap'

# Validate the OU.
$TargetOUObject = Get-ADOrganizationalUnit `
    -Identity $TargetOU `
    -Properties DistinguishedName

if ($TargetOUObject.DistinguishedName -match '^OU=Domain Controllers,') {
    throw 'Refusing to deploy to the Domain Controllers OU.'
}

# ---------------------------------------------------------------------------
# Removal
# ---------------------------------------------------------------------------

if ($Remove) {
    Write-Host "Removing deployment from $TargetOU..." -ForegroundColor Yellow

    $ExistingGPO = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue

    if ($ExistingGPO) {
        Remove-GPLink `
            -Name $GpoName `
            -Target $TargetOU `
            -Confirm:$false `
            -ErrorAction SilentlyContinue

        Remove-GPO `
            -Name $GpoName `
            -Confirm:$false
    }

    Remove-Item `
        -LiteralPath $PayloadUNC, $BootstrapUNC `
        -Force `
        -ErrorAction SilentlyContinue

    Write-Host 'The GPO and deployment files were removed.' -ForegroundColor Green
    Write-Warning @"
The scheduled task and local payload may remain on clients.

Run this on each lab client to remove them:

Unregister-ScheduledTask -TaskName '$TaskName' -Confirm:`$false
Remove-Item '$LocalRoot' -Recurse -Force
"@

    return
}

# ---------------------------------------------------------------------------
# Copy the supplied payload into NETLOGON
# ---------------------------------------------------------------------------

$ResolvedPayloadPath = (Resolve-Path -LiteralPath $PayloadPath).Path

Copy-Item `
    -LiteralPath $ResolvedPayloadPath `
    -Destination $PayloadUNC `
    -Force

# Optional integrity value shown after deployment.
$PayloadHash = Get-FileHash `
    -LiteralPath $PayloadUNC `
    -Algorithm SHA256

# ---------------------------------------------------------------------------
# Client bootstrap
# ---------------------------------------------------------------------------

$BootstrapTemplate = @'
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$SourcePayload = '__PAYLOAD_UNC__'
$ExpectedHash  = '__PAYLOAD_HASH__'
$LocalRoot     = '__LOCAL_ROOT__'
$LocalPayload  = Join-Path $LocalRoot 'Payload.ps1'
$TaskName      = '__TASK_NAME__'
$Interval      = __INTERVAL__

New-Item `
    -Path $LocalRoot `
    -ItemType Directory `
    -Force | Out-Null

# Copy the centrally managed payload locally.
Copy-Item `
    -LiteralPath $SourcePayload `
    -Destination $LocalPayload `
    -Force

# Verify that the copied file matches the deployed payload.
$LocalHash = (
    Get-FileHash `
        -LiteralPath $LocalPayload `
        -Algorithm SHA256
).Hash

if ($LocalHash -ne $ExpectedHash) {
    throw "Payload hash mismatch. Expected $ExpectedHash, received $LocalHash."
}

$PowerShellPath = Join-Path `
    $env:SystemRoot `
    'System32\WindowsPowerShell\v1.0\powershell.exe'

$Action = New-ScheduledTaskAction `
    -Execute $PowerShellPath `
    -Argument (
        "-File `"$LocalPayload`" " +
        "-TargetDirectory `"C:\WiperDirectory`"
    )

$Trigger = New-ScheduledTaskTrigger `
    -Once `
    -At ((Get-Date).AddMinutes(2)) `
    -RepetitionInterval (New-TimeSpan -Minutes $Interval) `
    -RepetitionDuration (New-TimeSpan -Days 3650)

$Principal = New-ScheduledTaskPrincipal `
    -UserId 'SYSTEM' `
    -LogonType ServiceAccount `
    -RunLevel Highest

$Settings = New-ScheduledTaskSettingsSet `
    -MultipleInstances IgnoreNew `
    -StartWhenAvailable `
    -RestartCount 2 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 10)

$Task = New-ScheduledTask `
    -Action $Action `
    -Trigger $Trigger `
    -Principal $Principal `
    -Settings $Settings `
    -Description 'Authorized recurring PowerShell payload for a defensive lab.'

Register-ScheduledTask `
    -TaskName $TaskName `
    -InputObject $Task `
    -Force | Out-Null

# Execute immediately rather than waiting for the first scheduled interval.
Start-ScheduledTask -TaskName $TaskName
'@

$Bootstrap = $BootstrapTemplate.
    Replace('__PAYLOAD_UNC__', $PayloadUNC).
    Replace('__PAYLOAD_HASH__', $PayloadHash.Hash).
    Replace('__LOCAL_ROOT__', $LocalRoot).
    Replace('__TASK_NAME__', $TaskName).
    Replace('__INTERVAL__', $IntervalMinutes.ToString())

$Bootstrap |
    Set-Content `
        -LiteralPath $BootstrapUNC `
        -Encoding UTF8 `
        -Force

# ---------------------------------------------------------------------------
# Create and configure GPO
# ---------------------------------------------------------------------------

$GPO = Get-GPO `
    -Name $GpoName `
    -ErrorAction SilentlyContinue

if (-not $GPO) {
    $GPO = New-GPO `
        -Name $GpoName `
        -Comment 'Authorized lab GPO that deploys a recurring PowerShell task.'
}

$PowerShellPath = '%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe'

$BootstrapCommand = @(
    $PowerShellPath
    '-NoLogo'
    '-NoProfile'
    '-NonInteractive'
    "-File `"$BootstrapUNC`""
) -join ' '

Set-GPRegistryValue `
    -Name $GpoName `
    -Key $RunKey `
    -ValueName $RunValueName `
    -Type String `
    -Value $BootstrapCommand

$ExistingLink = (
    Get-GPInheritance -Target $TargetOU
).GpoLinks | Where-Object {
    $_.DisplayName -eq $GpoName
}

if (-not $ExistingLink) {
    New-GPLink `
        -Name $GpoName `
        -Target $TargetOU `
        -LinkEnabled Yes | Out-Null
}

# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------

Write-Host ''
Write-Host 'Deployment configured successfully.' -ForegroundColor Green
Write-Host "GPO:              $GpoName"
Write-Host "Target OU:        $TargetOU"
Write-Host "Original payload: $ResolvedPayloadPath"
Write-Host "NETLOGON payload: $PayloadUNC"
Write-Host "Payload SHA-256:  $($PayloadHash.Hash)"
Write-Host "Bootstrap:        $BootstrapUNC"
Write-Host "Client payload:   $LocalPayload"
Write-Host "Scheduled task:   $TaskName"
Write-Host "Frequency:        Every $IntervalMinutes minutes"
Write-Host ''
Write-Warning 'Confirm that only authorized lab systems are inside the target OU.'
