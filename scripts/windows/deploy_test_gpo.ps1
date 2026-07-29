# Run this script in an elevated PowerShell window on the Domain Controller.
# The GPO startup script registers a Scheduled Task on targeted clients.
# The task then runs the payload every minute as SYSTEM.

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string]$GpoName = 'Wiper',

    [string]$TargetOuDn = 'OU=Janus-Clients,DC=purplelab,DC=local',

    [string]$TaskName = 'cleany'
)

$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory
Import-Module GroupPolicy

# Confirm that the target OU exists before creating or linking anything.
Get-ADOrganizationalUnit -Identity $TargetOuDn | Out-Null

# Source payload stored beside this GPO deployment script.
$LocalPayloadPath = Join-Path $PSScriptRoot 'simulated_wiper.ps1'

# Central SYSVOL folder
$SysvolFolder = '\\purplelab.local\SYSVOL\purplelab.local\scripts\Janus'
$PayloadUncPath = Join-Path $SysvolFolder 'simulated_wiper.ps1'

# FIX: lab.json is no longer required. The wiper now accepts only
# -TargetDirectory and -Execute.
if (-not (Test-Path -LiteralPath $LocalPayloadPath -PathType Leaf)) {
    throw "Required source file not found: $LocalPayloadPath"
}

# Create the SYSVOL folder and copy the payload.
New-Item -Path $SysvolFolder -ItemType Directory -Force | Out-Null
Copy-Item -LiteralPath $LocalPayloadPath -Destination $PayloadUncPath -Force

# These are the arguments passed to simulated_wiper.ps1 by the scheduled task.
# Change C:\WiperTest here if the disposable client directory changes.
$PayloadArguments = '-TargetDirectory "C:\WiperTest" -Execute'

# Confirm that clients can reach the payload before deploying the GPO.
if (-not (Test-Path -LiteralPath $PayloadUncPath -PathType Leaf)) {
    throw "Payload not found: $PayloadUncPath"
}

if (-not $PSCmdlet.ShouldProcess(
        $TargetOuDn,
        "Create/update '$GpoName' and schedule '$PayloadUncPath' every minute"
    )) {
    return
}

# Create the GPO if it does not already exist.
$gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
if (-not $gpo) {
    $gpo = New-GPO -Name $GpoName
}

# Link it to the dedicated client OU if the link does not already exist.
$existingLink = (Get-GPInheritance -Target $TargetOuDn).GpoLinks |
    Where-Object DisplayName -eq $GpoName

if (-not $existingLink) {
    New-GPLink -Name $GpoName -Target $TargetOuDn -LinkEnabled Yes | Out-Null
}

# Enable PowerShell script execution through this GPO.
Set-GPRegistryValue `
    -Name $GpoName `
    -Key 'HKLM\Software\Policies\Microsoft\Windows\PowerShell' `
    -ValueName 'EnableScripts' `
    -Type DWord `
    -Value 1

Set-GPRegistryValue `
    -Name $GpoName `
    -Key 'HKLM\Software\Policies\Microsoft\Windows\PowerShell' `
    -ValueName 'ExecutionPolicy' `
    -Type String `
    -Value 'RemoteSigned'

# Store a bootstrap script inside this GPO's machine Startup folder.
$domain = Get-ADDomain
$gpoGuid = $gpo.Id.ToString('B').ToUpperInvariant()
$gpoRoot = "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)\Policies\$gpoGuid"
$startupDirectory = Join-Path $gpoRoot 'Machine\Scripts\Startup'
$startupScriptName = 'Register-JanusMinuteTask.ps1'
$startupScriptPath = Join-Path $startupDirectory $startupScriptName

New-Item -ItemType Directory -Path $startupDirectory -Force | Out-Null

# Escape single quotes before placing parameter values in the generated script.
$escapedPayloadPath = $PayloadUncPath.Replace("'", "''")
$escapedPayloadArguments = $PayloadArguments.Replace("'", "''")
$escapedTaskName = $TaskName.Replace("'", "''")

$bootstrapScript = @"
`$ErrorActionPreference = 'Stop'

`$payloadPath = '$escapedPayloadPath'
`$payloadArguments = '$escapedPayloadArguments'
`$taskName = '$escapedTaskName'

`$actionArguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File ```"`$payloadPath```" `$payloadArguments"
`$action = New-ScheduledTaskAction `
    -Execute 'powershell.exe' `
    -Argument `$actionArguments

`$trigger = New-ScheduledTaskTrigger `
    -Once `
    -At (Get-Date).AddMinutes(1) `
    -RepetitionInterval (New-TimeSpan -Minutes 1)

`$settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -MultipleInstances IgnoreNew

Register-ScheduledTask `
    -TaskName `$taskName `
    -Action `$action `
    -Trigger `$trigger `
    -Settings `$settings `
    -User 'SYSTEM' `
    -RunLevel Highest `
    -Force | Out-Null
"@

[System.IO.File]::WriteAllText(
    $startupScriptPath,
    $bootstrapScript,
    [System.Text.UTF8Encoding]::new($true)
)

# Register the bootstrap on the PowerShell Scripts tab of the GPO's
# computer Startup policy.
$scriptsIniPath = Join-Path $gpoRoot 'Machine\Scripts\psscripts.ini'
$scriptsIni = @"
[Startup]
0CmdLine=$startupScriptName
0Parameters=
"@

[System.IO.File]::WriteAllText(
    $scriptsIniPath,
    $scriptsIni,
    [System.Text.Encoding]::Unicode
)

# Register the Scripts client-side extension and increment the computer-side
# GPO version so clients detect the startup-script change.
$gpo = Get-GPO -Name $GpoName -ErrorAction Stop

if ([string]::IsNullOrWhiteSpace($gpo.Path)) {
    throw "GPO '$GpoName' has no Active Directory path."
}

$gpoDn = $gpo.Path -replace '^LDAP://', ''

$gpoAdObject = Get-ADObject `
    -Identity $gpoDn `
    -Properties gPCMachineExtensionNames, versionNumber

if ($null -eq $gpoAdObject) {
    throw "Could not retrieve the AD object for GPO '$GpoName'."
}

if ($null -eq $gpoAdObject.versionNumber) {
    throw "GPO versionNumber was not returned."
}

$scriptsExtensionPair =
    '[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]'

$extensions = [string]$gpoAdObject.gPCMachineExtensionNames
$oldVersion = [int]$gpoAdObject.versionNumber

$userVersion = ($oldVersion -shr 16) -band 0xFFFF
$computerVersion = (($oldVersion -band 0xFFFF) + 1) -band 0xFFFF
$newVersion = ($userVersion -shl 16) -bor $computerVersion

$updatedAttributes = @{
    versionNumber = $newVersion
}

if ($extensions -notmatch [regex]::Escape(
        '{42B5FAAE-6536-11D2-AE5A-0000F87571E3}'
    )) {
    $updatedAttributes.gPCMachineExtensionNames =
        $extensions + $scriptsExtensionPair
}

Set-ADObject -Identity $gpoDn -Replace $updatedAttributes

# FIX: Removed the old ADSI statements below:
# $gpoDirectoryEntry.Properties['versionNumber'].Value = $newVersion
# $gpoDirectoryEntry.CommitChanges()
# $gpoDirectoryEntry was never initialized, so indexing Properties caused:
# "Cannot index into a null array." Set-ADObject above already applies the
# required Active Directory update.

$gptIniPath = Join-Path $gpoRoot 'gpt.ini'

if (-not (Test-Path -LiteralPath $gptIniPath -PathType Leaf)) {
    throw "GPO configuration file not found: $gptIniPath"
}

$gptIni = Get-Content -LiteralPath $gptIniPath -Raw
if ($gptIni -match '(?m)^Version=\d+\s*$') {
    $gptIni = $gptIni -replace '(?m)^Version=\d+\s*$', "Version=$newVersion"
}
else {
    $gptIni = $gptIni.TrimEnd() + "`r`nVersion=$newVersion`r`n"
}

[System.IO.File]::WriteAllText(
    $gptIniPath,
    $gptIni,
    [System.Text.Encoding]::Unicode
)

Write-Host "Configured GPO: $GpoName"
Write-Host "Linked OU:      $TargetOuDn"
Write-Host "Startup script: $startupScriptPath"
Write-Host "Scheduled task: $TaskName (every minute)"
Write-Host ''
Write-Host 'On the client, run: gpupdate /force'
Write-Host 'Then restart the client to run the startup bootstrap.'