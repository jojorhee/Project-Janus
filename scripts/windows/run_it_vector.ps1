$AttackRoot = "C:\CyberRangers\evidence\attack\it"

$RunNumber = 1
do {
    $RunDirectory = Join-Path $AttackRoot ("run-{0:D3}" -f $RunNumber)
    $RunNumber++
} while (Test-Path $RunDirectory)

New-Item -ItemType Directory -Path $RunDirectory | Out-Null

$discovery = & ".\win_discovery.ps1" -OutputDirectory $RunDirectory
& ".\test_dc_access.ps1" -DomainControllerEvidencePath $discovery.runDirectory 

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& '\\purplelab.local\netlogon\simulated_wiper.ps1' -TargetDirectory 'C:\WiperTest'"

& ".\export_win_events.ps1" -OutputDirectory $RunDirectory

& ".\cleanup.ps1"