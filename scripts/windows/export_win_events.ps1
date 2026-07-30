[CmdletBinding()]
param(
    <#[Parameter(Mandatory)]
    [datetime]$StartTime,

    [Parameter(Mandatory)]
    [datetime]$EndTime,#>

    [Parameter(Mandatory)]
    [string]$OutputDirectory
)

$StartTime = (Get-Date).AddMinutes(-1)
$EndTime = (Get-Date).AddMinutes(1)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($EndTime -le $StartTime) {
    throw "EndTime must be later than StartTime."
}

if(!(Test-Path -Path $OutputDirectory)) {
    New-Item -Path $OutputDirectory -ItemType Directory
}

$Logs = @(
    'Microsoft-Windows-Sysmon/Operational'
    'Microsoft-Windows-PowerShell/Operational'
    #'group-policy' = 'Microsoft-Windows-GroupPolicy/Operational'
)

foreach ($Log in $Logs) {
    
    # Create a safe filename by replacing slashes and spaces with underscores
    $SafeName = $Log -replace '[/ ]', '_'
    $CsvPath  = Join-Path $OutputDirectory "EventLog_$SafeName.csv"
    
    # Query the single log source
    $Events = Get-WinEvent -FilterHashtable @{
        LogName   = $Log
        StartTime = $StartTime
        EndTime   = $EndTime
    } -ErrorAction SilentlyContinue

    if ($Events) {
        # Export fields. Message is expanded to full text.
        $Events | Select-Object TimeCreated, LogName, Id, MachineName, Message | 
            Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
            
        Write-Host "Successfully exported $($Events.Count) events to $CsvPath" -ForegroundColor Green
    } else {
        Write-Host "No events found in '$Log' for this time range." -ForegroundColor Yellow
    }
}