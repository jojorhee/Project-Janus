[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$OutputDirectory,

    [Parameter(Mandatory)]
    [datetime]$StartTime,

    [Parameter(Mandatory)]
    [datetime]$EndTime,

    # RDP authentication normally occurs before the attack script starts.
    [datetime]$AttributionStartTime = $StartTime.AddMinutes(-1)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($EndTime -le $StartTime) {
    throw "EndTime must be later than StartTime."
}
if ($AttributionStartTime -gt $EndTime) {
    throw "AttributionStartTime must not be later than EndTime."
}

New-Item $OutputDirectory -ItemType Directory -Force | Out-Null

$QueryStart = $StartTime.AddSeconds(-10)
$QueryEnd = $EndTime.AddSeconds(10)

# Query only the event IDs used by the MVP detection specification. Filtering
# at Get-WinEvent prevents unrelated records from inflating the raw CSV and the
# normalized JSONL while preserving the complete, padded attack window.
$DetectionSources = @(
    @{
        LogName  = "Microsoft-Windows-Sysmon/Operational"
        EventIds = @(1)
    },
    @{
        LogName  = "Microsoft-Windows-PowerShell/Operational"
        EventIds = @(4103, 4104)
    }
)

foreach ($Source in $DetectionSources) {
    $Log = $Source.LogName
    $SafeName = $Log -replace "[/ ]", "_"
    $CsvPath = Join-Path $OutputDirectory "EventLog_$SafeName.csv"

    try {
        $Events = @(
            Get-WinEvent -FilterHashtable @{
                LogName   = $Log
                Id        = $Source.EventIds
                StartTime = $QueryStart
                EndTime   = $QueryEnd
            } -ErrorAction Stop |
                Sort-Object TimeCreated
        )
    }
    catch {
        $Events = @()
        Write-Warning "Unable to query $Log`: $($_.Exception.Message)"
    }

    if ($Events.Count -gt 0) {
        $Events |
            Select-Object -Property `
                TimeCreated,LogName,Id,RecordId,MachineName,ProviderName,UserId,Message |
            Export-Csv $CsvPath -NoTypeInformation -Encoding UTF8

        Write-Host "Exported $($Events.Count) events to $CsvPath" -ForegroundColor Green
    }
    else {
        $ExpectedIds = $Source.EventIds -join ", "
        Write-Warning (
            "No expected events (IDs $ExpectedIds) found in $Log " +
            "for the padded attack window."
        )
        Export-Csv $CsvPath -NoTypeInformation -Encoding UTF8
    }
}

# Convert named EventData XML fields into a PowerShell hashtable.
function Get-EventDataMap {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$Event)

    [xml]$Xml = $Event.ToXml()
    $Map = @{}

    foreach ($Node in @($Xml.Event.EventData.Data)) {
        $Name = $Node.GetAttribute("Name")
        if ($Name) {
            $Map[$Name] = $Node.InnerText
        }
    }

    return $Map
}

# Security 4624 Logon Type 10 is the preferred historical RDP attribution source.
try {
    $SecurityEvents = @(
        Get-WinEvent -FilterHashtable @{
            LogName   = "Security"
            Id        = 4624
            StartTime = $AttributionStartTime
            EndTime   = $QueryEnd
        } -ErrorAction Stop
    )
}
catch {
    $SecurityEvents = @()
    Write-Warning "Unable to query Security 4624 events: $($_.Exception.Message)"
}

$Rdp4624Rows = @(
    foreach ($Event in $SecurityEvents) {
        $Data = Get-EventDataMap $Event
        if ($Data["LogonType"] -ne "10") {
            continue
        }

        [PSCustomObject]@{
            TimeCreated              = $Event.TimeCreated
            LogName                 = $Event.LogName
            Id                      = $Event.Id
            RecordId                = $Event.RecordId
            MachineName             = $Event.MachineName
            ProviderName            = $Event.ProviderName
            TargetUserName          = $Data["TargetUserName"]
            TargetDomainName        = $Data["TargetDomainName"]
            TargetLogonId           = $Data["TargetLogonId"]
            LogonType               = $Data["LogonType"]
            IpAddress               = $Data["IpAddress"]
            IpPort                  = $Data["IpPort"]
            LogonProcessName        = $Data["LogonProcessName"]
            AuthenticationPackage   = $Data["AuthenticationPackageName"]
            Message                 = $Event.Message
        }
    }
)

if ($Rdp4624Rows.Count -gt 0) {
    $SecurityCsv = Join-Path $OutputDirectory "EventLog_Security_4624_RDP.csv"
    $Rdp4624Rows |
        Sort-Object TimeCreated |
        Export-Csv $SecurityCsv -NoTypeInformation -Encoding UTF8
    Write-Host "Exported $($Rdp4624Rows.Count) RDP logon events to $SecurityCsv" `
        -ForegroundColor Green
}
else {
    Write-Warning "No Security 4624 Logon Type 10 events were found."
    $SecurityCsv = Join-Path $OutputDirectory "EventLog_Security_4624_RDP.csv"
    Export-Csv $SecurityCsv -NoTypeInformation -Encoding UTF8
}

# Event 1149 is useful when available, but its absence must not fail the run.
$RcmLog = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
try {
    $RcmEvents = @(
        Get-WinEvent -FilterHashtable @{
            LogName   = $RcmLog
            Id        = 1149
            StartTime = $AttributionStartTime
            EndTime   = $QueryEnd
        } -ErrorAction Stop
    )
}
catch {
    $RcmEvents = @()
    Write-Warning "RDP Event 1149 was unavailable: $($_.Exception.Message)"
}

$RcmRows = @(
    foreach ($Event in $RcmEvents) {
        $Data = Get-EventDataMap $Event
        [PSCustomObject]@{
            TimeCreated   = $Event.TimeCreated
            LogName      = $Event.LogName
            Id           = $Event.Id
            RecordId     = $Event.RecordId
            MachineName  = $Event.MachineName
            ProviderName = $Event.ProviderName
            TargetUserName   = $Data["Param1"]
            TargetDomainName = $Data["Param2"]
            IpAddress        = $Data["Param3"]
            Message          = $Event.Message
        }
    }
)

if ($RcmRows.Count -gt 0) {
    $RcmSafeName = $RcmLog -replace "[/ ]", "_"
    $RcmCsv = Join-Path $OutputDirectory "EventLog_$RcmSafeName.csv"
    $RcmRows |
        Sort-Object TimeCreated |
        Export-Csv $RcmCsv -NoTypeInformation -Encoding UTF8
    Write-Host "Exported $($RcmRows.Count) Event 1149 records to $RcmCsv" `
        -ForegroundColor Green
}
else {
    Write-Warning "No Event 1149 records found; continuing with other attribution sources."
}