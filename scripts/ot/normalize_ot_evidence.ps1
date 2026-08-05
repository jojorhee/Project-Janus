[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$PcapPath,

    [Parameter(Mandatory)]
    [string]$OutputDirectory,

    [Parameter(Mandatory)]
    [ValidatePattern("^run-\d{3,}$")]
    [string]$RunId,

    [Parameter(Mandatory)]
    [ValidateSet("baseline", "attack")]
    [string]$Label
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Tshark = "C:\Program Files\Wireshark\tshark.exe"
$OutputCsv = Join-Path $OutputDirectory "modbus_normalized.csv"

if (-not (Test-Path $Tshark -PathType Leaf)) {
    throw "TShark not found: $Tshark"
}

if (-not (Test-Path $PcapPath -PathType Leaf)) {
    throw "PCAP not found: $PcapPath"
}

if (Test-Path $OutputCsv) {
    throw "Normalized output already exists: $OutputCsv"
}

New-Item $OutputDirectory -ItemType Directory -Force | Out-Null

$TsharkArguments = @(
    "-r", $PcapPath
    "-Y", "modbus"
    "-T", "fields"
    "-E", "header=y"
    "-E", "separator=,"
    "-E", "quote=d"
    "-E", "occurrence=f"

    "-e", "frame.number"
    "-e", "frame.time_epoch"
    "-e", "ip.src"
    "-e", "ip.dst"
    "-e", "tcp.srcport"
    "-e", "tcp.dstport"
    "-e", "mbtcp.trans_id"
    "-e", "mbtcp.unit_id"
    "-e", "modbus.func_code"
    "-e", "modbus.reference_num"
    "-e", "modbus.write_reference_num"
    "-e", "modbus.bitval"
    "-e", "modbus.data"
    "-e", "modbus.exception_code"
    "-e", "tcp.payload"
)

$Packets = @(
    & $Tshark @TsharkArguments |
        ConvertFrom-Csv
)

if ($LASTEXITCODE -ne 0) {
    throw "TShark exited with code $LASTEXITCODE."
}

if ($Packets.Count -eq 0) {
    throw "No Modbus packets were found."
}

$NormalizedPackets = foreach ($Packet in $Packets) {
    $FunctionCode = $Packet.'modbus.func_code'
    $Data = $Packet.'modbus.data'

    # Use the write-specific address when available.
    $CoilAddress = $Packet.'modbus.write_reference_num'

    if (-not $CoilAddress) {
        $CoilAddress = $Packet.'modbus.reference_num'
    }

    # Determine whether this is a client request or server response.
    $MessageType = if ($Packet.'tcp.dstport' -eq "502") {
        "request"
    }
    elseif ($Packet.'tcp.srcport' -eq "502") {
        "response"
    }
    else {
        "unknown"
    }

    $Operation = switch ($FunctionCode) {
        "1"  { "read_coils" }
        "5"  { "write_single_coil" }
        "15" { "write_multiple_coils" }
        default { "function_$FunctionCode" }
    }

    # Decode the first coil value.
    $CoilValue = $null
    $CleanData = ($Data -replace "[:\s]", "").ToLower()

    if ($FunctionCode -eq "5") {
        if ($CleanData -eq "ff00") {
            $CoilValue = "true"
        }
        elseif ($CleanData -eq "0000") {
            $CoilValue = "false"
        }
    }
    elseif ($FunctionCode -eq "15" -and $CleanData.Length -ge 2) {
        # Multiple-coil values are packed into bits.
        $FirstByte = [Convert]::ToInt32(
            $CleanData.Substring(0, 2),
            16
        )

        $CoilValue = if (($FirstByte -band 1) -eq 1) {
            "true"
        }
        else {
            "false"
        }
    }
    elseif ($Packet.'modbus.bitval') {
        $CoilValue = $Packet.'modbus.bitval'
    }

    # Classify the packet's role in the run.
    $Phase = if ($Label -eq "baseline") {
        "baseline"
    }
    elseif ($FunctionCode -in "5", "15" -and $CoilValue -eq "true") {
        "write"
    }
    elseif ($FunctionCode -in "5", "15" -and $CoilValue -eq "false") {
        "restore"
    }
    else {
        "background"
    }

    try {
        $Milliseconds = [long](
            [double]$Packet.'frame.time_epoch' * 1000
        )

        $TimestampUtc = [DateTimeOffset]::FromUnixTimeMilliseconds(
            $Milliseconds
        ).UtcDateTime.ToString("o")
    }
    catch {
        $TimestampUtc = $null
    }

    [PSCustomObject]@{
        timestamp_utc    = $TimestampUtc
        frame_number     = $Packet.'frame.number'
        src_ip           = $Packet.'ip.src'
        dst_ip           = $Packet.'ip.dst'
        src_port         = $Packet.'tcp.srcport'
        dst_port         = $Packet.'tcp.dstport'
        transaction_id   = $Packet.'mbtcp.trans_id'
        unit_id          = $Packet.'mbtcp.unit_id'
        function_code    = $FunctionCode
        operation        = $Operation
        message_type     = $MessageType
        coil_address     = $CoilAddress
        coil_value       = $CoilValue
        exception_code   = $Packet.'modbus.exception_code'
        phase            = $Phase
        run_id           = $RunId
        label            = $Label
        raw_file         = $PcapPath
        raw_frame        = $Packet.'frame.number'
        raw_payload      = $Packet.'tcp.payload'
    }
}

$NormalizedPackets |
    Export-Csv $OutputCsv -NoTypeInformation -Encoding UTF8

Write-Host "Normalized $($NormalizedPackets.Count) Modbus packets."
Write-Host "Saved: $OutputCsv"