# Sysmon and Windows Event Forwarding Setup

## Purpose

Sysmon and Windows Event Forwarding provide centralized Windows telemetry for Project Janus. Sysmon records detailed endpoint activity on the Windows 11 client, while Windows Event Forwarding sends those events to Windows Server for centralized review and later detection processing.

## Architecture

```text
Windows 11 Endpoint
    Sysmon 15.2
    Olaf Hartong configuration
            |
            | WinRM / WEF over HTTP 5985
            v
Windows Server
    Windows Event Collector
    Forwarded Events log
```

## Endpoint Configuration

| Item | Value |
|---|---|
| Endpoint | Windows 11 Enterprise |
| Sysmon version | 15.2 |
| Configuration | Olaf Hartong Sysmon configuration |
| Executable | `Sysmon64.exe` |
| Install command | `Sysmon64.exe -accepteula -i sysmonconfig.xml` |

The Sysmon service was confirmed running on the endpoint. The local Sysmon Operational log contained thousands of events, including process, network, DNS, file, and registry activity.

## Forwarding Configuration

The Windows endpoint forwards all Sysmon events to Windows Server using a source-initiated Windows Event Forwarding subscription named `Sysmon`.

The working transport configuration uses:

- WinRM
- HTTP
- TCP port `5985`

The server receives events in the **Forwarded Events** log.

## Validation

The following evidence confirmed the implementation:

- `Sysmon64.exe` running on the Windows endpoint
- Local Sysmon Operational events on the endpoint
- Forwarded events visible on Windows Server
- Event ID `3` showing a network connection
- Event ID `11` showing file creation
- Source and destination addressing visible in forwarded network events
- Process, user, image, target filename, and timestamps visible in forwarded events

Example observations:

- Event ID `3`: connection involving source `10.10.10.30` and destination `10.10.10.10` on port `5985`
- Event ID `11`: PowerShell creating `C:\Users\jdoe\Downloads\Sysmon\file.txt`

## Problems Encountered

The main challenge was getting endpoint events to appear on Windows Server.

Troubleshooting steps included:

1. Deleting and recreating the event subscriptions
2. Confirming WinRM was running
3. Checking network connectivity between client and server
4. Reviewing the subscription configuration
5. Changing the connection from HTTPS on port `5986` to HTTP on port `5985`

The final change to HTTP/5985 resolved the forwarding issue.

## Evidence

Recommended screenshots:

- Sysmon64 running in Task Manager
- Local Sysmon Operational log
- Forwarded Event ID `3`
- Forwarded Event ID `11`
- Windows Event Viewer Forwarded Events log
- Subscription configuration

Store screenshots in:

```text
docs/assets/sysmon-wef/
```

## Security Notes

HTTP/5985 is acceptable for this isolated lab but should not automatically be treated as the preferred production configuration. Production deployments should evaluate authentication, encryption, segmentation, and certificate management requirements.

## Current Limitations

- A dedicated SIEM has not yet been added.
- Forwarded event filtering and retention have not yet been fully tuned.
- Automated detection rules have not yet been generated or evaluated.
- Event normalization for LLM processing is still planned.

## Remaining Details to Add

- Event-query XML
- Windows Event Collector service configuration
- Log-retention settings
