# Windows Client Setup

## Purpose

The Windows 11 Enterprise endpoint represents a normal user workstation inside the Project Janus IT environment. It receives network services from Windows Server, authenticates against Active Directory, and serves as the primary Windows telemetry source for Sysmon and Windows Event Forwarding.

## System Information

| Item | Value |
|---|---|
| Operating system | Windows 11 Enterprise |
| Hostname | `purplelab-win-client` |
| IP assignment | DHCP |
| Current IPv4 address | `10.10.10.3/24` |
| Default gateway | `10.10.10.1` |
| DHCP server | `10.10.10.10` |
| DNS server | `10.10.10.10` |
| DNS suffix | `purplelab.local` |
| Domain | `purplelab.local` |

## Configuration Summary

The client was configured to obtain its IPv4 address and DNS settings automatically. Windows Server assigned the endpoint an address from the IT subnet and provided the domain controller as its DNS server.

The endpoint was then joined to the `purplelab.local` Active Directory domain.

Sysmon 15.2 was installed on the endpoint using the Olaf Hartong configuration:

```powershell
Sysmon64.exe -accepteula -i sysmonconfig.xml
```

The endpoint records local Sysmon events and forwards selected Windows events to the Windows Server collector.

## Validation

The following tests confirmed that the endpoint was working correctly:

- `ipconfig /all` showed DHCP enabled.
- The client received `10.10.10.3/24`.
- The client received `10.10.10.1` as its gateway.
- The client received `10.10.10.10` as its DHCP and DNS server.
- The client successfully pinged the Windows Server.
- The client successfully pinged the pfSense IT gateway.
- `nslookup purplelab.local` returned `10.10.10.10`.
- `whoami` returned a `PURPLELAB\...` domain identity.
- Sysmon64 was visible as a running process.
- The local Sysmon Operational log contained events.

## Evidence

Recommended evidence:

- `ipconfig /all`
- Ping to `10.10.10.10`
- Ping to `10.10.10.1`
- `nslookup purplelab.local`
- `whoami`
- Domain membership screen
- Sysmon64 running in Task Manager
- Sysmon Operational event log

Store sanitized screenshots in:

```text
docs/assets/windows-client/
```

## Problems Encountered

The main challenge was forwarding Sysmon events to Windows Server. Troubleshooting included:

- Deleting and recreating the event subscription
- Verifying WinRM functionality
- Confirming network connectivity
- Checking client and server configuration
- Changing the subscription transport from HTTPS on port `5986` to HTTP on port `5985`

The HTTP/5985 configuration allowed forwarded events to reach the collector.

## Security Notes

The client is intentionally used for safe, authorized telemetry generation. Do not run destructive scripts against the actual operating system. Any impact simulation should affect only temporary lab files.

## Current Limitations

- Only one Windows endpoint is currently deployed.
- Sysmon events are forwarded to Windows Server, but a dedicated SIEM is not yet in place.
- Automated detection generation is still planned.
