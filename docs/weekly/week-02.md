# Week 2 Progress Log

**Dates:** July 19-23, 2026

## Focus

Week 2 focused on improving Windows telemetry, validating segmented connectivity, finishing the first OT attack-action scripts, and converting the Sandworm campaign research into a practical Project Janus attack chain.

## Goals

- Install and validate Sysmon on the Windows endpoint
- Configure Windows Event Forwarding to Windows Server
- Confirm that required cross-subnet traffic is allowed while unrelated traffic remains blocked
- Begin scripting the Sandworm-inspired attack workflow
- Build safe Modbus baseline, write, and restore actions
- Finalize the Sandworm MITRE ATT&CK mapping

## Completed Work

### Windows Telemetry

- Installed Sysmon 15.2 on the Windows 11 endpoint
- Used the Olaf Hartong Sysmon configuration without modification
- Confirmed that `Sysmon64.exe` was running
- Confirmed local Sysmon Operational events
- Created a source-initiated WEF subscription named `Sysmon`
- Forwarded all Sysmon events to the Windows Server `Forwarded Events` log
- Confirmed Sysmon Event IDs:
  - `3` - Network connection
  - `11` - File creation
  - `13` - Registry value set
  - `22` - DNS query

### Windows Event Forwarding Troubleshooting

Forwarding initially failed because of WSMan and FQDN-related issues. Troubleshooting included:

1. Deleting and recreating the subscription
2. Verifying WinRM functionality
3. Confirming network connectivity
4. Checking the client FQDN
5. Replacing HTTPS/5986 with HTTP/5985

The final HTTP/5985 configuration allowed events to reach Windows Server.

WEF was successfully implemented and validated. However, it is not being used as the final export workflow because exported logs were not reliable enough for the planned evidence pipeline.

### Network Validation

- Confirmed that ATTACK-to-Conpot traffic on TCP/502 was allowed
- Confirmed that ATTACK-to-IT traffic on TCP/80 timed out
- Verified that pfSense rules could permit only approved attack traffic while blocking unrelated cross-subnet access

### OT Action Scripts

The Week 2 OT workflow was divided into four Python files plus one PowerShell orchestrator:

- `modbus_client.py`
- `modbus_baseline.py`
- `modbus_write.py`
- `modbus_restore.py`
- `run_ot_action.ps1`

The workflow:

1. Reads and saves the approved baseline values
2. Requires an explicit operator confirmation
3. Performs one allowlisted coil write
4. Saves normalized evidence
5. Restores the original value using the exact baseline file
6. Adds actions to the attack timeline

The controlled test changed Conpot coil 1 to `True`, confirmed the action, and restored the coil to its baseline value.

### Sandworm Research

The Sandworm mapping for the 2022 Ukraine electric-power attack was completed. The real campaign combined enterprise and OT activity, including PowerShell, Group Policy modification, lateral movement, unauthorized SCADA commands, and destructive impact.

Project Janus intentionally excludes unknown initial access and the Neo-REGEORG web shell. The lab starts from assumed attacker access and focuses on safe, observable behaviors.

## Planned Janus Attack Chain

```text
Kali RDP to Windows client
    ->
PowerShell discovery on the client
    ->
Assumed administrative access
    ->
PowerShell remoting from client to Server/DC
    ->
Test GPO distributed back to the client
    ->
Safe wiper executes on disposable client files
    ->
Compromised client runs Modbus scripts
    ->
Controlled coil change on Conpot
```

## Validation Summary

| Test | Expected Result | Actual Result | Status |
|---|---|---|---|
| Sysmon service | Running on endpoint | Confirmed | Complete |
| Local Sysmon events | Events generated | Confirmed | Complete |
| WEF subscription | Client active | Confirmed | Complete |
| Forwarded events | Events visible on server | Confirmed | Complete |
| TCP/502 | Allowed to Conpot | Open | Complete |
| TCP/80 | Blocked to IT target | Timed out | Complete |
| Modbus baseline | Baseline JSON saved | Confirmed | Complete |
| Controlled coil write | Coil changed | Confirmed | Complete |
| Modbus restoration | Original value restored | Confirmed | Complete |
| Sandworm mapping | Completed | Confirmed | Complete |

## Problems Encountered

- WEF subscription did not initially deliver events
- WSMan and FQDN issues complicated troubleshooting
- HTTPS/5986 did not work in the current lab
- WEF export reliability was insufficient for the final evidence workflow
- OT actions required careful separation of baseline, write, and restore behavior

## Key Lessons

- A working telemetry source is not enough; collection and export must also be reliable
- Firewall validation should prove both allowed and blocked paths
- OT attack actions should be narrow, allowlisted, reversible, and evidence-producing
- The Sandworm campaign should be mirrored at the tactic and behavior level, not reproduced exactly

## Next Steps

- Build the Windows-side attack scripts
- Configure RDP and PowerShell remoting for the approved path
- Create a test GPO
- Develop a safe wiper for disposable files
- Integrate the Windows and OT actions into one timeline
- Export telemetry through a more reliable collection workflow
