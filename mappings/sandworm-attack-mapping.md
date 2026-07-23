# Sandworm ATT&CK Mapping for Project Janus

## Source Campaign

2022 Ukraine electric-power attack.

## Campaign Mapping from the Brief

| Tactic / Category | Technique | ID |
|---|---|---|
| Execution | PowerShell | T1059.001 |
| Execution | Scheduled Task | T1053.005 |
| Execution | Autorun Image | T0895 |
| Execution | Command-Line Interface | T0807 |
| Execution | Scripting | T0853 |
| Persistence | Systemd Service | T1543.002 |
| Persistence | Scheduled Task | T1053.005 |
| Persistence | Web Shell | T1505.003 |
| Privilege Escalation | Systemd Service | T1543.002 |
| Privilege Escalation | Group Policy Modification | T1484.001 |
| Privilege Escalation | Scheduled Task | T1053.005 |
| Evasion | System Binary Proxy Execution | T0894 |
| Evasion / ICS | Command Message | T1692.001 |
| Stealth | Masquerade Task or Service | T1036.004 |
| Defense Impairment | Group Policy Modification | T1484.001 |
| Lateral Movement | Lateral Tool Transfer | T1570 |
| Command and Control | Non-Application Layer Protocol | T1095 |
| Command and Control | Protocol Tunneling | T1572 |
| Impair Process Control | Command Message | T1692.001 |
| Impact | Data Destruction | T1485 |

## Project Janus Mapping

| Janus Step | Campaign Behavior | Mapping |
|---|---|---|
| Kali RDP to client | Remote access to compromised environment | Lab setup step; not claimed as a campaign technique |
| PowerShell discovery | PowerShell and command-line execution | T1059.001 |
| Assumed admin access | Privileged state | Assumption; no credential-theft technique simulated |
| PowerShell remoting to server | Lateral movement using native administration | Closest behavioral fit: T1570 plus PowerShell usage |
| Test GPO distribution | Group Policy modification and deployment | T1484.001 |
| Safe wiper | Data destruction | T1485 |
| Client executes Modbus scripts | Scripting and command-line interface | T0853 / T0807 |
| Controlled Conpot coil write | Unauthorized command message / process manipulation | T1692.001 |

## Excluded Campaign Techniques

| Technique | Reason |
|---|---|
| T1505.003 Web Shell | Neo-REGEORG is outside scope |
| T1572 Protocol Tunneling | Not required for the first Janus chain |
| T1095 Non-Application Layer Protocol | Not required for the first Janus chain |
| T1543.002 Systemd Service | Current chain focuses on Windows and Modbus |
| T1036.004 Masquerade Task or Service | Not needed for the core demonstration |
| T0895 Autorun Image | Not planned |
| Unknown initial access | Not reported in the source campaign and intentionally assumed |

## Notes

The mapping is behavioral. Project Janus does not claim to reproduce Sandworm malware or every technical detail of the campaign.
