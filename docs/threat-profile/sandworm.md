# Sandworm Threat Profile and Project Janus Emulation Plan

## Scope

This profile is based on the 2022 Ukraine electric-power attack described in the Project Janus Sandworm campaign brief.

The brief describes Sandworm as a Russian state-aligned threat actor associated with disruptive operations and OT/ICS intrusion capability. The campaign combined enterprise techniques, legitimate administrative functionality, unauthorized OT commands, and destructive impact.

## Real Campaign Objectives

The campaign brief identifies these primary objectives:

- Maintain access inside a Ukrainian electric-utility environment
- Reach OT systems
- Send unauthorized operational commands
- Deploy destructive malware
- Delay recovery

Secondary objectives included covert communication, blending into legitimate administrative activity, and using native tools when possible.

## Simplified Real Attack Timeline

```text
Unknown initial access
    ->
Neo-REGEORG web shell
    ->
GOGETTER persistence
    ->
Encrypted command-and-control tunneling
    ->
GPO-based malware distribution
    ->
Access to MicroSCADA
    ->
Unauthorized SCADA commands
    ->
Power disruption
    ->
CaddyWiper deployment
    ->
System destruction and recovery impairment
```

## Campaign Behaviors Relevant to Project Janus

The campaign brief maps activity across:

- Execution
- Persistence
- Privilege escalation
- Evasion
- Defense impairment
- Lateral movement
- Command and control
- Impair process control
- Impact

The most relevant behaviors for Project Janus are:

| Campaign Behavior | ATT&CK Reference in Brief | Project Janus Relevance |
|---|---|---|
| PowerShell | T1059.001 | Safe discovery and remote administration |
| Scheduled task | T1053.005 | Possible persistence telemetry |
| Group Policy modification | T1484.001 | Controlled GPO distribution |
| Lateral tool transfer | T1570 | Movement between approved lab systems |
| Protocol tunneling | T1572 | Not currently planned |
| Command message | T1692.001 | Controlled Modbus command |
| Data destruction | T1485 | Safe deletion of disposable files |
| Web shell | T1505.003 | Excluded |
| Systemd service | T1543.002 | Not part of the current chain |
| Non-application-layer protocol | T1095 | Not currently planned |

## Project Janus Attack Chain

Project Janus does not reproduce the real campaign exactly. It mirrors selected phases and behaviors using safe, reversible actions in an isolated lab.

```text
Kali attacker
    |
    | RDP
    v
Windows 11 client
    |
    | PowerShell discovery
    v
Assumed administrative access
    |
    | PowerShell remoting
    v
Windows Server / Domain Controller
    |
    | Test Group Policy
    v
Windows 11 client
    |
    | Safe wiper against disposable files
    v
Compromised client
    |
    | Modbus scripts
    v
Conpot honeypot
    |
    | Controlled coil change and restoration
    v
OT evidence and telemetry
```

## Included Behaviors

### 1. RDP Access from Kali to the Windows Client

Purpose:

- Establish the attacker-controlled entry point for the lab
- Generate authentication and network telemetry
- Avoid claiming to reproduce the campaign's unknown initial-access method

### 2. PowerShell Discovery

Purpose:

- Represent living-off-the-land activity
- Generate process, command-line, registry, DNS, and network telemetry
- Mirror the campaign's use of PowerShell

### 3. Assumed Administrative Access

Project Janus begins from an explicitly assumed administrative state. Credential theft and privilege-escalation exploitation are outside the current scope.

### 4. PowerShell Remoting to Windows Server

Purpose:

- Represent movement from the compromised client to the server
- Exercise WinRM and administrative telemetry
- Support a controlled GPO action

### 5. Test GPO Distribution

Purpose:

- Mirror the campaign's GPO-based deployment behavior
- Use a harmless lab payload
- Generate Group Policy and Windows event evidence

### 6. Safe Wiper

Purpose:

- Represent T1485 Data Destruction without damaging the operating system
- Delete only pre-created disposable files
- Record file hashes and paths before deletion
- Preserve enough evidence for validation

### 7. Modbus Action from the Compromised Client

Purpose:

- Represent the transition from IT compromise to OT impact
- Execute the already-developed Modbus workflow
- Save a baseline before any write
- Perform one allowlisted coil change
- Restore the original value

### 8. Controlled Conpot Coil Change

Purpose:

- Represent unauthorized process-control messaging
- Produce protocol-specific OT telemetry
- Avoid physical impact
- Validate restoration after the test

## Explicitly Excluded

- Unknown initial access
- Neo-REGEORG web shell
- Real credential theft
- Real destructive malware
- CaddyWiper reproduction
- External command-and-control infrastructure
- Encrypted tunneling
- Unrestricted lateral movement
- Actions against systems outside the isolated lab

## Expected Telemetry

| Janus Step | Expected Evidence |
|---|---|
| RDP access | Windows authentication logs, Sysmon network events, firewall logs |
| PowerShell discovery | Sysmon process creation, command line, DNS, registry, and network events |
| PowerShell remoting | WinRM traffic, authentication logs, PowerShell logs |
| GPO distribution | Group Policy changes, task or script execution, Windows events |
| Safe wiper | File creation/deletion telemetry, PowerShell logs, hashes, timeline entries |
| Modbus action | JSON evidence, Conpot logs, packet capture, firewall logs |
| Coil restore | Restore JSON, timeline entry, Conpot confirmation |

## Detection Opportunities

The campaign brief emphasizes monitoring:

- Unusual PowerShell execution
- New or modified GPOs
- Scheduled-task deployment through GPO
- Web-shell indicators
- Tunneling
- Unauthorized SCADA commands
- VBS or batch execution on engineering systems

For Project Janus, the strongest planned detections are:

- RDP from the ATTACK subnet
- PowerShell discovery commands
- PowerShell remoting from client to server
- GPO changes
- Safe-wiper file deletion activity
- Modbus write operations
- ATTACK-to-OT traffic outside the approved path

## Interpretation

Project Janus is an emulation, not a reproduction. The goal is to preserve the campaign's defensive lessons:

- IT and OT visibility must be connected
- Native tools can be abused
- GPO activity can distribute impact
- Unauthorized OT commands require protocol-aware monitoring
- Segmentation must be validated, not assumed
