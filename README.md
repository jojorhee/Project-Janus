# Project Janus

**AI-Driven Purple-Team Automation and Threat Intelligence Across IT/OT Environments**

Project Janus is a small, script-driven purple-team lab that is being developed during an internship at the **Technology Advancement Center (TAC)**. The project is designed to automate a mapped adversary attack, collect the resulting telemetry, use a large language model to generate detection rules and a threat-intelligence report, and ultimately close the loop by automatically blocking the attacker when a validated rule fires.

> **Current status:** Week 4 complete — Clean evidence runs, normalization, and detection specifications  
> **Author:** Josiah Rhee  
> **Organization:** Technology Advancement Center  
> **Internship period:** July 26–August 26, 2026

## Project Goals

Project Janus aims to demonstrate a complete, controlled purple-team workflow:

1. Build a segmented IT, OT, and attacker lab.
2. Map a real-world threat actor's behaviors to MITRE ATT&CK Enterprise and ATT&CK for ICS.
3. Execute safe, repeatable, script-controlled attack techniques.
4. Collect Windows, Linux, honeypot, and network telemetry.
5. Use an LLM to draft detection rules, indicators of compromise, and a concise cyber-threat-intelligence report.
6. Validate generated detections manually.
7. Automatically add a pfSense block rule when a validated detection fires.

The project uses **signature-based detection against labeled lab activity**. It is not intended to perform unsupervised anomaly detection.

## Current Progress

The following infrastructure has been deployed and validated:

- [x] Six virtual machines created in VirtualBox
- [x] IT, OT, and ATTACK networks segmented through pfSense
- [x] Windows Server 2025 configured with Active Directory and DHCP
- [x] Windows 11 Enterprise endpoint joined to `purplelab.local`
- [x] Windows endpoint successfully receives DHCP and DNS services
- [x] Conpot ICS/SCADA honeypot deployed on Linux Mint
- [x] Modbus/TCP traffic generator deployed on Linux Mint
- [x] Baseline Modbus traffic captured with `tcpdump`
- [x] Conpot and Linux telemetry collected
- [x] Kali Linux attacker VM configured
- [x] Sandworm ATT&CK mapping completed
- [x] Sysmon 15.2 deployed on the Windows endpoint
- [x] Source-initiated Windows Event Forwarding validated
- [x] Allowed TCP/502 and blocked TCP/80 paths validated
- [x] Safe Modbus baseline, write, and restore workflow completed
- [x] PowerShell OT orchestration script completed
- [x] Separate Sandworm-inspired IT and OT attack vectors completed
- [x] Clean, timestamped IT evidence run preserved
- [x] Clean, timestamped OT evidence run preserved
- [x] Windows and OT baseline/attack evidence organized and normalized
- [x] Remote PowerShell/WinRM execution and client-side process activity documented
- [x] Modbus coil write verified through structured evidence and packet capture
- [x] Windows and OT detection specifications completed
- [ ] LLM-assisted detection generation
- [ ] Detection validation against baseline and attack evidence
- [ ] Automated rule deployment
- [ ] CTI-report generation
- [ ] pfSense automatic block-on-detection response

## Week 4 Completion Summary

Week 4 focused on proving the two attack vectors with direct, timestamped evidence before beginning LLM-assisted rule generation.

### Completed

- Preserved one canonical clean IT run and one canonical clean OT run.
- Recorded exact timestamps, notes, and artifact locations for both scenarios.
- Proved the IT chain through PowerShell discovery, WinRM remoting, client-side PowerShell activity, marker-protected wiper execution, and dummy-file deletion.
- Proved the OT chain through baseline capture, Modbus/TCP coil write, readback verification, restoration, JSON outputs, and packet-level confirmation.
- Organized raw evidence under separate baseline and attack folders.
- Created normalized Windows and OT evidence without overwriting raw artifacts.
- Compared baseline and attack behavior.
- Wrote one Windows detection specification and one OT detection specification.
- Froze the project scope for Week 5: one Sigma rule, one executable Windows JSON rule, and one Suricata rule.

### Week 5 Entry Point

The next phase is to generate schema-valid candidate detections, validate them against baseline and attack evidence, and deploy only approved artifacts.

## Lab Architecture

| Network | Subnet | Gateway | Systems |
|---|---|---|---|
| IT | `10.10.10.0/24` | `10.10.10.1` | Windows Server, Windows Endpoint |
| OT | `10.10.20.0/24` | `10.10.20.1` | Conpot Honeypot, Modbus Traffic Generator |
| ATTACK | `10.10.30.0/24` | `10.10.30.1` | Kali Linux Attacker |
| WAN | VirtualBox NAT | `10.0.2.15/24` on pfSense | Controlled external connectivity |

### Virtual Machines

| System | Operating System | Address | Purpose |
|---|---|---|---|
| pfSense Firewall | FreeBSD-based pfSense | WAN `10.0.2.15/24`; IT `10.10.10.1/24`; OT `10.10.20.1/24`; ATTACK `10.10.30.1/24` | Stateful routing, segmentation, filtering, and future automated response |
| Windows Server | Windows Server 2025 | `10.10.10.10/24` | Active Directory, DNS, DHCP, and IT administration |
| Windows Endpoint | Windows 11 Enterprise | DHCP; currently `10.10.10.3/24` | Domain-joined user workstation and future endpoint-telemetry source |
| SCADA Honeypot | Linux Mint | `10.10.20.10/24` | Conpot-based ICS/SCADA emulation and telemetry collection |
| Modbus Traffic Generator | Linux Mint | `10.10.20.30/24` | Generates representative Modbus/TCP baseline traffic |
| Linux Attacker | Kali Linux | `10.10.30.10/24` | Controlled Sandworm-inspired attack execution |

## Validated Functionality

### Windows IT Environment

- Windows Server uses the static address `10.10.10.10/24`.
- The Windows endpoint receives its address from Windows Server DHCP.
- The endpoint uses `10.10.10.10` for DNS.
- The endpoint is joined to the `purplelab.local` domain.
- Domain-user authentication was confirmed.
- Connectivity to Windows Server and the pfSense IT gateway was confirmed.
- DNS resolution for `purplelab.local` was confirmed.

### OT Environment

Conpot is running as an ICS/SCADA honeypot and exposes Modbus/TCP on port `502`.

The traffic-generator script uses `pymodbus` to repeatedly read holding registers from the Conpot host. Baseline communication has been confirmed through:

- Successful Modbus responses
- Conpot logs
- Linux logs
- Packet capture between `10.10.20.30` and `10.10.20.10`

Representative packet-capture command:

```bash
sudo tcpdump -ni any tcp port 502
```

### Network Segmentation

pfSense is configured as the routed security boundary between all three internal networks. Intended policy includes:

- Blocking unsolicited inbound WAN traffic
- Preventing normal IT systems from initiating access to OT
- Preventing normal OT systems from initiating access to IT
- Allowing only explicitly approved ATTACK-network traffic during controlled tests
- Supporting a future API-driven block rule when a detection fires

## Threat-Actor Emulation

The initial threat profile is based on **Sandworm**, with behaviors mapped to MITRE ATT&CK Enterprise and ATT&CK for ICS.

The mapping is intended to guide:

- Attack-script design
- Telemetry requirements
- Detection-rule generation
- CTI-report structure
- Validation of defensive coverage

Only safe, low-impact techniques are executed inside the isolated lab. The project now uses two separate Sandworm-inspired scenarios rather than presenting them as one historically exact chain:

- **IT vector:** assumed Kali/RDP foothold → PowerShell host/domain discovery on the Windows client → WinRM/PowerShell remoting to Windows Server → approved safe-wiper script retrieved from a domain-accessible NETLOGON location → marker-protected execution against disposable client files.
- **OT vector:** assumed compromised Windows client → Modbus/TCP baseline capture → allowlisted coil write against Conpot → readback verification → restoration to the original value.

GPO automation was attempted and retired after it did not execute reliably. The validated IT workflow uses PowerShell remoting instead.

## Planned Workflow

### Phase 1 — Infrastructure and Baseline Telemetry

Deploy the lab, validate segmentation and domain services, operate Conpot, generate normal Modbus traffic, and collect clean baseline telemetry.

### Phase 2 — Endpoint and Network Visibility

Sysmon 15.2 and source-initiated Windows Event Forwarding were implemented and validated. Windows event exports, discovery output, wiper evidence, Modbus JSON, packet captures, and supporting notes are now organized into baseline, attack, and normalized evidence sets.

### Phase 3 — Safe Attack Execution and Evidence Collection

The Week 3 attack workflows and Week 4 evidence runs are complete.

#### IT vector

- Manual Kali-to-client RDP foothold
- PowerShell host/domain discovery on the Windows client
- WinRM/PowerShell remoting to Windows Server
- Approved script staging through the domain-accessible NETLOGON folder
- Marker-protected safe-wiper execution in `C:\WiperTest`
- Before/after file evidence, Windows event exports, and cleanup

#### OT vector

- Baseline coil capture
- Controlled Modbus/TCP coil write
- Readback verification
- Restoration using the exact baseline
- JSON outputs, timestamps, notes, and packet-level evidence

The two scenarios feed one detection pipeline but are not presented as a single historically exact Sandworm chain.

### Phase 4 — AI-Assisted Detection Engineering

Week 4 produced one Windows and one OT detection specification based on verified evidence.

Week 5 will use normalized evidence and ATT&CK context to generate:

- One Sigma rule for the Windows behavior
- One small executable Janus JSON rule for normalized Windows events
- One Suricata rule for the confirmed Modbus write
- Structured indicators and concise supporting analysis

All LLM-generated output is treated as a proposed hypothesis until it passes schema/syntax checks and validation against both attack and baseline evidence.

### Phase 5 — Closed-Loop Response

After the Windows and OT detections are validated and approved, Project Janus will automatically deploy them and connect the confirmed OT alert to one constrained response:

```text
Confirmed OT alert
→ extract observed Windows-client source IP
→ check response allowlist and protected systems
→ add that IP to JANUS_BLOCKLIST
→ verify IT-to-OT traffic is blocked
→ remove the block during cleanup
```

The controller will not create arbitrary firewall rules or trust an unchecked LLM-provided IP.

## Expected Deliverables

- Documented IT/OT/ATTACK lab architecture
- Repeatable attack scripts mapped to ATT&CK
- Baseline and attack telemetry
- Detection signatures
- Structured indicators of compromise
- Concise CTI report
- Automated pfSense block-on-detection integration
- Evaluation of LLM strengths and limitations
- Final project website and presentation

## Repository Structure

```text
project-janus/
├── README.md
├── LICENSE
├── .gitignore
├── docs/
│   ├── index.html
│   ├── assets/
│   ├── architecture/
│   └── screenshots/
├── configs/
│   ├── pfsense/
│   ├── conpot/
│   ├── sysmon/
│   └── logging/
├── scripts/
│   ├── traffic-generator/
│   ├── attack/
│   ├── collection/
│   ├── detection/
│   └── response/
├── mappings/
│   └── sandworm-attack-mapping.md
├── detections/
│   ├── sigma/
│   ├── network/
│   └── yara/
├── intel/
│   ├── iocs/
│   └── reports/
├── tests/
├── samples/
│   └── sanitized/
└── requirements.txt
```

Only add folders when they contain useful work. Empty placeholder folders can be avoided until the related phase begins.

## Safety and Authorization

This project is intended exclusively for an isolated, authorized laboratory environment.

- Do not run attack scripts against systems outside the lab.
- Do not commit passwords, API keys, tokens, private certificates, or production configuration exports.
- Do not publish unredacted logs containing personal or organizational information.
- Do not upload full virtual-machine disks, licensed operating-system images, or proprietary TAC material.
- Sanitize packet captures and configuration files before publication.
- Keep offensive scripts clearly labeled and limited to approved targets.

## Installation and Reproduction

Full reproduction instructions will be added as scripts and configurations are finalized. The current lab requires:

- VirtualBox
- pfSense
- Windows Server 2025
- Windows 11 Enterprise
- Kali Linux
- Linux Mint
- Docker
- Conpot
- Python 3
- `pymodbus`
- `tcpdump`

Specific software versions, VM resources, network-adapter assignments, and installation steps will be documented as the project progresses.

## Documentation

The current infrastructure documentation is available in the `docs/` directory. It includes:

- Network architecture
- VM inventory
- pfSense interface and firewall configuration
- Windows domain and DHCP validation
- Conpot deployment
- Modbus traffic generation
- Packet capture
- Initial Sandworm research
- Current status and roadmap

## Known Limitations

- The project models two separate Sandworm-inspired scenarios rather than reproducing one exact historical attack chain.
- Initial access and privileged access are assumed preconditions.
- GPO automation was retired after the startup-script path did not execute reliably.
- Conpot provides a simplified honeypot and PLC-like coil state rather than a real physical process.
- Week 4 evidence supports the demonstrated lab behaviors only; it does not establish broad detection accuracy.
- No AI-generated detection is considered valid until tested against both attack and baseline evidence.
- Automatic deployment and pfSense response have not yet been implemented.

## License

A license has not yet been selected. Before making the repository public, confirm with TAC whether the project may be published and which license is appropriate.

## Acknowledgments

Developed by **Josiah Rhee** during an internship with the **Technology Advancement Center**.
