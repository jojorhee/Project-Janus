# Project Janus

**AI-Driven Purple-Team Automation and Threat Intelligence Across IT/OT Environments**

Project Janus is a small, script-driven purple-team lab that is being developed during an internship at the **Technology Advancement Center (TAC)**. The project is designed to automate a mapped adversary attack, collect the resulting telemetry, use a large language model to generate detection rules and a threat-intelligence report, and ultimately close the loop by automatically blocking the attacker when a validated rule fires.

> **Current status:** Phase 1 — Infrastructure and baseline telemetry  
> **Author:** Josiah Rhee  
> **Organization:** Technology Advancement Center  

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
- [x] Initial Sandworm ATT&CK mapping created
- [ ] Sysmon and Windows Event Forwarding
- [ ] Scripted attack execution
- [ ] Automated log harvesting
- [ ] LLM-assisted detection generation
- [ ] CTI-report generation
- [ ] Detection validation and measurement
- [ ] pfSense automatic block-on-detection response

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

Only safe, low-impact techniques will be executed inside the isolated lab. The mapping and scripts are works in progress and should not be treated as a complete reproduction of a real intrusion.

## Planned Workflow

### Phase 1 — Infrastructure and Baseline Telemetry

Deploy the lab, validate segmentation and domain services, operate Conpot, generate normal Modbus traffic, and collect clean baseline telemetry.

### Phase 2 — Endpoint and Network Visibility

Install and configure Sysmon and Windows Event Forwarding, standardize timestamps, and centralize Windows, Linux, honeypot, and packet-capture data.

### Phase 3 — Automated Attack Execution

Develop controlled Python modules for selected IT and OT techniques. Planned tools may include:

- Paramiko for SSH-controlled execution
- Scapy for crafted network traffic
- PowerShell for controlled Windows living-off-the-land behavior
- `pymodbus` or Scapy for unauthorized Modbus operations

### Phase 4 — AI-Assisted Detection Engineering

Send normalized telemetry and ATT&CK context to an approved LLM through a restricted prompt and request draft outputs such as:

- Sigma rules for Windows behavior
- Snort or Suricata-style network signatures
- YARA rules where appropriate
- Structured indicators of compromise
- A concise CTI-report draft

All generated material will be reviewed and validated manually before use.

### Phase 5 — Closed-Loop Response

Replay a controlled attack, trigger a validated detection, and use the pfSense API to block the offending source address. The response is deliberately limited to one action: **block the detected source**.

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

## Repository Structure (In Progress)

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

Specific software versions, VM resources, network-adapter assignments, and installation steps will be documented as the project progresses.

## Documentation

The current infrastructure documentation is available in the `docs/` directory (not quite yet). It includes:

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

- Sysmon and Windows Event Forwarding are not yet deployed.
- The current Sandworm mapping is preliminary.
- Automated attack execution is not yet complete.
- No AI-generated detection should be considered valid until tested.
- Automatic pfSense response has not yet been implemented.
- Conpot provides a simplified honeypot rather than a full physical-process simulation.
