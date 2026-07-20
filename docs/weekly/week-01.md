# Week 1 Progress Log

## Focus

Build and validate the virtual infrastructure needed for Project Janus.

## Completed

- Created six VirtualBox virtual machines:
  - pfSense firewall
  - Windows Server 2025
  - Windows 11 Enterprise endpoint
  - Linux Mint Conpot honeypot
  - Linux Mint Modbus traffic generator
  - Kali Linux attacker
- Created separate IT, OT, and ATTACK networks.
- Configured pfSense with four interfaces.
- Configured routing and firewall rules.
- Configured Windows Server with:
  - Static addressing
  - Active Directory Domain Services
  - DNS
  - DHCP
- Created the `purplelab.local` domain.
- Created a domain user.
- Joined the Windows endpoint to the domain.
- Confirmed that the endpoint receives DHCP and DNS settings.
- Deployed Conpot through Docker.
- Confirmed that Conpot exposes Modbus/TCP.
- Created a Python Modbus traffic generator.
- Generated three Modbus sessions.
- Captured more than 500 packets over approximately 15 minutes.
- Confirmed traffic in `tcpdump` and Conpot logs.
- Configured the Kali attacker on the ATTACK subnet.
- Began mapping the 2022 Sandworm electric-power attack to MITRE ATT&CK Enterprise and ATT&CK for ICS.

## Validation Highlights

| Test | Result |
|---|---|
| Windows endpoint DHCP | Passed |
| Domain join | Passed |
| Domain-user creation | Passed |
| IT gateway connectivity | Passed |
| OT Modbus communication | Passed |
| Conpot logging | Passed |
| Packet capture | Passed |
| ATTACK gateway connectivity | Passed |

## Problems Encountered

### pfSense Web Interface

Accessing and configuring the pfSense GUI required troubleshooting interface and network settings.

### Windows DHCP and DNS

The Windows endpoint initially required troubleshooting before it could consistently receive the correct address, DNS, and gateway configuration.

### Internal Network Internet Access

The internal subnets required additional routing and firewall work before internet access operated correctly without removing segmentation.

### Modbus Connectivity

Early Conpot testing produced connection resets or unexpected disconnects. Packet capture and log comparison were used to verify that requests still reached Conpot and received responses.

## Skills Practiced

- VirtualBox network design
- Stateful firewall configuration
- Active Directory administration
- DHCP and DNS configuration
- Linux and Docker administration
- Python scripting
- Modbus/TCP traffic generation
- Packet analysis
- OT honeypot deployment
- MITRE ATT&CK mapping
- Technical troubleshooting

## Evidence

Permanent documentation:

- [Windows Server setup](../setup/windows-server.md)
- [Windows client setup](../setup/windows-client.md)
- [pfSense setup](../setup/pfsense.md)
- [Conpot setup](../setup/conpot.md)
- [Modbus traffic generator](../setup/modbus-traffic-generator.md)
- [Kali attacker setup](../setup/kali-attacker.md)

## Next Steps

- Deploy Sysmon on the Windows endpoint
- Configure Windows Event Forwarding
- Expand the Sandworm attack mapping
- Select a small set of safe attack behaviors
- Begin building the controlled attack sequence
- Standardize telemetry collection

> Note: Sysmon and Windows Event Forwarding were completed after the initial Week 1 infrastructure milestone and are documented separately.
