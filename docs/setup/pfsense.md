# pfSense Setup

## Purpose

pfSense provides routing, segmentation, and stateful firewall enforcement between the WAN, IT, OT, and ATTACK networks in Project Janus. It also serves as the planned enforcement point for automatic attacker blocking when a validated detection fires.

## System Information

| Interface | Address | Purpose |
|---|---|---|
| WAN | `10.0.2.15/24` | Controlled external connectivity through VirtualBox NAT |
| IT | `10.10.10.1/24` | Gateway for Windows Server and Windows endpoint |
| OT | `10.10.20.1/24` | Gateway for Conpot and Modbus traffic generator |
| ATTACK | `10.10.30.1/24` | Gateway for Kali Linux attacker |

pfSense is FreeBSD-based.

## Configuration Summary

Three internal subnets were created to separate enterprise, operational-technology, and attacker systems.

The intended policy is:

- Block unsolicited inbound WAN traffic.
- Allow required internet access from internal systems.
- Block normal IT systems from initiating access to OT.
- Block normal OT systems from initiating access to IT.
- Restrict ATTACK-network access to only the systems and ports needed for approved tests.
- Allow approved attack traffic to Conpot on Modbus/TCP port `502`.
- Allow approved management or remote-execution traffic only when needed.

## Current Rules

The current screenshots show rules for WAN, IT, OT, and ATTACK interfaces.

Important note:

A rule on the OT interface was labeled as blocking OT outbound access to IT, but the interface displayed a pass action. The actual rule action should be verified and corrected so that the configuration matches the intended policy.

## Validation

The following tests confirmed basic firewall and routing functionality:

- Each internal system reached its assigned gateway.
- The Kali attacker reached `10.10.30.1`.
- The Modbus traffic generator reached Conpot on port `502`.
- Windows systems reached required IT services.
- Network segmentation rules were applied and tested.

## Evidence

Recommended evidence:

- pfSense console interface assignment
- WAN rules
- IT rules
- OT rules
- ATTACK rules
- Successful gateway connectivity tests
- Blocked-traffic test evidence
- Allowed Modbus connection evidence

Store screenshots in:

```text
docs/assets/pfsense/
```

## Problems Encountered

Challenges included:

- Accessing the pfSense web interface
- Configuring internal interfaces correctly
- Providing internet access to isolated subnets
- Ensuring firewall rule order matched the intended security policy

## Security Notes

Do not publish:

- Full pfSense backups
- API keys
- Passwords
- Public-facing configuration details
- Rules containing real organizational addresses

## Current Limitations

- Automatic block-on-detection has not yet been implemented.
- Firewall logging and alert integration are not yet fully documented.
- Some rules are temporary for setup and testing and should be reviewed before final publication.

## Remaining Details to Add

- Exact aliases used in rules
- Exact allowed Windows-management ports
- Screenshots or test results proving IT-to-OT and OT-to-IT blocking
- Final rule order after cleanup
