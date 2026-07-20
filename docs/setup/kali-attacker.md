# Kali Attacker Setup

## Purpose

The Kali Linux virtual machine represents the controlled adversary system in Project Janus. It will launch authorized, Sandworm-inspired simulations against approved IT and OT lab targets.

## System Information

| Item | Value |
|---|---|
| Operating system | Kali Linux 2024.4 |
| IP address | `10.10.30.10/24` |
| Default gateway | `10.10.30.1` |
| Network | ATTACK subnet, `10.10.30.0/24` |

## Configuration Summary

The attacker VM was placed on a separate subnet behind pfSense. This design allows attack traffic to be explicitly permitted, monitored, and blocked without treating the attacker as a trusted IT or OT system.

The VM currently has basic network connectivity and can reach its assigned pfSense gateway.

## Planned Use

The attacker will be used for safe simulations such as:

- Harmless remote PowerShell execution
- Benign file transfer
- Scheduled-task persistence
- Controlled local beaconing
- Approved Modbus register writes against Conpot
- Dummy-file deletion as simulated impact

## Validation

The following checks were completed:

- `ifconfig` showed `10.10.30.10/24`
- The attacker successfully pinged `10.10.30.1`
- Packet transmission and reception were confirmed

## Evidence

Store screenshots in:

```text
docs/assets/kali-attacker/
```

## Security Notes

All testing must remain inside the authorized Project Janus lab. Do not reuse attack scripts against systems outside the lab.

## Current Limitations

- The full attack chain has not yet been automated.
- Remote execution and lateral-movement paths are still being designed.
- The initial Sandworm mapping is not yet comprehensive.

## Remaining Details to Add

- VM resource allocation
- Installed Python packages
- Remote-management tools
- Final approved target list
