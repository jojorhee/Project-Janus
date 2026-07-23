# Week 2 Validation Record

## Summary

Week 2 validated Windows telemetry, source-initiated event forwarding, firewall enforcement, and the complete safe Modbus baseline-write-restore workflow.

## Validation Matrix

| ID | Validation | Evidence | Result |
|---|---|---|---|
| W2-01 | Sysmon running on endpoint | Task Manager | Pass |
| W2-02 | Local Sysmon events generated | Sysmon Operational log | Pass |
| W2-03 | Event ID 3 observed | Expanded event | Pass |
| W2-04 | Event ID 11 observed | Expanded event | Pass |
| W2-05 | Event ID 13 observed | Expanded event | Pass |
| W2-06 | Event ID 22 observed | Expanded event | Pass |
| W2-07 | WEF source active | Subscription Runtime Status | Pass |
| W2-08 | Forwarded events arrive on server | Forwarded Events log | Pass |
| W2-09 | ATTACK to Conpot TCP/502 | `nc -nvz -w 3 10.10.20.10 502` | Pass |
| W2-10 | ATTACK to IT TCP/80 blocked | `nc -nvz -w 3 10.10.10.20 80` | Pass |
| W2-11 | Modbus baseline saved | Baseline JSON path displayed | Pass |
| W2-12 | Controlled coil write executed | Write JSON path displayed | Pass |
| W2-13 | Coil restored | Orchestrator output | Pass |
| W2-14 | Timeline updated | `attack_timeline.csv` path displayed | Pass |

## Sysmon Validation

Confirmed Event IDs:

- `3` - Network connection
- `11` - File creation
- `13` - Registry value set
- `22` - DNS query

## WEF Validation

- Subscription: `Sysmon`
- Type: source initiated
- Source: `purplelab-win-client.purplelab.local`
- Destination: `Forwarded Events`
- Transport: HTTP/5985
- Subscription status: active
- Events forwarded: all Sysmon events

## Firewall Validation

### Approved Path

```text
Source: Kali attacker
Destination: 10.10.20.10
Port: TCP/502
Result: Open
```

### Blocked Path

```text
Source: Kali attacker
Destination: 10.10.10.20
Port: TCP/80
Result: Connection timed out
```

## OT Workflow Validation

### Baseline

`modbus_baseline.py` saved approved baseline values to a normalized JSON file.

### Write

`modbus_write.py` required an explicit `WRITE` confirmation and changed Conpot coil 1 to `True`.

### Restore

`modbus_restore.py` used the exact baseline file and restored the Conpot coil to its original value.

### Orchestration

`run_ot_action.ps1` executed the write and restore sequence and recorded the timeline path.

## Limitation

WEF forwarding worked, but the export process was not reliable enough for the final evidence pipeline. This is a collection limitation, not a forwarding failure.
