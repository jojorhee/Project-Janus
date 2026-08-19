# OT Detection Validation Summary

The selected logic alerts on Modbus function-code-5 requests to
`10.10.20.10:502`.

## Offline validation

| Dataset class | PCAPs | Result |
|---|---:|---|
| Attack | 3 | Detected in 3/3; controlled write and restore alerted |
| Baseline | 3 | Zero alerts in 3/3 |

Offline validation used candidate SID `1000001`. The final deployed rule uses
SID `1002001` with the same monitored endpoint and function-code-5 behavior,
plus an explicit Modbus application-protocol constraint.

## Live deployment and response

- Final candidate SHA-256:
  `f17ffc4ebc24e930a3c2cbd86d4e53a7ad33607823a291009a6219e1864aa5be`
- Suricata loaded 382 rules with zero load failures.
- SID `1002001` generated a live alert for `10.10.10.30` to
  `10.10.20.10:502`.
- The response controller added the observed source to `JANUS_BLOCKLIST`.
- A new TCP/502 connection was blocked.
- Removing the source from the table restored connectivity.

## Limitation

The rule detects function-code-5 traffic, not a specific coil value. The
controlled `65280` write and the restoration write both satisfy the rule.
Authorized maintenance using the same function and destination can also alert.

