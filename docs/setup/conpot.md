# Conpot Honeypot Setup

## Purpose

The Conpot virtual machine emulates a simplified ICS/SCADA environment inside the OT network. It provides industrial-protocol services that can receive normal and unauthorized traffic while producing logs for analysis and detection development.

## System Information

| Item | Value |
|---|---|
| Operating system | Linux Mint |
| IP address | `10.10.20.10/24` |
| Default gateway | `10.10.20.1` |
| Network | OT subnet, `10.10.20.0/24` |
| Deployment method | Docker |
| Primary tested protocol | Modbus/TCP |
| Modbus port | `502/TCP` |
| Conpot version | `0.6.0` |

## Configuration Summary

Conpot was deployed as a Docker container using the Honeynet Conpot image with the following command:

```bash
docker run -it -p 80:8800 -p 102:10201 -p 502:5020 -p 161:16100/udp --network=bridge honeynet/conpot
```

The resulting container name is `sharp_villani`.

The container exposed several industrial and supporting services, including Modbus/TCP on port `502`.

Startup output confirmed that the Modbus protocol was enabled and that the Conpot process initialized successfully.

## Validation

The deployment was validated through:

- Docker container status
- Conpot startup logs
- Successful Modbus register reads
- Packet captures showing traffic between `10.10.20.30` and `10.10.20.10`
- Conpot logs showing requests from the traffic generator

## Evidence

Recommended evidence:

- `docker ps`
- Conpot startup log
- Modbus service initialization
- Successful request logs
- Packet capture of Modbus/TCP traffic

Store evidence in:

```text
docs/assets/conpot/
```

Conpot test logs are stored on the host at:

```text
/home/jack/janus-tests
```

## Problems Encountered

Observed issues included connection resets or disconnects during early testing. Troubleshooting focused on:

- Confirming the container was running
- Confirming port `502` was exposed
- Verifying the target IP and port
- Comparing traffic-generator output with packet captures
- Reviewing Conpot logs for request handling

## Security Notes

Conpot is a honeypot and simplified protocol emulator. It should not be treated as a real PLC or safety-critical control system.

Do not expose the container directly to the public internet.

## Current Limitations

- Conpot does not reproduce a complete physical process.
- The current test focuses mainly on Modbus/TCP.
- Register writes have not yet been fully documented as an attack simulation.
- Detection coverage is still under development.

## Remaining Details to Add

- Container image tag
- Conpot template name
- Any custom template or register changes
