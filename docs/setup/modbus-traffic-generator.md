# Modbus Traffic Generator Setup

## Purpose

The Modbus traffic generator creates repeatable baseline OT traffic between a Linux Mint system and the Conpot honeypot. This traffic establishes a normal reference for later comparison against unauthorized Modbus actions.

## System Information

| Item | Value |
|---|---|
| Operating system | Linux Mint |
| IP address | `10.10.20.30/24` |
| Default gateway | `10.10.20.1` |
| Target | Conpot at `10.10.20.10` |
| Protocol | Modbus/TCP |
| Port | `502/TCP` |
| Main language | Python 3.12.3 |
| Library | `pymodbus` 3.14.0 |

## Script Behavior

The current Python script:

- Creates a `ModbusTcpClient`
- Connects to `10.10.20.10:502`
- Reads five holding registers beginning at address `0`
- Uses device ID `2`
- Prints the response
- Closes the connection
- Waits five seconds
- Repeats continuously

## Validation

The traffic generator was validated through:

- Successful `ReadHoldingRegistersResponse` output
- Repeated traffic over several sessions
- More than 500 captured packets during testing
- Packet capture on the Conpot host
- Corresponding Conpot log entries

Representative capture command:

```bash
sudo tcpdump -ni any tcp port 502
```

## Evidence

Recommended evidence:

- Python source code
- Successful script output
- Packet capture
- Conpot logs
- Test timing and packet count

Store evidence in:

```text
docs/assets/modbus-generator/
```

## Problems Encountered

Early tests produced connection resets and unexpected disconnects. Troubleshooting included:

- Confirming Conpot was listening
- Confirming the generator used the correct IP address and port
- Checking packet flow with `tcpdump`
- Reviewing server responses
- Adjusting the script to reconnect for each request

## Security Notes

The current generator performs read-only baseline activity. Unauthorized write operations should be implemented only against Conpot and should restore any modified test value after validation.

## Current Limitations

- The script currently generates a narrow pattern of repeated register reads.
- Traffic variation and timing randomization have not yet been added.
- Unauthorized Modbus writes are planned but not yet documented.

## Remaining Details to Add

- Virtual-environment setup command
- `requirements.txt` entry
- Final script filename and repository path
