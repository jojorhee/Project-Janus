# Project Janus

**AI-assisted purple-team detection and response across a segmented IT/OT lab**

Project Janus demonstrates a controlled workflow from safe attack simulation to
validated detection, automatic rule deployment, and reversible firewall
containment. It was developed in an isolated internship lab and is not intended
for use against production or unauthorized systems.

## Final status

The technical MVP is complete:

- Segmented IT, OT, and ATTACK networks behind pfSense.
- Safe Windows discovery, remote PowerShell execution, and marker-protected
  simulated-wiper workflow.
- Safe Modbus/TCP baseline, single-coil write, verification, and restoration.
- Normalized Windows and Modbus evidence tied to preserved lab runs.
- LLM-generated Windows JSON/Sigma and Suricata candidates.
- Schema, syntax, attack, baseline, deployment, and rollback gates.
- Automatic Windows JSON-rule deployment and rollback.
- Automatic Suricata deployment with local and remote SHA-256 verification.
- Dynamic publication of the deployed Suricata SID to the response controller.
- Automatic, reversible `JANUS_BLOCKLIST` containment from a confirmed alert.

## Demonstrated workflow

```text
Safe simulation
→ preserved evidence
→ normalization
→ detection specification
→ LLM candidate
→ validation and approval
→ automatic deployment
→ confirmed alert
→ guarded pfSense block
→ rollback
```

## Final results

| Area | Demonstrated result |
|---|---|
| Windows detection | Correlated attack behavior detected in three attack datasets; zero correlated detections in three baseline datasets |
| OT detection | Function-code-5 candidate logic detected the controlled write/restore traffic in three attack PCAPs; zero alerts in three baseline PCAPs |
| OT deployment | Candidate hash verified on Linux and pfSense; Suricata syntax test and live reload passed |
| OT live alert | Deployed SID `1002001` alerted on the Windows-to-Conpot Modbus write |
| Response | Alert source was validated, added to `JANUS_BLOCKLIST`, blocked from TCP/502, removed, and connectivity restored |

These are controlled-lab validation results, not claims of production detection
accuracy.

## Lab architecture

| Zone | Subnet | Main systems |
|---|---|---|
| IT | `10.10.10.0/24` | Windows Server `10.10.10.10`, Windows client `10.10.10.30` |
| OT | `10.10.20.0/24` | Conpot `10.10.20.10`, traffic generator `10.10.20.30` |
| ATTACK | `10.10.30.0/24` | Kali Linux `10.10.30.10` |

pfSense provides the `.1` gateway on each internal subnet.

## Repository map

```text
project-janus/
├── README.md
├── SANITIZATION.md
├── LICENSE
├── detections/
│   ├── it/                  # Final Windows JSON and Sigma artifacts
│   └── ot/                  # Final deployed Suricata rule
├── docs/
│   ├── index.html           # Latest historical project site
│   ├── week-01.html
│   ├── week-02.html
│   ├── assets/
│   ├── setup/
│   └── threat-profile/
├── evidence/
│   ├── deployment/          # Curated successful deployment proof
│   ├── response/            # Minimal alert/block evidence
│   └── validation/          # Human-readable validation summaries
├── mappings/                # Sandworm ATT&CK mapping
├── samples/sanitized/       # Small publication-safe examples
└── scripts/
    ├── ai/                  # Generation, validation, deployment, rollback
    ├── config/              # Lab configuration template
    ├── ot/                  # Modbus execution and normalization
    ├── response/            # pfSense alert-to-block controller
    └── windows/             # Windows simulation, collection, normalization
```

## Setup

From `scripts/`:

```powershell
uv sync
Copy-Item ai/.env.example ai/.env
Copy-Item config/lab.example.json config/lab.json
```

Add the API key only to the ignored local `.env`, then adjust `lab.json` for the
authorized lab. Confirm the generation interface with:

```powershell
uv run python ai/janus_pipeline.py generate --help
```

The OT deployment script runs on Linux:

```bash
./ai/deploy_ot_rule.sh <local-rule-file> <approved-sha256>
```

It uploads the exact candidate to pfSense, verifies the hash again, tests the
combined ruleset, reloads Suricata, and publishes the approved SID only after a
successful activation.

## Response safeguards

The pfSense response controller:

- reads new Suricata EVE JSON alerts;
- requires the alert SID to appear in the deployment-managed SID file;
- validates the observed source as IPv4;
- restricts blocking authority to the IT subnet;
- rejects protected gateways, servers, and the OT endpoint;
- updates only the preconfigured `JANUS_BLOCKLIST` table; and
- records each response decision.

The watcher is operator-started for the demonstration; it is not installed as a
persistent pfSense service.

## Detection scope

The final OT rule detects Modbus function-code-5 requests to the monitored
Conpot endpoint. It does **not** distinguish the controlled `65280` write from
the restoration write, and it does not infer intent. Authorized maintenance
using the same function and destination can alert.

The Windows rule detects the demonstrated correlation of network-hosted
PowerShell execution and destructive PowerShell content. Initial access and
privileged access remain assumed preconditions.

## Publication safety

The public archive intentionally omits API keys, raw PCAPs, full event and
firewall logs, uncurated working screenshots, local Git metadata, and generated
caches. See [SANITIZATION.md](SANITIZATION.md) for the complete list.

## Documentation

- [Project site](docs/index.html)
- [Lab setup](docs/setup/)
- [Sandworm threat profile](docs/threat-profile/sandworm.md)
- [ATT&CK mapping](mappings/sandworm-attack-mapping.md)
- [Curated evidence](evidence/README.md)

## Safety and limitations

- Run only in an isolated, authorized lab.
- The scenarios are Sandworm-inspired, not exact historical reproductions.
- Conpot is a honeypot, not a physical industrial process.
- Raw evidence remains outside the public repository.
- LLM output is treated as a hypothesis until deterministic validation passes.
- Results cover the demonstrated datasets and cannot establish broad accuracy.

Developed by **Josiah Rhee** during an internship with the
**Technology Advancement Center**.

