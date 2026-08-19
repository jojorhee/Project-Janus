# Project Janus Scripts

Scripts for the safe IT/OT simulation, evidence normalization, AI-assisted rule
generation, deterministic validation, deployment, rollback, and pfSense
response workflow.

## Layout

- `ai/` — generation pipeline, schemas, specifications, validators, deployment,
  rollback, and safe mocks.
- `windows/` — IT simulation, collection, normalization, and cleanup.
- `ot/` — Modbus baseline, write, restore, orchestration, and normalization.
- `response/` — fail-closed pfSense EVE-alert validator and blocklist updater.
- `config/` — publication-safe lab configuration template.
- `docs/LAB_CHECKLIST.md` — original OT laboratory checklist.

Generated logs, raw PCAPs, full normalized datasets, and local configuration are
excluded from publication.

## Setup

```powershell
uv sync
Copy-Item ai/.env.example ai/.env
Copy-Item config/lab.example.json config/lab.json
```

Set `OPENAI_API_KEY` only in the ignored `ai/.env`. Review every address and
safety boundary in `config/lab.json` before executing a simulation.

## Generation

```powershell
uv run python ai/janus_pipeline.py generate --help
```

Candidate output remains untrusted until the appropriate validator, attack
dataset, baseline dataset, hash gate, and deployment health check all pass.

## OT offline validation

```bash
./ai/rule_test.sh \
  <rule-file> <sid> <output-directory> \
  <attack.pcap> <baseline.pcap>
```

## OT deployment

Run from Linux:

```bash
./ai/deploy_ot_rule.sh <local-rule-file> <approved-sha256>
```

The deployment verifies the candidate before and after transfer, validates the
combined Suricata ruleset, reloads the live process, and publishes the deployed
SID for the response controller.

## Safety

These scripts are for the documented isolated lab only. The Windows wiper is
marker-protected and targets disposable files. The Modbus workflow requires an
approved target, allowlisted coil, captured baseline, explicit confirmation,
and restoration.
