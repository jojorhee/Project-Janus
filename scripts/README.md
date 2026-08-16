# Project Janus Scripts

Scripts and evidence-processing components for the Project Janus IT/OT
purple-team pipeline.

## Repository map

- `ai/` — LLM pipeline, schemas, detection specifications, mocks, and prior candidates.
- `windows/` — IT simulation, collection, normalization, and cleanup scripts.
- `ot/` — Modbus simulation, evidence collection, and OT normalization scripts.
- `evidence/normalized/it/` — analysis-ready IT JSONL, labeled by filename and record.
- `evidence/normalized/ot/` — analysis-ready OT JSONL, labeled by filename and record.
- `evidence/raw/it/` and `evidence/raw/ot/` — immutable source evidence organized by run.
- `lab/` — lab-only PCAP location configuration and pre-lab material.
- `workspace/` — generated rules, validation logs, screenshots, backups, and final evidence.
- `docs/LAB_CHECKLIST.md` — exact lab execution checklist and expected artifacts.

## Setup

```powershell
uv sync
Copy-Item ai/.env.example ai/.env
```

Put the API key only in `ai/.env`. The real `.env`, virtual environment,
PCAPs, and generated working output are excluded from Git.

Before entering the lab, complete `docs/LAB_CHECKLIST.md`. The JSONL files are
inputs to generation; the original PCAP/PCAPNG files are separate validation inputs.
