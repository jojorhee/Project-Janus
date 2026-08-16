# Project Janus — OT Lab Checklist

## Before lab access

- [ ] Run `uv sync` from the repository root.
- [ ] Copy `ai/.env.example` to `ai/.env` and add the API key locally.
- [ ] Locate the original attack and baseline `.pcap` or `.pcapng` captures.
- [ ] Record their absolute paths before attempting Suricata validation.
- [ ] Confirm `workspace/backups/pipeline/janus_pipeline.pre_lab.py` matches the current pipeline.
- [ ] Confirm the four required OT inputs exist:
  - `ai/specifications/ot_detection_spec.json`
  - `ai/schemas/ot_schema.json`
  - `evidence/normalized/ot/attack_modbus_requests.jsonl`
  - `evidence/normalized/ot/baseline_modbus_requests.jsonl`

## Preflight commands

Run from the repository root in PowerShell:

```powershell
Get-FileHash ai/janus_pipeline.py -Algorithm SHA256
Get-FileHash workspace/backups/pipeline/janus_pipeline.pre_lab.py -Algorithm SHA256
uv run python ai/janus_pipeline.py generate --help
```

Expected result: both pipeline hashes match and help lists the `generate`
command and OT target.

## Exact OT generation command

```powershell
uv run python ai/janus_pipeline.py generate --target ot --spec ai/specifications/ot_detection_spec.json --attack evidence/normalized/ot/attack_modbus_requests.jsonl --baseline evidence/normalized/ot/baseline_modbus_requests.jsonl --model gpt-5.6-terra --input-schema ai/schemas/ot_schema.json --schema ai/schemas/llm_detection_output_schema.json --candidates workspace/raw_llm_output
```

Expected artifacts in the next numbered folder under `workspace/raw_llm_output/`:

- `llm_response.json` — schema-valid raw candidate response.
- `ot.rules` — extracted proposed Suricata rule.

Copy the rule selected for testing into `workspace/generated_rules/ot/`; do not
rename or modify the raw LLM response.

## OT validation

- [ ] Record the original attack and baseline PCAP paths in the validation log.
- [ ] If no PCAPs can be recovered, record packet-level Suricata validation as blocked; do not rename JSONL files as PCAPs.
- [ ] Syntax-check the selected rule and save output under `workspace/validation_logs/ot/`.
- [ ] Test against the attack PCAP; record alert count and packet/timestamp evidence.
- [ ] Test against the baseline PCAP; record observed false-positive count.
- [ ] Capture screenshots under `workspace/screenshots/`.
- [ ] Copy the rule, logs, hashes, screenshots, and concise limitations note into `workspace/final_evidence/`.
- [ ] Preserve the original PCAPs unchanged outside Git.

## Completion proof

- [ ] Generation command exits successfully.
- [ ] `llm_response.json` and `ot.rules` exist.
- [ ] Attack and baseline validation logs exist.
- [ ] PCAP locations are recorded and resolve to real files.
- [ ] Final evidence contains the selected rule, logs, screenshots, hashes, and limitations.
