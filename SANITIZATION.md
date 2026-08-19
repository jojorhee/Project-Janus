# Repository Sanitization

This distribution is a publication-safe copy of the working Project Janus
repository. The original archive was preserved separately.

## Required credential action

The supplied working archive contained a live-format OpenAI API key in
`scripts/ai/.env`. That file is absent from this distribution and was not found
in the supplied Git history, but deleting it does not invalidate the key.
Revoke or rotate the key before treating this copy as publication-ready.

## Excluded

- Local `.git` history, remote metadata, hooks, and editor swap files.
- The local `ai/.env` file and its API-key value.
- Python bytecode and `__pycache__` directories.
- Raw PCAPs and full normalized Windows/OT datasets.
- Full pfSense `eve.json`, `filter.log`, and combined ruleset exports.
- Repeated deployment/rollback logs and transient working directories.
- Uncurated workspace screenshots containing a local Windows username and
  absolute workstation paths.
- Redundant mock candidate folders and unreferenced duplicate screenshots.

## Retained

- Reusable source code, schemas, detection specifications, and generated-rule
  history.
- Final Windows and OT detection artifacts.
- Parameterized deployment and rollback tooling.
- Publication-safe architecture and lab screenshots.
- Minimal alert, firewall, deployment, and response evidence.
- Sanitized example telemetry and human-readable validation summaries.

## Before publishing

1. Review organization and licensing requirements.
2. Confirm no new `.env`, PCAP, EVTX, or workspace files are staged.
3. Run a secret scanner against the final Git working tree.
4. Review screenshots manually before adding new ones.
5. Never commit private keys or production configuration exports.
