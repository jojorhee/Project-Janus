"""Read approved Conpot coils and save a run-scoped state record.

Usage:
    py modbus_baseline.py run-001 pre-write
    py modbus_baseline.py run-001 post-write
    py modbus_baseline.py run-001 post-restore

This script performs no Modbus writes.
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from modbus_client import (
    SafeModbusClient,
    build_run_paths,
    configure_logging,
    load_config,
    require_unused_output,
)


PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = PROJECT_ROOT / "config" / "lab.json"


STAGE_FILENAMES = {
    "pre-write": "01-pre-write-state",
    "post-write": "03-post-write-verification",
    "post-restore": "05-post-restore-verification",
}


def load_json(path: Path) -> dict:
    """Load one required earlier record from the same run."""
    if not path.is_file():
        raise FileNotFoundError(f"Required run evidence not found: {path}")
    with path.open(encoding="utf-8") as file:
        return json.load(file)


def get_run_and_stage() -> tuple[str, str]:
    """Require an explicit run ID and approved read stage."""
    if len(sys.argv) != 3 or sys.argv[2] not in STAGE_FILENAMES:
        stages = "|".join(STAGE_FILENAMES)
        raise SystemExit(
            f"Usage: py modbus_baseline.py <run-###> <{stages}>"
        )
    return sys.argv[1], sys.argv[2]

def main() -> None:
    """Connect, collect approved coil values, and save them."""
    config = load_config(CONFIG_PATH)
    run_id, stage = get_run_and_stage()
    run_paths = build_run_paths(config, run_id)
    output_path = run_paths["raw"] / f"{STAGE_FILENAMES[stage]}.json"
    require_unused_output(output_path)

    # This is a human-readable script action log, separate from the baseline JSON.
    log_path = output_path.with_suffix(".log")
    logger = configure_logging(log_path)

    client = SafeModbusClient(config, logger)

    # The JSON will use string keys because JSON object keys are strings.
    baseline = {
        "run_id": run_id,
        "stage": stage,
        "capture_timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": {
            "ip": client.host,
            "port": client.port,
            "unit_id": client.unit_id,
        },
        "coils": {},
    }

    try:
        client.connect()

        for coil in client.allowed_coils:
            read_coil = client.read_coil(coil)
            baseline["coils"][str(coil)] = read_coil

    finally:
        # Always close the TCP connection, including when a read fails.
        client.close()

    # The two verification stages independently compare current coil state with
    # an earlier record from this same run.
    if stage == "post-write":
        source_path = run_paths["raw"] / "02-write-result.json"
        write_result = load_json(source_path)
        if write_result.get("run_id") != run_id:
            raise ValueError("Write-result run ID does not match this run.")
        expected = {str(write_result["coil"]): write_result["requested_value"]}
        baseline["verification_source"] = str(source_path)
        baseline["expected_coils"] = expected
        baseline["verified"] = baseline["coils"] == expected
    elif stage == "post-restore":
        source_path = run_paths["raw"] / "01-pre-write-state.json"
        pre_write = load_json(source_path)
        if pre_write.get("run_id") != run_id:
            raise ValueError("Pre-write state run ID does not match this run.")
        expected = pre_write["coils"]
        baseline["verification_source"] = str(source_path)
        baseline["expected_coils"] = expected
        baseline["verified"] = baseline["coils"] == expected

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(baseline, file, indent=2)

    print(f"{stage} evidence saved: {output_path}")
    if stage != "pre-write" and not baseline["verified"]:
        raise RuntimeError(f"{stage} verification failed; inspect {output_path}")


if __name__ == "__main__":
    main()