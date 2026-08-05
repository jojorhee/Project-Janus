"""Perform one controlled, allowlisted Conpot coil write.

This script is intentionally narrow:
  * it requires a baseline JSON created by modbus_baseline.py;
  * it writes only a coil/value allowed in lab.json; and
  * it immediately reads the coil back to record whether the change occurred.

It does NOT restore the original value. That is the separate responsibility of
modbus_restore.py, which uses the pre-write state from the same numbered run.

Usage:
    py modbus_write.py run-001
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


# The script is stored in sandworm-simulation/ot/.  Deriving these paths means the
# project can be moved without editing hard-coded Kali or Windows paths.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = PROJECT_ROOT / "config" / "lab.json"


def load_baseline(baseline_path: Path, client: SafeModbusClient) -> dict:
    """Load and validate the pre-write baseline against the configured target."""
    if not baseline_path.is_file():
        raise FileNotFoundError(f"Baseline file not found: {baseline_path}")

    with baseline_path.open(encoding="utf-8") as file:
        baseline = json.load(file)

    # A baseline from another Conpot device, port, or unit must never authorize
    # a write here.  The values must match the currently configured target.
    target = baseline.get("target", {})
    expected_target = {
        "ip": client.host,
        "port": client.port,
        "unit_id": client.unit_id,
    }
    if target != expected_target:
        raise ValueError(
            "Baseline target does not match the configured Conpot target. "
            "Create a fresh baseline before writing."
        )

    if not baseline.get("coils"):
        raise ValueError("Baseline contains no coil values to restore.")

    return baseline


def choose_write(client: SafeModbusClient) -> tuple[int, bool]:
    """Return the single coil and value approved by lab.json.

    Keeping selection in the configuration prevents command-line input from
    turning this lab script into a general-purpose Modbus write tool.
    """
    if len(client.allowed_coils) != 1:
        raise ValueError(
            "This lab script requires exactly one allowed coil in lab.json."
        )

    address = next(iter(client.allowed_coils))
    value = client.allowed_write_values.get(address)

    if not isinstance(value, bool):
        raise ValueError(
            f"Configured write value for coil {address} must be true or false."
        )

    return address, value


def main() -> None:
    """Load a baseline, request confirmation, write one coil, and verify it."""
    config = load_config(CONFIG_PATH)
    if len(sys.argv) != 2:
        raise SystemExit("Usage: py modbus_write.py <run-###>")

    run_id = sys.argv[1]
    run_paths = build_run_paths(config, run_id)
    baseline_path = run_paths["raw"] / "01-pre-write-state.json"

    # Save attacker-side evidence separately from the baseline.  This record
    # documents the requested value and the read-back result after the write.
    output_path = run_paths["raw"] / "02-write-result.json"
    require_unused_output(output_path)
    logger = configure_logging(output_path.with_suffix(".log"))
    client = SafeModbusClient(config, logger)

    baseline = load_baseline(baseline_path, client)
    if baseline.get("run_id") != run_id or baseline.get("stage") != "pre-write":
        raise ValueError("Baseline must be the pre-write state from this run.")
    address, requested_value = choose_write(client)

    if str(address) not in baseline["coils"]:
        raise ValueError(
            f"Baseline does not contain allowlisted coil {address}."
        )
    if baseline["coils"][str(address)] == requested_value:
        raise ValueError(
            f"Coil {address} already equals attack value {requested_value}. "
            "Restore the safe state and start a new run."
        )

    print(
        f"About to write coil {address} = {requested_value} on "
        f"{client.host}:{client.port} (unit {client.unit_id})."
    )

    confirm = input("Type WRITE to continue: ")
    if confirm != "WRITE":
        print("Write cancelled")
        return

    result = {
        "run_id": run_id,
        "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "baseline_file": str(baseline_path),
        "target": {"ip": client.host, "port": client.port, "unit_id": client.unit_id},
        "coil": address,
        "original_value": baseline["coils"][str(address)],
        "requested_value": requested_value,
        "readback_value": None,
        "verified": False,
    }

    try:
        client.connect()

        client.write_coil(address, requested_value)
        read_val = client.read_coil(address)
        result["readback_value"] = read_val
        result["verified"] = read_val == requested_value
        if not result["verified"]:
            raise RuntimeError(
                f"Write verification failed: expected {requested_value}, "
                f"got {read_val}."
            )
    finally:
        # close() runs even if Conpot rejects the operation or verification fails.
        client.close()

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(result, file, indent=2)

    print(f"Saved at: {output_path}")


if __name__ == "__main__":
    main()