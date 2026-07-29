"""Perform one controlled, allowlisted Conpot coil write.

This script is intentionally narrow:
  * it requires a baseline JSON created by modbus_baseline.py;
  * it writes only a coil/value allowed in lab.json; and
  * it immediately reads the coil back to record whether the change occurred.

It does NOT restore the original value.  That is the separate responsibility of
modbus_restore.py, which uses the same baseline file.
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from modbus_client import SafeModbusClient, configure_logging, load_config


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

    # TODO 1: Change this to the *exact* baseline JSON you just created.
    # Do not point to a made-up filename.  The file contains the pre-write value
    # that modbus_restore.py will need later.
    baseline_path = Path(sys.argv[1])

    # Save attacker-side evidence separately from the baseline.  This record
    # documents the requested value and the read-back result after the write.
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    evidence_root = Path(config["evidence"]["windows_root"])
    output_path = (
        evidence_root
        / config["evidence"]["attack_folder"]
        / config["evidence"]["normalized_folder"]
        / f"modbus-write-{timestamp}.json"
    )
    logger = configure_logging(output_path.with_suffix(".log"))
    client = SafeModbusClient(config, logger)

    baseline = load_baseline(baseline_path, client)
    address, requested_value = choose_write(client)

    # TODO 2: Before writing, ensure str(address) exists in baseline["coils"].
    # Why? A coil must be recorded before it is changed, otherwise it cannot be
    # restored reliably.  Raise ValueError with a clear message if it is absent.
    if not baseline.get("coils"):
        raise ValueError("Baseline contains no coil values to restore.")

    print(
        f"About to write coil {address} = {requested_value} on "
        f"{client.host}:{client.port} (unit {client.unit_id})."
    )

    # TODO 3: Ask the operator to type exactly WRITE.  If the input is not
    # WRITE, print "Write cancelled." and return before opening a connection.
    # This is a deliberate safety gate, not just a cosmetic prompt.
    confirm = input("Type WRITE to continue: ")
    if confirm != "WRITE":
        print("Write cancelled")
        return

    result = {
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

        # TODO 4: Call the helper method that writes the coil, then call the
        # helper method that reads one coil back. Store the read-back value in
        # result["readback_value"]. Set result["verified"] to whether the
        # read-back value equals requested_value. Raise RuntimeError if false.
        # Expected helper names from the coil version of modbus_client.py are:
        #     client.write_coil(address, requested_value)
        #     client.read_coil(address)
        client.write_coil(address, requested_value)
        read_val = client.read_coil(address)
        result["readback_value"] = read_val
        result["verified"] = read_val == requested_value
        if not result["verified"]:
            raise RuntimeError
    finally:
        # close() runs even if Conpot rejects the operation or verification fails.
        client.close()

    # TODO 5: Create output_path.parent and write result as indented JSON with
    # UTF-8 encoding. Then print the saved output path.
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with output_path.open("w", encoding="utf-8") as file:
        json.dump(result, file, indent=2)

    print(f"Saved at: {output_path}")


if __name__ == "__main__":
    main()