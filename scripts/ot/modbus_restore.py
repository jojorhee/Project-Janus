"""Restore allowlisted Conpot coil values from one exact baseline capture.

Usage (run from the Windows client):
    py .\modbus_restore.py "C:\\CyberRange\\Evidence\\baseline\\normalized\\modbus-baseline-...json"

This script does not select a "latest" baseline automatically.  The operator
must supply the exact pre-write baseline that recorded the values to restore.
That makes the restoration reference explicit and preserves older baseline
captures for later behavioral analysis.
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from modbus_client import SafeModbusClient, configure_logging, load_config


# This file is <project root>/ot/modbus_restore.py.  Building paths from the
# script location lets the project run from Z:, C:, or another copied folder
# without editing a hard-coded project location.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = PROJECT_ROOT / "config" / "lab.json"


def get_baseline_path() -> Path:
    """Read and validate the required exact baseline-file argument."""
    if len(sys.argv) != 2:
        raise SystemExit(
            "Usage: py modbus_restore.py <exact-baseline-json-path>"
        )

    baseline_path = Path(sys.argv[1]).expanduser().resolve()
    if not baseline_path.is_file():
        raise FileNotFoundError(f"Baseline file not found: {baseline_path}")

    return baseline_path


def load_and_validate_baseline(
    baseline_path: Path, client: SafeModbusClient
) -> dict[int, bool]:
    """Return baseline coil values after strict target and allowlist checks.

    A baseline is usable only when it came from this exact configured Conpot
    host, TCP port, and Modbus unit ID.  It must also contain values for only
    coils the current lab configuration permits this script to touch.
    """
    with baseline_path.open(encoding="utf-8") as file:
        baseline = json.load(file)

    expected_target = {
        "ip": client.host,
        "port": client.port,
        "unit_id": client.unit_id,
    }
    if baseline.get("target") != expected_target:
        raise ValueError(
            "Baseline target does not match the configured Conpot target. "
            "Refusing restoration."
        )

    coils = baseline.get("coils")
    if not isinstance(coils, dict) or not coils:
        raise ValueError("Baseline contains no coil values to restore.")

    # JSON object keys are strings.  Convert them back to integer Modbus
    # addresses, while refusing malformed addresses or non-Boolean values.
    restored_values: dict[int, bool] = {}
    for address_text, value in coils.items():
        try:
            address = int(address_text)
        except (TypeError, ValueError) as error:
            raise ValueError(
                f"Baseline has an invalid coil address: {address_text!r}"
            ) from error

        if address not in client.allowed_coils:
            raise ValueError(
                f"Baseline coil {address} is not allowlisted in lab.json."
            )

        # Use type(...) rather than isinstance(...), because Python treats
        # integers 0 and 1 as instances of bool.  Restoration should accept
        # only the real JSON values true and false.
        if type(value) is not bool:
            raise ValueError(
                f"Baseline value for coil {address} must be true or false."
            )

        restored_values[address] = value

    return restored_values


def build_output_path(config: dict, timestamp: str) -> Path:
    """Build a separate JSON evidence path for the restoration result."""
    return (
        Path(config["evidence"]["windows_root"])
        / config["evidence"]["attack_folder"]
        / config["evidence"]["normalized_folder"]
        / f"modbus-restore-{timestamp}.json"
    )


def main() -> None:
    """Confirm, restore every saved coil value, read back, and save evidence."""
    config = load_config(CONFIG_PATH)
    baseline_path = get_baseline_path()

    timestamp_for_file = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_path = build_output_path(config, timestamp_for_file)
    logger = configure_logging(output_path.with_suffix(".log"))
    client = SafeModbusClient(config, logger)

    # Validate everything before the confirmation prompt and before opening a
    # TCP connection.  This way a bad file can never cause a partial restore.
    saved_coils = load_and_validate_baseline(baseline_path, client)

    print(f"Baseline: {baseline_path}")
    for address, original_value in sorted(saved_coils.items()):
        print(f"  Coil {address} will be restored to {original_value}.")
    print(f"Target: {client.host}:{client.port} (unit {client.unit_id})")

    confirmation = input("Type RESTORE to restore these values: ")
    if confirmation != "RESTORE":
        print("Restoration cancelled.")
        return

    result = {
        "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "baseline_file": str(baseline_path),
        "target": {
            "ip": client.host,
            "port": client.port,
            "unit_id": client.unit_id,
        },
        "coils": {},
        "verified": False,
    }

    try:
        client.connect()

        for address, original_value in sorted(saved_coils.items()):
            # restore_coil() is deliberately separate from the strict attack
            # write helper: it accepts only an allowlisted coil and a Boolean
            # value after this script has validated the exact baseline.
            client.restore_coil(address, original_value)
            readback_value = client.read_coil(address)
            restored = readback_value == original_value

            result["coils"][str(address)] = {
                "original_baseline_value": original_value,
                "readback_value": readback_value,
                "restored": restored,
            }

            if not restored:
                raise RuntimeError(
                    f"Restoration verification failed for coil {address}: "
                    f"expected {original_value}, got {readback_value}."
                )

        result["verified"] = True
    except Exception as error:
        # Preserve failed verification/connection evidence as well.  The error
        # is re-raised after the JSON is saved so the terminal still shows the
        # failure clearly to the operator.
        result["error"] = str(error)
        raise
    finally:
        # Closing in finally prevents an open Modbus TCP session after either
        # a successful restore or a failed write/read-back verification.
        client.close()
        # Save evidence even when the restore fails midway.  In that case,
        # verified remains false and the error field explains why.
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as file:
            json.dump(result, file, indent=2)

    print(f"Restoration verified. Evidence saved: {output_path}")


if __name__ == "__main__":
    main()