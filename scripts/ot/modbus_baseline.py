"""
Read approved Conpot holding registers and save their original values.

This script performs no Modbus writes.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from modbus_client import SafeModbusClient, configure_logging, load_config


# TODO 1:
# Find the project root based on this script's location.
# Hint: this file is in project_root/ot/, so use Path(__file__).resolve().
PROJECT_ROOT = Path(__file__).resolve().parent.parent


# TODO 2:
# Build the path to config/lab.json.
CONFIG_PATH = PROJECT_ROOT / "config" / "lab.json"


def build_output_path(config: dict, timestamp: str) -> Path:
    """
    Return a path like:
    C:\\CyberRange\\Evidence\\baseline\\normalized\\modbus-baseline-<timestamp>.json

    Why timestamped?
    Each baseline capture remains separate and can later be compared with attack data.
    """
    # Get the Windows evidence root and baseline folder from lab.json.
    # Add "normalized" because this JSON is AI-ready structured data.
    # Use config["modbus"]["baseline_filename_prefix"] for the filename.
    evidence_root = Path(config["evidence"]["windows_root"]) 
    baseline_folder = config["evidence"]["baseline_folder"]
    normalized_folder = config["evidence"]["normalized_folder"]
    prefix = config["modbus"]["baseline_filename_prefix"]
    
    return (
        evidence_root
        / baseline_folder 
        / normalized_folder 
        / f"{prefix}-{timestamp}.json"
    )

def main() -> None:
    """Connect, collect approved register values, and save them."""
    config = load_config(CONFIG_PATH)

    # Use UTC in the file so timestamps are unambiguous across systems.
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    output_path = build_output_path(config, timestamp)

    # This is a human-readable script action log, separate from the baseline JSON.
    log_path = output_path.with_suffix(".log")
    logger = configure_logging(log_path)

    client = SafeModbusClient(config, logger)

    # The JSON will use string keys because JSON object keys are strings.
    baseline = {
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

        # TODO 3:
        # Loop through client.allowed_registers in sorted order.
        # For each address:
        #   - call client.read_holding_register(address)
        #   - save it as baseline["holding_registers"][str(address)]
        for coil in client.allowed_coils:
            read_coil = client.read_coil(coil)
            baseline["coils"][str(coil)] = read_coil

    finally:
        # Always close the TCP connection, including when a read fails.
        client.close()

    # TODO 4:
    # Create output_path.parent, then write baseline as formatted JSON.
    # Use encoding="utf-8" and indent=2.
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with output_path.open("w", encoding="utf-8") as file:
        json.dump(baseline, file, indent=2)

    #print(f"Baseline saved: {output_path.parent / 'baseline.json'}")


if __name__ == "__main__":
    main()