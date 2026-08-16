#!/usr/bin/env python3
"""Convert Project Janus flat Modbus CSV exports into schema-valid JSONL.

Only Modbus request rows are emitted. Response rows are counted and skipped
because the current normalized OT schema models client-to-server requests.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SUPPORTED_FUNCTIONS = {1, 5}
BOOLEAN_TO_MODBUS_VALUE = {
    "true": "0xFF00",
    "false": "0x0000",
    "1": "0xFF00",
    "0": "0x0000",
    "0xff00": "0xFF00",
    "0x0000": "0x0000",
}


class NormalizationError(ValueError):
    """Raised when a CSV row contradicts or lacks required evidence."""


@dataclass
class Counts:
    input_rows: int = 0
    request_rows: int = 0
    response_rows_skipped: int = 0
    output_records: int = 0


def require_text(row: dict[str, str], field: str) -> str:
    value = (row.get(field) or "").strip()
    if not value:
        raise NormalizationError(f"missing required field {field!r}")
    return value


def require_int(row: dict[str, str], field: str) -> int:
    text = require_text(row, field)
    try:
        return int(text, 10)
    except ValueError as exc:
        raise NormalizationError(f"{field!r} must be a base-10 integer, got {text!r}") from exc


def normalize_timestamp(value: str) -> str:
    """Convert an ISO timestamp to UTC RFC 3339 with at most six decimals."""
    text = value.strip()
    if not text:
        raise NormalizationError("timestamp_utc is empty")

    # datetime supports microseconds, so trim a seventh-or-later fractional digit.
    text = re.sub(r"(\.\d{6})\d+(?=Z$|[+-]\d{2}:\d{2}$)", r"\1", text)
    python_text = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(python_text)
    except ValueError as exc:
        raise NormalizationError(f"invalid timestamp_utc {value!r}") from exc

    if parsed.tzinfo is None:
        raise NormalizationError("timestamp_utc must include Z or a UTC offset")

    utc_value = parsed.astimezone(timezone.utc)
    rendered = utc_value.isoformat(timespec="microseconds")
    return rendered.replace("+00:00", "Z")


def parse_modbus_request_payload(raw_payload: str) -> dict[str, int | str]:
    """Extract fields from a Modbus TCP request ADU represented as hex."""
    compact = re.sub(r"\s+", "", raw_payload)
    try:
        payload = bytes.fromhex(compact)
    except ValueError as exc:
        raise NormalizationError("raw_payload is not valid hexadecimal") from exc

    # MBAP header (7 bytes) + function-specific request data (5 bytes).
    if len(payload) < 12:
        raise NormalizationError(
            f"raw_payload is too short for a supported Modbus request: {len(payload)} bytes"
        )

    protocol_id = int.from_bytes(payload[2:4], "big")
    declared_length = int.from_bytes(payload[4:6], "big")
    if protocol_id != 0:
        raise NormalizationError(f"protocol ID must be 0 for Modbus TCP, got {protocol_id}")
    if declared_length != len(payload) - 6:
        raise NormalizationError(
            f"MBAP length says {declared_length} bytes but payload contains {len(payload) - 6}"
        )

    function_code = payload[7]
    parsed: dict[str, int | str] = {
        "transaction_id": int.from_bytes(payload[0:2], "big"),
        "unit_id": payload[6],
        "function_code": function_code,
        "coil_address": int.from_bytes(payload[8:10], "big"),
    }

    if function_code == 1:
        parsed["quantity"] = int.from_bytes(payload[10:12], "big")
    elif function_code == 5:
        wire_value = int.from_bytes(payload[10:12], "big")
        if wire_value not in {0x0000, 0xFF00}:
            raise NormalizationError(
                f"function 5 coil value must be 0x0000 or 0xFF00, got 0x{wire_value:04X}"
            )
        parsed["coil_value"] = f"0x{wire_value:04X}"
    else:
        raise NormalizationError(
            f"unsupported function code {function_code}; expected one of {sorted(SUPPORTED_FUNCTIONS)}"
        )

    return parsed


def ensure_equal(field: str, csv_value: Any, payload_value: Any) -> None:
    if csv_value != payload_value:
        raise NormalizationError(
            f"{field} mismatch: CSV has {csv_value!r}, raw_payload has {payload_value!r}"
        )


def normalize_request(row: dict[str, str]) -> dict[str, Any]:
    """Normalize and cross-check one request row."""
    function_code = require_int(row, "function_code")
    if function_code not in SUPPORTED_FUNCTIONS:
        raise NormalizationError(
            f"unsupported function_code {function_code}; expected {sorted(SUPPORTED_FUNCTIONS)}"
        )

    payload = parse_modbus_request_payload(require_text(row, "raw_payload"))
    transaction_id = require_int(row, "transaction_id")
    unit_id = require_int(row, "unit_id")
    coil_address = require_int(row, "coil_address")

    ensure_equal("transaction_id", transaction_id, payload["transaction_id"])
    ensure_equal("unit_id", unit_id, payload["unit_id"])
    ensure_equal("function_code", function_code, payload["function_code"])
    ensure_equal("coil_address", coil_address, payload["coil_address"])

    frame_number = require_int(row, "frame_number")
    raw_frame_text = (row.get("raw_frame") or "").strip()
    if raw_frame_text:
        try:
            raw_frame = int(raw_frame_text, 10)
        except ValueError as exc:
            raise NormalizationError(f"raw_frame must be an integer, got {raw_frame_text!r}") from exc
        ensure_equal("frame_number/raw_frame", frame_number, raw_frame)

    data: dict[str, Any] = {
        "transaction_id": transaction_id,
        "unit_id": unit_id,
        "function_code": function_code,
        "coil_address": coil_address,
    }

    if function_code == 1:
        # The flat CSV lacks quantity, so preserve it from the captured wire bytes.
        data["quantity"] = payload["quantity"]
    else:
        csv_coil_value = require_text(row, "coil_value").lower()
        if csv_coil_value not in BOOLEAN_TO_MODBUS_VALUE:
            raise NormalizationError(
                f"unsupported coil_value {csv_coil_value!r}; expected true/false or a wire value"
            )
        normalized_value = BOOLEAN_TO_MODBUS_VALUE[csv_coil_value]
        ensure_equal("coil_value", normalized_value, payload["coil_value"])
        data["coil_value"] = normalized_value

    return {
        "schema_version": "1.0",
        "record_type": "modbus_transaction",
        "timestamp_utc": normalize_timestamp(require_text(row, "timestamp_utc")),
        "run_id": require_text(row, "run_id"),
        "label": require_text(row, "label").lower(),
        "source": {
            "raw_file": require_text(row, "raw_file"),
            "packet_number": frame_number,
        },
        "network": {
            "source_ip": require_text(row, "src_ip"),
            "source_port": require_int(row, "src_port"),
            "destination_ip": require_text(row, "dst_ip"),
            "destination_port": require_int(row, "dst_port"),
            "protocol": "modbus_tcp",
        },
        "data": data,
    }


def format_validation_errors(validator: Any, record: dict[str, Any]) -> list[str]:
    errors = sorted(validator.iter_errors(record), key=lambda item: list(item.absolute_path))
    messages: list[str] = []
    for error in errors:
        location = ".".join(str(part) for part in error.absolute_path) or "<root>"
        messages.append(f"{location}: {error.message}")
    return messages


def load_validator(schema_path: Path) -> Any:
    try:
        from jsonschema import Draft202012Validator, FormatChecker
        from jsonschema.exceptions import SchemaError
    except ImportError as exc:  # pragma: no cover - produces a clear runtime message
        raise SystemExit(
            "Missing dependency: jsonschema\n"
            "Install it with: python -m pip install jsonschema"
        ) from exc

    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Could not read schema {schema_path}: {exc}") from exc

    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        raise SystemExit(f"Invalid Draft 2020-12 schema: {exc.message}") from exc
    return Draft202012Validator(schema, format_checker=FormatChecker())


def read_requests(csv_paths: Iterable[Path], counts: Counts) -> list[tuple[str, dict[str, Any]]]:
    normalized: list[tuple[str, dict[str, Any]]] = []
    for csv_path in csv_paths:
        try:
            csv_file = csv_path.open("r", encoding="utf-8-sig", newline="")
        except OSError as exc:
            raise SystemExit(f"Could not open CSV {csv_path}: {exc}") from exc

        with csv_file:
            reader = csv.DictReader(csv_file)
            if not reader.fieldnames:
                raise SystemExit(f"CSV has no header: {csv_path}")
            for line_number, row in enumerate(reader, start=2):
                counts.input_rows += 1
                message_type = (row.get("message_type") or "").strip().lower()
                if message_type == "response":
                    counts.response_rows_skipped += 1
                    continue
                if message_type != "request":
                    raise SystemExit(
                        f"{csv_path}:{line_number}: unsupported message_type {message_type!r}"
                    )
                counts.request_rows += 1
                location = f"{csv_path}:{line_number}"
                try:
                    normalized.append((location, normalize_request(row)))
                except NormalizationError as exc:
                    raise SystemExit(f"{location}: {exc}") from exc
    return normalized


def write_jsonl(records: list[dict[str, Any]], output_path: Path, overwrite: bool) -> None:
    if output_path.exists() and not overwrite:
        raise SystemExit(f"Output already exists: {output_path} (use --overwrite to replace it)")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = output_path.with_name(output_path.name + ".tmp")
    try:
        with temporary_path.open("w", encoding="utf-8", newline="\n") as output:
            for record in records:
                output.write(json.dumps(record, separators=(",", ":"), ensure_ascii=False))
                output.write("\n")
        temporary_path.replace(output_path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Normalize Project Janus Modbus CSV requests into validated JSONL."
    )
    parser.add_argument("inputs", nargs="+", type=Path, help="One or more flat Modbus CSV files")
    parser.add_argument("--schema", required=True, type=Path, help="Normalized OT JSON Schema")
    parser.add_argument("--output", required=True, type=Path, help="Destination JSONL file")
    parser.add_argument("--overwrite", action="store_true", help="Replace an existing output file")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    validator = load_validator(args.schema)
    counts = Counts()
    located_records = read_requests(args.inputs, counts)

    validation_failures: list[str] = []
    for location, record in located_records:
        for message in format_validation_errors(validator, record):
            validation_failures.append(f"{location}: {message}")

    if validation_failures:
        print("Schema validation failed:", file=sys.stderr)
        for failure in validation_failures:
            print(f"  {failure}", file=sys.stderr)
        return 1

    records = [record for _, record in located_records]
    write_jsonl(records, args.output, args.overwrite)
    counts.output_records = len(records)
    print(f"PASS: wrote {counts.output_records} schema-valid request records to {args.output}")
    print(
        f"Input rows: {counts.input_rows}; requests: {counts.request_rows}; "
        f"responses skipped: {counts.response_rows_skipped}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())