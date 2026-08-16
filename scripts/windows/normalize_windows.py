#!/usr/bin/env python3
"""Convert Project Janus normalized Windows CSVs to schema-valid JSONL.

The input CSVs are treated as immutable evidence derivatives. This adapter
coerces their string fields, creates the nested Windows record structure, and
validates every record before atomically writing a combined JSONL file.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import re
import sys
import tempfile
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping


SCHEMA_VERSION = "1.0"
TIMESTAMP_RE = re.compile(
    r"^(?P<prefix>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<fraction>\d+))?(?P<zone>Z|[+-]\d{2}:\d{2})$"
)


class NormalizationError(ValueError):
    """Raised when a CSV row cannot be safely normalized."""


def required_text(row: Mapping[str, str], field: str) -> str:
    value = (row.get(field) or "").strip()
    if not value:
        raise NormalizationError(f"{field} is empty")
    return value


def integer(
    row: Mapping[str, str],
    field: str,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    raw = required_text(row, field)
    try:
        value = int(raw, 10)
    except ValueError as exc:
        raise NormalizationError(f"{field} must be an integer, got {raw!r}") from exc
    if minimum is not None and value < minimum:
        raise NormalizationError(f"{field} must be at least {minimum}, got {value}")
    if maximum is not None and value > maximum:
        raise NormalizationError(f"{field} must be at most {maximum}, got {value}")
    return value


def boolean(row: Mapping[str, str], field: str) -> bool:
    raw = required_text(row, field).casefold()
    if raw in {"true", "1", "yes"}:
        return True
    if raw in {"false", "0", "no"}:
        return False
    raise NormalizationError(f"{field} must be a Boolean, got {raw!r}")


def normalize_timestamp(raw: str) -> str:
    """Return RFC 3339 UTC text, trimming Windows' 7th fractional digit.

    Python and most JSON Schema format checkers support microseconds (six
    digits). Extra digits are truncated, not rounded, so the timestamp never
    moves into a different second.
    """
    value = raw.strip()
    match = TIMESTAMP_RE.fullmatch(value)
    if not match:
        raise NormalizationError(f"timestamp_utc is not RFC 3339-like: {value!r}")

    fraction = (match.group("fraction") or "")[:6].rstrip("0")
    normalized = match.group("prefix")
    if fraction:
        normalized += f".{fraction}"
    normalized += match.group("zone")

    parseable = normalized[:-1] + "+00:00" if normalized.endswith("Z") else normalized
    try:
        datetime.fromisoformat(parseable)
    except ValueError as exc:
        raise NormalizationError(f"timestamp_utc is invalid: {value!r}") from exc
    return normalized


def canonical_user(row: Mapping[str, str]) -> str:
    user = required_text(row, "user")
    domain = (row.get("domain") or "").strip()
    if domain and "\\" not in user and "@" not in user:
        return f"{domain}\\{user}"
    return user


def base_record(row: Mapping[str, str], record_type: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "record_type": record_type,
        "timestamp_utc": normalize_timestamp(required_text(row, "timestamp_utc")),
        "host": required_text(row, "host"),
        "user": canonical_user(row),
        "provider": required_text(row, "provider"),
        "run_id": required_text(row, "run_id"),
        "label": required_text(row, "label").casefold(),
        "source": {
            "raw_file": required_text(row, "raw_file"),
            "raw_row": integer(row, "raw_row", minimum=1),
        },
    }


def normalize_sysmon(row: Mapping[str, str]) -> dict[str, Any]:
    record = base_record(row, "process_creation")
    record["data"] = {
        "event_id": integer(row, "event_id"),
        "process_image": required_text(row, "process_image"),
        "process_id": integer(row, "process_id", minimum=0),
        "parent_image": required_text(row, "parent_image"),
        "parent_process_id": integer(row, "parent_process_id", minimum=0),
        # An empty command line is allowed by the schema and is not invented.
        "command_line": row.get("command_line") or "",
    }
    return record


def normalize_powershell(row: Mapping[str, str]) -> dict[str, Any]:
    record = base_record(row, "powershell")
    record["data"] = {
        "event_id": integer(row, "event_id"),
        "event_type": required_text(row, "event_type"),
        # Empty script text is allowed because an event may contain no body.
        "script_text": row.get("script_text") or "",
        "record_id": integer(row, "record_id", minimum=1),
    }
    return record


def normalize_rdp(row: Mapping[str, str]) -> dict[str, Any]:
    source_ip = required_text(row, "source_ip")
    try:
        ipaddress.IPv4Address(source_ip)
    except ipaddress.AddressValueError as exc:
        raise NormalizationError(f"source_ip is not valid IPv4: {source_ip!r}") from exc

    stated_ip_valid = boolean(row, "source_ip_valid")
    if not stated_ip_valid:
        raise NormalizationError(
            "source_ip_valid is false even though source_ip parsed as IPv4; "
            "review the source row instead of silently changing it"
        )

    data: dict[str, Any] = {
        "source_ip": source_ip,
        # Security 4624 exports use 0 when no source port was recorded.
        "source_port": integer(row, "source_port", minimum=0, maximum=65535),
        "local_port": integer(row, "local_port", minimum=1, maximum=65535),
        "logon_type": required_text(row, "logon_type"),
        "attribution_source": required_text(row, "attribution_source"),
        "source_ip_valid": stated_ip_valid,
    }

    local_ip = (row.get("local_ip") or "").strip()
    if local_ip:
        try:
            ipaddress.IPv4Address(local_ip)
        except ipaddress.AddressValueError as exc:
            raise NormalizationError(f"local_ip is not valid IPv4: {local_ip!r}") from exc
        data["local_ip"] = local_ip

    record = base_record(row, "rdp_session")
    record["data"] = data
    return record


NORMALIZERS: dict[str, Callable[[Mapping[str, str]], dict[str, Any]]] = {
    "sysmon": normalize_sysmon,
    "powershell": normalize_powershell,
    "rdp": normalize_rdp,
}

REQUIRED_HEADERS: dict[str, set[str]] = {
    "sysmon": {
        "timestamp_utc", "host", "user", "event_id", "provider",
        "process_image", "process_id", "parent_image", "parent_process_id",
        "command_line", "run_id", "label", "raw_file", "raw_row",
    },
    "powershell": {
        "timestamp_utc", "host", "user", "event_id", "provider",
        "event_type", "script_text", "record_id", "run_id", "label",
        "raw_file", "raw_row",
    },
    "rdp": {
        "timestamp_utc", "host", "user", "source_ip", "source_port",
        "local_ip", "local_port", "logon_type", "provider",
        "attribution_source", "source_ip_valid", "run_id", "label",
        "raw_file", "raw_row",
    },
}


def read_and_normalize(path: Path, kind: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    try:
        handle = path.open("r", encoding="utf-8-sig", newline="")
    except OSError as exc:
        raise NormalizationError(f"cannot open {path}: {exc}") from exc

    with handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise NormalizationError(f"{path}: missing CSV header")
        missing = REQUIRED_HEADERS[kind] - set(reader.fieldnames)
        if missing:
            raise NormalizationError(
                f"{path}: missing required columns: {', '.join(sorted(missing))}"
            )

        for csv_line, row in enumerate(reader, start=2):
            try:
                records.append(NORMALIZERS[kind](row))
            except NormalizationError as exc:
                raise NormalizationError(f"{path}, CSV line {csv_line}: {exc}") from exc
    return records


def error_path(error: Any) -> str:
    parts = [str(part) for part in error.absolute_path]
    return ".".join(parts) if parts else "<root>"


def validate_records(
    records: Iterable[dict[str, Any]], schema_path: Path
) -> list[dict[str, Any]]:
    try:
        from jsonschema import Draft202012Validator, FormatChecker
        from jsonschema.exceptions import SchemaError
    except ImportError as exc:  # pragma: no cover - depends on local environment
        raise NormalizationError(
            "missing dependency: jsonschema; install it with "
            "'python -m pip install jsonschema'"
        ) from exc

    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise NormalizationError(f"cannot load schema {schema_path}: {exc}") from exc

    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        raise NormalizationError(f"invalid Draft 2020-12 schema: {exc.message}") from exc

    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    validated: list[dict[str, Any]] = []
    failures: list[str] = []
    for index, record in enumerate(records, start=1):
        errors = sorted(
            validator.iter_errors(record),
            key=lambda item: (list(item.absolute_path), item.message),
        )
        if errors:
            identity = f"record {index} ({record['record_type']}, {record['run_id']})"
            for error in errors:
                failures.append(f"{identity} at {error_path(error)}: {error.message}")
        else:
            validated.append(record)

    if failures:
        preview = "\n".join(f"  - {item}" for item in failures[:20])
        remainder = len(failures) - 20
        if remainder > 0:
            preview += f"\n  - ... and {remainder} more validation error(s)"
        raise NormalizationError(f"schema validation failed:\n{preview}")
    return validated


def enforce_one_run(records: list[dict[str, Any]]) -> None:
    run_ids = {record["run_id"] for record in records}
    labels = {record["label"] for record in records}
    if len(run_ids) != 1:
        raise NormalizationError(
            f"inputs contain multiple run IDs: {', '.join(sorted(run_ids))}"
        )
    if len(labels) != 1:
        raise NormalizationError(
            f"inputs contain multiple labels: {', '.join(sorted(labels))}"
        )


def write_jsonl(records: list[dict[str, Any]], output: Path, overwrite: bool) -> None:
    if output.exists() and not overwrite:
        raise NormalizationError(
            f"output already exists: {output} (use --overwrite to replace it)"
        )
    output.parent.mkdir(parents=True, exist_ok=True)

    temp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=output.parent,
            prefix=f".{output.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_name = handle.name
            for record in records:
                handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")))
                handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, output)
    finally:
        if temp_name and os.path.exists(temp_name):
            os.unlink(temp_name)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Normalize Sysmon, PowerShell, and RDP CSVs into validated JSONL."
    )
    parser.add_argument("--sysmon", required=True, type=Path, help="Sysmon normalized CSV")
    parser.add_argument(
        "--powershell", required=True, type=Path, help="PowerShell normalized CSV"
    )
    parser.add_argument("--rdp", required=True, type=Path, help="RDP normalized CSV")
    parser.add_argument("--schema", required=True, type=Path, help="Windows JSON Schema")
    parser.add_argument("--output", required=True, type=Path, help="Output JSONL path")
    parser.add_argument(
        "--overwrite", action="store_true", help="Replace an existing output file"
    )
    parser.add_argument(
        "--allow-mixed-runs",
        action="store_true",
        help="Allow more than one run ID or label (not recommended for finalization)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        records: list[dict[str, Any]] = []
        records.extend(read_and_normalize(args.sysmon, "sysmon"))
        records.extend(read_and_normalize(args.powershell, "powershell"))
        records.extend(read_and_normalize(args.rdp, "rdp"))
        if not records:
            raise NormalizationError("no input records found")
        if not args.allow_mixed_runs:
            enforce_one_run(records)
        validated = validate_records(records, args.schema)
        write_jsonl(validated, args.output, args.overwrite)
    except NormalizationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    counts = Counter(record["record_type"] for record in validated)
    print(f"PASS: wrote {len(validated)} validated records to {args.output}")
    print(
        "Counts: "
        f"process_creation={counts['process_creation']}, "
        f"powershell={counts['powershell']}, "
        f"rdp_session={counts['rdp_session']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())