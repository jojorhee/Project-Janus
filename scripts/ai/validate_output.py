from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

try:
    from jsonschema import Draft202012Validator
    from jsonschema.exceptions import SchemaError
except ImportError:
    print(
        "ERROR: Missing dependency 'jsonschema'. Install it with: "
        "python -m pip install jsonschema",
        file=sys.stderr,
    )
    raise SystemExit(2)


SCRIPT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_SCHEMA = SCRIPT_DIR / "schemas/llm_detection_output_schema.json"


class DuplicateKeyError(ValueError):
    """Raised when JSON contains an ambiguous duplicate object key."""


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate object key: {key!r}")
        result[key] = value
    return result


def load_json(path: Path, description: str) -> Any:
    try:
        with path.open("r", encoding="utf-8-sig") as handle:
            return json.load(handle, object_pairs_hook=reject_duplicate_keys)
    except FileNotFoundError as exc:
        raise ValueError(f"{description} not found: {path}") from exc
    except PermissionError as exc:
        raise ValueError(f"cannot read {description.lower()}: {path}") from exc
    except (json.JSONDecodeError, DuplicateKeyError) as exc:
        raise ValueError(f"invalid JSON in {description.lower()} {path}: {exc}") from exc


def json_path(parts: Any) -> str:
    rendered = "$"
    for part in parts:
        rendered += f"[{part}]" if isinstance(part, int) else f".{part}"
    return rendered


def validation_errors(validator: Draft202012Validator, candidate: Any) -> list[str]:
    errors = sorted(
        validator.iter_errors(candidate),
        key=lambda error: (list(error.absolute_path), error.message),
    )
    return [f"{json_path(error.absolute_path)}: {error.message}" for error in errors]


def write_validated_output(candidate: Any, output_path: Path, overwrite: bool) -> None:
    if output_path.exists() and not overwrite:
        raise ValueError(
            f"output already exists: {output_path} (use --overwrite to replace it)"
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=output_path.parent,
            prefix=f".{output_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_name = handle.name
            json.dump(candidate, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, output_path)
    finally:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate a Project Janus LLM detection output against its JSON Schema."
    )
    parser.add_argument("candidate", type=Path, help="LLM candidate JSON file")
    parser.add_argument(
        "--schema",
        type=Path,
        default=DEFAULT_SCHEMA,
        help=f"output schema (default: {DEFAULT_SCHEMA})",
    )
    parser.add_argument(
        "--target",
        choices=("windows", "ot"),
        help="also require the candidate to have this target",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="atomically copy valid JSON here; omit for validation only",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="allow replacement of an existing --output file",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.overwrite and args.output is None:
        print("ERROR: --overwrite requires --output", file=sys.stderr)
        return 2

    try:
        schema = load_json(args.schema, "Schema")
        candidate = load_json(args.candidate, "Candidate")
        Draft202012Validator.check_schema(schema)
    except (ValueError, SchemaError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    validator = Draft202012Validator(schema)
    errors = validation_errors(validator, candidate)
    if errors:
        print(
            f"INVALID: {args.candidate} failed with {len(errors)} error(s):",
            file=sys.stderr,
        )
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    if args.target is not None and candidate.get("target") != args.target:
        print(
            f"INVALID: expected target {args.target!r}, got "
            f"{candidate.get('target')!r}",
            file=sys.stderr,
        )
        return 1

    if args.output is not None:
        try:
            write_validated_output(candidate, args.output.resolve(), args.overwrite)
        except (OSError, ValueError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        print(f"VALID: accepted output written to {args.output}")
    else:
        print(
            f"VALID: {args.candidate} matches the Project Janus "
            f"{candidate['target']} output contract"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())