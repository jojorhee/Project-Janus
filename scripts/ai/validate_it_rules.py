from __future__ import annotations
import json
from datetime import datetime
from pathlib import Path
import argparse
import sys
import subprocess

SCRIPT_DIR = Path(__file__).resolve().parent.parent

def send_notif(rule, det_count):
    title = "Project Janus IT IDS Alert"
    message = (
        f"{rule['title']} detected!" + "\n" +
        f"Correlated detections: {det_count}"
    )

    subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            (
                "Import-Module BurntToast; "
                f"New-BurntToastNotification "
                f"-Text '{title}', '{message}'"
            ),
        ],
        check=True,
    )

def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise KeyError(f"duplicate object key: {key!r}")
        result[key] = value
    return result

def load_json(path: Path, description: str):
    try:
        with path.open("r", encoding="utf-8-sig") as handle:
            return json.load(handle, object_pairs_hook=reject_duplicate_keys)
    except FileNotFoundError as exc:
        raise ValueError(f"{description} not found: {path}") from exc
    except PermissionError as exc:
        raise ValueError(f"cannot read {description.lower()}: {path}") from exc
    except (json.JSONDecodeError) as exc:
        raise ValueError(f"invalid JSON in {description.lower()} {path}: {exc}") from exc

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate a Windows Project Janus LLM detection rule against attack or baseline data"
    )
    parser.add_argument(
        "--mode",
        choices=("attack", "baseline"),
        help="Expected dataset type being validated",
        required=True
    )
    parser.add_argument(
        "--rule_file",
        type=Path,
        help="Path to the Janus Windows JSON rule being evaluated",
        required=True
    )
    parser.add_argument(
        "--event_file",
        type=Path,
        required=True
    )
    return parser.parse_args()

def get_nested_field(record: dict, field_path: str):
    """
    Retrieve a nested value using a dotted path such as:
    data.process_image
    """
    current = record

    for part in field_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]

    return current

def normalize_comparison_value(value, case_sensitive: bool) -> str:
    """Convert a scalar rule or event value into comparable text."""
    rendered = str(value)
    return rendered if case_sensitive else rendered.casefold()


def condition_matches(event: dict, condition: dict) -> bool:
    """Evaluate one scalar or list condition against one event field."""
    try:
        field = condition["field"]
        operator = condition["operator"]
    except KeyError as exc:
        raise ValueError(f"Malformed condition missing {exc.args[0]!r}") from exc

    actual_value = get_nested_field(event, field)
    if actual_value is None:
        return False

    # JSON Schema defaults are annotations and are not inserted into the rule,
    # so the evaluator must apply the contract's false default itself.
    case_sensitive = condition.get("case_sensitive", False)
    actual = normalize_comparison_value(actual_value, case_sensitive)

    scalar_operators = {"equals", "contains", "starts_with", "ends_with"}
    list_operators = {
        "in",
        "contains_any",
        "contains_all",
        "starts_with_any",
        "ends_with_any",
    }

    if operator in scalar_operators:
        if "value" not in condition:
            raise ValueError(f"Operator {operator!r} requires 'value'")
        expected = normalize_comparison_value(
            condition["value"], case_sensitive
        )

        if operator == "equals":
            return actual == expected
        if operator == "contains":
            return expected in actual
        if operator == "starts_with":
            return actual.startswith(expected)
        return actual.endswith(expected)

    if operator in list_operators:
        values = condition.get("values")
        if not isinstance(values, list) or not values:
            raise ValueError(f"Operator {operator!r} requires non-empty 'values'")
        expected_values = [
            normalize_comparison_value(value, case_sensitive)
            for value in values
        ]

        if operator == "in":
            return actual in expected_values
        if operator == "contains_any":
            return any(expected in actual for expected in expected_values)
        if operator == "contains_all":
            return all(expected in actual for expected in expected_values)
        if operator == "starts_with_any":
            return any(actual.startswith(expected) for expected in expected_values)
        return any(actual.endswith(expected) for expected in expected_values)

    raise ValueError(f"Unsupported operator: {operator}")


def expression_matches(event: dict, expression: dict) -> bool:
    """Recursively evaluate a condition or an all/any expression group."""
    is_group = "logic" in expression or "expressions" in expression
    if not is_group:
        return condition_matches(event, expression)

    logic = expression.get("logic")
    expressions = expression.get("expressions")
    if logic not in {"all", "any"}:
        raise ValueError(f"Unsupported expression logic: {logic}")
    if not isinstance(expressions, list) or not expressions:
        raise ValueError("Expression group requires non-empty 'expressions'")

    matches = (expression_matches(event, child) for child in expressions)
    return all(matches) if logic == "all" else any(matches)


def stage_matches(event: dict, stage: dict) -> bool:
    """
    Determine whether one event satisfies one detection stage.
    """
    if event.get("record_type") != stage["record_type"]:
        return False

    return expression_matches(event, stage["criteria"])

def parse_timestamp(timestamp: str) -> datetime:
    return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))

def correlate_matches(comp_a_matches, comp_b_matches, window):
    """ Compare A events against B events"""
    correlations = []
    for event_a in comp_a_matches:
        for event_b in comp_b_matches:
            if event_a.get("host") != event_b.get("host"):
                continue
            time_a = parse_timestamp(event_a["timestamp_utc"])
            time_b = parse_timestamp(event_b["timestamp_utc"])

            diff = abs((time_b - time_a).total_seconds())

            if diff <= window:
                correlations.append({
                    "host": event_a["host"],
                    "component_a_timestamp": event_a["timestamp_utc"],
                    "component_b_timestamp": event_b["timestamp_utc"],
                    "difference_seconds": diff
                })

    return correlations

def eval_validation(mode, det_count, rule):
    if mode == "attack":
        expected_minimum = (rule["expected_attack_result"]["expected_minimum_matches"])

        return det_count >= expected_minimum
    elif mode == "baseline":
        expected_matches = (rule["expected_baseline_result"]["expected_matches"])

        return det_count == expected_matches

    raise ValueError(f"Unsupported mode: {mode}")

def main():
    args = parse_args()

    #rule_file = load_json(args.rule_file, "Rule File")
    #event_file = load_json(args.event_file, "Event File")

    rule = load_json(args.rule_file, "Rule File")

    events = []

    stages = rule["detection_logic"]["stages"]

    with open(args.event_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    events.append(json.loads(line))

    component_a = next(
        stage for stage in stages
        if stage["stage_id"] == "component_a"
    )

    component_a_matches = [
        event
        for event in events
        if stage_matches(event, component_a)
    ]

    component_b = next(
        stage for stage in stages
        if stage["stage_id"] == "component_b"
    )

    component_b_matches = [
        event
        for event in events
        if stage_matches(event, component_b)
    ]

    print(f"Component A matches: {len(component_a_matches)}")

    '''for event in component_a_matches:
        print(f"host={event.get('host')}" + "\n" + f"timestamp={event.get('timestamp_utc')}")'''

    print(f"Component B matches: {len(component_b_matches)}")

    '''for event in component_b_matches:
            print(f"host={event.get('host')}" + "\n" + f"timestamp={event.get('timestamp_utc')}")'''

    print(f"Mode: {args.mode}")
    print(f"Loaded rule(s): {rule['rule_id']}")
    print(f"Loaded events: {len(events)}")
    print("-----------------------------------------------------------")

    window = rule["detection_logic"]["correlation"]["window_seconds"]

    correlations = correlate_matches(component_a_matches, component_b_matches, window)
    print(f"Correlated detections: {len(correlations)}")

    for detection in correlations:
        print(f"host={detection['host']}" + " " + f"differrence={detection['difference_seconds']}s")

    print("---------------------------------------------------------------")
    passed = eval_validation(args.mode, len(correlations), rule)
    print(f"Validation mode: {args.mode}")
    print(f"Correlated detections: {len(correlations)}")
    print(f"Verdict: {'PASS' if passed else 'REVISE'}")

    if args.mode == "attack" and passed and len(correlations) > 0:
        send_notif(rule, len(correlations))

    return 0 if passed else 2



if __name__ == "__main__":
    sys.exit(main())