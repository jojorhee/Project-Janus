#!/usr/bin/env bash

set -euo pipefail

usage() {
    echo "Usage: $0 <rule-file> <sid> <output-directory> <attack.pcap> <baseline.pcap>" >&2
    exit 2
}

[ "$#" -eq 5 ] || usage

RULE_PATH="$1"
SID="$2"
OUTPUT_ROOT="$3"
ATTACK_PCAP="$4"
BASELINE_PCAP="$5"

[[ "$SID" =~ ^[1-9][0-9]*$ ]] || {
    echo "ERROR: SID must be a positive integer." >&2
    exit 1
}

for path in "$RULE_PATH" "$ATTACK_PCAP" "$BASELINE_PCAP"; do
    [ -f "$path" ] || {
        echo "ERROR: Required file not found: $path" >&2
        exit 1
    }
done

RUN_ROOT="$OUTPUT_ROOT/run_$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$RUN_ROOT"
printf 'label\tpcap\texit_status\talert_count\n' > "$RUN_ROOT/results.tsv"

run_case() {
    local label="$1"
    local pcap_path="$2"
    local pcap_name
    local output_dir
    local suricata_exit
    local alert_count

    pcap_name="$(basename "$pcap_path")"
    output_dir="$RUN_ROOT/${label}_${pcap_name%.*}"
    mkdir -p "$output_dir"

    set +e
    sudo suricata \
        -r "$pcap_path" \
        -k none \
        -c /etc/suricata/suricata.yaml \
        -S "$RULE_PATH" \
        -l "$output_dir" \
        2>&1 | tee "$output_dir/suricata_console.log"
    suricata_exit="${PIPESTATUS[0]}"
    set -e

    alert_count="$(
        jq -s --argjson sid "$SID" \
            '[.[] | select(.event_type == "alert" and .alert.signature_id == $sid)] | length' \
            "$output_dir/eve.json"
    )"

    printf '%s\t%s\t%s\t%s\n' \
        "$label" "$pcap_name" "$suricata_exit" "$alert_count" \
        | tee "$output_dir/result.tsv" >> "$RUN_ROOT/results.tsv"
}

run_case attack "$ATTACK_PCAP"
run_case baseline "$BASELINE_PCAP"

cat "$RUN_ROOT/results.tsv"

