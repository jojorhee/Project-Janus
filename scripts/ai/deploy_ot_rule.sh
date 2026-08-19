#!/usr/bin/env bash

set -euo pipefail

usage() {
    echo "Usage: $0 <local-rule-file> <approved-sha256>" >&2
    exit 2
}

[ "$#" -eq 2 ] || usage

LOCAL_RULE="$1"
EXPECTED_SHA256="${2,,}"

SSH_KEY="${JANUS_SSH_KEY:-$HOME/.ssh/janus_pfsense}"
PFSENSE_HOST="${JANUS_PFSENSE_HOST:-admin@10.10.20.1}"
REMOTE_UPLOAD="/tmp/.janus-ot.rules.upload"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_DIR="${JANUS_LOG_DIR:-$SCRIPTS_ROOT/deployment-logs}"
mkdir -p "$LOG_DIR"
DEPLOY_LOG="$LOG_DIR/ot_deploy_$(date -u +%Y%m%dT%H%M%SZ).log"

# Capture local validation, transfer, and remote deployment in one log.
exec > >(tee "$DEPLOY_LOG") 2>&1

[ -f "$LOCAL_RULE" ] || {
    echo "ERROR: Rule file does not exist: $LOCAL_RULE"
    exit 1
}

[ -r "$LOCAL_RULE" ] || {
    echo "ERROR: Rule file is not readable: $LOCAL_RULE"
    exit 1
}

[[ "$EXPECTED_SHA256" =~ ^[0-9a-f]{64}$ ]] || {
    echo "ERROR: Expected hash must be exactly 64 hexadecimal characters."
    exit 1
}

[ -f "$SSH_KEY" ] || {
    echo "ERROR: SSH key does not exist: $SSH_KEY"
    exit 1
}

LOCAL_ACTUAL="$(sha256sum "$LOCAL_RULE" | awk '{print $1}')"

[ "$LOCAL_ACTUAL" = "$EXPECTED_SHA256" ] || {
    echo "ERROR: Local rule hash mismatch."
    echo "Expected: $EXPECTED_SHA256"
    echo "Actual:   $LOCAL_ACTUAL"
    exit 1
}

echo "Local candidate hash approved: $LOCAL_ACTUAL"
echo "Uploading candidate to $PFSENSE_HOST:$REMOTE_UPLOAD"

scp -i "$SSH_KEY" -- "$LOCAL_RULE" "$PFSENSE_HOST:$REMOTE_UPLOAD"

# Everything inside this heredoc executes on pfSense. The approved hash is
# passed as remote argument $1.
ssh -i "$SSH_KEY" "$PFSENSE_HOST" sh -s -- "$EXPECTED_SHA256" <<'JANUS'
set -eu

EXPECTED="$1"

CFGDIR="/usr/local/etc/suricata/suricata_29549_em2"
RULEDIR="$CFGDIR/rules"
ACTIVE="$RULEDIR/suricata.rules"
REMOTE_UPLOAD="/tmp/.janus-ot.rules.upload"
CANDIDATE="/tmp/janus-ot.rules"
JANUS_RULE="$RULEDIR/janus.rules"
STAGED="$RULEDIR/.suricata.rules.janus-stage"
SOCKET="/var/run/suricata-ctrl-socket-29549"

BACKUP_DIR="/var/backups/project-janus"
BASELINE="$BACKUP_DIR/suricata.rules.initial"
PREVIOUS="$BACKUP_DIR/suricata.rules.predeploy"

RESPONSE_DIR="/usr/local/etc/janus"
APPROVED_SIDS="$RESPONSE_DIR/approved_sids.txt"
APPROVED_SIDS_STAGE="$RESPONSE_DIR/.approved_sids.stage"
APPROVED_SIDS_RAW="$RESPONSE_DIR/.approved_sids.raw"

[ -f "$REMOTE_UPLOAD" ] || {
    echo "ERROR: Uploaded rule is missing: $REMOTE_UPLOAD"
    exit 1
}

[ -f "$ACTIVE" ] || {
    echo "ERROR: Active ruleset does not exist: $ACTIVE"
    rm -f "$REMOTE_UPLOAD"
    exit 1
}

# Verify the transferred bytes again before promoting the upload.
REMOTE_ACTUAL="$(sha256 -q "$REMOTE_UPLOAD")"

[ "$REMOTE_ACTUAL" = "$EXPECTED" ] || {
    echo "ERROR: Remote rule hash mismatch."
    echo "Expected: $EXPECTED"
    echo "Actual:   $REMOTE_ACTUAL"
    rm -f "$REMOTE_UPLOAD"
    exit 1
}

chmod 0600 "$REMOTE_UPLOAD"
mv "$REMOTE_UPLOAD" "$CANDIDATE"
echo "Remote candidate hash approved: $REMOTE_ACTUAL"

# Extract the response-authorized SID from the approved candidate.
mkdir -p "$RESPONSE_DIR"
chmod 0755 "$RESPONSE_DIR"

sed -n \
    's/.*sid:[[:space:]]*\([0-9][0-9]*\)[[:space:]]*;.*/\1/p' \
    "$CANDIDATE" > "$APPROVED_SIDS_RAW"

sort -u "$APPROVED_SIDS_RAW" > "$APPROVED_SIDS_STAGE"
rm -f "$APPROVED_SIDS_RAW"

SID_COUNT="$(wc -l < "$APPROVED_SIDS_STAGE" | tr -d '[:space:]')"

[ "$SID_COUNT" -eq 1 ] || {
    echo "ERROR: Expected exactly one SID; found $SID_COUNT"
    rm -f "$APPROVED_SIDS_STAGE"
    exit 1
}

chmod 0600 "$APPROVED_SIDS_STAGE"
echo "Staged response SID: $(cat "$APPROVED_SIDS_STAGE")"

# Preserve the original ruleset once and the current ruleset before each run.
mkdir -p "$BACKUP_DIR"
[ -f "$BASELINE" ] || cp -p "$ACTIVE" "$BASELINE"
cp -p "$ACTIVE" "$PREVIOUS"

# Build and test the combined ruleset without changing the active file.
cp -p "$BASELINE" "$STAGED"
printf '\n# Project Janus managed OT rule\n' >> "$STAGED"
cat "$CANDIDATE" >> "$STAGED"
printf '\n' >> "$STAGED"

echo "Testing combined ruleset..."
if ! suricata -T -c "$CFGDIR/suricata.yaml" -S "$STAGED"; then
    echo "ERROR: Suricata syntax test failed."
    rm -f "$STAGED" "$APPROVED_SIDS_STAGE"
    exit 1
fi

# Atomically install the Janus rule and combined active ruleset.
cp -p "$CANDIDATE" "$RULEDIR/.janus.rules.stage"
chmod 0644 "$RULEDIR/.janus.rules.stage"
mv "$RULEDIR/.janus.rules.stage" "$JANUS_RULE"
mv "$STAGED" "$ACTIVE"

echo "Reloading OT Suricata..."
if ! suricatasc "$SOCKET" -c reload-rules; then
    echo "ERROR: Reload failed; restoring previous rules."
    rm -f "$APPROVED_SIDS_STAGE"
    cp -p "$PREVIOUS" "$STAGED"
    mv "$STAGED" "$ACTIVE"

    if ! suricatasc "$SOCKET" -c reload-rules; then
        echo "ERROR: Rollback reload also failed."
        exit 1
    fi

    echo "Previous active ruleset restored."
    exit 1
fi

# Publish the trusted SID only after the approved rule is active.
mv "$APPROVED_SIDS_STAGE" "$APPROVED_SIDS"

echo "Candidate hash: $(sha256 -q "$JANUS_RULE")"
echo "Active combined hash: $(sha256 -q "$ACTIVE")"
echo "Approved response SID: $(cat "$APPROVED_SIDS")"
suricatasc "$SOCKET" -c ruleset-stats
echo "OT DEPLOYMENT PASS"
JANUS

echo "Deployment log: $DEPLOY_LOG"
