#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_DIR="${JANUS_LOG_DIR:-$SCRIPTS_ROOT/deployment-logs}"
mkdir -p "$LOG_DIR"
ROLLBACK_LOG="$LOG_DIR/ot_rollback_$(date -u +%Y%m%dT%H%M%SZ).log"

ssh -i ~/.ssh/janus_pfsense admin@10.10.20.1 'sh -s' <<'JANUS' 2>&1 | tee "$ROLLBACK_LOG"
set -eu

CFGDIR="/usr/local/etc/suricata/suricata_29549_em2"
RULEDIR="$CFGDIR/rules"
ACTIVE="$RULEDIR/suricata.rules"
JANUS_RULE="$RULEDIR/janus.rules"
SOCKET="/var/run/suricata-ctrl-socket-29549"
BACKUP_DIR="/var/backups/project-janus"
BASELINE="$BACKUP_DIR/suricata.rules.initial"
BEFORE_ROLLBACK="$BACKUP_DIR/suricata.rules.before-rollback"
STAGED="$RULEDIR/.suricata.rules.rollback-stage"
EXPECTED="426b8a2db51362c5cb961c88fff6bec5fe5d021ac0f70c760c8dab57477900f2"

BASELINE_HASH="$(sha256 -q "$BASELINE")"
[ "$BASELINE_HASH" = "$EXPECTED" ] || {
    echo "ERROR: Baseline backup hash mismatch: $BASELINE_HASH"
    exit 1
}

cp -p "$ACTIVE" "$BEFORE_ROLLBACK"
cp -p "$BASELINE" "$STAGED"
mv "$STAGED" "$ACTIVE"

echo "Reloading original OT rules..."
if ! suricatasc "$SOCKET" -c reload-rules; then
    echo "ERROR: Rollback reload failed; restoring deployed rules."
    cp -p "$BEFORE_ROLLBACK" "$STAGED"
    mv "$STAGED" "$ACTIVE"
    suricatasc "$SOCKET" -c reload-rules
    exit 1
fi

ACTIVE_HASH="$(sha256 -q "$ACTIVE")"
[ "$ACTIVE_HASH" = "$EXPECTED" ] || {
    echo "ERROR: Restored hash mismatch: $ACTIVE_HASH"
    exit 1
}

echo "Restored active hash: $ACTIVE_HASH"
suricatasc "$SOCKET" -c ruleset-stats
echo "OT ROLLBACK PASS"
JANUS
