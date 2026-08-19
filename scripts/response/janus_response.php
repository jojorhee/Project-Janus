#!/usr/local/bin/php
<?php

/*
 * Project Janus pfSense response validator
 *
 * Reads Suricata EVE JSON records from standard input.
 * Only an approved alert may update JANUS_BLOCKLIST.
 */

const APPROVED_SID_FILE = '/usr/local/etc/janus/approved_sids.txt';
const ALLOWED_SOURCE_CIDR = '10.10.10.0/24';
const TABLE_NAME = 'JANUS_BLOCKLIST';
const RESPONSE_LOG = '/var/log/janus_response.log';

$protectedIps = [
    '10.10.10.1',   // pfSense IT gateway
    '10.10.20.1',   // pfSense OT gateway
    '10.10.30.1',   // pfSense ATTACK gateway
    '10.10.10.10',  // IT server
    '10.10.20.10',  // Conpot OT server
];

/*
 * Record an automation decision in the response log and terminal.
 */
function recordResult($message, $isError = false)
{
    $line = gmdate('c') . ' ' . $message . PHP_EOL;

    file_put_contents(
        RESPONSE_LOG,
        $line,
        FILE_APPEND | LOCK_EX
    );

    if ($isError) {
        fwrite(STDERR, $line);
    } else {
        fwrite(STDOUT, $line);
    }
}

function ipv4InCidr($ip, $cidr)
{
    [$network, $prefix] = explode('/', $cidr, 2);

    $ipNumber = ip2long($ip);
    $networkNumber = ip2long($network);
    $prefix = (int) $prefix;

    if (
        $ipNumber === false ||
        $networkNumber === false ||
        $prefix < 0 ||
        $prefix > 32
    ) {
        return false;
    }

    $mask = $prefix === 0
        ? 0
        : (-1 << (32 - $prefix));

    return ($ipNumber & $mask) ===
           ($networkNumber & $mask);
}

function loadApprovedSids()
{
    if (!is_readable(APPROVED_SID_FILE)) {
        return [];
    }

    $lines = file(
        APPROVED_SID_FILE,
        FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES
    );

    $approvedSids = [];

    foreach ($lines as $line) {
        $line = trim($line);

        if (preg_match('/^[1-9][0-9]*$/', $line)) {
            $approvedSids[] = (int) $line;
        }
    }

    return array_values(array_unique($approvedSids));
}


/*
 * Process EVE JSON records one line at a time.
 *
 * This works with both:
 *   grep ... | janus_response.php
 * and:
 *   tail -F eve.json | janus_response.php
 */
while (($line = fgets(STDIN)) !== false) {
    $event = json_decode($line, true);

    if (!is_array($event)) {
        recordResult('REJECT: invalid JSON', true);
        continue;
    }

    /*
     * Ignore non-alert EVE records such as flows and statistics.
     */
    if (($event['event_type'] ?? null) !== 'alert') {
        continue;
    }

    /*
     * Only the validated Project Janus Suricata SID is trusted.
     */
    $observedSid = filter_var(
        $event['alert']['signature_id'] ?? null,
        FILTER_VALIDATE_INT
    );

    if ($observedSid === false) {
        recordResult('REJECT: invalid alert SID', true);
        continue;
    }

    $approvedSids = loadApprovedSids();

    if ($approvedSids === []) {
        recordResult(
            'REJECT: no approved response SIDs configured',
            true
        );
        continue;
    }

    if (!in_array($observedSid, $approvedSids, true)) {
        recordResult(
            'IGNORE: SID ' . $observedSid . ' is not approved',
            true
        );
       continue;
    }

    /*
     * Extract and validate the source IPv4 address.
     */
    $sourceIp = $event['src_ip'] ?? null;

    if (
        !is_string($sourceIp) ||
        filter_var(
            $sourceIp,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_IPV4
        ) === false
    ) {
        recordResult(
            'REJECT: invalid source IPv4 address',
            true
        );
        continue;
    }

    /*
     * Never block protected infrastructure.
     */
    if (in_array($sourceIp, $protectedIps, true)) {
        recordResult(
            'REJECT: protected infrastructure address ' .
            $sourceIp,
            true
        );
        continue;
    }

    /* Limit response authority to eligible clients on the IT subnet. */
    if (!ipv4InCidr($sourceIp, ALLOWED_SOURCE_CIDR)) {
        recordResult(
            'REJECT: source is outside authorized subnet ' .
            $sourceIp,
            true
        );
        continue;
    }    

    /*
     * Add the validated source to the existing pfSense table.
     */
    $addCommand =
        '/sbin/pfctl -t ' . escapeshellarg(TABLE_NAME) .
        ' -T add ' . escapeshellarg($sourceIp) .
        ' 2>&1';

    $addOutput = [];
    $addExitCode = 1;

    exec($addCommand, $addOutput, $addExitCode);

    if ($addExitCode !== 0) {
        recordResult(
            'FAILED: could not update ' . TABLE_NAME .
            ' SRC=' . $sourceIp .
            ' PFCTL="' . implode(' ', $addOutput) . '"',
            true
        );
        continue;
    }
 
    recordResult(
        'BLOCKED' .
        ' SID=' . $observedSid .
        ' SRC=' . $sourceIp .
        ' TABLE=' . TABLE_NAME
    );
}
