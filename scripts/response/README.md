# pfSense Response Controller

`janus_response.php` consumes Suricata EVE JSON records from standard input. It
accepts only SIDs published by the approved deployment workflow, validates the
observed source IPv4 address, enforces the authorized IT subnet and protected
infrastructure list, and adds the source to the preconfigured
`JANUS_BLOCKLIST` table.

Example operator-started watcher on pfSense:

```sh
tail -n 0 -F /path/to/eve.json | php /usr/local/etc/janus/janus_response.php
```

The watcher is not installed as a persistent service. Test block and unblock
behavior only in the authorized lab and retain console, response-log, and
firewall-log evidence.

