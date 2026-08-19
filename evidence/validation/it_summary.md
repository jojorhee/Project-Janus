# IT Detection Validation Summary

The executable Windows JSON rule correlated network-hosted PowerShell execution
with destructive PowerShell content on the same normalized host.

| Dataset class | Runs | Correlated detections | Result |
|---|---:|---:|---|
| Attack | 3 | 1 per run | Pass |
| Baseline | 3 | 0 per run | Pass |

The three attack inputs contained 200, 200, and 195 normalized records. Each
produced one correlation with a three-to-four-second component separation. The
three baseline inputs contained 480 records each and produced zero correlated
detections.

These results demonstrate behavior on the six preserved lab datasets only.

