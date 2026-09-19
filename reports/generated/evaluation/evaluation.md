# Telemetry comparison

Origin: **handcrafted-fixture**; split: heldout. NOT a native Windows benchmark.

Unit: one scenario run. 7 malicious and 12 benign runs. Components and combined incidents count once for case coverage.

| View | TP | FP cases | FN | TN | Precision | Recall | False alerts | Source bytes | Replay seconds |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| iis-only | 0 | 0 | 7 | 12 | undefined | 0.000 | 0 | 1513 | 0.108063 |
| iis-application | 2 | 0 | 5 | 12 | 1.000 | 0.286 | 0 | 11696 | 0.129694 |
| windows-only | 4 | 1 | 3 | 11 | 0.800 | 0.571 | 1 | 22432 | 0.101356 |
| combined | 6 | 1 | 1 | 11 | 0.857 | 0.857 | 1 | 34128 | 0.183466 |

The same files are filtered before parsing for each view. IIS-only establishes request metadata, not tenant policy or host consequences. Application context reveals policy decisions and resource identity. Windows-only reveals process activity but cannot recover application actor/resource context. Combined attribution requires independently matching launch identities.

## Detection improvement

Same report-run cases; baseline alerts on every worker child, tuned rule requires an interpreter. Benign maintenance that actually uses a shell still alerts.

| Method | TP | FP | FN | TN |
| --- | ---: | ---: | ---: | ---: |
| basic-any-worker-child | 4 | 6 | 0 | 0 |
| tuned-interpreter-child | 4 | 1 | 0 | 5 |

See [machine-readable metrics](evaluation.json) for per-rule prerequisite availability, conditional performance, case verdicts, links and source counts. Offline processing excludes export and rendering; live detection latency is not measured.

Blind spots: the unlogged policy case is missed even in the combined view; uninstrumented execution stays unattributed. Synthetic hosts, paths, users, identifiers and order differ between development and held-out splits, but both use one handcrafted behavioural model. These are held-out fixture checks, not independent external validation.
