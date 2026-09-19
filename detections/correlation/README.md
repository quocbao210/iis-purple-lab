# Explicit correlation logic

Executable request/process logic lives in [correlate.py](../../analysis/iis_purple/correlate.py), with application-policy and incident grouping in [detection.py](../../analysis/iis_purple/detection.py). These are Python correlation, not Sigma correlation YAML.

A strong launch association needs host, child PID, parent PID, bounded launch time, a captured parent GUID and matching parent start, a successful launch record, and a unique candidate. Subsequent descendants use ParentProcessGuid. Two viable owners become ambiguous. Missing identity gives low confidence; independent processes remain unattributed. The two-second skew allowance is a documented lab bound, not clock synchronisation proof. Worker recycle/PID reuse must not borrow another process's context.

See [adversarial tests](../../tests/test_correlate.py). Source ablation happens before normalization, so excluded application request IDs cannot enrich the Windows-only view.
