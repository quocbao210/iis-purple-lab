# Detection catalogue

Six detections execute through [production Python](../analysis/iis_purple/detection.py). Two event predicates are valid Sigma, converted by **pySigma 1.5.0 / SQLite backend 1.2.4** and executed against an in-memory SQLite table. They do not execute directly in Wazuh. The remaining policy, GUID-chain and multi-source conditions are explicit Python logic. [Tests](../tests/test_detection.py) execute positive and near-miss cases; [evaluation](../reports/generated/evaluation/evaluation.md) scores the same held-out workload.

| ID | Hypothesis and executable logic | Required fields | Severity / classification |
| --- | --- | --- | --- |
| IPL-001 | A successful read violates tenant, sharing and admin policy. Recompute the policy from server-side context. | application action/outcome, actor, actor_tenant, resource_tenant, resource_id, role, shared_with | High: observed policy violation; CWE-639 / OWASP API1. |
| IPL-002 | A direct IIS child is an interpreter. [Sigma](sigma/web_worker_interpreter.yml) selects image and parent suffixes. | Sysmon1 Image, ParentImage | Medium hunting lead: shell ancestry alone is not intent; T1059.003 only for the command shell demonstration. |
| IPL-003 | Identity/host discovery belongs to an observed worker chain. [Sigma](sigma/discovery_process.yml) selects candidates, then Python traverses host-scoped GUIDs. | Sysmon1 Image, host, time, ProcessGuid, ParentProcessGuid; observed parent chain | Medium hunting lead: possible discovery; whoami supports T1033, hostname supports T1082 only when actually observed. |
| IPL-004 | An interpreter in a worker chain creates a file under a configured application data root. | Sysmon1 ancestry; Sysmon11 ProcessGuid, TargetFilename, host, time; deployment policy | Medium hunting lead: unexpected writer, not proof of file read, theft or persistence. |
| IPL-005 | A worker descendant connects to an unapproved destination. | Sysmon1 ancestry; Sysmon3 ProcessGuid, DestinationIp/Port, host, time; destination policy | Medium hunting lead: observed network connection; does not independently prove exfiltration. |
| IPL-006 | Accepted shell-control syntax in report input and independent execution evidence share a strong launch attribution. | application report_title/outcome/request_id; launch host, parent/child PID, parent start, interval; Sysmon1 GUID identities | High correlated incident; grouped with components rather than another attack. |

All rule records contain stable ID, evidence IDs and rationale. Sigma UUIDs are stable source-rule identities; IPL IDs are the evaluation-facing detection identities. `availability.json` reports eligible/missing field stages, not a blanket claim that logging was healthy.

Triage and near misses:

- IPL-001: check the server-derived role, tenant and explicit sharing list; successful same-tenant, shared and admin reads are exclusions. A denied request is an attempted access, not a successful compromise. Missing auth context is a blind spot.
- IPL-002: examine the original command and job. The basic comparison alerts on every worker child; the tuned predicate excludes the compiled export helper but retains real interpreter-based maintenance. Do not suppress all maintenance accounts. This can miss in-process abuse and non-interpreter malicious helpers.
- IPL-003: preserve the parent GUID chain and assess whether the job normally discovers identity. A standalone administrator whoami outside the worker chain is excluded. Renamed binaries and built-in commands are blind spots.
- IPL-004: verify root boundary matching and parent chain. A sibling directory with a similar prefix is excluded; the ordinary compiled helper is excluded. Trusted-helper abuse and writes outside configured roots can be missed. Review [policy](policy.json) for the deployment.
- IPL-005: verify destination against the intended business workflow and inspect receiver evidence. A specifically approved IP/port is excluded. A loopback sink is unexpected for the normal export function but is not an internet transfer. Collection gaps and in-process networking complicate attribution.
- IPL-006: inspect the launch interval, parent start and ProcessGuids. A missing/ambiguous launch remains a hunting lead, not a high-confidence request link. An accepted ordinary title with a maintenance shell is a near miss. Shell syntax is indicative, not a comprehensive parser for arbitrary input.

False-positive workload: normal compiled export helpers, same/shared/admin policy reads, denied attempts, repeated legitimate reads, overlapping jobs and shell maintenance. The retained maintenance false alert is reported alongside missed attacks. No labels, scenario names, vulnerable flags, magic payload strings or fixture addresses enter detection decisions. Configuration provides ordinary application roots and approved destinations, with the same policy in all views.

References: [primary sources](../docs/sources.md), [policy](../docs/access-policy.md), [schema](../docs/data-model.md), [rule tests](../tests/test_detection.py). Native rules remain experimental until the Windows capture/retest gates pass.
