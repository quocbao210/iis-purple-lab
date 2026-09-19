# Case B: a report request crosses into a shell

**The idea:** A customer-support report title should remain data. This case studies the request-to-process evidence needed when an unsafe report implementation gives shell syntax unintended meaning.

**What it does:** The [application implementation](../../app/IisPurpleLab/Reports.cs) deliberately interpolates titles into `cmd.exe` only in acknowledged vulnerable mode. Hardened mode validates the title and writes a managed report; a legitimate helper uses a fixed executable and separate arguments. This investigation uses [handcrafted fixture records](../generated/demo/source-manifest.json), with native execution still pending.

**How it helps the company:** A supported request/child-process link could justify containing the affected pool and help distinguish expected helpers from unexpected shell execution. The link must survive worker recycling and PID reuse; mere timing proximity does not justify attributing one customer's request.

**The outcome:** The fixture [application launch](../generated/demo/report.html#e-5a071b4a17a06082bee6d42a), [worker record](../generated/demo/report.html#e-edfbccc54f67737793b39083) and [child record](../generated/demo/report.html#e-a9dda72ad80a573c2d9eb5db) produced a high-confidence represented link and IPL-006 incident. Actual application tests verified the unsafe construction and hardened rejection with a mocked launcher; they did not execute the Windows command.

**Comparison with another method:** On the same fixture report runs, an any-worker-child baseline had 4 TP/6 FP; the interpreter-focused rule had 4 TP/1 FP, with no added misses among these runs. The remaining benign maintenance shell still alerts. This measured [tuning comparison](../generated/evaluation/evaluation.md) is not an EDR comparison or native benchmark.

**Experience gained:** The [launch-boundary tests](../../app/IisPurpleLab.Tests/ApplicationTests.cs), [correlation implementation](../../analysis/iis_purple/correlate.py) and [remediation report](../vulnerabilities/report-execution.md) support explaining command injection, process identity and confidence. Native IIS administration and execution still require hands-on VM validation.

## Analyst assessment and timeline

The correlated represented incident has **high severity** because accepted shell-control input and independently represented endpoint execution agree. An interpreter child alone is a **medium-severity hunting lead**: legitimate maintenance remains an alternative.

| UTC on 21 August 2026 | Fixture observation | Evidence |
| --- | --- | --- |
| 10:05:23.000 | `web-76.lab` worker PID 3286 begins, GUID `{59802d7d-e425-a7f2-c761-62580654fefa}` | [Worker](../generated/demo/report.html#e-edfbccc54f67737793b39083) |
| 10:05:30.000 | `user-909` from `tenant-35` submits an accepted report title containing `& whoami`; request `0a89b575-4d5e-79c0-3859-ebe20e2e57bc`, job `3ea79315-649a-6219-8c0e-b989a8dcd17c` | [Application request](../generated/demo/report.html#e-d80ff433f8159581ada2f1a8) |
| 10:05:30.000 | IIS represents `POST /api/reports`, 200 | [IIS row](../generated/demo/report.html#e-f465f851ec292994aeb82ed0) |
| 10:05:30.020 | `cmd.exe` PID 7795, GUID `{3e0455f5-669a-2e0d-e00f-fbbd861af995}`, has the worker's ParentProcessGuid | [Sysmon-shaped child](../generated/demo/report.html#e-a9dda72ad80a573c2d9eb5db) |
| 10:05:30.080 | App records child PID 7795 and worker PID/start time; launch interval is 10:05:30.000–10:05:30.100 | [Launch boundary](../generated/demo/report.html#e-5a071b4a17a06082bee6d42a) |

The tree **represented by the fixture**, not observed on the development Windows host, is:

```text
web-76.lab: w3wp.exe  PID 3286  GUID 59802d7d-...
└── cmd.exe          PID 7795  GUID 3e0455f5-...
```

The unique host, bounded launch interval, matching parent/child PIDs, observed parent GUID and matching worker start support the high-confidence link in [correlation.json](../generated/demo/correlation.json). The request ID comes from application instrumentation, not Sysmon or a client header. The IIS row is contextual; it does not carry that trusted request ID. No later `whoami` process or output exists in this particular represented case, so its command text alone does not establish that `whoami` completed.

Scope is this represented host, worker, child, actor and report job. The fixture request lacks ticket identity; the report must not invent an affected ticket or confidential file read. There is no evidence here of administrator/SYSTEM execution, persistence, lateral movement, an uploaded web shell or real data theft.

The [uninstrumented shell fixture](../generated/demo/report.html#e-c74ce06592427b10b577b77f) remains separately observable and unattributed. A nearby IIS request or the evaluation manifest's case label cannot manufacture a link. Missing launch/parent telemetry and concurrent lookalike launches are explicit alternatives to precise attribution.

## Reproduction, containment and remediation

Native prerequisites are the disposable VM, actual non-admin pool identity, explicit vulnerable configuration and an authenticated synthetic report request. The [bounded B harness](../../scenarios/run.py) uses the same harmless `monthly & whoami & rem ` payload for both modes and checks the returned identity in vulnerable mode. Native execution is reserved for the VM; endpoint prevention stays enabled and is recorded if it blocks the action. Reproduce this review with `iis-purple analyze --dataset datasets/fixtures/heldout --output artifacts/case-review`.

Preserve original application/IIS/XML events, the worker and child GUIDs, code/configuration hashes and precise collection window before stopping the verified pool. [Contain-Lab.ps1](../../lab/windows/Contain-Lab.ps1) defaults to dry run; [Restore-Lab.ps1](../../lab/windows/Restore-Lab.ps1) restores the previous pool state. Do not kill every `cmd.exe` or IIS worker on the host.

[The implemented fix](../vulnerabilities/report-execution.md) removes shell interpretation from normal hardened reports, applies an allowlist, and uses a fixed safe helper with `ArgumentList` when needed. Actual in-process application tests verify denial without invoking the launcher, managed exports and helper arguments. [Portable HTTP results](../validation/portable-http.json) also verify a real successful managed export. Windows shell outcome, actual process GUID attribution, hardened B denial with healthy native telemetry and benign helper regression results remain the [pending native gates](../../docs/windows-runbook.md).

After preservation, return to hardened mode, repeat legitimate exports and retire only owned resources using [Remove-Lab.ps1](../../lab/windows/Remove-Lab.ps1), which preserves files in a retirement directory. No unexecuted native step is counted as a successful remediation or cleanup test.
