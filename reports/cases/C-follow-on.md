# Case C: reconstruct discovery, staging and a network lead

**The idea:** After a suspicious report launch, the fictional company needs to establish what the process actually did and distinguish a network lead from evidence of transferred content.

**What it does:** This case follows a ProcessGuid chain in [handcrafted fixture evidence](../generated/demo/source-manifest.json), identifies represented discovery, a file write and a connection, and states which conclusions are unsupported. The separate [native C harness](../../scenarios/run.py) will use the B request primitive to stage harmless text and send it to a loopback receiver; that Windows run is pending.

**How it helps the company:** An analyst could preserve the specific process chain and staged artefact, prioritise the right application pool, and avoid overstating real customer-data loss. Benefits such as faster triage or prevented loss are unmeasured.

**The outcome:** Executed fixture analysis produced IPL-003/004/005 leads and an IPL-006 correlated incident for the records below. It did **not** establish actual Windows execution, a file read or transferred bytes. No receiver receipt or native artefact hash is bundled for this fixture.

**Comparison with another method:** Windows-only can identify represented ancestry and consequences but cannot recover the application actor/request context. Combined sources support a represented high-confidence launch link. IIS-only supplies request outcome. The [controlled source comparison](../generated/evaluation/evaluation.md) uses identical source files and excludes unavailable sources before enrichment.

**Experience gained:** The [correlation logic](../../analysis/iis_purple/correlate.py), [collector](../../lab/windows/Collect-Evidence.ps1), [receiver harness](../../scenarios/run.py) and bounded conclusions support practising evidence preservation and scope assessment. This is AI-assisted lab work; native collection and response operation remain to be exercised personally.

## Timeline and scope

Severity is **high for the combined represented execution-boundary incident**, while discovery, file-write and connection alerts are **medium hunting leads**. They are components of one scenario, not three extra attacks.

| UTC on 21 August 2026 | Observation within the fixture | Evidence |
| --- | --- | --- |
| 10:02:03.000 | `web-67.lab` worker PID 4565 begins, GUID `{947b812e-b152-47c1-11d8-53ebe3a6c1d3}` | [Worker](../generated/demo/report.html#e-44c6350abc3a5c895571f05d) |
| 10:02:10.000 | `user-355` / `tenant-28` has an accepted report request containing shell-control syntax; request `880f9d36-26da-a95b-2566-8eed8ec92668`, job `6f2d499f-8aff-9ad1-41ef-9fd735ca8916` | [Application request](../generated/demo/report.html#e-73632973018b03632f84775d) |
| 10:02:10.020 | Worker launches `cmd.exe` PID 6865, GUID `{f2477408-ba9e-aea5-27fb-643d648eecb6}` | [Process creation](../generated/demo/report.html#e-db60ba62c67ba3bc399bbafb) |
| 10:02:10.080 | Application records that child, the matching worker PID/start and launch interval | [Launch record](../generated/demo/report.html#e-9e25cbbc5c09f242ea2fce79) |
| 10:02:10.300 | `whoami.exe` PID 6869, GUID `{a04779b9-b299-f219-a53f-28dbb0a0bf09}`, descends from that shell GUID | [Discovery process](../generated/demo/report.html#e-7cc941d7f2a9908b0ebabd3f) |
| 10:02:10.400 | Shell GUID is associated with creation/overwrite of `C:\IISPurpleLab\data\work\6f2d499f-8aff-9ad1-41ef-9fd735ca8916\stage.txt` | [File creation](../generated/demo/report.html#e-0f648897a75aefa4f1b25f32) |
| 10:02:10.500 | Same GUID has a TCP connection to `127.0.0.1:5091`, outside the configured legitimate report destination policy | [Connection](../generated/demo/report.html#e-686c868170dd18e201c7e252) |

Tree **represented by the fixture**:

```text
web-67.lab: w3wp.exe  PID 4565  GUID 947b812e-...
└── cmd.exe          PID 6865  GUID f2477408-...
    └── whoami.exe   PID 6869  GUID a04779b9-...
```

Facts within these records are the launch fields, GUID ancestry, path creation and connection tuple. The [computed correlation](../generated/demo/correlation.json) links the launch with high confidence using unique host/PID/time plus observed worker GUID/start, then propagates via ParentProcessGuid. Intent remains an inference. A legitimate diagnostic report or maintenance action is an alternative until evaluated against the application action, command content and reviewed destination policy.

Scope is the named synthetic actor/tenant, host, job, process chain and file path. The application fixture does not identify an affected ticket, so no ticket is inferred. Event 11 cannot establish a source-file read. Event 3 cannot establish content, destination ownership, successful application receipt or exfiltration. In particular, this loopback connection is not evidence of internet transfer.

The fixture's compact follow-on model assigns the write/connection to `cmd.exe` and uses varied lab port 5091. It is **not a captured trace of the native C payload**, which launches Windows PowerShell and uses the fixed receiver at `127.0.0.1:8099`. The actual sender process, ancestry and connection delivery must come from native capture, never from copying the fixture tree into a report.

## Native reproduction and response plan

The [native runbook](../../docs/windows-runbook.md) installs the low-privilege pool and telemetry, then captures the identical B/C requests in both modes. C is requested through the vulnerable report interpolation boundary; the harness starts only the local receiver separately. The sender's discovery/write/transfer are intended exploit-derived activity and remain unproven until executed. No pre-existing administrator shell is presented as an acquired capability.

The harness stages only the fixed synthetic string within the lab working directory. Its receiver limits payload size, records the received SHA-256 and saves actual bytes. The collector checks receipt/file hash agreement and preserves receiver bytes. A future native transfer conclusion needs that receiver observation, staged-file hash and process/request evidence together; it should still say **synthetic local transfer**, not customer exfiltration. A prevented or missing transfer must remain a failure/unknown with its original evidence.

Preserve process GUIDs, original XML, application launch records, the staged artefact and its hash, receiver bytes/receipts, relevant configuration and source availability before containment. Use [Contain-Lab.ps1](../../lab/windows/Contain-Lab.ps1) in dry-run mode, then stop only the verified pool if needed. Keep the VM and evidence available for scope review; do not isolate the user's workstation or clear endpoint logs. [Restore-Lab.ps1](../../lab/windows/Restore-Lab.ps1) and a successful benign export establish the intended recovery check.

The [report-boundary remediation](../vulnerabilities/report-execution.md) removes normal shell execution and validates titles. Its mocked-launch tests passed, and portable managed export succeeded. The hardened C native retest must return denial, preserve application visibility, show no dummy receipt, retain healthy telemetry prerequisites, and keep benign/concurrent exports working. Native Windows execution, script-block fragments, receiver proof and that remediation retest remain pending. Complete the [recoverable cleanup](../../lab/windows/Remove-Lab.ps1) only after evidence preservation.
