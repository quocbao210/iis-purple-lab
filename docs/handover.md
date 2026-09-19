# Review handover

Release label: **IIS Purple Lab 0.1 portable preview**. Published publicly at [quocbao210/iis-purple-lab](https://github.com/quocbao210/iis-purple-lab) with the owner's explicit authorization. This publishes project source and reviewed fixture reports, not a hosted application or native endpoint logs. An anonymous public clone passed replay, all 63 Python tests plus 7 subtests, and source/evidence hash checks.

Start with [README](../README.md), [the status audit](../IMPLEMENTATION_STATUS.md), [fresh-checkout instructions](runbook.md), [sample report](../reports/generated/demo/report.html) and [comparison](../reports/generated/evaluation/evaluation.md). The [validation summary](../reports/validation/summary.json) distinguishes local Python/.NET/PowerShell checks, actual Kestrel HTTP, fixture replay, and pending native Windows gates.

Implemented: synthetic authenticated support/reporting API, vulnerable/hardened policy and report boundaries, six executable detections, strict normalization, confidence-aware GUID correlation, four-view evaluation, evidence-linked HTML/Markdown bundles, bounded workload harness, scoped Windows setup/preflight/collector/containment/restore/retirement, three fixture cases, and two vulnerability/fix reports. The lab primitives and collection scripts remain unproven on native IIS.

Measured fixture results: 19 held-out runs (7 malicious labels, 12 benign); combined 6 TP, 1 FP, 1 FN, 11 TN. IIS-only 0 TP, application+IIS 2 TP, Windows-only 4 TP. On the 10 report-run comparison cases, the tuned predicate retains 4 TP and reduces FP from 6 to 1. The remaining maintenance false positive and unlogged-policy miss are visible, not suppressed from denominators. No live latency, analyst-time, collection CPU or economic benefit was measured.

Native blocker: no disposable configured/elevated IIS/.NET10/Sysmon VM was available. Windows PowerShell syntax and static path/selector checks ran on the development host without configuration changes. Follow [the native runbook](windows-runbook.md) for actual setup/capture/correlation/receiver-hash/remediation/cleanup gates before naming a validated Windows release. [All five hosted CI jobs passed](https://github.com/quocbao210/iis-purple-lab/actions/runs/35430608975); the tested commit and public-clone checks are recorded in [publication verification](../reports/validation/publication.json).

GitHub description: “Evidence-linked IIS purple-team lab: tenant authorization, request-to-process attribution, Sigma/SQLite detections and remediation checks. Portable preview.”

Topics: `purple-team`, `iis`, `windows-security`, `detection-engineering`, `sigma`, `incident-response`, `aspnet-core`, `security-lab`, `evidence-analysis`.

Two truthful CV bullets, **only after personally reviewing and reproducing the linked work**:

- Developed and validated an AI-assisted ASP.NET Core/Python security-lab preview linking tenant authorization tests, six executable detections, and evidence-based investigation reports; reproduced an authorization fix through actual local HTTP checks.
- Evaluated four telemetry views on 19 explicitly handcrafted scenario runs, documenting 6/7 combined attack detections, one benign false-positive run, attribution limits and outstanding native Windows validation.

Neither bullet claims production deployment, authentic native capture, paid bounty success, or unaided authorship. The [five-minute demo](demo.md) and [ownership checklist](learning-checklist.md) support a candid presentation.

Interview prompts:

1. Why can a cross-tenant incident have no suspicious endpoint process?
2. What proves that the actor's tenant came from authentication rather than a client header?
3. Why do an IIS request and Sysmon event not automatically share a request ID?
4. Which facts make a launch link high confidence, and how do recycling/concurrency undermine it?
5. What can a file-create event or network event prove, and what additional evidence is needed for transfer?
6. How did the rule change affect both false positives and misses on the same workload?
7. Why is source removal performed before normalization, and why are labels loaded after detection?
8. What did the real .NET/HTTP tests establish, and what remains untested on Windows?
9. Why does a hash protect later integrity without proving the host told the truth?
10. What would you change before a production deployment, and which result would you revalidate first?
