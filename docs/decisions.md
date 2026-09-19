# Decision log

| Decision | Reason and limit |
| --- | --- |
| Use the expanded brief | It contains the full original plus explicit implementation/audit/handover requirements. |
| One loopback-only disposable VM, IIS in-process | Fits the request-to-worker research question; topology must be observed on Windows. |
| .NET 10, Python, SQLite, pySigma SQLite | Supported application platform and a real executable event-rule backend; exact working versions will be recorded after restore/test. |
| Server-generated request IDs, GUID-based process trees | A client header or timestamp alone cannot prove attribution. |
| Handcrafted fixtures are labelled throughout | They test logic and formats; they do not establish Windows behaviour. |
| Source removal happens before parsing | Reduced views cannot inherit information from excluded sources. |
| Shared CI mocks process launch | Real host command reproductions and machine changes belong on the disposable lab VM. |
| No installation on the WSL host's Windows workstation | PowerShell availability does not identify a disposable machine or authorise repurposing the workstation. Read-only checks and syntax validation are feasible. |

Research hypothesis: application identity/resource context supports policy violation detection without endpoint process activity; instrumented process launches plus Windows process GUIDs can support bounded attribution for execution cases. Controlled fixture evaluation tests implementation behaviour. Native workload capture is required to evaluate the hypothesis against real IIS/Windows activity.

Validated implementation choices: SDK10.0.401/runtime10.0.12 and locked NuGet restore; Python3.14.4 with pySigma1.5.0/backend1.2.4 and SQLite3.46.1. A separate source copy/new venv/rebuild verified the reviewer sequence. Native Windows PowerShell5.1 syntax/static checks were feasible on the workstation; native lab installation/capture was not.

Review refinements: field prerequisites are explicit rather than treating source presence as completeness; observed/denied resources are not labelled affected; identical second-resolution W3C rows remain separate requests; high launch links require a successful start and unique identities; HTTP redirects are refused, receiver reads are bounded, cookie keys stay under owned state, and IIS anonymous authentication explicitly uses the dedicated pool identity.

Publication decision (2026-09-19): after the initial local handover, the owner requested a further polish/verification pass and explicitly authorized the public repository `quocbao210/iis-purple-lab`. That later instruction supersedes the original local-only publication restriction. Only project source, handcrafted fixtures, reviewed reports and a fixture-report screenshot are included; native logs, workstation preflight, credentials and raw development test reports remain excluded. LF checkout rules keep evidence hashes stable across operating systems. Hosted CI results will be recorded separately from local checks and native Windows integration.
