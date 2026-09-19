# Defensive tooling review

Independent review covered the application, pipeline, evaluation, client boundaries and Windows resource ownership. Findings were fixed and regression checks added where they affect evidence correctness or scope.

| Boundary | Review outcome and verification |
| --- | --- |
| Authentication/policy | Server cookie identity, parameterized SQLite and resource checks; default hardened mode; [.NET tests](../app/IisPurpleLab.Tests/ApplicationTests.cs). |
| Report interpretation | Managed CSV or fixed executable/ArgumentList in hardened mode; mocked launch tests. Actual native interpretation remains pending. |
| Application secrets | Passwords/cookies excluded from events, bounded untrusted client ID separate from trusted request ID; cookie keys persist under owned state. |
| Client target | Literal loopback/port only, proxies disabled and redirects refused; [harness tests](../scenarios/test_harness.py). |
| Controlled receiver | Loopback-only, 4 KiB bound, accepted socket timeout and exact Content-Length; hash/content receipts. Native sender outcome remains pending. |
| Log parsing | Bounded files/records/events, named XML fields, entity/DOCTYPE rejection, duplicate-key rejection, explicit UTC, dynamic W3C fields and non-destructive repeated-request handling. |
| SQL | Only repository-owned Sigma creates SQL text; all event values use parameters and fixed schema/table identifiers. No log command is executed. |
| Paths/output | Relative input paths, symlink/reparse checks, output/input separation and bounded bundle destinations; escaping links rejected. No archive extraction is used. |
| HTML/Markdown | Event values escaped; normalized evidence IDs validated; material links checked; no fetched external assets. Original private evidence must still be reviewed before sharing. |
| Correlation | Successful launch, unique host/parent/child/time/start identities; GUID descendants; no scenario/mode/ground-truth shortcuts. Missing and ambiguous records remain visible. |
| Evaluation | Labels loaded after detection; source removal before parsing; affected successful resources distinguished from observed/denied resources; missing required fields exposed as unavailable. |
| Windows mutation | Fixed owned root/site/pool, identity/binding/consumer checks, no pre-existing Sysmon takeover, dry-run containment and recoverable retirement. Native integration remains untested. |
| Windows collection | Time/chain/site-scoped structured originals; bounded app-owned logs; no credentials/database collection; original evidence preserved with hashes. |

Residual limits: no comprehensive independent penetration test of the tooling, no proof of host truthfulness, no production authentication/hardening audit, and no native VM integration run. This review is evidence of inspected boundaries and executed regressions, not a general security certification.

## Publication recheck

The second independent review added regressions for host-scoped incident matching, duplicate-event ground-truth scoring, case-specific correlation evidence, detection-time rule hash verification, and duplicate XML timestamp rejection. IIS now uses the same 4 KiB request-body limit as Kestrel. Capture validation rejects both missing evidence files and absent hash inventories, even when a source is declared available.

The final suites pass 63 Python tests plus 7 subtests and 22 .NET tests, with 14 actual portable HTTP checks. Native PowerShell static checks include the two new negative capture gates. Actual Chromium checks confirm desktop/mobile/dark-mode layout, source filtering and evidence expansion without JavaScript errors. These checks do not execute native payloads or validate native IIS telemetry.
