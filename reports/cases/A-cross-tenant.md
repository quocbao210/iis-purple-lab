# Case A: private ticket access across tenants

**The idea:** The fictional support portal must keep one customer's private tickets separate from another customer's records. The question is whether application identity/resource evidence can reveal a violation without requiring a new Windows process.

**What it does:** The [portable HTTP reproduction](../validation/portable-http.json) submits the same authenticated ticket/attachment reads in vulnerable and hardened modes. The investigation below replays separately labelled [handcrafted evidence](../generated/demo/source-manifest.json); it does not describe a native Windows incident.

**How it helps the company:** Actor, tenant and resource context could identify which synthetic records need review and whether sharing actually permitted the access. This supports scope assessment; no customer loss or response-time saving has been measured.

**The outcome:** Real portable HTTP checks returned 200 for private cross-tenant reads in vulnerable mode and 403 after hardening; same-tenant, explicitly shared and application-admin controls continued to return 200. Fixture replay identified the [ticket-policy violation](../generated/demo/report.html#e-c81d582516c96afacff0e20e) and [attachment-policy violation](../generated/demo/report.html#e-1a99c365bc06037f51882aef). Native IIS retesting remains pending.

**Comparison with another method:** IIS-only shows request metadata and 200 status but lacks the authenticated tenant and resource policy. Windows process rules do not establish this violation. IIS-plus-application and combined views detect these two represented violations; an unlogged-policy case remains missed even with combined sources. See the [same-workload comparison](../generated/evaluation/evaluation.md).

**Experience gained:** The source, [policy tests](../../app/IisPurpleLab.Tests/ApplicationTests.cs) and [vulnerability report](../vulnerabilities/authorization.md) support explaining broken object authorization, legitimate exceptions, detection prerequisites and a repeatable fix. They are AI-assisted lab artefacts, not a paid bounty or production incident.

## Analyst assessment and evidence

Severity is **high for a demonstrated confidentiality-policy violation within the synthetic scenario**, not a claim about production business impact. Two distinct fixture requests support that assessment:

| UTC on 21 August 2026 | Record and fact in the fixture | Affected scope |
| --- | --- | --- |
| 10:02:30.000 | [Application record 13](../generated/demo/report.html#e-1a99c365bc06037f51882aef): `attachment_access`, allowed, user role, no sharing, policy false | `user-594`, `tenant-39` accessed the attachment associated with `ticket-6154`, owned by `tenant-72`, on `web-73.lab` |
| 10:02:30.000 | [IIS row 10](../generated/demo/report.html#e-f40b1c5df71e6a8a2742e89e): 200 response in the represented resource context | Supporting request metadata; not an authenticated identity source |
| 10:02:50.000 | [Application record 14](../generated/demo/report.html#e-c81d582516c96afacff0e20e): `ticket_access`, allowed, user role, no sharing, policy false | `user-957`, `tenant-29` accessed `ticket-2200`, owned by `tenant-63`, on `web-43.lab` |
| 10:02:50.000 | [IIS row 11](../generated/demo/report.html#e-1dd611d56ac82158b161a50b): 200 response | Request outcome only |

The application record's authenticated identity, resource ownership, role and sharing list are sufficient for the policy decision. The detector independently evaluates those fields; the evaluation label is not detector input. The simultaneous IIS rows are contextual corroboration, not a shared request-ID join. No Windows process tree is required or claimed for this family. An absence of process events would not, by itself, prove absence of host activity.

Confidence is high **within the represented application records**, contingent on truthful server-side authentication/logging. Alternatives to exclude in a real capture include an application-admin role, an explicit share, ownership changes during the request, stale policy context, or tampered logs. The linked records say user role and empty sharing; the real [access policy](../../app/IisPurpleLab/Domain.cs) and positive controls define the intended exceptions. The records establish these synthetic resources, not all customers or all historical reads.

The separate [unlogged-policy IIS row](../generated/demo/report.html#e-d911910d33e8cd6c7bc2996a) supports only a successful request. Its evaluation label cannot supply missing actor/tenant fields to an analyst or detector. That deliberate blind spot remains a miss.

## Reproduction, response and retest

Preconditions are a loopback deployment, a real synthetic-account session, known target object identifier and deliberate vulnerable configuration. Run `python scenarios/portable_check.py` for the actual portable application checks, or follow the [Windows runbook](../../docs/windows-runbook.md) for IIS. Run `iis-purple analyze --dataset datasets/fixtures/heldout --output artifacts/case-review` to reproduce this fixture investigation.

Preserve the application events, affected record/attachment identifiers, policy/sharing state, corresponding IIS rows and collection hashes before containment. Review successful cross-tenant reads first; do not isolate the whole workstation merely because a ticket access policy failed. If containment is needed during the VM exercise, collect evidence and dry-run [Contain-Lab.ps1](../../lab/windows/Contain-Lab.ps1), which targets only the verified lab pool. [Restore-Lab.ps1](../../lab/windows/Restore-Lab.ps1) restores its prior state.

Recovery uses hardened mode and the same central ticket policy for tickets, attachments, exports and export downloads. [The remediation report](../vulnerabilities/authorization.md) links the implementation difference. [Executed HTTP results](../validation/portable-http.json) show identical private reads denied and legitimate controls retained; [application tests](../../app/IisPurpleLab.Tests/ApplicationTests.cs) additionally cover list/export authorization. Denials remain visible in application telemetry. Native IIS capture, its original endpoint evidence and cleanup verification remain pending.

Retire only verified project resources with the [recoverable cleanup command](../../lab/windows/Remove-Lab.ps1) after preservation. The provided evidence is either a real portable application test or an explicitly handcrafted investigation fixture; neither is a Windows breach capture.
