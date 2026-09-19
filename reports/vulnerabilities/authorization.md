# IPL-VULN-001: cross-tenant object authorization

This is an intentionally introduced lab flaw, classified CWE-639 / OWASP API1:2023. It is not a new CVE or a paid bounty finding. Native IIS execution is pending; the route/policy behavior was tested through actual in-process ASP.NET HTTP tests.

Root cause: the deliberate vulnerable configuration authorizes a resource read using `settings.Vulnerable || AccessPolicy.CanRead(...)`. Knowing an object identifier then bypasses the authenticated tenant's policy. Merely hiding IDs would not repair the defect.

Prerequisites: authenticated synthetic alice, target south ticket 2001, the explicit local vulnerable configuration, and only a loopback lab deployment. Demonstrated application impact: the same GET returns 200 in vulnerable mode and 403 in hardened mode without a process launch. The private attachment and export-download routes use the same underlying ticket policy. No claim is made about real customer data.

Reproduce and retest: run `dotnet test app/IisPurpleLab.Tests/IisPurpleLab.Tests.csproj` and `python scenarios/portable_check.py`. The latter starts local Kestrel instances and tests actual cookies/requests in both configurations; it is not native IIS evidence. For IIS, use the [native capture runbook](../../docs/windows-runbook.md) with both modes and preserve scenario A output.

Effective remediation difference (the implementation keeps both configurations for comparison):

```diff
- allowed = settings.Vulnerable || AccessPolicy.CanRead(actor, ticket);
+ allowed = AccessPolicy.CanRead(actor, ticket);
```

Keep hardened mode enabled. [AccessPolicy](../../app/IisPurpleLab/Domain.cs) centrally allows same tenant, explicit tenant sharing or application admin. Apply it on read, attachment, export generation and export download; do not infer permission from an export identifier.

Retest evidence: [SameBolaRequestIsAllowedOnlyInDeliberateVulnerableMode and policy controls](../../app/IisPurpleLab.Tests/ApplicationTests.cs), [portable HTTP outcomes](../validation/portable-http.json), and the separate [fixture-based investigation](../cases/A-cross-tenant.md). A blocked request still produces application security events. Legitimate same-tenant/shared/admin reads continue to return 200. This finding does not require endpoint process alerts.

Recovery: return to hardened mode, preserve original access logs before cleanup, review successful cross-tenant reads and affected ticket/export identifiers, and invalidate exposed test sessions if relevant. The lab has no production notification or customer-remediation claim. A CVSS number is omitted because exposure and data sensitivity are intentionally constrained lab assumptions.
