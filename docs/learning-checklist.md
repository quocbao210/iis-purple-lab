# Hands-on ownership checklist

The repository was built with AI assistance. Completing these exercises is the basis for personal learning claims; this document does not assert that Quoc Bao has already performed them.

- [ ] Explain IPL-001 from a raw application record through the recomputed policy. Show why the same record's `policy_allowed` flag alone is not trusted as the detector decision.
- [ ] Ask a reviewer to choose an unfamiliar case without revealing its label. Decide escalate/close/needs-evidence, cite records, state one benign explanation, then compare with ground truth. Record the rationale and any error.
- [ ] Change a rule on the development split, run its positive/near-miss tests, and record the TP/FP/FN tradeoff. Create a new held-out set before making a fresh generalisation claim.
- [ ] Run the actual portable HTTP remediation check and explain why cross-tenant 403 and legitimate 200 are both required. On the disposable VM later, repeat B/C and distinguish successful prevention from unknown missing telemetry.
- [ ] Demonstrate a correlation failure by removing parent identity or adding a second viable launch. Explain why the confidence becomes low/ambiguous rather than forcing an exact link.
- [ ] Explain one parser boundary (W3C field order, duplicate identities, UTC versus collection time, XML entities or output escaping) using its test.
- [ ] Locate a native gate still pending and describe the exact evidence needed to pass it. State which code/analysis was AI-assisted and which experiments you personally ran.

Keep your own dated notes and links to changed code/output. Lab practice is not production incident response, a newly discovered vulnerability, or a paid bounty result.

| Skill | Work to explain or reproduce | Evidence boundary |
| --- | --- | --- |
| Security research | [Four-view hypothesis and held-out experiment](../reports/generated/evaluation/evaluation.md) | Authored fixtures, not external validation. |
| Web penetration testing | [Authorization finding and retest](../reports/vulnerabilities/authorization.md) | Deliberate synthetic lab flaw, no bounty/new CVE. |
| Windows penetration testing | [IIS token/topology/permissions and native gates](windows-runbook.md) | Native hands-on demonstration still pending. |
| SOC analysis | [Benign alternatives and incident decisions](../reports/cases/B-execution.md) | Document a personal unfamiliar-case triage before claiming practice. |
| Detection engineering | [Executable rules and near misses](../detections/README.md) | Rerun changed rule against separate data. |
| Incident response | [Evidence collector and recovery decisions](../reports/cases/C-follow-on.md) | Native containment/rollback still pending. |
| Purple-team workflow | [Attack/fix/visibility cycle](demo.md) | Personal ownership requires reproducing the linked exercises. |
