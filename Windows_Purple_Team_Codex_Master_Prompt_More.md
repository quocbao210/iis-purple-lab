# IIS Purple Lab — Codex Master Prompt

**Execution instruction to Codex:** Read this entire file and implement the project in the current workspace. This Markdown file is the build brief. The deliverable is a working repository containing source code, configuration, tests, detections, reports, and documentation. Do not respond by rewriting this prompt or producing only Markdown documentation.

Complete all core requirements in sections 0–12 and the final handover in section 14. Section 13 is the clearly labelled future roadmap. Work continuously through implementation and validation, making reasonable routine decisions without repeatedly asking whether to continue. Follow applicable environment permissions and repository instructions, and preserve unrelated user work.

Maintain `IMPLEMENTATION_STATUS.md` with a row for every core requirement: requirement, implementation path, verification command, actual result, evidence path, and remaining blocker. Keep it current as work progresses. Environment-dependent Windows checks may be pending only when they truly cannot be executed; finish all other feasible work and supply the precise native Windows runbook.

Act as a senior Windows security researcher, web penetration tester, detection engineer, and incident responder. Build a complete, reviewable GitHub portfolio project called **IIS Purple Lab: Windows Web-to-Host Detection and Response**.

My name is Quoc Bao Huynh. My target roles include security research, bug bounty hunting, web and infrastructure penetration testing, SOC analysis, detection engineering, and incident response. I want one coherent project that connects these skills. This is a Windows-focused purple-team project with a reproducible research contribution.

The central question is:

**Which combinations of IIS, application, and Windows endpoint telemetry let an analyst distinguish legitimate application behaviour from exploitation, reconstruct the affected resources and processes, and verify remediation?**

Build working software and evidence, not just a plan, collection of tools, or documentation of intended features. Work through the core milestones below. Do not claim a feature works until the relevant checks have actually run.

## 0. Mandatory project narrative: explain the business purpose before the tools

Present the project in this exact order in the README overview, project brief, case studies, and demonstration script:

**The idea → What it does → How it helps the company → The outcome → Comparison with another method → Experience gained.**

Use plain English and concrete examples. Keep the opening overview short enough for a recruiter to understand within two minutes, then link to the detailed technical evidence. Use planned/future tense for unimplemented capabilities and measured past tense only for completed, verified work. The project is a lab study until a real deployment is separately demonstrated.

### 0.1 The idea

Frame the project around a fictional company that operates a Windows IIS customer-support portal containing private customer tickets and a report-export feature. The problem to investigate is that evidence of an attack can be divided between the web application and the Windows host, making it difficult to establish what happened, which records were affected, and what should be contained.

The idea is to build a repeatable purple-team workflow that connects an authorised web attack to defensive evidence, a justified analyst decision, a vulnerability fix, and a retest. The niche is request-to-process attribution with an explicit confidence level and a measured comparison of available log sources.

Do not suggest that every organisation has this exact visibility gap. Present it as the scenario and hypothesis being tested.

### 0.2 What it does

Describe the observable workflow: reproduce a bounded lab vulnerability, collect IIS/application/Windows events, normalise the records, run detections, connect related events, identify affected synthetic resources, create an incident report, implement remediation, and repeat the scenario.

Show two distinct examples. In the first, unauthorised access to another tenant's ticket is established through application identity/resource context without assuming a new Windows process. In the second, a report request leads to unexpected process execution, whose ancestry and consequences are reconstructed from native Windows evidence. State when any correlation is ambiguous.

Make each advertised capability clickable through to its working command, source code, sample output, test, or case report. A planned feature must be visibly labelled.

### 0.3 How it helps the company

Explain practical decisions the project could support:

| Company need | How the project could help | Evidence required before claiming an achieved benefit |
| --- | --- | --- |
| Protect customer information | Reveal a demonstrated cross-tenant access flaw and verify its repair | Reproduction evidence, access-policy tests, and post-fix results |
| Prioritise incident response | Connect a suspicious request with affected resources or observed Windows processes | Evidence-linked timeline, correlation confidence, and correct scope assessment |
| Reduce unnecessary investigation | Test detections against legitimate exports and maintenance behaviour | False-alert counts on the same defined benign workload before/after tuning |
| Choose useful logging | Identify which sources supply otherwise missing evidence | Controlled source-removal comparison and measured event/storage volumes |
| Verify security changes | Repeat the same attack and legitimate workflow after a fix | Attack outcome, visibility, and regression-test results |
| Improve handover between teams | Package a reproducible finding with an analyst timeline and remediation details | Reviewable case reports linking the offensive and defensive evidence |

Treat shorter investigation time, fewer interruptions, and lower loss exposure as potential operational benefits until measured. Do not invent company savings, revenue impact, breach-prevention rates, or production return on investment. Report additional logging, maintenance, storage, and review costs as trade-offs where measured.

### 0.4 The outcome

Separate **delivered artefacts** from **measured security outcomes**.

Delivered artefacts should include the working lab and portable demo, approximately six tested detections, three scenario case reports, at least two vulnerability/fix reports, a reusable evidence collector, and the telemetry-comparison results. Record actual completed counts rather than treating targets as achievements.

Measured outcomes should identify detected and missed cases, false alerts on a stated benign workload, affected-resource identification, correctly supported request/process links, remaining ambiguous links, and attack-versus-legitimate behaviour after remediation. Record runtime or detection delay using the definitions in section 8.

Include a compact results table with the metric, comparison baseline, observed result, evidence link, and limitation. Leave unmeasured results explicitly marked as not measured. Never fill the table with invented demonstration percentages.

If reporting analyst time, define the investigation task and completion criteria, use comparable case difficulty, account for practice/order effects, and state the number and background of participants. A single author's faster second attempt is not evidence of a general productivity improvement. If no credible timing study is feasible, report reproducible processing time and evidence completeness instead.

### 0.5 How it compares with another method

Use the same captured workload and labelled evaluation cases to compare IIS-only, IIS-plus-application, Windows-only, and combined views. State the decision each method supports and the information it lacks. Do not give reduced-source views enriched information derived from excluded sources.

Compare a basic process-ancestry rule with a tuned contextual rule using the same benign and suspicious cases. Report both missed cases and false alerts so suppression does not appear beneficial while hiding attacks.

Explain that a vulnerability reproduction and fix test establishes exploitability and remediation; the additional purple-team exercise also tests observability, detection behaviour, investigation evidence, and retest visibility. This is a comparison of the tested workflows, not a claim that professional penetration tests never include those activities.

Do not claim superiority to an enterprise SIEM or EDR, or to products that were not evaluated. The project supplies an application-specific validation and investigation workflow that may complement those tools. More data may improve attribution but also increases collection and operational overhead. Use conclusions such as “provided more complete attribution for these evaluated scenarios” only when the results support them.

### 0.6 Experience gained

Link each skill to work I can personally explain or reproduce:

| Skill or role | Evidence of experience within this project |
| --- | --- |
| Security research | Define a hypothesis, construct controlled comparisons, analyse held-out cases, and explain limitations |
| Bug bounty / web penetration testing | Reproduce an access-control or execution-boundary flaw, assess demonstrated impact, and write a remediation/retest report |
| Windows penetration testing | Explain the IIS execution context, actual permissions, process ancestry, and boundaries of the demonstrated attack path |
| SOC analysis | Triage an unfamiliar alert, consider a benign explanation, establish scope, and justify escalation or closure |
| Detection engineering | Modify a rule, test it against positive and benign cases, tune it, and quantify the trade-off |
| Incident response | Collect relevant evidence, reconstruct a timeline, recommend proportionate containment, and verify recovery |
| Purple-team collaboration | Connect reproduction, detection feedback, remediation, and repeated validation in one documented exercise |

Distinguish hands-on lab experience from production experience, genuine vulnerability discoveries, and paid bounty results. Include a learning checklist requiring me to investigate an unfamiliar case, explain a correlation failure, change a detection, and demonstrate a fix. Label AI assistance honestly and do not create resume claims for skills I have not exercised.

For each scenario case report, use a compact six-part opening in this exact order and link the following technical sections to the claims. The final five-minute demo should follow the same order and show an actual result during the “What it does” stage.

## 1. Operating approach and scope

- Inspect the workspace, capabilities, existing repository, and applicable AGENTS.md instructions. Preserve unrelated work.
- Create a short implementation plan and maintain a decision log. Resolve routine choices independently. If agents are available, delegate independent code review or testing without allowing conflicting edits.
- Make the first release centred on one disposable Windows VM, one small web application, three scenario families, approximately six useful detections, and one portable investigation pipeline.
- Keep an explicit status matrix: implemented, tested offline, tested on native Windows, blocked, or planned. Do not label Windows integration tests as passed because equivalent Linux unit tests passed.
- Pin supported dependency versions after verifying compatibility. Record the Windows edition/build, IIS configuration, .NET version, PowerShell version, Sysmon version, and detection backend used in actual tests.
- Build the core first. Keep Active Directory, lateral movement, cloud identity, kernel research, malware development, and a large SOAR platform outside the initial release.
- Prepare the repository locally. I will publish it to GitHub. Do not create or push a public repository, publish a website, or upload raw endpoint logs.

## 2. Architecture and execution modes

Use:

- C# and a supported ASP.NET Core release for a fictional multi-tenant support/reporting application.
- IIS on a native Windows VM for the full lab. Select and explicitly configure **in-process hosting** for the baseline release, then verify the actual process topology.
- SQLite for synthetic application data.
- PowerShell for Windows setup, preflight checks, event export, evidence collection, and cleanup.
- Sysmon, IIS access logs, application security events, and selected Windows event channels for telemetry.
- Python for normalisation, offline replay, correlation, evaluation, and incident report generation.
- Sigma for suitable event-level detections, using a real, tested execution path such as pySigma with its SQLite backend and appropriate logsource/field mappings.
- pytest, suitable .NET tests, PowerShell validation where feasible, and GitHub Actions.

Provide two modes:

1. **Portable reviewer demo:** runs on Windows, Linux, or macOS after documented dependencies are installed. Replays bundled fixtures or sanitised captures and produces alerts, an evidence-linked timeline, and an HTML/Markdown report. It must not require IIS, paid services, or an LLM API.
2. **Native Windows live lab:** installs/configures the dedicated lab application and telemetry, exercises scenarios, collects actual Windows evidence, and runs that evidence through the same analysis code.

WSL and Linux containers may support development and replay. They are not substitutes for validating IIS worker processes, Windows audit policies, Sysmon, or Windows event collection. Do not make Docker a requirement for the portable demo or pretend an ordinary Linux container provides a native Windows endpoint.

If native Windows is unavailable, finish the portable implementation, application code, setup scripts, tests, and runbook. Mark native capture and validation as blocked. Supply precise next commands rather than manufacturing Windows evidence.

## 3. Lab application and attack surface

Implement a small but believable application with synthetic organisations, users, roles, private support tickets, attachments, and a report-export workflow. Provide normal authentication and an explicit access policy.

Implement separated vulnerable and hardened lab configurations. Hardened mode is the default. Enabling vulnerable mode must require a deliberate local lab configuration.

Use a dedicated low-privilege IIS application pool. Record the permissions each scenario actually needs. Do not run the web application as Administrator or SYSTEM merely to make demonstrations succeed.

Keep the vulnerable service local to the disposable VM by default. Use only generated accounts, harmless files, and explicit lab services. Setup and cleanup must affect only project-owned resources. Keep host protections enabled; record a blocked action as prevention evidence.

Do not create an arbitrary internet-target scanner, general remote shell, or an endpoint security bypass toolkit. The offensive component is a bounded validation harness for this lab.

## 4. Three core scenario families

### A. Cross-tenant access without conspicuous endpoint activity

Reproduce a genuine broken object-level authorisation flaw in the lab application: one authenticated tenant accesses another tenant's private ticket or export. Demonstrate the issue using synthetic records.

Implement the policy correctly in hardened mode and rerun identical requests. Include legitimate sharing, same-tenant access, and administrative behaviour allowed by the policy.

This scenario should test whether application context reveals an incident that endpoint process rules alone cannot identify. Do not manufacture a child process merely to make endpoint alerts fire.

### B. Web request to Windows process execution

Implement an isolated unsafe report-generation workflow where mishandled input crosses from application data into command execution in vulnerable mode. Use harmless demonstrations confined to the VM and lab working directory.

The hardened workflow should remove unnecessary shell interpretation, use an appropriate managed implementation or safe executable invocation, validate arguments, and retain useful operational logging.

Capture the initiating request, application action, actual Windows process creation, and harmless host outcome. Include benign report processing that legitimately launches a helper process so detections must consider context.

Record the real process tree. In-process ASP.NET Core normally runs within the IIS worker, whereas other hosting models can produce different ancestry. Do not treat every child of w3wp.exe as conclusively malicious.

An ASP.NET Core upload directory does not automatically execute uploaded .aspx files. Do not claim a working web shell or map T1505.003 unless an actual supported execution/persistence mechanism is implemented and demonstrated. The core project does not require a web shell.

### C. Windows follow-on activity and analyst reconstruction

From the controlled execution context in B, where actually supported by the demonstrated primitive and permissions, perform harmless discovery, write or stage dummy data in a lab directory, and send a synthetic artefact to a local evidence sink if feasible.

If an action is triggered separately by the test harness, identify it as a separate emulation step. Do not present pre-existing administrator access or a manually executed command as an exploit-derived capability.

Keep evidence of data access or transfer proportional to the available sources. A network connection alone is not proof of exfiltration, and a file creation event is not proof of a file read. Use the controlled receiver and content hashes for any claimed dummy-data transfer.

Each family needs preconditions, reproduction, expected observable behaviour, benign controls, observed results, remediation, cleanup, and limitations.

## 5. Telemetry and Windows correctness

Implement and document a telemetry matrix:

| Source | Purpose | Important prerequisites or limits |
| --- | --- | --- |
| IIS W3C access logs | Request metadata and response outcome | Parse actual #Fields headers and configuration; do not assume a fixed field order |
| Application JSON events | Actor, tenant, resource, policy context, action, outcome, request and job identity | Identity must come from server-side authentication; never log credentials or session secrets |
| Sysmon process creation, event 1 | Process ancestry, image, command line, ProcessGuid | Verify collection and normalisation using real captured events |
| Sysmon network connection, event 3 | Process-associated network connections | Explicitly configure and verify it; do not assume it is enabled by default |
| Sysmon file creation, event 11 | File creation/overwrite evidence | Does not provide general file-read auditing |
| Selected PowerShell operational events | Script processing where the scenario uses PowerShell | Verify engine, channel, policy, and provider; Windows PowerShell 5.1 and PowerShell 7 differ |
| Selected Security events | Supplementary Windows process/logon/task evidence | Enable required audit policies; application login failure is not automatically Windows event 4625 |

Use Security 4688 only when correctly configured. Do not assume command-line data is present. Use 4698 only for an implemented scheduled-task extension with the required audit policy.

Provide preflight checks that verify the expected channels and test events actually exist. Record missing telemetry as unknown or unavailable, not as evidence that nothing happened.

Export structured event XML/JSON with provider, channel, event version, record identity, timestamps, and named event fields. Do not rely on localised human-readable event messages. Preserve the original evidence alongside normalised records. For PowerShell script block events, handle fragments when relevant and document unsupported cases.

Use UTC and preserve event time separately from collection time. Sanitise event values and generated HTML. Redact sensitive query/header fields without removing the behavioural evidence required by the experiment.

## 6. Request-to-process correlation

Make honest correlation a central feature.

IIS and Sysmon do not automatically share an application request ID. Generate trustworthy server-side request IDs and preserve separate client-supplied IDs only as untrusted metadata.

Instrument the legitimate report-launch boundary to record the request/job ID, host, application process identity, child PID, launch time interval, action, and outcome. Apply this consistently to benign and suspicious activity.

Join process launches to Sysmon using host, parent/child identity, and bounded time. Use ProcessGuid and ParentProcessGuid for subsequent process relationships. Account for PID reuse, worker recycling, concurrency, time skew, missing events, and long-running jobs.

Provide a confidence explanation for each link. A time-only association must be labelled as such. Do not claim exact attribution where evidence is ambiguous. Preserve an unattributed-process path when execution bypasses instrumented application code.

Never use scenario IDs, expected labels, specially named payloads, hardcoded fixture IPs, ground-truth markers, or the vulnerable-mode flag to decide whether to alert or to manufacture a correlation.

## 7. Detection implementation

Target approximately six well-supported detections, adapting the exact count to demonstrated coverage:

1. Cross-tenant resource access violating the documented policy.
2. Suspicious shell/script-interpreter execution from the observed web-worker ancestry.
3. Suspicious descendant process behaviour after the web-triggered execution.
4. Unexpected writes into a relevant application directory with contextual evidence.
5. An unexpected outbound connection from a relevant process chain, with bounded claims.
6. A correlated incident that combines independently supported application and endpoint findings.

Broad hunting leads may be retained, but distinguish them from high-confidence incident detections. Do not count a combined incident and its component alerts as independent attacks in evaluation.

For each rule provide: stable ID, hypothesis, required sources/fields, executable logic, severity rationale, positive and near-miss benign tests, false positives, tuning rationale, blind spots, triage guidance, and references.

Use valid Sigma only for logic supported by the selected backend. Execute converted queries against the project's documented event schema and test the resulting matches. Schema validation and successful conversion alone do not prove detection correctness.

Use explicit Python/SQL correlation for application-policy and multi-source logic where necessary. Document the distinction between native correlation logic and Sigma. Do not claim that arbitrary YAML is Sigma or that Sigma files execute directly in Wazuh.

Map behaviours to MITRE ATT&CK only when the demonstrated action supports the mapping. Use CWE and OWASP classifications for application flaws where appropriate. A lab reproduction is not a newly discovered CVE or a verified bug bounty finding.

## 8. Research contribution: compare telemetry coverage

Evaluate the same workload under four analysis views:

1. IIS access logs only.
2. IIS plus application security events.
3. Windows endpoint events only.
4. Combined IIS, application, and Windows evidence.

For replay experiments, remove unavailable sources before normalisation/enrichment or correlation so information cannot leak back into a reduced view. Treat unavailable detection prerequisites separately from an executed rule that misses an attack. Report prerequisite availability and conditional rule performance alongside overall incident coverage across all planned cases, so excluding unavailable rules cannot inflate apparent effectiveness. Explain what each view can detect, what it can attribute, and what remains unknown.

Predefine evaluation units: individual alert, request, scenario run, and correlated incident must not be mixed. Keep tuning data separate from held-out evaluation scenarios.

Include benign report exports, allowed shared access, administrator maintenance, repeated legitimate requests, application restarts, and concurrent jobs. Vary users, hosts, paths, identifiers, request ordering, and timing within documented lab behaviour.

Report measured true positives, false positives, false negatives, precision/recall where defined, and false alerts per stated amount of benign activity. Explain undefined denominators. Add evidence-completeness or attribution measures only after defining an objective rubric.

Measure live detection latency separately from offline processing time, and only when an actual collection/analysis cadence has been implemented and exercised. If collection uses manual exports, report export-to-report processing time instead. Measure event counts and storage overhead if available. Do not infer collection CPU overhead or operational savings merely by filtering captured logs offline.

Include one meaningful detection improvement and at least one documented blind spot. Missing application context, missing endpoint events, concurrent process launches, and activity that does not create a new process are useful limitations to test or explicitly describe.

Ground truth belongs in an evaluation-only manifest. Disabling or changing labels must not change the detector's output.

## 9. Evidence provenance and incident response

Separate:

- Actual native Windows captures.
- Sanitised derivatives of those captures.
- Handcrafted parser/rule fixtures.
- Scenario ground truth and expected results.

Every dataset needs origin, tool/configuration versions, collection conditions, sanitisation notes, and hashes where appropriate. Do not fabricate EVTX files, screenshots, logs, successful captures, or benchmark results.

Produce evidence bundles with original/normalised events, rule versions, source references, hashes, and collection metadata. Explain that hashing protects later integrity checks but does not establish that a compromised host originally reported the truth.

Create three analyst case reports with:

- A concise executive summary and defensible severity.
- UTC event timeline and an observed process tree where available.
- Affected accounts, tenants, resources, and processes.
- A fact/inference distinction, confidence, and alternative explanations.
- Scope assessment, containment options, preservation priorities, remediation, recovery, and retest findings.
- Direct links from material conclusions to evidence records.

Create a PowerShell evidence collector limited to relevant project events, process metadata, configuration, and artefact hashes. Document required privileges and collection side effects. Prefer collecting evidence before destructive cleanup.

Containment actions should default to a dry run and target only verified project resources, such as the dedicated app pool. Include rollback. Do not automatically isolate the user's entire workstation or block generic processes by name.

## 10. Remediation and code security

Implement real fixes and repeat the same reproduction against hardened mode. Verify that legitimate workflows still work and attempted abuse remains observable.

Provide at least two vulnerability reports: broken authorisation and the unsafe report-execution boundary. Include root cause, demonstrated impact, prerequisites, remediation diff, and retest evidence. If using CVSS, document assumptions rather than selecting an impressive number.

Review the defensive tooling itself: untrusted log parsing, path handling, SQL construction, report HTML escaping, archive handling if used, and secret leakage. The analysis pipeline must never execute a command extracted from an event.

## 11. Repository and reviewer experience

Use a clear structure, adapting names when necessary:

- `app/` — ASP.NET Core application and tests.
- `lab/windows/` — setup, preflight, collection, capture, cleanup, and rollback.
- `scenarios/` — bounded reproductions and legitimate workloads.
- `detections/sigma/` — portable event-level rules.
- `detections/correlation/` — explicit application and sequence logic.
- `analysis/` — normalisation, replay, evaluation, and reporting.
- `datasets/` — documented fixtures and permitted sanitised captures.
- `tests/` — behavioural and regression tests.
- `reports/` — measured evaluations, cases, and vulnerability reports.
- `docs/` — architecture, policy, data model, decisions, limitations, and runbooks.
- `.github/workflows/` — honest automated checks.

The README must open with the six-part narrative in section 0, followed by a visible quick-start and links to evidence. It should let a reviewer find within two minutes: the problem, what is implemented, a real sample result or clearly labelled fixture demo, how to run it, the telemetry comparison, a vulnerability fix, and the verification status.

Include a compact architecture diagram, an evidence-linked incident view, and a short demo script. Generate the report from actual analysis output. A polished, self-contained HTML report with filters or expandable evidence is sufficient; do not delay the core for a full frontend.

Document where third-party tools end and my project contribution begins. Attribute adapted rules and datasets and respect their licences. Obtain Windows and vendor tools through official sources; do not bundle proprietary installers. Include an appropriate project licence and example configuration without secrets.

## 12. Tests and release gates

Tests must cover meaningful risks: policy enforcement, safe report processing, parser correctness, rule matches and benign exclusions, loss of a required source, concurrency, PID reuse, duplicate/out-of-order events, correlation confidence, evidence links, and hardened-mode regressions.

Use actual observed event formats where available. State when synthetic fixtures are the only coverage for a parser. Reuse the production detection code in tests and in both demo modes.

CI should run portable replay and behaviour tests, .NET tests, rule validation plus actual query execution, and suitable PowerShell checks. Use in-process application tests with mocked process launch and canned endpoint events on shared hosted runners. Reserve real host command-execution reproductions, persistence emulation, and live endpoint configuration changes for the disposable native VM. Describe native VM integration tests separately. Do not label a workflow passed merely because its YAML exists.

Milestones:

1. Threat model, access policy, scope, environment preflight, and schema.
2. App implementation with vulnerable/hardened flows and legitimate workloads.
3. Telemetry collection, normalisation, portable replay, and initial detections.
4. Native Windows capture and correlation, where environment access permits.
5. Held-out evaluation, remediation retests, incident reports, and reviewer demo.

Call a version with native Windows validation still pending a **portable preview**. Reserve **validated Windows release** for successful native capture, correlation, and remediation retests as well as the other core gates. Finish the feasible work and explain blockers precisely without presenting a preview as a fully validated Windows release.

## 13. Later extensions, only after the core is credible

Document these as a prioritised roadmap rather than inflating initial scope:

- **SIEM integration:** one end-to-end Wazuh or Microsoft Sentinel integration with explicit collection, field mappings, detection execution, and evidence. Keep costs/licences optional. Wazuh's server is a separate supported host; do not imply it runs natively as the Windows endpoint. Label example KQL or SPL as unvalidated until actually executed against the specified tables.
- **Windows persistence study:** a harmless, removable scheduled task writing a lab marker, with observed task-creation evidence and realistic permission requirements. Do not imply escalation if an administrator created it separately.
- **Hosting-model study:** compare observed in-process and out-of-process IIS ancestry and detection portability.
- **Independent validation:** apply selected detections to a licensed public Windows dataset, document schema/domain differences, and report results honestly.
- **Identity extension:** a separate small Active Directory lab with synthetic identities, explicit prerequisites, and a new threat model. This is a later release, not a prerequisite for the web-to-host core.

## 14. Final handover

Before the handover, review every row of `IMPLEMENTATION_STATUS.md` against the actual repository. Replace core stubs and placeholders with working implementations wherever feasible, run the relevant checks, and fix failures caused by the implementation. A placeholder, a proposed command, or an empty report is not a completed deliverable. Explain genuinely blocked requirements accurately without marking them passed.

Provide a concise runbook for a fresh checkout, covering dependency setup, the portable demo, evaluation, tests, Windows preflight/setup, live scenario execution, evidence collection, hardened-mode retesting, and cleanup. Use commands that match the implemented entry points. Validate the fresh-checkout sequence in an isolated temporary copy where the environment permits.

Return the implemented capabilities, exact commands, tests actually run, measured results, native Windows validation status, remaining blockers, and limitations. Provide a suggested GitHub description/topics, two truthful CV bullets, a five-minute demonstration script, and interview questions about the design and evidence.

Also deliver a concise `docs/project-brief.md` using the six-part narrative from section 0. Use that same order for the opening project summary, scenario case summaries, and demonstration script. Show the connection from company problem to mechanism, measured outcome, fair comparison, and experience gained. Attach evidence links to completed claims and clearly label expected benefits.

Also create a short hands-on learning checklist for me: explain one detection, investigate an unfamiliar benign case, modify a rule and rerun evaluation, reproduce a fix, and explain a blind spot. I must be able to defend this work in an interview, including which parts were AI-assisted.

Do not claim employer endorsement, novelty over all existing projects, production readiness, a real breach, a paid bounty, or a new vulnerability discovery unless independently established.

Begin implementation now. Use official sources to verify platform behaviour. If runtime validation is blocked, complete the feasible implementation and clearly separate verified results from remaining native execution.

## Primary references to consult during implementation

These sources support the design, not a claim that this project has already been built. Check current documentation and the exact versions used.

- Microsoft, IIS in-process hosting: https://learn.microsoft.com/en-us/aspnet/core/host-and-deploy/iis/in-process-hosting
- Microsoft, IIS out-of-process hosting: https://learn.microsoft.com/en-us/aspnet/core/host-and-deploy/iis/out-of-process-hosting
- Microsoft, Sysmon: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Microsoft, PowerShell logging on Windows: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows
- Microsoft, Security event 4688: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688
- Microsoft, Security event 4698: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698
- OWASP, Logging Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- OWASP, Broken Object Level Authorization: https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/
- SigmaHQ, rule repository and specification links: https://github.com/SigmaHQ/sigma
- SigmaHQ, pySigma SQLite backend: https://github.com/SigmaHQ/pySigma-backend-sqlite
- MITRE ATT&CK, Exploit Public-Facing Application: https://attack.mitre.org/techniques/T1190/
- MITRE ATT&CK, PowerShell: https://attack.mitre.org/techniques/T1059/001/
- MITRE ATT&CK, Web Shell definition and detection strategy: https://attack.mitre.org/techniques/T1505/003/
