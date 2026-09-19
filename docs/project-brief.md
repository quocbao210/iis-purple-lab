# IIS Purple Lab — project brief

## The idea

A fictional company operates a Windows customer-support portal. Private tickets and report exports create two distinct investigation questions: who accessed a resource, and whether a report request caused unexpected host activity. The lab tests how much evidence each logging source supplies.

## What it does

The [application](../app/IisPurpleLab) provides deliberately vulnerable and default hardened modes. [Actual portable HTTP checks](../reports/validation/portable-http.json) reproduce a tenant authorization flaw and its fix. A [shared analysis pipeline](../analysis/iis_purple) normalizes evidence, executes six detections, assigns request/process confidence, and generates an [evidence-linked fixture report](../reports/generated/demo/report.html). Windows installation/capture scripts are implemented; native B/C validation is pending.

## How it helps the company

Evidence could help developers verify an object-access repair, analysts identify affected synthetic resources, and responders choose proportionate containment. Testing legitimate behavior reveals false alerts; source removal clarifies what each log adds. Faster investigation or avoided losses would need a separate credible study.

## The outcome

Delivered artifacts include the working portable preview, six executable detections, three [fixture case reports](../reports/cases), two [vulnerability reports](../reports/vulnerabilities), a Windows collector and reproducible comparison. The [held-out fixture experiment](../reports/generated/evaluation/evaluation.md) detected 6/7 labelled attacks with 1 false-positive run among 12 benign runs. Real Kestrel access/fix checks passed. Native Windows outcomes are unmeasured.

## Comparison with another method

The same 19 fixture runs yielded 0/7 detections with IIS-only, 2/7 with application context, 4/7 with Windows-only, and 6/7 combined. The interpreter predicate reduced false-positive report runs from 6 to 1 while retaining 4 positive runs. Combined evidence costs extra collection/storage and still misses unlogged policy abuse. This complements conventional exploit/fix testing by also testing visibility and response evidence; it is not a claim that professional pentests omit those activities or that this replaces enterprise detection tools.

## Experience gained

The project offers concrete work to explain in policy enforcement, safe process boundaries, rule execution, source-ablation experiments, confidence-aware correlation and evidence preservation. It was AI-assisted and needs [hands-on ownership exercises](learning-checklist.md) before making personal experience claims. It does not establish production experience, an undisclosed CVE, a real breach or bounty success.
