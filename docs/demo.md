# Five-minute demonstration — portable preview

## The idea (0:00–0:35)

“This fictional support company needs to understand both unauthorized ticket access and unexpected activity after report requests. I am testing how application identity and Windows process evidence support those decisions.” Show the [architecture](architecture.md). State that today's process records are handcrafted fixtures and native validation is pending.

## What it does (0:35–1:50)

Run a real replay now:

```bash
python -m iis_purple demo --dataset datasets/fixtures/heldout --output artifacts/demo
```

Open `artifacts/demo/report.html`. Expand an IPL-001 record to show tenant/resource policy context without an endpoint child. Expand IPL-006 and its launch/ProcessGuid link to show why that fixture association has high confidence. Follow an original record link. Show an unattributed process and explain why its request is unknown. Do not describe fixture contents as an observed native attack.

## How it helps the company (1:50–2:25)

Use [case A](../reports/cases/A-cross-tenant.md) to explain the affected synthetic ticket and developer fix. Use [case B](../reports/cases/B-execution.md) to explain preservation and a dry-run proposal to stop the dedicated pool. These are potential operational uses; no time-saving or loss-reduction study was performed.

## The outcome (2:25–3:10)

Open [actual HTTP outcomes](../reports/validation/portable-http.json): the same private-ticket request went from 200 to 403, with sharing/admin controls still 200. Open [fixture evaluation](../reports/generated/evaluation/evaluation.md): 6/7 labelled attacks detected and 1/12 benign runs alerted. Point to the missed unlogged-policy case and retained maintenance false positive.

## Comparison with another method (3:10–4:10)

Show the four source views and the basic/tuned rule table on the same case population. Explain why IIS alone lacks resource ownership, why Windows alone lacks authenticated application context, and why more evidence still cannot establish every link. Report the recorded processing time/bytes as offline overhead, not live latency or analyst productivity.

## Experience gained (4:10–5:00)

Open [the repair](../app/IisPurpleLab/Reports.cs) and [tests](../app/IisPurpleLab.Tests/ApplicationTests.cs). Explain why managed CSV generation removes shell interpretation and why an optional benign helper uses a fixed executable/argument list. End by identifying the outstanding native capture/retest gates and the AI assistance. Choose one [learning exercise](learning-checklist.md) to perform without assistance; do not claim skills merely because code exists.
