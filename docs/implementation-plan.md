# Implementation plan

The expanded `Windows_Purple_Team_Codex_Master_Prompt_More.md` is the implementation contract. The original brief and `Idea.txt` are preserved.

1. Establish scope, policy, event contracts, and environment evidence.
2. Implement the support portal, separate vulnerable/hardened flows, bounded reproductions and in-process tests.
3. Build Windows configuration/collection and the shared portable normalisation, correlation, Sigma and reporting pipeline.
4. Execute parser, policy, detection, correlation and remediation checks. Native execution requires a disposable Windows VM; a WSL host is not that VM.
5. Run held-out fixture evaluation, generate evidence-linked cases, review security boundaries and validate a fresh-checkout sequence. Record native gates separately.

Work ownership: application agent owns `app/`, `scenarios/`, access policy and vulnerability reports; Windows agent owns `lab/windows/`, Windows runbook and telemetry reference; pipeline agent owns parsers, correlation and reports; primary agent owns detections, controlled datasets, evaluation, integration and reviewer documentation. Independent reviews follow implementation.

The release is a **portable preview** until native captures and remediation gates pass. The original implementation was prepared locally; the owner subsequently requested a second verification and GitHub publication. Private runtime evidence remains excluded from publication.
