# Evidence classes and fixture protocol

| Directory | Origin | What it proves |
| --- | --- | --- |
| fixtures/development | Handcrafted deterministic records | Parser and tuning behaviour within the authored model. |
| fixtures/heldout | Separately seeded/order-varied handcrafted records | Regression/generalisation checks within that model; not independent real-world validation. |
| native | Currently no bundled capture | Reserved for actual Windows collection; ignored by git. |
| sanitised | Currently no bundled derivative | Reserved for documented native derivatives; ignored by git. |

The fixture manifest declares origin, authoring conditions, versions marked not executed, and hashes for each source. Event XML uses published Windows field names but was **not emitted by Windows**. There are no manufactured EVTX files or screenshots. `collected_at` in a fixture is a simulated collection timestamp, not a real acquisition claim. [Generator](build_fixtures.py) deterministically rebuilds the two sets.

Ground truth is stored only in `ground_truth.json`. Replay and detectors never load it. Evaluation runs each source view first, then loads labels for scoring. The unit is one scenario run; component alerts and their correlated incident count once for coverage. Per-rule eligibility uses actual source/event/field prerequisites, and unconditional incident coverage retains cases whose evidence is unavailable.

Each split contains 19 runs: 7 malicious labels and 12 benign labels. The controls include compiled helpers, allowed sharing and admin reads, repeated legitimate reads, concurrent helpers sharing a worker, and legitimate shell maintenance. Correlation unit tests separately exercise worker recycle, PID reuse, duplicates, event disorder, ambiguity and skew. A case lacking application context and a separate uninstrumented execution case expose blind spots. Users, hosts, identifiers and request order differ by deterministic seed. These variations do not establish external validity beyond the shared authored model.

The tuning choice (interpreter child rather than every worker child) is fixed before the held-out evaluation. Development results and held-out results are generated separately; do not tune to held-out outcomes and continue calling the same set held-out. Create a new documented holdout after changing the hypothesis.

Raw native evidence remains local. For a public derivative, record original hashes, every transformation and changed field, preserved behavioural relationships, and new hashes. Hashes establish later integrity, not truthful acquisition from a compromised host.
