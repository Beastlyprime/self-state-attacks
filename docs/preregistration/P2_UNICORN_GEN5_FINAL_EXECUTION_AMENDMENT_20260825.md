# UNICORN gen5 final-population execution amendment

Date: 2026-08-25. This amendment was written after the 291-graph adapter
preflight and before running the official UNICORN parser, analyzer, or modeler.
No WL label, HistoSketch, cluster model, anomaly verdict, TPR, or FPR had been
observed when this amendment was made. The initial failed gate report is
retained as `GATES_REPORT_INITIAL_FAILED.json`.

## Why an amendment was necessary

The first full-corpus preflight passed G1 on 291/291 graphs, but failed the
literal all-population G2 check and one graph's G3 check. Inspection identified
two protocol issues rather than a detector result.

First, the implementation omitted three spellings already covered in intent by
the preregistered role table: `/lib64/**` loader objects are system libraries;
`stage_g_v6/**` is collection apparatus; and a run-relative document leaf is a
declared attachment input. They are mapped respectively to `system.library`,
`apparatus.collection`, and `external_input`. No emitted type contains the
path, filename, run identifier, arm, timestamp, PID, or inode.

Second, G2 is a representation-development gate and must not use attack or
held-out outcomes. Applying pairwise vocabulary stability to attack graphs
would reject any structural difference that UNICORN is supposed to detect,
conditioning admission on the test result. G2 is therefore evaluated only on
the 176 clean training graphs, separately by workload profile, at the unchanged
0.95 floor. G1 remains evaluated on every graph.

G3 remains a per-graph hard gate. A graph that fails G3 is not scored and is
reported as `data_insufficient`; it is never coerced to a negative. The
preregistered run-level interpretability rule remains unchanged: the result is
inconclusive if at least 50% of held-out graphs are data-insufficient.

## What did not change

- ROLE_ONLY typing and the semantic role families;
- graph topology, node identities, relation types, and edge order;
- the 176 clean-training, 60 natural-clean-test, and 55 attack-test split;
- profile-conditioned training;
- the official pinned parser, WL/HistoSketch analyzer, and modeler commits;
- ordered 10% base/stream split, analyzer parameters, seed, metric, and primary
  `STD=3.0` operating point;
- the G1, G2, G3 numeric thresholds and the `<50%` data-insufficient rule.

This is a transparent execution-protocol correction, not an amendment to a
score or threshold after seeing detector performance.
