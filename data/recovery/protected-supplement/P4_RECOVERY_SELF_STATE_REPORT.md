# P4 Recovery Self-State Measurement

Generated: `2026-08-22T05:51:40.161922+00:00`

Scope: first-round P4 recovery measurement over a formal seed copied from a real post-session accumulated workspace. Existing `VerifiedBackupManager` and canonical attack execution are reused; the P4 runner adds seed provenance, five-metric reporting, and repository-mode / backup-destruction orchestration.

Hash equality is reported only as byte restoration. Functional health is a separate healthcheck result.

Formal seed source: `<GUEST_HOME>/assa-bench/data/dataset_v1/batch1_granularity_20260807_v2/clean24/batches/repeat_000/runs/G024_W4_C3_V6_W3_C2_V3_W3_C5_V6__clean`

| case | admissible | byte restore | health | rollback-loss paths | restore latency ns | backup available |
|---|---:|---:|---:|---:|---:|---:|
| protected-normal | True | True | True | 1 | 22690051 | True |
| protected-normal | True | True | True | 1 | 22026033 | True |
| protected-normal | True | True | True | 1 | 21386811 | True |
| protected-normal | True | True | True | 1 | 22272527 | True |
| protected-normal | True | True | True | 1 | 21954038 | True |
| protected-normal | True | True | True | 1 | 21844501 | True |
| protected-normal | True | True | True | 1 | 22782835 | True |
| protected-normal | True | True | True | 1 | 23574564 | True |

Five metrics are separate: byte restoration, functional health, rollback loss, restore latency, and backup availability.
IMA is not part of this recovery measurement.
Failure discipline: repository isolation, legitimate update, attack execution, restore attempt, and health command execution are separately recorded; failed scenarios remain failed.
