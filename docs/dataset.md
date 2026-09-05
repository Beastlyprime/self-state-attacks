# Dataset

Three evidence populations, built independently, plus a separate
measurement-validation population. All membership is fixed in
`data/detection/FINAL_3POOL_SPLIT_MANIFEST.json`; that manifest is the
authoritative definition and everything below describes it.

## Self-state roles

The benchmark addresses self-state through a logical schema, so that selecting a
different file-backed agent requires a new state manifest rather than a new
definition of the attack space. For the reference adapter
(`experiments/agent/openclaw_core`, with `workload/self_state_openclaw.json`):

| Role | Concrete binding |
|---|---|
| Instruction | `SOUL.md`, `IDENTITY.md`, `USER.md`, `AGENTS.md`, `TOOLS.md` |
| Durable global memory | `MEMORY.md` |
| Episodic / topic-scoped memory | `memory/*.md` |
| Runtime configuration | `openclaw.json` |
| Automation | `HEARTBEAT.md` |
| Capability binding | `credentials/.env` |

Attacks and measurements retain both the logical role and the concrete path.

## Populations

### Clean training — 176 executions, 81 scenarios

Used only to fit learned baselines. Never used for false-positive measurement.
`pool1_clean_training_gen2_176` in the split manifest.

### Held-out natural — 60 executions, 20 scenarios, 3 replicates each

Used only for false-positive evaluation. Disjoint from training at the scenario
level. Split by outcome into 32 natural-write and 28 clean-no-write executions,
because a mutation detector can look sensitive to attacks merely by flagging any
self-state update. `pool2_clean_heldout_test_gen2_60`.

Both clean pools are drawn from four workload profiles that exercise different
regimes of legitimate self-state activity: coding (W1, from the Aider polyglot
benchmark), knowledge work (W2, from FRAMES), operations (W3) and general
assistance (W4). The profiles are contrastive, not a sample of a deployment
population.

### Attack — 55 adjudicated executions, 52 folds

`pool3_attack_test_55`. Two groups:

- **35 model-driven** executions, where malicious content arrives through a
  poisoned user message, an ingested workspace file, or tool-delivered content;
  the agent then runs normally and a before/after marker test determines whether a
  persistent self-state modification resulted.
- **20 directly instantiated** metadata or namespace mutations executed under the
  compromised agent principal.

Both enter the OS-level attack denominator; the distinction records only whether
an execution additionally demonstrates end-to-end model inducibility.

`b1b2_definable_n` is 23: the subset with a resolvable self-state write and valid
size features, which is the population the write-specific methods are defined on.
The other 32 are reported as outside those methods' definition, never as negative
predictions.

### Operation-observability validation — 16 cases

A separate measurement-only population: write, rename, unlink and chmod crossed
with memory-root, memory-log, instruction and configuration targets. It validates
that the collection substrate witnesses each operation, and contributes no attack
observations. `data/observability/operation-matrix/`.

## Attack catalog

Fixing the temporal axis to T1, the valid Target × Mechanism × Granularity
projection contains 23 structural cells, which expand to 43 parameterized
operations because a cell can bind multiple concrete files. Mechanisms are M1
modify, M2 add, M3 delete, M4 deny; granularities G1–G4 run from whole-object to
minimal change.

The catalog is a coverage scaffold — it defines what an OS defense should be asked
to observe or control. Catalog entries and attack executions are different
counting units, and catalog entries without an admitted execution are not counted
as empirical coverage. Rebuild it with `canonical_matrix_audit.py`.

## Telemetry

Five host views are collected per run — inotify, fanotify, auditd, eBPF and native
Sysdig capture. The normalizer joins audit, eBPF, fanotify and libsinsp-reconstructed
SCAP evidence into a syscall stream and provenance graph; inotify is kept as an
independent chronology and overflow check. Detector inputs are then exported in
each baseline's native form.

Five-source collection is a measurement-integrity property, not a claim that every
detector consumes all five streams. No detector does.

### Admission

A run is admitted only if required streams are non-empty, drop and overflow
counters are zero, SCAP termination is valid, the effective file-descriptor-to-path
resolution rate is at least 0.95, and no self-state write is excluded by the
normalizer. All 236 pass, with zero drops, zero overflows and zero excluded writes recorded
for every one. The resolution rate is recorded as 1.0 for the 100 executions
whose per-run readiness record survives; the other 136 are attested only by the
`>= 0.95` gate they were admitted under. The per-run evidence is in the corpus at
`tier_a/clean_admission/` and is recomputed by
`python3 data/corpus-manifests/check_admission.py` — **not** in the split
manifest's `anti_leakage_asserts`, which are population, disjointness and
substrate-presence checks. `docs/results.md` has the coverage table.

Observation-generation and derivation-generation identifiers, input hashes,
commands, tool exits and output hashes are retained so that cross-generation mixing
is rejected rather than silently scored.

## Record schemas

The scored outputs share a per-run row shape:

| Field | Meaning |
|---|---|
| `run_id` | execution identity; the `__poisoned` / `__clean` suffix marks the arm |
| `side` | `attack` or `clean` |
| `status` | `passed`, `data_insufficient`, or `failed` |
| `reason` | why a non-passed row was not scored |
| `binary_decision` | the detector's per-execution verdict, or null when unscored |
| `profile` | W1–W4 |
| `scenario_id` | clustering unit for the clean side |

Failed parsing or analyzer execution is data-insufficient, never a negative
prediction — treating it as negative would artificially improve specificity.

Point estimates use executions. Confidence intervals resample independent clean
scenarios or attack folds while retaining correlated executions; boundary cells
additionally report cluster-any Wilson intervals.

## What is not here

The raw per-run telemetry — syscall captures, provenance graphs, SCAP captures,
detector staging trees — is archived separately, 19.5 GB unpacked in twelve
compressed volumes. UNICORN's sketch and profile models are **not** in it: the
analyzer rebuilds those from the published graphs when the arm runs. `data/corpus-manifests/` records its provenance and checksums. Upstream
task corpora (HotpotQA, Wikipedia and FRAMES caches) are cited rather than
redistributed.
