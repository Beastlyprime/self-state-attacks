# Methodology

How the data was produced, in the order it was produced. This is a summary; the
paper is the authority, and [`results.md`](results.md) maps each reported number to
its file.

## 1. Reference adapter

Runs execute against `experiments/agent/openclaw_core`, a lightweight
implementation of the agent loop, tool dispatch and file-backed state loading.
Each run starts from a recorded workspace seed and executes under an unprivileged
agent principal, producing ordinary Linux files and processes rather than
simulator-only events. `experiments/agent_packs/` supplies the per-profile
instruction packs; `experiments/tasks/` supplies the task definitions and seeds.

## 2. Contrastive workloads

Four profiles create contrasting regimes of legitimate self-state activity: coding
(W1), knowledge work (W2), operations (W3) and general assistance (W4). Their
purpose is to exercise different combinations of code editing, information
synthesis, self-configuration and everyday file operations — not to estimate a
population distribution of agent users.

Drivers: `measurement/task_runner.py`, `task_runner_w2w3.py`; success criteria in
`measurement/task_eval.py`.

## 3. Attack construction

Two execution modes.

**Model-driven.** The harness builds an attack branch and a task-matched clean
branch from the same task bundle, initial state, tool environment and model
setting. Only the adversarial carrier differs — a poisoned user message, an
ingested workspace file, or tool-delivered content. The agent then runs normally.
A before/after marker test determines whether induced content persisted.

**Direct instantiation.** Metadata and namespace mutations are executed directly
under the compromised agent principal, consistent with a post-compromise threat
model. These test whether OS defenses can handle the resulting operation, not
whether the operation can be elicited by injection.

Carrier binding logic is in `dataset_builder/injection_routes.py`. Every
model-driven branch retains the initial state, a primary post-execution snapshot
and a later persistence snapshot (`before_a`, `after_a`, `after_b`); the primary
mutation comparison is `before_a` → `after_a`, and `after_b` is a persistence
diagnostic that is never substituted for the primary outcome.

Operational landing and semantic polarity are separate labels: a persisted marker
does not by itself establish maliciousness, which is determined by a pre-specified
adjudication procedure. Only valid executions adjudicated as malicious enter the
attack denominator; invalid, error, pending and data-insufficient runs are retained
with reasons and never converted to negative decisions.

## 4. Collection

`dataset_builder/paired_live_four_source.py` runs the paired collection with five
host views; `five_source_graph_bridge.py` bridges a run into the provenance graph.
`dataset_builder/run_safety.py` implements fail-closed pre-launch validation for
live poisoned collection, and `model_proxy.py` / `proxy_runtime.py` keep model
credentials outside the agent child process.

Each run retains raw inotify, fanotify, audit, eBPF and SCAP streams together with
source-health records, snapshots, task and state manifests, and an environment
fingerprint containing kernel and tool versions, clock state, runner identity and
collector/eBPF binary hashes.

## 5. Normalization and export

`measurement/stage_g_harness/normalize.py` joins subject identity, process lineage,
operation, resolved object, outcome and evidence provenance.
`libsinsp_extract.py` and `libsinsp_reattribute.py` rebuild file identity from the
SCAP capture; `libsinsp_compare.py` checks the normalizer's attribution against
libsinsp's event by event.

`export_p2_detector_inputs.py` then materializes each baseline's native substrate:
before/after snapshots for AIDE, the native SCAP capture for Falco, normalized
per-process syscall sequences for STIDE, and role-typed nodes and edges for the
provenance arm.

`generation_contract.py` binds inputs, commands and outputs to a named generation
so that cross-generation mixing fails closed rather than being silently scored.

## 6. Admission and observability validation

`dataset_builder/recollection_readiness.py` implements the admission gates
described in [`dataset.md`](dataset.md).

Separately, a 16-case validation suite crosses four operations with four target
roles and requires every case to be witnessed in the normalized graph. It is not
part of the admitted detector corpus, so the corpus threshold is neither relaxed
nor reused for it, and it contributes no attack observations.

## 7. Defense evaluation

**Prevention.** A six-operation replay — direct write, append, truncate,
rename-over, unlink, and chmod-then-write — against five configurations:
self-owned read-only DAC, root-owned read-only DAC, inode immutability, AppArmor
and Landlock. A trusted supervisor installs each policy before the agent-principal
probe. Success is determined from the requested post-state, not from the absence
of an error return: overwrite and rename-over must produce the marker bytes,
truncate must produce the requested size, unlink must remove the path, and
chmod/write must both reset the mode and land the overwrite. A separate paired
direct-write probe compares an attack-designated write with an operator-approved
write under the same principal and policy.

**Detection.** Four baselines over different forms of host evidence — file
integrity (AIDE), runtime rules (Falco), syscall-sequence novelty (STIDE) and
role-typed provenance graphs (UNICORN) — plus pooled and workload-conditioned
write size/timing baselines and three small supervised models. Configurations,
features and thresholds are selected without held-out natural executions. The unit
of decision is one execution.

**Provenance.** For each of 21 model-driven operational landings and its
task-matched clean branch, whether the OS can resolve the destination object,
attribute the writer to the agent process tree, and connect an ingested filesystem
carrier to that writer.

**Recovery.** From a post-session workspace: snapshot, one legitimate
post-snapshot update, a canonical corruption, then restore. The repository
experiment crosses protected-principal against same-user backup storage, and
ordinary corruption against an attack that also destroys reachable backups. A
protected supplement repeats restoration across eight attacks.

## 8. Reporting

Attack TPR is reported alongside the attack population a method is defined on, and
natural-workload FPR on the separate held-out corpus. Natural-write and
clean-no-write controls are reported separately. `final_aggregate.py` assembles the
comparison and is the one step that re-runs from this repository alone.
