# Paper → code → file

Every estimate reported in the paper, the code that produced it, and where it was
read from. Paths are repository-relative.

One entry below points outside this repository and is marked as such: the
per-run rows of Table 11's execution environment, which are recorded in each run
bundle in the archived corpus rather than in any single frozen file. Everything
else resolves to a file here.

`DET` below is `data/detection`.

Not every table appears here, by design. Figures 1–3 and Tables 1–3 are
definitional: the attack-space axes, the logical self-state roles, and the
mapping from OS capability to the decision each defence dimension must make.
They contain no measured value, so there is nothing to trace to a file. Table 13
lists the detectors' pre-specified decision rules, which the scorers named below
implement. Everything that reports a number is in one of the two tables that
follow.

## Results

| Paper | Produced by | Read from |
|---|---|---|
| **Table 7** — prevention replay, 6 operations × 5 configurations on `MEMORY.md` | `data/prevention/bin/run_p3_op_matrix.sh`, `bin/p3_op_matrix_incontainer.py` | `data/prevention/p3_op_replay_matrix_result.json` — 36 cells over six operations and six mechanisms. Thirty of those are the five policy configurations of Table 7; the other six are the unprotected `none` control, which the paper does not tabulate. Eleven cells landed their requested post-state |
| **Table 7** — paired direct-write probe (authorized-update selectivity) | `experiments/code/measurement/p3_prevention_self_state_errno.py`; policies in `experiments/code/defenses/prevention/` (`backends.py`, `permission_policies_v4.py`, `apparmor_profiles.py`, `chattr_lifecycle.sh`, `landlock_launcher.c`) | `data/prevention/paired-probe/P3_PREVENTION_SELF_STATE_ERRNO_REPORT.json` — a separate probe, because the six-operation replay JSON has no approved-update arm. Four mechanisms, each recording `marker_blocked`, `legitimate_update_blocked_collateral` and `same_errno_for_marker_and_legitimate`: the same policy rejects the attack write and the approved update, with the same errno |
| **Table 8, Table 14** — AIDE | `DET/score_aide_3pool.py` → `experiments/code/measurement/stage_g_harness/p2_aide_fpr_gen2.py` | `DET/scored_aide_3pool.json` |
| **Table 8, Table 14** — Falco | `DET/falco_remote.py`, `DET/merge_falco_3pool.py`, `experiments/code/measurement/stage_g_harness/falco_rules.py` | `DET/scored_falco_3pool.json` |
| **Table 8, Table 14** — STIDE | `DET/score_stide_3pool.py` → `stage_g_harness/{stide_bridge,stide_core_tail,stide_saturation}.py` | `DET/scored_stide_3pool.json` |
| **Table 8, Table 14** — UNICORN | `DET/score_unicorn_gen5_3pool.py` → `stage_g_harness/{unicorn_adapter_role,unicorn_role_typing}.py` | `DET/unicorn/UNICORN_GEN5_FINAL_REPORT.json`; per-run verdicts in `SCORED_ROWS.json`, per-run pipeline status in `SKETCH_STATUS.json` |
| **Table 8, Table 14** — B1 pooled / B2 per-profile | `DET/score_ours_3pool.py`, reusing the Eq. 1 detector math verbatim from `data/superseded/score_ours.py` | `DET/scored_ours_3pool.json`. The frozen operating points these are calibrated against are in `DET/b1b2/REPORT.json`, produced by `DET/b1b2/run_size_timing_libsinsp.py`; three `DET/supervised/*.py` scripts assert their populations against it |
| **Table 8, Table 14** — L1 logistic / CART / FIGS | `DET/rebuild_supervised_3pool.py` | `DET/FINAL_3POOL_SUPERVISED.json` |
| **Table 8, Table 14** — assembled comparison | `DET/final_aggregate.py` | `DET/FINAL_3POOL_REPORT.json`, and **`DET/FINAL_3POOL_HEADTOHEAD_TABLE.md`**, which carries every point estimate and interval from both tables in one place |
| **Table 9** — provenance on 21 landings vs 21 clean branches | `data/provenance/p5_analyze.py` | `P5_NAMEABILITY_ATTRIBUTION_REPORT.json` / `.md`. **The two sides are equal in size, not pairwise matched** — see the note below. Recomputable: unpack `provenance-inputs` and re-run, the report rebuilds byte-for-byte |
| **Table 10** — recovery repository isolation matrix | `experiments/code/measurement/p4_recovery_self_state.py`; `experiments/code/defenses/recovery/{backup_manager_v4,healthcheck_v4}.py` | `data/recovery/isolation-matrix/P4_RECOVERY_SELF_STATE_REPORT.{json,md}` — the four cases with byte-restore, health, rollback-loss and backup-availability columns |
| **§5.3** — eight-attack protected supplement | same runner over the eight attack cells | `data/recovery/protected-supplement/P4_RECOVERY_SELF_STATE_REPORT.{json,md}` |
| **Table 15** — distinct self-state objects modified per clean session | `data/recovery/rollback-cost/bin/p4_recovery_cost.py` | `p4_recovery_cost_result.json` — 236 scanned, 150 writing, 86 non-writing |
| **§5.2** — matched-control validation (nested-CV AUC 0.5983) | `DET/rebuild_supervised_3pool.py`, `DET/supervised/*.py` | `DET/FINAL_3POOL_SUPERVISED_TABLEFRAG.md`, `DET/supervised/REPORT.json` |

### Table 9's clean side is a size-matched control, not a paired one

The paper describes Table 9 as 21 landings against 21 *matched* clean branches.
The two published populations are equal in size; they are not a pairing
assignment. The inventory:

| | Count | Which |
|---|---|---|
| attacks paired with their own `__clean` twin (same run id) | 17 | |
| attacks with no unused clean branch left for a one-to-one match | 2 | `C510_w3_db_query_vendor_package`, `C515_…_user_message` — a same-case clean is in the benign set, but it is already consumed as another attack's exact twin |
| attacks matchable only at case granularity | 2 | `C511_…_user_message` (two unused same-case cleans available), `C513_…_user_message` (one) |
| clean branches matching no unpaired attack's case | 1 | `C401_w4_replication_article_bias_external_content__clean` |

Read that as a relation inventory, not an assignment: a strict one-to-one
matching completes at most **19 pairs** and leaves two attacks and two clean
branches over. The four unpaired attacks are exactly the C-series landings the
report's own `par21_note` records as having no paired clean available.

**This does not move the table's numbers or its conclusion.** Every cell is a
marginal count over each side independently — destination nameable 21/21 both
sides, principal attributed 21/21 both sides — so nothing in it is computed as a
within-pair difference, and no paired test is performed. The supportable claim is
that across these two equal-sized populations the attribution properties are
identical, so they yield no attack-specific verdict. What the pairing language
would additionally license — a per-pair comparison — the design does not support.
The paper's caption and its "task-matched clean branches test whether…" phrasing
are stronger than that; closing it is an arXiv revision item, not a reason to
change any data here.

### Section 5.2: substrate A reproduces exactly; substrate B cannot

Running `rebuild_supervised_3pool.py` against the corpus turned up two separate
problems. One was a defect in this archive and is fixed; the other is a
limitation of the original computation and is not fixable here.

**The archive shipped the wrong C520 pair, and that is now corrected.** Of the
22 C-series runs in `tier_b/*_lockedpop_cseries`, twenty were the
`gemini-3-flash` executions the published population is defined over. The other
two were both halves of `C520_w3_alert_webhook_runbook` — attack and twin — taken
from the `grok-4.6` re-collection in
`p2_llmtrace_grok_attack_native_20260823`, a different execution that happens to
share the run id. The published rows never used it: the detector staging tree
they were scored from held the gemini execution, as does every other pool.
Substituting the
gemini pair back makes **substrate A recompute exactly** — nested-CV AUC .5983,
its interval, every control, the placebo and the McNemar counts all match the
shipped file field for field, verified in a tree holding nothing but this
repository and the unpacked volumes.

The same substitution was needed one tier down. `tier_c`, which carries the
native SCAP captures, held the grok C520 attack and twin as well — the archived
captures hashed to the grok sources, and their recorded sizes were the grok
sizes. Both are now the gemini captures, and the two acquisition manifests that
recorded the grok source paths (`manifests/cseries11_source_paths.json`,
`manifests/scap_targets.json`) say so.

**Substrate B's two shipped AUCs are not reproducible, and the reason predates
this release.** Its stream selector was
`glob("**/<run_id>/graph/normalized/syscalls.jsonl")[0]`, whose result depends on
directory traversal order. On the collection host several of the 46 streams it
reads had more than one distinct copy — sixteen for
`C512_w3_audit_rotate_runbook__clean`, one per parity-pilot replicate across
three arms — so which one the published fit read was decided by traversal order
and never written down. The shipped **.4991 / .4915** therefore cannot be checked
against anything, and we do not claim otherwise.

What replaces it is checkable in a stronger sense than a fixed ordering. Across
the published volumes each of the 46 streams exists exactly once, except one
(`MCAW402_w4_blanket_approval_false_memory__poisoned`, in both `staging` and
`tier_b/attacks`) whose two copies are byte-identical — so from this corpus the
result does not depend on the order at all. It is **.5123 / .3837**, and the
recomputed block carries a `stream_selection` map giving the path and SHA-256 of
every stream read, so a reader can confirm the inputs rather than trust the
selector.

Both pairs sit either side of .5 on L1 logistic and below it on RuleFit, so the
paper's characterisation of substrate B as *at chance* survives. An earlier
version of this section listed three orderings, including .538/.471 as
"archive-first". That figure came from a development tree rather than the
published inputs and no selection map backs it; it is withdrawn.

`rebuild_supervised_3pool.py` and `supervised/paired_vs_b1b2.py` write
`*.recomputed.json` and never overwrite the shipped files, so both are available
and the difference stays visible.

**A correction to an earlier version of this file.** It attributed the
discrepancy to three twins (MCAW101, MCAW201, MCAW402) having zero-byte libsinsp
streams. Those files are indeed empty in the `p2_mass_attack_lane2` trees, but
`locate()` checked the detector staging tree *first* and staging carried all
three complete, so they were never read. The cause was the C520 substitution
above.

### The first corpus build did not actually publish eleven attack graphs

Worth recording because it is the failure mode that hid the two above, and
because it invalidated every reproduction check run on the authors' own machine.
The `staging` volume shipped the eleven W3 C-series attacks as **absolute
symlinks** into a path that exists only on the collection host. Here they
resolved and every scorer looked correct; anywhere else they dangled, and
`score_ours_3pool.py` — which had no population gate — exited 0 having evaluated
12 of 23 definable attacks and overwritten the frozen rows with the smaller
number. The trees were also covered by no checksum, since the index lists
regular files.

Three things changed. The symlinks are gone and the eleven trees resolve from
`tier_b/attacks_lockedpop_cseries`, whose copies are byte-identical to the
staging trees the rows were frozen from on every stream the scorers read
(`libsinsp_events.jsonl`, `graph/normalized/syscalls.jsonl`, and the
`resolution_spine_effective` graph). `score_ours_3pool.py` and
`score_stide_3pool.py` now fail closed on their full populations rather than
scoring what they can find — STIDE's gate also catches an absent backend, which
otherwise reports as a uniform `data_insufficient`. And the reproduction checks
were re-run in a tree holding nothing but the repository and the unpacked
volumes, with no path back to the collection host: Table 9, the B1/B2 rows,
STIDE, Falco's attack side and the aggregate all come back byte-identical there,
and `build_manifest.py`'s fourteen anti-leakage asserts all pass.

## Populations, catalog, and measurement quality

| Paper | Produced by | Read from |
|---|---|---|
| **Table 4** — clean corpus by workload profile (176 train / 60 held out) | `experiments/code/dataset_builder/{build_p2_clean_split,extend_p2_clean_split,build_p2_gen2_clean_inputs,build_p2_clean_user_message_cases}.py`; frozen by `measurement/freeze_p2_{clean,gen2_clean,heldout}_accounting.py` | `DET/FINAL_3POOL_SPLIT_MANIFEST.json`, pools 1–2 |
| **Table 5, Table 12** — 23 structural cells → 43 executable bindings | `experiments/code/dataset_builder/canonical_matrix_audit.py`, `attacks/canonical_v4.py`, `workload/taxonomy.py` | recomputable — see [`REPRODUCE.md`](../REPRODUCE.md). `data/superseded/COVERAGE_23CELL_RECOMPUTE.json` separately records which cells the attack corpus actually fills |
| **§4.3** — the 55 attack executions (52 folds) | user-message carriers: `build_mass_um_profile_inputs{,_w2w4}.py` (MUC/MUI); content-append: `build_mass_profile_content_append_inputs.py` (MCAW); semantic: `build_mass_profile_semantic_inputs.py` (MSI); chmod: `build_mass_profile_chmod_inputs.py` (MCH); truncate/unlink: `build_mass_profile_destructive_inputs.py` (MTR/MUL); W3 C-series: `build_p2_l0_newcase_inputs{,_b2,_b3}.py`, `build_p2_l0_um_instcfg_inputs.py`, `build_p2_l0_archetype_inputs.py` | `DET/FINAL_3POOL_SPLIT_MANIFEST.json`, pool 3 and `fold_map_attack_loso` |
| **Table 6** — five co-collected host views | `dataset_builder/paired_live_four_source.py`, `five_source_graph_bridge.py`, `live_trace/live_ebpf.bpf.c` | the archived corpus ships the *derived* evidence — the normalized provenance graph, the libsinsp reconstruction and the native SCAP capture. The raw inotify, fanotify, auditd and eBPF streams are retained per run in the full archive, not in the reproduction corpus |
| **Table 6 → detector inputs** — normalization and export | `measurement/stage_g_harness/{normalize,audit,scap,sidecars,libsinsp_extract,libsinsp_reattribute,libsinsp_compare,export_p2_detector_inputs}.py` | `data/superseded/DERIVATION_AVAILABILITY_MATRIX.json` |
| **§4.4, §5 preamble** — admission gates (fd→path ≥ 0.95, zero drops, no excluded writes) | `dataset_builder/recollection_readiness.py` | `DET/FINAL_3POOL_SPLIT_MANIFEST.json`, `anti_leakage_asserts` |
| **§4.4** — 16-case operation-observability validation | `dataset_builder/{mutation_matrix_canary,mutation_canary_five_source,mutation_matrix_run,mutation_op_canary}.py` | `data/observability/operation-matrix/REPORT.md` — 4 mechanisms × 4 target roles, all 16 graph-witnessed, with the full run bundle. `data/observability/four-operation-canary/` is the earlier 4-operation run that established the integration |
| **§D.4** — fail-closed cross-generation binding | `measurement/stage_g_harness/generation_contract.py` | `DET/FINAL_3POOL_SPLIT_MANIFEST.json`, `generation_contract` |
| **Table 11** — execution environment | the values are set by `dataset_builder/paired_live_four_source.py` and recorded per run in the environment fingerprint inside each run bundle | `DET/FINAL_3POOL_SPLIT_MANIFEST.json` carries the `generation_contract` and `uid_spotcheck` — the auditd, eBPF-object, libsinsp, monitor-version and runner-UID entries. The remaining rows (kernel build, filesystem, cgroup limits, clock discipline) are set in the collector and recorded per run in the archived corpus, not in any single frozen file here |
| **§4.1, Table 1** — reference adapter, state roles, role→path map | `workload/{state_schema,taxonomy}.py`, `workload/self_state_openclaw.json`, `experiments/agent/openclaw_core/` | — |
| **§4.1, Table 4** — W1–W4 profiles and task definitions | `workload/{profiles,agent_packs,generator_v4}.py`, `measurement/{task_runner,task_runner_w2w3,task_eval}.py` | `experiments/tasks/W{1,2,3,4}/*.json`, `experiments/agent_packs/` |

## A note on the UNICORN arm

The paper's UNICORN row uses the role-typed adapter
(`role_table_version = assa.unicorn_role_table.v1.1-final-amendment`). Earlier
adapter generations were superseded before the final population and are not part
of this repository.

Fourteen of the 55 attack graphs and thirteen of the 60 natural graphs are
unscored. `data/detection/unicorn/SKETCH_STATUS.json` gives the reason per run:
26 of the 27 are `official_parser_or_analyzer_failed` — the upstream analyzer
aborted — and one is `adapter_gate_or_fewer_than_two_edges`. These are reported as
data-insufficient rather than as negative predictions, which is why UNICORN's
coverage is 41/55 rather than 55/55.

## Superseded material

`data/superseded/` holds earlier population cuts and the aggregators that produced
them. They are retained for provenance and are **not** paper estimates:

- `UNIFIED_CLEAN40_REPORT.json` and `detection/supervised/*clean40*` — the clean-40
  comparison, which is leaky: half of that set overlaps the training freeze.
- `FULL_HEADTOHEAD_REPORT.json`, `PARTIAL_HEADTOHEAD_REPORT.json`,
  `W3THICK_HEADTOHEAD_REPORT.json` and the `aggregate_*.py` scripts that produced
  them. These cuts predate the final UNICORN run and record UNICORN as
  `non_evaluable_on_this_population`; that status is superseded. The paper's
  UNICORN row comes from `data/detection`, as the table above sets out.
