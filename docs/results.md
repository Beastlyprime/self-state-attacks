# Paper → code → file

Every estimate reported in the paper, the code that produced it, and the frozen
output it was read from. Paths are repository-relative.

`DET` below is `data/detection`.

## Results

| Paper | Produced by | Read from |
|---|---|---|
| **Table 7** — prevention replay, 6 operations × 5 configurations on `MEMORY.md` | `data/prevention/bin/run_p3_op_matrix.sh`, `bin/p3_op_matrix_incontainer.py` | `data/prevention/p3_op_replay_matrix_result.json` — 36 cells, 11 with the requested post-state landed |
| **Table 7** — paired direct-write probe (authorized-update selectivity) | `experiments/code/measurement/p3_prevention_self_state_errno.py`; policies in `experiments/code/defenses/prevention/` (`backends.py`, `permission_policies_v4.py`, `apparmor_profiles.py`, `chattr_lifecycle.sh`, `landlock_launcher.c`) | same result JSON, `install_info` and errno fields |
| **Table 8, Table 14** — AIDE | `DET/score_aide_3pool.py` → `experiments/code/measurement/stage_g_harness/p2_aide_fpr_gen2.py` | `DET/scored_aide_3pool.json` |
| **Table 8, Table 14** — Falco | `DET/falco_remote.py`, `DET/merge_falco_3pool.py`, `experiments/code/measurement/stage_g_harness/falco_rules.py` | `DET/scored_falco_3pool.json` |
| **Table 8, Table 14** — STIDE | `DET/score_stide_3pool.py` → `stage_g_harness/{stide_bridge,stide_core_tail,stide_saturation}.py` | `DET/scored_stide_3pool.json` |
| **Table 8, Table 14** — UNICORN | `DET/score_unicorn_gen5_3pool.py` → `stage_g_harness/{unicorn_adapter_role,unicorn_role_typing}.py` | `DET/unicorn/UNICORN_GEN5_FINAL_REPORT.json`; per-run verdicts in `SCORED_ROWS.json`, per-run pipeline status in `SKETCH_STATUS.json` |
| **Table 8, Table 14** — B1 pooled / B2 per-profile | `DET/score_ours_3pool.py`, reusing the Eq. 1 detector math verbatim from `data/superseded/score_ours.py` | `DET/scored_ours_3pool.json` |
| **Table 8, Table 14** — L1 logistic / CART / FIGS | `DET/rebuild_supervised_3pool.py` | `DET/FINAL_3POOL_SUPERVISED.json` |
| **Table 8, Table 14** — assembled comparison | `DET/final_aggregate.py` | `DET/FINAL_3POOL_REPORT.json`, and **`DET/FINAL_3POOL_HEADTOHEAD_TABLE.md`**, which carries every point estimate and interval from both tables in one place |
| **Table 9** — provenance on 21 landings vs 21 matched clean branches | `data/provenance/p5_analyze.py` | `P5_NAMEABILITY_ATTRIBUTION_REPORT.json` / `.md` |
| **Table 10** — recovery repository isolation matrix | `experiments/code/measurement/p4_recovery_self_state.py`; `experiments/code/defenses/recovery/{backup_manager_v4,healthcheck_v4}.py` | `data/recovery/isolation-matrix/P4_RECOVERY_SELF_STATE_REPORT.{json,md}` — the four cases with byte-restore, health, rollback-loss and backup-availability columns |
| **§5.3** — eight-attack protected supplement | same runner over the eight attack cells | `data/recovery/protected-supplement/P4_RECOVERY_SELF_STATE_REPORT.{json,md}` |
| **Table 15** — distinct self-state objects modified per clean session | `data/recovery/rollback-cost/bin/p4_recovery_cost.py` | `p4_recovery_cost_result.json` — 236 scanned, 150 writing, 86 non-writing |
| **§5.2** — matched-control validation (nested-CV AUC 0.5983) | `DET/rebuild_supervised_3pool.py`, `DET/supervised/*.py` | `DET/FINAL_3POOL_SUPERVISED_TABLEFRAG.md`, `DET/supervised/REPORT.json` |

## Populations, catalog, and measurement quality

| Paper | Produced by | Read from |
|---|---|---|
| **Table 4** — clean corpus by workload profile (176 train / 60 held out) | `experiments/code/dataset_builder/{build_p2_clean_split,extend_p2_clean_split,build_p2_gen2_clean_inputs,build_p2_clean_user_message_cases}.py`; frozen by `measurement/freeze_p2_{clean,gen2_clean,heldout}_accounting.py` | `DET/FINAL_3POOL_SPLIT_MANIFEST.json`, pools 1–2 |
| **Table 5, Table 12** — 23 structural cells → 43 executable bindings | `experiments/code/dataset_builder/canonical_matrix_audit.py`, `attacks/canonical_v4.py`, `workload/taxonomy.py` | recomputable — see [`REPRODUCE.md`](../REPRODUCE.md). `data/superseded/COVERAGE_23CELL_RECOMPUTE.json` separately records which cells the attack corpus actually fills |
| **§4.3** — the 55 attack executions (52 folds) | user-message carriers: `build_mass_um_profile_inputs{,_w2w4}.py` (MUC/MUI); content-append: `build_mass_profile_content_append_inputs.py` (MCAW); semantic: `build_mass_profile_semantic_inputs.py` (MSI); chmod: `build_mass_profile_chmod_inputs.py` (MCH); truncate/unlink: `build_mass_profile_destructive_inputs.py` (MTR/MUL); W3 C-series: `build_p2_l0_newcase_inputs{,_b2,_b3}.py`, `build_p2_l0_um_instcfg_inputs.py`, `build_p2_l0_archetype_inputs.py` | `DET/FINAL_3POOL_SPLIT_MANIFEST.json`, pool 3 and `fold_map_attack_loso` |
| **Table 6** — five co-collected host views | `dataset_builder/paired_live_four_source.py`, `five_source_graph_bridge.py`, `live_trace/live_ebpf.bpf.c` | per-run collector records in the archived corpus |
| **Table 6 → detector inputs** — normalization and export | `measurement/stage_g_harness/{normalize,audit,scap,sidecars,libsinsp_extract,libsinsp_reattribute,libsinsp_compare,export_p2_detector_inputs}.py` | `data/superseded/DERIVATION_AVAILABILITY_MATRIX.json` |
| **§4.4, §5 preamble** — admission gates (fd→path ≥ 0.95, zero drops, no excluded writes) | `dataset_builder/recollection_readiness.py` | `DET/FINAL_3POOL_SPLIT_MANIFEST.json`, `anti_leakage_asserts` |
| **§4.4** — 16-case operation-observability validation | `dataset_builder/{mutation_matrix_canary,mutation_canary_five_source,mutation_matrix_run,mutation_op_canary}.py` | `data/observability/operation-matrix/REPORT.md` — 4 mechanisms × 4 target roles, all 16 graph-witnessed, with the full run bundle. `data/observability/four-operation-canary/` is the earlier 4-operation run that established the integration |
| **§D.4** — fail-closed cross-generation binding | `measurement/stage_g_harness/generation_contract.py` | `DET/FINAL_3POOL_SPLIT_MANIFEST.json`, `generation_contract` |
| **Table 11** — execution environment fingerprint | recorded per run by `paired_live_four_source.py` | `DET/FINAL_3POOL_SPLIT_MANIFEST.json`, `generation_contract` and `uid_spotcheck` |
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
