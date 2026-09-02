# B1/B2 size+timing anomaly detector on REAL pinned libsinsp traces

**Derivation generation:** `p2_b1b2_size_timing_libsinsp_20260822` — NEW generation. **NOT comparable to any prior size+timing numbers.** The prior version scored SYNTHETIC `WorkloadGeneratorV4` ops with SYNTHETIC gamma timestamps (`exp2b_temporal.generate_timestamps`) and is withdrawn-class; those numbers must not be cited. This run feeds the SAME z-score method (paper §5.1 Eq.1) REAL write syscalls + REAL nanosecond timestamps from `graph/libsinsp/libsinsp_events.jsonl` and REAL net size deltas from `state_snapshots/{before_a,after_a}`. Same fix pattern as the P5 recompute.

Defensive analysis. Offline, read-only on sources, no network, no VM, no payload execution.

## 1. Method (exact feature / threshold defs, verbatim from code)

Detector = per-`(file, op_type)` z-score, paper §5.1 Eq.1:
`score(e) = max( |Δsize − μ_s|/σ_s , |logΔt − μ_t|/σ_t )`, decision at **τ = 2.0**.

- **size feature**: `Δsize = size_after − size_before` (net per-`(run,file)` from state_snapshots); `σ_eff = max(σ_size, |μ_size|·0.1, 1.0)`; `size_z = |Δsize − μ_size|/σ_eff`. Verbatim from `exp2b_anomaly.py::compute_anomaly_score` Term 1.
- **timing feature**: `logΔt` of consecutive same-`(bucket,op)` write syscalls within a run (real ns→s, 1 ms floor); `timing_z = |logΔt − μ_t|/σ_t` (σ=0→5.0 if logΔt≠μ). Verbatim from `compute_anomaly_score` Term 2 / `exp2b_temporal.py` inter-write interval.
- **combined** = `max(size_z, timing_z)` (Eq.1 max()).
- **unseen `(file,op)` key → score = 1e6** (paper +∞), i.e. flagged.
- Bucket collapse `workspace/memory/*.md` via `workload.taxonomy.bucket_key`.

**Runtime self-check:** my scorer reproduces the library `compute_anomaly_score` exactly on a constructed event (lib=1.365385, mine=1.365385, match=True).

**Code paths:** `experiments/code/measurement/exp2b_anomaly.py::compute_anomaly_score`; `trace_baseline.py::fit_baseline_from_train_events`; `exp2b_temporal.py`; `trace_injection_detection.py` (B2 driver); `exp2_b1_workload_blind.py` (B1 ablation).

**Size-dedup note:** size baseline uses ONE net delta per `(clean run, file)`; timing baseline uses all intra-run inter-write intervals. Minor deviation from the library fitter (which duplicates the net delta per write syscall); justified because the net snapshot delta is a per-`(run,file)` quantity — libsinsp write events carry no byte count.

## 2. Corpus & baseline

- Census landers: 21. Analyzable with LOCAL libsinsp: **17** (per class {'Instruction': 5, 'Configuration': 6, 'Memory': 6}; profiles {'W3': 11, 'W4': 6}).
- **Excluded 4** (no local `graph/libsinsp/libsinsp_events.jsonl`; par21_original graph format only): C510, C515, C511, C513 (2 Instruction, 1 Config, 1 Memory).
- **Underpowered:** per-class cells (Inst/Cfg/Mem = 5/6/6) are all < 8 → underpowered. Pooled 17 is powered (census floor 8).
- **Baseline = AUXILIARY paired `__clean` control runs** (same bundles), fit per-`(file,op)`. **Deviation flagged:** the spec 156/20 clean freeze graphs are on a remote host, not local; this uses the paired clean control (same §5.2 / P5 convention). Clean FPR uses **leave-one-run-out** to avoid self-membership.
- **Denominator:** attack TPR is **DIAGNOSTIC** (operational-landing; polarity / manual review PENDING). Clean FPR is the meaningful near-final quantity.

## 3. B1 vs B2 — FPR (near-final) and diagnostic TPR

| arm | variant | TPR (diag) pooled | FPR pooled | Inst TPR | Cfg TPR | Mem TPR | Inst FPR | Cfg FPR | Mem FPR |
|---|---|---|---|---|---|---|---|---|---|
| B1 | combined | 0.3529 (6/17) | 0.1395 (6/43) | 0.4 | 0.1667 | 0.5 | 0.0909 | 0.1538 | 0.1579 |
| B1 | size | 0.2941 (5/17) | 0.0698 (3/43) | 0.2 | 0.1667 | 0.5 | 0.0 | 0.0769 | 0.1053 |
| B1 | timing | 0.25 (2/8) | 0.125 (3/24) | 0.5 | 0.0 | None | 0.2 | 0.1111 | 0.1 |
| B2 | combined | 0.3529 (6/17) | 0.2093 (9/43) | 0.4 | 0.1667 | 0.5 | 0.0909 | 0.3077 | 0.2105 |
| B2 | size | 0.2941 (5/17) | 0.1395 (6/43) | 0.2 | 0.1667 | 0.5 | 0.0 | 0.2308 | 0.1579 |
| B2 | timing | 0.3333 (3/9) | 0.1923 (5/26) | 0.5 | 0.0 | 1.0 | 0.2 | 0.2727 | 0.1 |

**ΔTPR / ΔFPR (B2 − B1):**

| variant | class | ΔTPR | ΔFPR |
|---|---|---|---|
| combined | Instruction | 0.0 | 0.0 |
| combined | Configuration | 0.0 | 0.1539 |
| combined | Memory | 0.0 | 0.0526 |
| combined | pooled | 0.0 | 0.0698 |
| size | Instruction | 0.0 | 0.0 |
| size | Configuration | 0.0 | 0.1539 |
| size | Memory | 0.0 | 0.0526 |
| size | pooled | 0.0 | 0.0697 |
| timing | Instruction | 0.0 | 0.0 |
| timing | Configuration | 0.0 | 0.1616 |
| timing | Memory | None | 0.0 |
| timing | pooled | 0.0833 | 0.0673 |

## 4. Does workload-conditioning narrow the gap? Is it ineffective on I-class?

**No — conditioning does not narrow the gap, and it raises FPR.** On real libsinsp traces:

- **ΔTPR(B2−B1) = 0.0 for combined and size across every class and pooled.** Per-profile conditioning yields ZERO attack-detection gain here.
- **I-class (Instruction): structurally ineffective, as §4.4 predicts.** ΔTPR = 0 and absolute TPR is low (combined 0.40, size 0.20): the legitimate `TOOLS.md` write distribution (clean net deltas ≈ 97–300 B) already contains the attack marker's size feature (attack deltas ≈ 259–396 B), so most attack writes score below τ regardless of baseline. Confirmed on real data.
- **Also ineffective on Config/Memory here** because in this corpus class and profile are confounded (Instruction + most Config = W3; Memory mostly W4), so a per-profile split ≈ a per-class split and adds no discriminative structure beyond the per-`(file,op)` key.
- **B2 is strictly worse on FPR:** ΔFPR(B2−B1) = +0.07 pooled (Config +0.15, Memory +0.05), including 2 unseen-key flags induced by the smaller per-profile clean pools. Splitting the baseline shrinks each pool and tightens/starves the per-key statistics.

Net: the §4.4 gap-narrowing hypothesis is **not observed** on this real corpus; conditioning's ineffectiveness on I-class is **confirmed**.

## 5. Size vs timing

Adding the timing feature **does change decisions, weakly and mostly unfavorably**, and is **inapplicable to the majority of landings** (single writes):

- Attack side (B1): combined TPR 6/17 vs size-only 5/17 — timing adds exactly **+1** detection (C514_um: size 1.91 < τ but timing 8.16 → flagged).
- Clean side (B1): combined FPR 6/43 vs size-only 3/43 — timing adds **+3** false flags.
- So over size-alone, timing buys +1 TPR at the cost of +3 FPR — net unfavorable.

## 6. Timing data_insufficient (feasibility)

- **Attack markers:** 9/17 (B1), 8/17 (B2) are single writes → per-file inter-write interval undefined → **data_insufficient, never imputed**.
- **Clean write-ops:** 19/43 (B1), 17/43 (B2) data_insufficient.
- Timing is thus a minority feature on this corpus; the size term carries the combined score for most landings.

## 7. Discipline
Real sizes/timestamps only; no synthetic data. Prior synthetic-data numbers discarded and not cited. Auxiliary-control deviation flagged (§2). Labeled a NEW derivation generation, not comparable to any prior generation. Read-only on all sources.
