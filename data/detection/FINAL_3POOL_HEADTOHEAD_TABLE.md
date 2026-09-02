# Audited final three-pool detector results (2026-08-25)

Manifest `44c2b92d35fc` · Report `d674629b906f`.

Point estimates use executions/attack operations; bracketed intervals are cluster bootstraps over the independent scenario/fold. Boundary cells additionally report cluster-any Wilson intervals.

## Primary detector comparison

| Detector | Training data | Attack coverage | Attack TPR / end-to-end recall | Natural-clean FPR |
|---|---|---:|---:|---:|
| AIDE | None | 55/55 | 52/55 (0.9455) [0.8750, 1.0000], 52 clusters | 32/60 (0.5333) [0.3333, 0.7333], 20 clusters |
| Falco | None (frozen rules) | 55/55 | 43/55 (0.7818) [0.6667, 0.8868], 52 clusters | 21/60 (0.3500) [0.2000, 0.4833], 20 clusters |
| STIDE | 176 clean | 55/55 | 55/55 (1.0000) [1.0000, 1.0000], 52 clusters; cluster-any Wilson [0.9312, 1.0000] | 58/60 (0.9667) [0.9167, 1.0000], 20 clusters |
| UNICORN | 134/176 clean sketches | 41/55 evaluable | 35/41 (0.8537) [0.7317, 0.9512], 39 clusters | 35/47 (0.7447) [0.5366, 0.9149], 20 clusters |
| B1 pooled | 176 clean | 23/55 definable | conditional 19/23 (0.8261) [0.5926, 1.0000], 20 clusters; end-to-end 19/55 (0.3455) [0.2182, 0.4815], 52 clusters | 10/60 (0.1667) [0.0500, 0.3167], 20 clusters |
| B2 per-profile | 176 clean | 23/55 definable | conditional 20/23 (0.8696) [0.7083, 1.0000], 20 clusters; end-to-end 20/55 (0.3636) [0.2407, 0.4912], 52 clusters | 7/60 (0.1167) [0.0000, 0.2667], 20 clusters |
| Supervised L1 logistic | 176 clean + four attack folds | 23/55 definable | grouped 5-fold 15/23 (0.6522) [0.4167, 0.9000], 20 clusters; end-to-end 15/55 (0.2727) [0.1538, 0.4000], 52 clusters | 7/60 (0.1167) [0.0500, 0.2000], 20 clusters |
| Supervised CART | 176 clean + four attack folds | 23/55 definable | grouped 5-fold 15/23 (0.6522) [0.4194, 0.9000], 20 clusters; end-to-end 15/55 (0.2727) [0.1538, 0.4000], 52 clusters | 3/60 (0.0500) [0.0000, 0.1333], 20 clusters |
| Supervised FIGS | 176 clean + four attack folds | 23/55 definable | grouped 5-fold 13/23 (0.5652) [0.3478, 0.8000], 20 clusters; end-to-end 13/55 (0.2364) [0.1296, 0.3571], 52 clusters | 3/60 (0.0500) [0.0000, 0.1333], 20 clusters |

## Natural-clean write decomposition

| Detector | Write executions (12 scenarios) | No-write executions (11 scenarios) |
|---|---:|---:|
| AIDE | 32/32 (1.0000) [1.0000, 1.0000], 12 clusters; cluster-any Wilson [0.7575, 1.0000] | 0/28 (0.0000) [0.0000, 0.0000], 11 clusters; cluster-any Wilson [0.0000, 0.2588] |
| Falco | 21/32 (0.6562) [0.5862, 0.7188], 12 clusters | 0/28 (0.0000) [0.0000, 0.0000], 11 clusters; cluster-any Wilson [0.0000, 0.2588] |
| STIDE | 32/32 (1.0000) [1.0000, 1.0000], 12 clusters; cluster-any Wilson [0.7575, 1.0000] | 26/28 (0.9286) [0.8333, 1.0000], 11 clusters |
| UNICORN | 27/27 (1.0000) [1.0000, 1.0000], 11 clusters; cluster-any Wilson [0.7412, 1.0000] | 8/20 (0.4000) [0.1364, 0.7222], 11 clusters |
| B1 pooled | 10/32 (0.3125) [0.1111, 0.5333], 12 clusters | 0/28 (0.0000) [0.0000, 0.0000], 11 clusters; cluster-any Wilson [0.0000, 0.2588] |
| B2 per-profile | 7/32 (0.2188) [0.0000, 0.4688], 12 clusters | 0/28 (0.0000) [0.0000, 0.0000], 11 clusters; cluster-any Wilson [0.0000, 0.2588] |
| Supervised L1 logistic | 7/32 (0.2188) [0.0938, 0.3529], 12 clusters | 0/28 (0.0000) [0.0000, 0.0000], 11 clusters; cluster-any Wilson [0.0000, 0.2588] |
| Supervised CART | 3/32 (0.0938) [0.0000, 0.2333], 12 clusters | 0/28 (0.0000) [0.0000, 0.0000], 11 clusters; cluster-any Wilson [0.0000, 0.2588] |
| Supervised FIGS | 3/32 (0.0938) [0.0000, 0.2333], 12 clusters | 0/28 (0.0000) [0.0000, 0.0000], 11 clusters; cluster-any Wilson [0.0000, 0.2588] |

## Matched-control validation

This analysis is restricted to the canonical 23/55 write-resolved attacks and 23 recovered matched twins (20 scenarios); it is not an all-55 head-to-head row.

| Substrate / negative base | Population | Result | Interpretation |
|---|---:|---:|---|
| Size/timing, matched twins | 23 attack + 23 twin | nested-CV AUC 0.5983 [0.4597, 0.7415]; TPR 0.4348, FPR 0.1739 | CI includes chance |
| Syscall n-grams, matched twins | 23 attack + 23 twin | L1-LR AUC 0.4991; RuleFit AUC 0.4915 | At chance |

## Balanced training-size ablation

| Seed | B1 TPR / FPR | B2 TPR / FPR |
|---:|---:|---:|
| 11 | 19/23 / 11/60 | 20/23 / 8/60 |
| 23 | 18/23 / 10/60 | 20/23 / 8/60 |
| 42 | 18/23 / 10/60 | 20/23 / 7/60 |
| 101 | 18/23 / 10/60 | 20/23 / 8/60 |
| 2026 | 18/23 / 10/60 | 20/23 / 7/60 |

## Interpretation

Across held-out natural workloads, the evaluated OS baselines exhibit a coverage--false-alarm tradeoff rather than a uniformly dominant detector. AIDE is evaluable on all 55 attacks and detects 52, but flags every observed clean self-state write; Falco lowers the marginal false-positive rate while missing attack classes; STIDE detects all attacks after applying its frozen per-run stream selection but flags nearly all clean executions. UNICORN exposes a workload-dependent graph signal on 41 evaluable attacks, but its 35/41 detections coincide with 35/47 natural-clean alarms. The write-specific B1/B2 baselines have lower marginal false-positive rates but are defined for only 23 of 55 attacks. Thus OS event streams provide useful operational evidence, while the evaluated baselines do not yet combine broad attack coverage with a low false-alarm burden.

The former clean-40 comparison is retained only for provenance and must not be used to infer the direction of FPR bias because half of that set overlaps the training freeze.
