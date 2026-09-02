# Reproduction

This document is explicit about three different things people mean by
"reproduce", because only the first is possible from this repository alone.

| Level | What it means | Possible here |
|---|---|---|
| **1. Check** | read a reported number out of a frozen output and compare it against the paper | yes, for every reported number |
| **2. Re-derive** | recompute a reported number from the shipped intermediate outputs | yes, for two steps |
| **3. Re-run** | recompute from raw telemetry, or collect new telemetry | no — needs the archived corpus, or a privileged Linux host |

## Setup

```bash
pip install -r requirements.txt
python3 -m pytest        # exercises the pipeline's invariants
```

`pytest.ini` supplies the import roots. 585 tests are collected and 1 is skipped.
Seven read frozen intermediate directories that are not shipped (see *Known
non-passing tests* below).

## Level 2 — what re-derives here

### The primary detector comparison (Tables 8 and 14)

```bash
python3 data/detection/final_aggregate.py
```

Reads the frozen per-detector scored outputs and the population manifest, and
rewrites `data/detection/FINAL_3POOL_REPORT.json` and
`data/detection/FINAL_3POOL_HEADTOHEAD_TABLE.md`. Every point estimate, confidence
interval and clean-control decomposition is reproduced unchanged.

### The structural attack catalog (Tables 5 and 12)

```bash
python3 experiments/code/dataset_builder/canonical_matrix_audit.py --output /tmp/matrix.json
```

Rebuilds the catalog from the taxonomy and the canonical attack suite:
`paper_cells` is 23, `summary.concrete_operations` is 43, and the per-cell
operation counts are the N column of Table 12.

## Level 1 — what is checkable

Everything else the paper reports is recorded in a frozen output you can read
directly. [`docs/results.md`](docs/results.md) maps each reported number to its
file. In particular:

- population definitions and anti-leakage assertions — `data/detection/FINAL_3POOL_SPLIT_MANIFEST.json`
- prevention replay cells — `data/prevention/p3_op_replay_matrix_result.json`
- provenance properties — `data/provenance/P5_NAMEABILITY_ATTRIBUTION_REPORT.json`
- recovery isolation matrix — `data/recovery/isolation-matrix/P4_RECOVERY_SELF_STATE_REPORT.json`
- rollback cost — `data/recovery/rollback-cost/p4_recovery_cost_result.json`
- operation-observability validation — `data/observability/operation-matrix/`

Each result directory carries a `SHA256SUMS` over the files it ships:

```bash
cd data/detection && sha256sum -c FINAL_3POOL_SHA256SUMS.txt
```

One inventory is expected **not** to verify:
`data/corpus-manifests/manifests/TIER_A_SHA256SUMS.txt` records acquisition-time
hashes for corpus tiers that are not in this repository. It is a provenance
record, not a manifest of shipped files.

## Level 3 — what needs the corpus

Each per-detector scorer consumes raw telemetry that is archived separately: the
per-run detector staging trees, syscall streams, provenance graphs, SCAP captures,
the pinned Python 2 UNICORN analyzer, and earlier frozen generations. These cannot
re-derive their outputs here:

`data/detection/score_aide_3pool.py`, `score_stide_3pool.py`, `score_ours_3pool.py`,
`merge_falco_3pool.py`, `score_unicorn_gen5_3pool.py`, `rebuild_supervised_3pool.py`,
`build_manifest.py`, `data/provenance/p5_analyze.py`,
`data/recovery/rollback-cost/bin/p4_recovery_cost.py`.

The prevention replay (`data/prevention/bin/`) is a live kernel probe, not a data
transformation: it needs a privileged container with AppArmor enforcing and a
Landlock-capable kernel.

**Running them here is safe.** Every one exits non-zero and leaves the shipped
outputs untouched. Three report the problem explicitly, stopping with a
`fail-closed:` message that names the absent input — `score_aide_3pool.py`,
`score_ours_3pool.py` and `p4_recovery_cost.py`. The rest stop on an ordinary
exception when an input path is missing, which is safe but less informative.

### Obtaining the corpus

The raw telemetry is roughly 18 GB and is archived outside this repository.
`data/corpus-manifests/ARCHIVE_MANIFEST.json` describes the tiers and
`manifests/` records per-file provenance and checksums.

> **Archive DOI:** _to be assigned._ Until the archive is published, the corpus is
> available on request.

### Collecting new telemetry

Fresh collection needs an unprivileged agent principal on a Linux host with
auditd, fanotify, eBPF (kernel BTF present) and Sysdig capture available, plus
model credentials. The reference environment is Ubuntu 22.04.5, Linux 6.8.0-136,
x86-64, ext4. `experiments/code/dataset_builder/paired_live_four_source.py` is the
collector and `recollection_readiness.py` implements the admission gates.

## Known non-passing tests

Seven tests read frozen intermediate directories that are too large to ship
(`dataset_v1_archive`, ~1.1 GB, and `p2_attack_tpr_expanded_v2`, ~4.9 GB): four in
`dataset_builder/tests/test_build_mass_*` and three in
`measurement/tests/test_p2_attack_stide_rebless.py`.

One more — `openclaw_core/tests/test_trace.py::test_truncate_rewrite_distinguishable_from_append`
— asserts on kernel write coalescing and is host-dependent. It passes on the
reference Linux 6.8 x86-64 configuration and is flaky on kernels that coalesce
more aggressively.
