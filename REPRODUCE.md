# Reproduction

This document is explicit about three different things people mean by
"reproduce", because only Level 1 holds for every reported number. Level 2 works
for two steps from a bare clone; Level 3 needs the archived corpus, and some arms
need more than that.

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
`summary.paper_cells` is 23, `summary.concrete_operations` is 43, and the
`operation_count` of each entry in the top-level `paper_cells` list is the N
column of Table 12.

This is a **structural** rebuild only. Run without `--bindings`, it reports
`gate.structural_passed = true` alongside `gate.production_complete = false` and
all 43 operations as `unbound`, because it has been given no execution records to
bind them to. It reproduces Tables 5 and 12; it does not attest that the catalog
was fully realised in production. That accounting is in
`data/superseded/COVERAGE_23CELL_RECOMPUTE.json`.

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
the pinned Python 2 UNICORN analyzer, and earlier frozen generations. None of them
re-derives its output from a bare clone:

`data/detection/score_aide_3pool.py`, `score_stide_3pool.py`, `score_ours_3pool.py`,
`merge_falco_3pool.py`, `score_unicorn_gen5_3pool.py`, `rebuild_supervised_3pool.py`,
`build_manifest.py`, `data/provenance/p5_analyze.py`,
`data/recovery/rollback-cost/bin/p4_recovery_cost.py`.

One of them needs **only** the corpus, nothing else, and genuinely recomputes
its shipped output — Table 9:

```bash
tar -I zstd -xf selfstate-corpus-provenance-inputs.tar.zst -C data/provenance/ \
  --transform 's|^provenance-inputs|inputs|'
python3 data/provenance/p5_analyze.py           # ~3 min, pure Python
git diff --stat data/provenance/                # expect no change
```

It refuses to emit a partial result: if the volume is missing bundles it exits
non-zero with a population mismatch rather than reporting a smaller,
plausible-looking count.

`merge_falco_3pool.py` is a partial case and we state the limit rather than
imply otherwise. With `tier_a` unpacked it reassembles the **55 attack
decisions** from the three published replay results, and normalises the rule
names on read (the corpus keeps the name Falco actually ran under, which differs
from the one the paper uses). The **60 clean decisions are carried forward** from
the shipped `scored_falco_3pool.json`: the held-out clean replay ran on the guest
and its raw output was never archived, so Falco's false-positive rate is
checkable but not recomputable. Re-running the script therefore reproduces the
shipped file byte-for-byte, which for the clean side is a copy, not evidence.

The prevention replay (`data/prevention/bin/`) is a live kernel probe, not a data
transformation: it needs a privileged container with AppArmor enforcing and a
Landlock-capable kernel.

### After unpacking the corpus, what still blocks each scorer

The scorers read repository-relative paths that the corpus volumes fill in, so
unpacking resolves their data inputs. Three need something the corpus cannot
supply, and we state that rather than imply otherwise:

| Scorer | Still needs |
|---|---|
| `score_stide_3pool.py` | the pinned STIDE implementation, expected at `/tmp/assa-stage-g-lid-ds` (commit `587d1587…`, recorded in the split manifest's `monitor_versions`) |
| `score_unicorn_gen5_3pool.py` | three pinned Python 2 checkouts — `/tmp/assa-stage-g-unicorn-parsers-py2-final`, `/tmp/assa-stage-g-unicorn-modeler-py2-final` and `/tmp/assa-stage-g-unicorn-analyzer` (the analyzer default carries no suffix; all three are `--*-repo` flags) and the container image `assa-stage-g/unicorn-python2:2.7.18`. The commit hashes are asserted by the scorer and recorded in `data/detection/unicorn/UNICORN_GEN5_FINAL_REPORT.json`; **we do not publish the upstream URLs or an image recipe**, so this arm is not re-runnable from this release alone |
| `score_aide_3pool.py` | a working AIDE container (`assa-stage-g/aide:0.19.3`) and a writable scratch directory, overridable with `ASSA_SCRATCH` |

`rebuild_supervised_3pool.py` additionally needs the four numerical packages at
the end of `requirements.txt`, which are **not** pinned to the versions that
produced the published numbers — see the note there.

`data/detection/supervised/*.py` — the §5.2 matched-control analysis — reads the
frozen B1/B2 operating points, now published at `data/detection/b1b2/`, but also
the mass-attack lane trees (`p2_mass_attack_lane*`) and the earlier
supervised-arm generation, which are **not** published. §5.2's shipped outputs
are checkable against `data/detection/supervised/SHA256SUMS.txt`; they are not
re-derivable from this release.

**Running them here is safe.** Every one exits non-zero and leaves the shipped
outputs untouched. Three report the problem explicitly, stopping with a
`fail-closed:` message that names the absent input — `score_aide_3pool.py`,
`score_ours_3pool.py` and `p4_recovery_cost.py`. The rest stop on an ordinary
exception when an input path is missing, which is safe but less informative.

### Obtaining the corpus

The archive is **19.5 GB unpacked / 3.1 GB compressed in 12 volumes**, scoped to
the populations the paper's results are computed from, and published as one
record of zstd volumes.
`data/corpus-manifests/ARCHIVE_MANIFEST.json` describes the tiers and
`manifests/` records per-file acquisition provenance and checksums.

| Volume | Populations | Unpack to |
|---|---|---|
| `tier_b-clean_train` | clean training, 176/176 | `data/corpus-manifests/` |
| `tier_b-clean_heldout` | clean held-out, 60/60 | `data/corpus-manifests/` |
| `tier_b-attacks` + `tier_b-attacks_lockedpop_cseries` | attacks, 55/55 | `data/corpus-manifests/` |
| `tier_b-twins` + `tier_b-twins_lockedpop_cseries` | 55 matched clean branches | `data/corpus-manifests/` |
| `tier_c` | SCAP captures for the Falco replay | `data/corpus-manifests/` |
| `tier_a`, `manifests` | manifests the scorers read, acquisition provenance | `data/corpus-manifests/` |
| `staging` | the 11 W3 attack graphs the UNICORN scorer reads | `data/superseded/staging/` |
| `aux` | STIDE stopping-rule preregistration; the landed census the provenance analysis reads | `data/aux/` |

Most volumes carry a `tier_*`/`manifests` root and belong under
`data/corpus-manifests/`, but three do not — unpack those from the repository
root so their own top-level directory lands in the right place:

```bash
mkdir -p data/corpus-manifests
for v in selfstate-corpus-tier_*.tar.zst selfstate-corpus-manifests.tar.zst; do
  tar -I zstd -xf "$v" -C data/corpus-manifests/
done
tar -I zstd -xf selfstate-corpus-staging.tar.zst           -C data/superseded/
tar -I zstd -xf selfstate-corpus-provenance-inputs.tar.zst -C data/provenance/ \
  --transform 's|^provenance-inputs|inputs|'
tar -I zstd -xf selfstate-corpus-aux.tar.zst               -C data/
```

Redaction in the archive is confined to metadata. Every file under
`state_snapshots/` is byte-identical to what the collector wrote, verified over
all 11,729 of them. Its `ARCHIVE_SHA256SUMS.txt` holds release checksums over the
redacted copy; acquisition-time hashes are in `manifests/`.

> **Archive DOI:** _to be assigned._ Until the record is published, the corpus is
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
