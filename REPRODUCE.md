# Reproduction

This document is explicit about three different things people mean by
"reproduce". Level 1 holds for every reported number bar one, noted in the table. Level 2 works
for two steps from a bare clone; Level 3 needs the archived corpus, and some arms
need more than that.

| Level | What it means | Possible here |
|---|---|---|
| **1. Check** | read a reported number out of a frozen output and compare it against the paper | yes, with one exception: §4.4's `= 1.0` resolution rate has per-run evidence for 100 of 236 clean executions, the rest only for the `≥ 0.95` gate it was admitted under. `docs/results.md` has the coverage table and lists the paper sentence as a revision item |
| **2. Re-derive** | recompute a reported number from the shipped intermediate outputs | yes, for two steps |
| **3. Re-run** | recompute from raw telemetry, or collect new telemetry | no — needs the archived corpus, or a privileged Linux host |

## Setup

```bash
pip install -r requirements.txt
python3 -m pytest        # exercises the pipeline's invariants
```

`pytest.ini` supplies the import roots. 585 tests are collected. Seven fail
because they read frozen intermediate directories that are not shipped, and one
more passes or fails with host timing — so 577 or 578 pass, depending on the
run. *Known non-passing tests* below names all eight.

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
- §4.4 admission gates — `tier_a/clean_admission/` in the corpus, recomputed by
  `python3 data/corpus-manifests/check_admission.py`. Its coverage is not uniform
  across the four quantities §4.4 reports; `docs/results.md` has the table

Each result directory carries a `SHA256SUMS` over the files it ships:

```bash
cd data/detection && sha256sum -c FINAL_3POOL_SHA256SUMS.txt
```

Two of these files are **not** directory inventories and `sha256sum -c` on them
is the wrong tool:

- `data/corpus-manifests/manifests/TIER_A_SHA256SUMS.txt` records
  acquisition-time hashes for corpus tiers that are not in this repository. It
  is a provenance record, not a manifest of shipped files.
- `data/corpus-manifests/ARCHIVE_SHA256SUMS.txt` is the corpus release index,
  mirrored here so the scorers can verify their inputs. Its 16,698 keys are
  relative to the corpus payload root, and the twelve volumes unpack to four
  different places under `data/`, so about 3,000 of them — everything under
  `staging/`, `provenance-inputs/` and `aux/` — cannot resolve from the
  directory it sits in. To check an unpacked corpus against it, use the mapping:

  ```bash
  python3 data/corpus-manifests/corpus_index.py --verify
  # 16698 verified, 0 not unpacked, 0 MISMATCHED     (~11 s)
  ```

  It reports what is not unpacked separately from what mismatches, and exits
  non-zero only on a mismatch, so it is also the quick way to see which volumes
  a partial unpack is missing.

One inventory is checked from a different place. `data/detection/unicorn/SHA256SUMS.txt`
lists its files relative to the repository root, because it also covers the
UNICORN adapter code under `experiments/code/measurement/`; run
`sha256sum -c data/detection/unicorn/SHA256SUMS.txt` from the root rather than
from inside the directory.

## Level 3 — what needs the corpus

Each per-detector scorer consumes per-run telemetry that is archived separately —
native SCAP captures, and the libsinsp reconstructions, normalized syscall
streams, provenance graphs and state snapshots derived from them, plus the
detector staging trees. No scorer reads all of those; which one reads what is in
the table further down. Two things the archive does **not** contain: the pinned
Python 2 UNICORN toolchain, published instead as a recipe in
[`data/detection/toolchain/`](data/detection/toolchain/README.md), and the
superseded generations, which are deliberately excluded. None of these scorers
re-derives its output from a bare clone:

`data/detection/score_aide_3pool.py`, `score_stide_3pool.py`, `score_ours_3pool.py`,
`merge_falco_3pool.py`, `score_unicorn_gen5_3pool.py`, `rebuild_supervised_3pool.py`,
`build_manifest.py`, `data/provenance/p5_analyze.py`,
`data/recovery/rollback-cost/bin/p4_recovery_cost.py`.

Three of them need **only** the corpus and genuinely recompute their shipped
output. The test we apply is stricter than re-running: delete the output first,
so a byte-identical result cannot come from the file itself.

```bash
tar -I zstd -xf selfstate-corpus-provenance-inputs.tar.zst -C data/provenance/ \
  --transform 's|^provenance-inputs|inputs|'
tar -I zstd -xf selfstate-corpus-tier_b-clean_train.tar.zst   -C data/corpus-manifests/
tar -I zstd -xf selfstate-corpus-tier_b-clean_heldout.tar.zst -C data/corpus-manifests/
tar -I zstd -xf selfstate-corpus-tier_b-attacks.tar.zst       -C data/corpus-manifests/
tar -I zstd -xf selfstate-corpus-tier_b-attacks_lockedpop_cseries.tar.zst \
                                                              -C data/corpus-manifests/
tar -I zstd -xf selfstate-corpus-staging.tar.zst              -C data/superseded/

rm data/provenance/P5_NAMEABILITY_ATTRIBUTION_REPORT.json
python3 data/provenance/p5_analyze.py           # Table 9, under a second, pure Python

rm data/detection/scored_ours_3pool.json
python3 data/detection/score_ours_3pool.py      # the B1/B2 rows of Tables 8 and 14

rm data/recovery/rollback-cost/p4_recovery_cost_result.json
python3 data/recovery/rollback-cost/bin/p4_recovery_cost.py   # Table 15, about ten seconds

git diff --stat data/                           # expect no change
```

All three come back byte-identical. Each also refuses to emit a partial
result: `p5_analyze.py` exits with a population mismatch if the volume is
missing bundles, `score_ours_3pool.py` does the same on all three of its
populations — 176 training runs, 23 b1b2-definable attacks, 60 held-out clean
runs — and `p4_recovery_cost.py` requires exactly the 236 clean sessions of the
frozen split, no fewer and no others. A short input reads exactly like a
detector that scored lower, or a write process that was quieter.

All four scripts that overwrite a frozen output from corpus inputs —
`p5_analyze.py`, `score_ours_3pool.py`, `score_stide_3pool.py` and
`p4_recovery_cost.py` — also check that each input **is the published input**,
not merely that a file is there. They hash every stream, graph and measured
snapshot they read against `data/corpus-manifests/ARCHIVE_SHA256SUMS.txt`, the
release checksum index mirrored here from the corpus, and refuse before fitting
or writing if anything differs — 123 inputs for Table 9, 259 streams plus 7,135
snapshot files for B1/B2, 291 streams for STIDE, and 236 streams for Table 15.
That is the only check a truncation cannot walk past: a stream cut down to its
first record is a parseable file whose every record still names the right run.

The other corpus readers: `build_manifest.py` and `rebuild_supervised_3pool.py`
never overwrite their frozen outputs by construction, and `merge_falco_3pool.py`
carries its clean side forward rather than deriving it. `score_aide_3pool.py`
does overwrite `scored_aide_3pool.json` when it completes, so it verifies every
snapshot tree against the same index before the container runs on any of them;
it still needs the image built from `data/detection/toolchain/`, and its rows
are not byte-reproducible. `score_unicorn_gen5_3pool.py` needs the Python 2
toolchain, is stochastic, and does not verify its inputs; its default `--output`
is the frozen `data/detection/unicorn/`, so pass another directory to keep the
published rows.

Two weaker checks are kept for the error messages they give — an empty stream,
or one carrying another run's records, is named as such — along with two outcome
assertions: each b1b2-definable attack must resolve a self-state write, and
every clean run recorded as performing one must show it. `corpus_index.py`
states the limit plainly: this is a reproduction check, not a security
boundary. Anyone who can rewrite the inputs can rewrite the index. What it buys
is that a truncated, half-copied or substituted input cannot quietly republish
different numbers under a frozen filename.

The B1/B2 test above was re-run in a tree that contains nothing but this
repository and the unpacked volumes, with no path back to the collection host.
That matters because an earlier version of the corpus shipped the eleven W3
C-series attacks in the `staging` volume as **absolute symlinks** into the
authors' own working tree: on this machine they resolved and the scorer looked
correct, and anywhere else they dangled and it silently evaluated 12 of 23. The
same eleven trees are published under `tier_b/attacks_lockedpop_cseries` and are
byte-identical on both streams the scorers read, so the symlinks were dropped
and the scorers resolve attacks from the attack pools when `staging` does not
carry them.

`merge_falco_3pool.py` is a partial case and we state the limit rather than
imply otherwise. With `tier_a` unpacked it reassembles the **55 attack
decisions** from the three published replay results, and normalises the rule
names on read (the corpus keeps the name Falco actually ran under, which differs
from the one the paper uses). The **60 clean decisions are carried forward** from
the shipped `scored_falco_3pool.json`: the held-out clean replay ran on the guest
and its raw output was never archived, so Falco's false-positive rate is
checkable but not recomputable. Apply the delete-first test and it fails
outright — that is the honest signature of a carried-forward side.

`rebuild_supervised_3pool.py` runs to completion from the corpus. Its
**substrate A block recomputes exactly** — nested-CV AUC .5983, its interval,
every control and the McNemar counts. Its **substrate B AUCs do not, and cannot**:
that block selected syscall streams with an unordered glob, several of the 46
streams it reads had more than one distinct copy on the collection host, and the
copy the published fit used was never recorded. What the corpus does yield is
order-independent — each of the 46 streams appears once in the published volumes,
the single duplicate is byte-identical — and the recomputed block publishes a
`stream_selection` map of every path and SHA-256 it read, so the replacement
figures can be checked even though the originals cannot. It writes
`FINAL_3POOL_SUPERVISED.recomputed.json` and leaves the shipped file untouched;
`docs/results.md` has the details. `score_aide_3pool.py` and `score_stide_3pool.py` resolve their
full populations from the corpus but still need, respectively, the AIDE
container image and the pinned STIDE checkout. Both are published as recipes in
[`data/detection/toolchain/`](data/detection/toolchain/README.md), so both can be
executed once they are built — and STIDE then reproduces its frozen rows
byte-for-byte.

The prevention replay (`data/prevention/bin/`) is a live kernel probe, not a data
transformation: it needs a privileged container with AppArmor enforcing and a
Landlock-capable kernel.

### After unpacking the corpus, what still blocks each scorer

The scorers read repository-relative paths that the corpus volumes fill in, so
unpacking resolves their data inputs. Three need something the corpus cannot
supply, and we state that rather than imply otherwise:

| Scorer | Still needs |
|---|---|
| `score_stide_3pool.py` | the pinned STIDE checkout at `/tmp/assa-stage-g-lid-ds` — `LID-DS/LID-DS` at commit `587d1587…`, recorded in the split manifest's `monitor_versions` and in [`data/detection/toolchain/`](data/detection/toolchain/README.md). With it the arm reproduces byte-for-byte |
| `score_unicorn_gen5_3pool.py` | three pinned `crimson-unicorn` checkouts and the image `assa-stage-g/unicorn-python2:2.7.18` — upstream URLs, commits and the Dockerfile are in [`data/detection/toolchain/`](data/detection/toolchain/README.md). The arm then produces its own ~18 GB of sketch and profile models from the `tier_b` graphs; those are the analyzer's work product, not a missing input, and are not archived because the run regenerates them |
| `score_aide_3pool.py` | the AIDE container `assa-stage-g/aide:0.19.3` — recipe in [`data/detection/toolchain/`](data/detection/toolchain/README.md) — and a writable scratch directory, overridable with `ASSA_SCRATCH` |

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

The archive is **19.5 GB unpacked / 3.0 GB compressed in 12 volumes**, scoped to
the populations the paper's results are computed from, and published as one
record of zstd volumes.
`data/corpus-manifests/ARCHIVE_MANIFEST.json` describes the tiers and
`manifests/` records per-file acquisition provenance and checksums.

Every volume carries its own top-level directory, so the column below is the
`tar -C` target, not where the content ends up — `staging` extracted into
`data/superseded/` produces `data/superseded/staging/`.

| Volume | Populations | `tar -C` |
|---|---|---|
| `tier_b-clean_train` | clean training, 176/176 | `data/corpus-manifests/` |
| `tier_b-clean_heldout` | clean held-out, 60/60 | `data/corpus-manifests/` |
| `tier_b-attacks` + `tier_b-attacks_lockedpop_cseries` | attacks, 55/55 | `data/corpus-manifests/` |
| `tier_b-twins` + `tier_b-twins_lockedpop_cseries` | 55 matched clean branches | `data/corpus-manifests/` |
| `tier_c` | SCAP captures for the Falco replay | `data/corpus-manifests/` |
| `tier_a`, `manifests` | manifests and the §4.4 admission evidence the scorers read, acquisition provenance | `data/corpus-manifests/` |
| `staging` | 102 detector staging runs — 44 attacks and 58 clean | `data/superseded/` |
| `provenance-inputs` | the graphs, ground truth and census Table 9 reads | `data/provenance/`, renamed to `inputs/` |
| `aux` | STIDE stopping-rule preregistration, and a second copy of the landed census (Table 9 reads the `provenance-inputs` copy) | `data/` |

Most volumes carry a `tier_*`/`manifests` root and belong under
`data/corpus-manifests/`; three do not:

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
— is a live inotify probe, and the kernel may coalesce the two MODIFY events an
`open(path, 'w')` produces into one. Its own docstring says so. It passes in
isolation and fails intermittently in a full-suite run on a loaded machine; it
is timing, not a property of the data or the code under test.
