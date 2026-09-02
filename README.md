# SELFSTATE

An OS-layer benchmark for **self-state attacks** on self-hosted AI agents: attacks
in which a semantically compromised agent uses its own authority to corrupt the
persistent state that governs its future behaviour — memory, instructions, and
configuration.

The benchmark exists to answer one question: **how far can ordinary operating-system
mechanisms go in defending that state?** It pairs an attack catalog and four
contrastive legitimate workloads with a five-source Linux telemetry pipeline, and
scores representative prevention, detection, provenance and recovery mechanisms on
the result.

This repository accompanies the paper [*Self-State Attacks on Self-Hosted AI Agents:
How Far Can OS Defenses Go?*](https://arxiv.org/abs/2607.17986) (arXiv:2607.17986).

---

## What you get

| | |
|---|---|
| **An attack catalog** | 23 structural cells expanded to 43 executable operations over memory, instruction and configuration state, with concrete file bindings |
| **An adjudicated attack corpus** | 55 attack executions in 52 folds — 35 model-driven persistent writes plus 20 metadata/namespace mutations |
| **A clean corpus** | 236 executions across four workload profiles: 176 for fitting, 60 held out for false-positive measurement, split into 32 natural-write and 28 no-write |
| **Frozen detector results** | AIDE, Falco, STIDE, UNICORN, two write-feature baselines and three supervised models, each with attack coverage, TPR, natural-workload FPR and cluster-bootstrap intervals |
| **Prevention, provenance and recovery results** | a six-operation × five-configuration kernel replay, a matched provenance comparison, and a recovery isolation matrix with rollback-cost analysis |
| **The measurement pipeline** | the collector, normalizer and detector-native exporters that produced all of it |

## Repository layout

```
data/            frozen experimental outputs, organised by what they measure
  detection/       detector comparison: population manifest, scored outputs, scorers
    unicorn/         role-typed provenance-graph arm
    supervised/      supervised secondary analysis
    aide-fixtures/   per-run materialized self-state, split by population
                     (44 of 55 attacks; see its README for coverage)
    falco-inputs/    the earlier-generation Falco result the merger reads
  prevention/
    paired-probe/    the authorized-update selectivity arm of Table 7
  prevention/      mechanism x operation kernel replay
  recovery/        isolation matrix, protected supplement, rollback-cost analysis
  provenance/      nameability / attribution / causal-carrier analysis
  observability/   operation-observability validation of the collection substrate
  corpus-manifests/  provenance manifests for the raw telemetry corpus (see below)
  superseded/      earlier population cuts, retained for provenance only

experiments/
  code/            the pipeline: attacks, dataset_builder, measurement, defenses, workload
  agent/           openclaw_core, the reference agent backend
  agent_packs/     per-profile instruction-pack seeds
  tasks/           W1-W4 task definitions, schema, and workspace seeds

docs/            dataset description, methodology, paper-to-file map, limitations
  preregistration/ the UNICORN role-typing preregistration and execution amendment
                   that the UNICORN scorer binds by hash
```

## Start here

- **[`docs/results.md`](docs/results.md)** — every number reported in the paper, the
  code that produced it, and the file it was read from. If you want to check a
  specific claim, start here.
- **[`docs/dataset.md`](docs/dataset.md)** — what the populations are, how they were
  split, and what the record schemas contain.
- **[`REPRODUCE.md`](REPRODUCE.md)** — what re-runs from this repository alone, what
  needs the raw corpus, and how to obtain it.
- **[`docs/limitations.md`](docs/limitations.md)** — the scope boundaries. Worth
  reading before building on any of this.

## Quick check

Two steps re-derive their published output from this repository with no additional
data:

```bash
pip install -r requirements.txt

# Rebuilds the primary detector comparison from the frozen scored outputs.
python3 data/detection/final_aggregate.py

# Rebuilds the 23-cell / 43-operation attack catalog from the taxonomy.
python3 experiments/code/dataset_builder/canonical_matrix_audit.py --output /tmp/matrix.json
```

The test suite covers the pipeline's invariants:

```bash
python3 -m pytest
```

## The raw telemetry corpus

The per-run provenance graphs, state snapshots and native SCAP captures the
detection, provenance and recovery results are computed from are archived
separately: **19.5 GB in 12 volumes, 3.1 GB compressed**. `data/corpus-manifests/`
records their provenance and checksums, and [`REPRODUCE.md`](REPRODUCE.md) says
where each volume unpacks to and, per scorer, what the archive still does not
supply. Some results ship only as their frozen report — the Table 7 paired probe
in particular, whose per-run trees carry credentials and are not published.

The analyzer's own intermediate output — the UNICORN sketch and profile models,
another 18 GB — is not archived. It is regenerable from the shipped graphs *by
the pinned Python 2 toolchain*, which this release does not distribute, so in
practice that arm is checkable rather than re-runnable; the scored rows it
produced are in `data/detection/unicorn/`.

> **Archive DOI:** _to be assigned — see [`REPRODUCE.md`](REPRODUCE.md) for the
> current access route._

## Licence

Apache-2.0 for everything in this repository; see [`LICENSE`](LICENSE) and
[`NOTICE`](NOTICE). Upstream task corpora and third-party detectors are cited
rather than redistributed.
