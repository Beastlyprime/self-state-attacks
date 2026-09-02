# Data

Frozen experimental outputs, organised by what they measure rather than by when
they were produced. [`../docs/results.md`](../docs/results.md) maps each number in
the paper to a file here.

| Directory | Contents |
|---|---|
| `detection/` | The primary detector comparison. `FINAL_3POOL_SPLIT_MANIFEST.json` defines all three populations and the anti-leakage assertions; `FINAL_3POOL_REPORT.json` and `FINAL_3POOL_HEADTOHEAD_TABLE.md` carry the assembled results; `scored_*.json` are the per-detector outputs; the `score_*.py` scripts produced them. |
| `detection/unicorn/` | The role-typed provenance-graph arm: final report, per-run verdicts, and the per-run pipeline status that explains every unscored graph. |
| `detection/supervised/` | The supervised secondary analysis — features, cross-validation outputs, and the matched-control comparison. |
| `detection/aide-fixtures/` | Per-run materialized self-state that the AIDE arm ran on, one directory per execution. |
| `prevention/` | The six-operation × five-configuration kernel replay and its result JSON. `bin/` holds the in-container probe. |
| `recovery/isolation-matrix/` | Protected vs same-user backup storage, crossed with ordinary corruption vs an attack that also destroys backups. |
| `recovery/protected-supplement/` | Restoration repeated across eight attacks spanning the state roles. |
| `recovery/rollback-cost/` | How much legitimate state a rollback discards, over 236 clean sessions. |
| `provenance/` | Nameability, principal attribution and causal-carrier analysis over 21 operational landings and their matched clean branches. |
| `observability/operation-matrix/` | The 16-case validation that the collection substrate witnesses every operation × target-role combination. `four-operation-canary/` is the earlier run that established the integration. |
| `corpus-manifests/` | Provenance and checksums for the raw telemetry corpus, which is archived separately. |
| `superseded/` | Earlier population cuts and their aggregators, retained for provenance. **Not paper estimates** — see the last section of `../docs/results.md`. |

## Checksums

Each directory carries a `SHA256SUMS` over the files it ships:

```bash
cd detection && sha256sum -c FINAL_3POOL_SHA256SUMS.txt
```

`corpus-manifests/manifests/TIER_A_SHA256SUMS.txt` is the one exception: it records
acquisition-time hashes for corpus tiers that are not in this repository, so it is
not expected to verify here.

## Redaction

Host paths, home directories, VM addresses and credential paths are replaced with
stable placeholders (`<REPO_ROOT>`, `<HOME>`, `<SCRATCH>`, `<GUEST_HOME>`,
`<COLLECTOR_HOST>`, `<GUEST_HOST_A/B/C>`). Run identifiers, timestamps, event
ordering, labels, counts and measured values are preserved verbatim.

Path strings recorded inside frozen result files refer to collection-time
locations and do not correspond to this repository's layout. They are left as
recorded rather than rewritten, so that the provenance in each result file remains
what the pipeline actually wrote.
