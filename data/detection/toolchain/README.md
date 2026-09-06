# Detector runtimes

Three detector arms need something built first: AIDE and UNICORN a container,
UNICORN three upstream checkouts, STIDE one. An earlier version of this release
named the images and commit hashes but published neither the recipes nor the
upstream URLs, which made those arms unbuildable from here for no good reason —
all three projects are public. The recipes below are the ones the published rows
were produced with, copied verbatim.

Building them does not make all three byte-reproducible. STIDE does reproduce its
frozen rows exactly. AIDE and UNICORN do not: `apt` snapshots move and the
UNICORN analyzer is stochastic. What the recipes buy for those two is that the
arms can be *built and run* rather than only read.

## AIDE — `assa-stage-g/aide:0.19.3`

Upstream <https://github.com/aide/aide>, release 0.19.3. `aide/Dockerfile`
expects the source in `source/`:

```bash
cd data/detection/toolchain/aide
git clone --depth 1 --branch v0.19.3 https://github.com/aide/aide source
docker build -t assa-stage-g/aide:0.19.3 .
```

`GIT_VERSION=v0.19.3` is passed to `autogen.sh` because the shallow clone has no
tag history to derive the version from. The scorer invokes the image with
`--config` and a per-run scratch directory; `score_aide_3pool.py` takes the
image name from the `AIDE_IMAGE` constant at the top of the file — there is no
command-line flag — and the scratch root from `ASSA_SCRATCH`.

## UNICORN — `assa-stage-g/unicorn-python2:2.7.18` and three checkouts

Upstream <https://github.com/crimson-unicorn>, the artifact of *UNICORN:
Runtime Provenance-Based Detector for Advanced Persistent Threats* (Han et al.,
NDSS 2020). The three repositories, pinned to the commits
`score_unicorn_gen5_3pool.py` asserts and
`data/detection/unicorn/UNICORN_GEN5_FINAL_REPORT.json` records:

| Repository | Commit | Clone to |
|---|---|---|
| `crimson-unicorn/parsers` | `8ae2d9e9c187cc78d8127b3abe1366a7ebc56e23` | `/tmp/assa-stage-g-unicorn-parsers-py2-final` |
| `crimson-unicorn/modeler` | `648e8605c4305c0f98d33d11d48d5719c555ac0b` | `/tmp/assa-stage-g-unicorn-modeler-py2-final` |
| `crimson-unicorn/analyzer` | `3026e8cbd6b0b7a0db07c0a815f064a69b924ff1` | `/tmp/assa-stage-g-unicorn-analyzer` |

```bash
for r in parsers modeler analyzer; do
  case $r in
    analyzer) dst=/tmp/assa-stage-g-unicorn-analyzer ;;
    *)        dst=/tmp/assa-stage-g-unicorn-$r-py2-final ;;
  esac
  git clone https://github.com/crimson-unicorn/$r.git "$dst"
done
git -C /tmp/assa-stage-g-unicorn-parsers-py2-final  checkout 8ae2d9e9c187cc78d8127b3abe1366a7ebc56e23
git -C /tmp/assa-stage-g-unicorn-modeler-py2-final  checkout 648e8605c4305c0f98d33d11d48d5719c555ac0b
git -C /tmp/assa-stage-g-unicorn-analyzer           checkout 3026e8cbd6b0b7a0db07c0a815f064a69b924ff1

cd data/detection/toolchain/unicorn
docker build -t assa-stage-g/unicorn-python2:2.7.18 .
```

The scorer asserts all three commit hashes and refuses to run on a mismatch, so
a wrong revision fails loudly rather than producing different rows. The paths
above are the defaults; each is overridable with a `--*-repo` flag.

Two things in `unicorn/Dockerfile` are worth reading before you copy it:

- The base is pinned by digest to `python:2.7.18`, and the Debian
  archive is pinned to the `20200414T000000Z` snapshot, because buster's
  Python 2 packages are long gone from the live mirrors. Both pins are what make
  a 2020-era Python 2 stack installable in 2026 at all.
- The `.aarch64-linux-gnu.so` symlink loop exists because the images were built
  on arm64, where Debian's Python 2 extension modules carry a multiarch suffix
  that the 2.7.18 interpreter in the base image does not look for. On x86-64 the
  loop matches nothing and is harmless; if you build on another architecture,
  adjust the suffix.

## STIDE — the pinned LID-DS checkout

Upstream <https://github.com/LID-DS/LID-DS>, the Leipzig Intrusion Detection Data
Set toolkit, whose `algorithms/` package provides the STIDE building block.
`score_stide_3pool.py` expects it at `/tmp/assa-stage-g-lid-ds`, pinned to the
commit the split manifest records under `generation_contract.monitor_versions`:

| Repository | Commit | Clone to |
|---|---|---|
| `LID-DS/LID-DS` | `587d15870843961acb78fbb4b8fcd0ede28eabcc` | `/tmp/assa-stage-g-lid-ds` |

```bash
git clone https://github.com/LID-DS/LID-DS.git /tmp/assa-stage-g-lid-ds
git -C /tmp/assa-stage-g-lid-ds checkout 587d15870843961acb78fbb4b8fcd0ede28eabcc
```

No container: the bridge in
`experiments/code/measurement/stage_g_harness/stide_bridge.py` imports
`algorithms.building_block` from the checkout directly. Unlike the other two,
this arm *is* byte-reproducible — `score_stide_3pool.py` rebuilds
`scored_stide_3pool.json` exactly, given the corpus and this checkout.

## Why these arms still are not reproducible from this release

Building the runtime is what was missing; it is not what makes the arm
byte-reproducible. `score_unicorn_gen5_3pool.py` builds ~18 GB of sketch and
profile models from the `tier_b` provenance graphs as it runs — those are the
analyzer's own work product, which is why they are not archived, not a missing
input you have to find. What you cannot get back is determinism: the analyzer is
stochastic, so a rerun gives its own numbers rather than the frozen ones. Those
are in `data/detection/unicorn/`, and `SKETCH_STATUS.json` records why 27 of the
115 runs are unscored. `score_aide_3pool.py` needs only the image and the corpus.
