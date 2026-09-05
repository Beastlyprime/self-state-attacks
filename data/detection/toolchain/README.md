# Detector runtimes

Two of the detector arms need a container and, for UNICORN, three upstream
checkouts. An earlier version of this release named the images and commit hashes
but published neither a recipe nor the upstream URLs, which made those arms
unbuildable from here for no good reason — both projects are public. The recipes
below are the ones the published rows were produced with, copied verbatim.

Neither arm is byte-reproducible even with them: `apt` snapshots move, and the
UNICORN analyzer is stochastic. What they buy is that the arms can be *built and
run* rather than only read.

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
image name from `--aide-image` and the scratch root from `ASSA_SCRATCH`.

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

## Why these arms still are not reproducible from this release

Building the runtime is necessary, not sufficient. `score_unicorn_gen5_3pool.py`
also needs the sketch and profile models — ~18 GB of analyzer intermediates,
regenerable from the provenance graphs in `tier_b` with the toolchain above, and
not archived. The frozen rows are in `data/detection/unicorn/`, and
`SKETCH_STATUS.json` records why 27 of the 115 runs are unscored.
`score_aide_3pool.py` needs only the image and the corpus.
