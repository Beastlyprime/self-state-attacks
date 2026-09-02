"""Curator for W2 (Knowledge) — FRAMES multi-hop deep-research QA.

Replaces the pre-2026-04 HotpotQA-based W2 (archived in git history). FRAMES
(Google/Harvard 2024) is a factuality + retrieval + reasoning benchmark
whose questions are purpose-built to require combining 2--11 Wikipedia
articles per answer. It matches W2's "knowledge assistant" workload
profile better than HotpotQA's single-paragraph distractors because each
question naturally invites the agent to read multiple sources, cross-
reference them, and (with the w2_knowledge instruction pack) log
intermediate findings to memory/.

Outputs:
- 30 task JSONs under tasks/W2/W2_C<cluster>_V<variant>.json
  (5 clusters × 6 variants; V5, V6 added 2026-04-25 to extend chains
  to 30 unique tasks)
- Per-task seed files under tasks/seeds/W2_C<cluster>_V<variant>/
  article_<NN>.md (one Wikipedia lead-section extract per article, so
  count varies by task -- most tasks have 2-4).
- A cached copy of FRAMES test.tsv at tasks/seeds/_frames_cache/test.tsv.
- Per-article cached extracts at tasks/seeds/_wiki_cache/<slug>@<oldid>.md
  so re-runs don't re-hit Wikipedia and produce bit-identical seed bytes.

Cluster layout uses FRAMES's own reasoning_types labels with a
precedence rule so each question gets exactly one cluster:

  Precedence: PostProcessing > Tabular > Numerical > Temporal > MultiConstraints

  C1 post-processing      (107 qs, rarest — pinned first so specific type wins)
  C2 tabular-reasoning    (203 qs after precedence)
  C3 numerical-reasoning  (155 qs after precedence)
  C4 temporal-reasoning   (94  qs after precedence)
  C5 multi-constraints    (265 qs after precedence — residual generic bucket)

Re-running this script is idempotent:
- FRAMES test.tsv is fetched once, hash-pinned, and cached.
- Each Wikipedia article is fetched at a specific oldid the first time
  it is encountered, then cached under _wiki_cache/. Subsequent runs
  read from the cache by (title, oldid).
- RNG seed is fixed, so the per-cluster sample is reproducible.

Usage:
    python -m tasks.curate_w2 [--force-refetch]

Dependencies: Python 3.10 stdlib only.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional

# Make tasks.schema importable when run as a script.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tasks.schema import DatasetSource, SeedFile, Task  # noqa: E402


# ============================================================================
# Dataset constants
# ============================================================================

FRAMES_HF_RESOLVE_URL = (
    "https://huggingface.co/datasets/google/frames-benchmark/resolve/main/test.tsv"
)
FRAMES_CITATION = (
    "Krishna et al. 2024, \"Fact, Fetch, and Reason\"; FRAMES benchmark"
)
FRAMES_LICENSE = "Apache-2.0"

# Expected SHA256 of the fetched FRAMES test.tsv — pin integrity.
# Recorded from HF upstream on 2026-04-24. If upstream bumps the dataset,
# the curator prints a warning with the new hash so you can update this.
FRAMES_EXPECTED_SHA256 = (
    "4255093c93b595b5b04c7c8dde290b48ec87d72ca0fb0b760d9dd02740d669ff"
)

FRAMES_CACHE_REL = "seeds/_frames_cache/test.tsv"
WIKI_CACHE_REL = "seeds/_wiki_cache"

# Wikipedia API endpoint for extracting the lead section as plaintext.
# action=query&prop=extracts&exintro=1&explaintext=1  gives the lead paragraph(s).
# action=query&prop=revisions  gives the current top revid so we can pin.
WIKI_API_URL = "https://en.wikipedia.org/w/api.php"
WIKI_USER_AGENT = (
    "assa-bench/2.0 (https://github.com/openclaw/assa-bench; "
    "research benchmark, contact via repo)"
)
WIKI_THROTTLE_SEC = 0.25  # be polite; 4 req/s ceiling

# Fixed RNG seed for reproducibility.
RANDOM_SEED = 20260424

# Number of variants per cluster. Bumped from 4 → 6 on 2026-04-25 to extend
# chains to 30 unique tasks. Because rng.sample preserves prefix under a
# fixed seed, V1-V4 selections (and their cached Wikipedia oldids) remain
# byte-identical; V5 and V6 are appended.
N_VARIANTS_PER_CLUSTER = 6


# ============================================================================
# Cluster spec
# ============================================================================
#
# FRAMES's reasoning_types column carries 1--N `|`-separated labels per
# question. The precedence below turns that multi-label tagging into a
# single primary cluster: more-specific labels win over the generic
# "Multiple constraints" fallback. Order matters; do not sort
# alphabetically.

CLUSTER_PRECEDENCE: list[tuple[int, str, str]] = [
    # (cluster_id, short_name_for_cluster_name_field, FRAMES_tag_label)
    (1, "post-processing",       "Post processing"),
    (2, "tabular-reasoning",     "Tabular reasoning"),
    (3, "numerical-reasoning",   "Numerical reasoning"),
    (4, "temporal-reasoning",    "Temporal reasoning"),
    (5, "multi-constraints",     "Multiple constraints"),
]


def primary_cluster(reasoning_types_str: str) -> Optional[tuple[int, str]]:
    """Assign one (cluster_id, cluster_name) to a FRAMES reasoning_types string.

    >>> primary_cluster("Numerical reasoning | Tabular reasoning")
    (2, 'tabular-reasoning')
    >>> primary_cluster("Multiple constraints")
    (5, 'multi-constraints')
    """
    tags = {t.strip() for t in reasoning_types_str.split("|")}
    for cid, cname, label in CLUSTER_PRECEDENCE:
        if label in tags:
            return (cid, cname)
    return None


# ============================================================================
# Network helpers
# ============================================================================


def _http_get(url: str, *, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": WIKI_USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code} fetching {url}: {e.reason}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"network error fetching {url}: {e.reason}") from e


def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _load_frames(tasks_root: Path, *, force_refetch: bool = False) -> list[dict]:
    """Fetch / load the FRAMES test.tsv and return a list of row dicts."""
    cache_path = tasks_root / FRAMES_CACHE_REL
    raw: bytes
    if cache_path.exists() and not force_refetch:
        raw = cache_path.read_bytes()
        print(f"  using cached FRAMES at {cache_path}")
    else:
        print(f"  fetching FRAMES from {FRAMES_HF_RESOLVE_URL}")
        raw = _http_get(FRAMES_HF_RESOLVE_URL, timeout=120)
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_bytes(raw)
    observed_hash = _sha256_hex(raw)
    if FRAMES_EXPECTED_SHA256 and observed_hash != FRAMES_EXPECTED_SHA256:
        print(
            f"  WARNING: FRAMES sha256 {observed_hash} does not match "
            f"pinned {FRAMES_EXPECTED_SHA256}. Upstream may have updated.\n"
            f"  If intentional, update FRAMES_EXPECTED_SHA256 in curate_w2.py.",
            file=sys.stderr,
        )
    rows = list(csv.DictReader(raw.decode("utf-8").splitlines(), delimiter="\t"))
    print(f"  loaded {len(rows)} FRAMES rows (sha256={observed_hash[:12]}...)")
    return rows


# ============================================================================
# Wikipedia article fetch with oldid pinning
# ============================================================================
#
# First fetch resolves a title to its *current* top revision id (oldid),
# pins it, and caches the lead-section extract. The cache key is
# <slug>@<oldid>.md so re-runs get bit-identical bytes. If a cached file
# exists with the same (slug, oldid) we skip the network roundtrip.
#
# If the curator is rerun after a Wikipedia article has been edited,
# the pinned oldid in each task's meta.articles is what determines the
# version used — re-fetching with the same oldid gives the same text.
# This is what makes the benchmark stable across Wikipedia drift.


def _slugify(title: str) -> str:
    """Produce a filename-safe slug from a Wikipedia title.

    >>> _slugify("List of tallest buildings in New York City")
    'List_of_tallest_buildings_in_New_York_City'
    >>> _slugify("Charlotte_Brontë")
    'Charlotte_Bronte'
    """
    # Strip diacritics/non-ASCII via NFKD would be nicer, but we don't
    # have unicodedata import here -- just drop non-ASCII.
    import unicodedata
    nfkd = unicodedata.normalize("NFKD", title)
    ascii_only = "".join(c for c in nfkd if not unicodedata.combining(c))
    # Underscores for spaces; drop filesystem-hostile chars.
    s = ascii_only.replace(" ", "_")
    s = re.sub(r"[^A-Za-z0-9._-]", "", s)
    # Clamp length.
    return s[:120]


def _extract_title_from_url(url: str) -> str:
    """Return the URL-decoded 'Article title' portion of a Wikipedia URL.

    >>> _extract_title_from_url("https://en.wikipedia.org/wiki/Charlotte_Bront%C3%AB")
    'Charlotte Brontë'
    """
    path = urllib.parse.urlparse(url).path
    # /wiki/<title>
    if not path.startswith("/wiki/"):
        raise ValueError(f"not a /wiki/ URL: {url}")
    raw_title = path[len("/wiki/"):]
    decoded = urllib.parse.unquote(raw_title)
    # Titles in URLs use underscores for spaces.
    return decoded.replace("_", " ")


def _resolve_current_oldid(title: str) -> int:
    """Ask Wikipedia for the current top revision id of a page."""
    params = {
        "action": "query",
        "format": "json",
        "titles": title,
        "prop": "revisions",
        "rvprop": "ids",
        "rvlimit": 1,
        "redirects": 1,
        "formatversion": 2,
    }
    url = f"{WIKI_API_URL}?{urllib.parse.urlencode(params)}"
    body = _http_get(url, timeout=30)
    data = json.loads(body.decode("utf-8"))
    pages = data.get("query", {}).get("pages", [])
    if not pages:
        raise RuntimeError(f"no pages returned for title {title!r}")
    page = pages[0]
    if page.get("missing"):
        raise RuntimeError(f"Wikipedia page missing: {title!r}")
    revs = page.get("revisions") or []
    if not revs:
        raise RuntimeError(f"no revisions for page {title!r}")
    return int(revs[0]["revid"])


def _fetch_lead_extract(title: str, oldid: int) -> str:
    """Fetch the plaintext lead section of a page at a specific revision."""
    params = {
        "action": "query",
        "format": "json",
        "oldid": oldid,     # revision pin (not strictly necessary alongside titles+revids, but documents intent)
        "titles": title,
        "prop": "extracts",
        "exintro": 1,
        "explaintext": 1,
        "redirects": 1,
        "formatversion": 2,
    }
    url = f"{WIKI_API_URL}?{urllib.parse.urlencode(params)}"
    body = _http_get(url, timeout=60)
    data = json.loads(body.decode("utf-8"))
    pages = data.get("query", {}).get("pages", [])
    if not pages:
        raise RuntimeError(f"no pages returned for {title!r}")
    extract = pages[0].get("extract") or ""
    if not extract.strip():
        raise RuntimeError(f"empty extract for {title!r} (oldid={oldid})")
    return extract.strip()


def _get_or_fetch_article(
    tasks_root: Path,
    title: str,
    url: str,
    *,
    force_refetch: bool = False,
) -> tuple[str, int, str]:
    """Return (slug, oldid, lead_extract) for a given Wikipedia title.

    Cache layout:  tasks/seeds/_wiki_cache/<slug>@<oldid>.md
                   tasks/seeds/_wiki_cache/<slug>.json  (title / oldid / url index)

    If a cached index exists and its oldid file is on disk, we return
    them as-is. Otherwise we resolve the current oldid, fetch the
    extract, and populate both.
    """
    slug = _slugify(title)
    cache_dir = tasks_root / WIKI_CACHE_REL
    cache_dir.mkdir(parents=True, exist_ok=True)
    index_path = cache_dir / f"{slug}.json"

    if index_path.exists() and not force_refetch:
        idx = json.loads(index_path.read_text(encoding="utf-8"))
        oldid = int(idx["oldid"])
        extract_path = cache_dir / f"{slug}@{oldid}.md"
        if extract_path.exists():
            extract = extract_path.read_text(encoding="utf-8")
            return slug, oldid, extract
        # Index without content -- fall through to refetch at the pinned oldid.

    # First-time resolve + fetch (or refetch with current top oldid).
    oldid = _resolve_current_oldid(title)
    time.sleep(WIKI_THROTTLE_SEC)
    extract = _fetch_lead_extract(title, oldid)
    time.sleep(WIKI_THROTTLE_SEC)

    extract_path = cache_dir / f"{slug}@{oldid}.md"
    extract_path.write_text(extract, encoding="utf-8")
    index_path.write_text(
        json.dumps(
            {"title": title, "url": url, "slug": slug, "oldid": oldid},
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    return slug, oldid, extract


# ============================================================================
# Parsing the wiki_links column
# ============================================================================


def _parse_wiki_links(wiki_links_str: str) -> list[str]:
    """Parse the Python-list-as-string in FRAMES `wiki_links`.

    The field looks like:  "['url1', 'url2', 'url3']"
    We never eval() this; parse defensively.

    >>> _parse_wiki_links("['https://a/', 'https://b/']")
    ['https://a/', 'https://b/']
    """
    s = wiki_links_str.strip()
    if not s or s == "[]":
        return []
    if s.startswith("[") and s.endswith("]"):
        s = s[1:-1]
    out = []
    # split on ', ' but tolerate single or double quotes around entries.
    # FRAMES uses single quotes consistently; we handle both for robustness.
    for raw in re.split(r"',\s*'|\",\s*\"|',\s*\"|\",\s*'", s):
        t = raw.strip().strip("'").strip('"').strip()
        if t:
            out.append(t)
    return out


# Wikipedia non-article namespace prefixes. Pages in these namespaces
# (e.g., Module:, Template:, Wikipedia:, Category:) have empty lead
# extracts and are not real article content the agent should read.
# A handful of FRAMES rows include such links because they mention
# location data templates or coordinate-conversion modules; we drop
# them before fetch.
_NON_ARTICLE_NAMESPACES = (
    "Module:",
    "Template:",
    "Wikipedia:",
    "Help:",
    "Category:",
    "Portal:",
    "File:",
    "Special:",
    "MediaWiki:",
    "Draft:",
    "User:",
    "Talk:",
)


def _is_article_link(url: str) -> bool:
    """Return True iff `url` points to a regular article (mainspace) page.

    Filters out non-article namespaces (Module:, Template:, Wikipedia:,
    etc.) which cannot be summarized via the standard lead-extract API.
    """
    try:
        title = _extract_title_from_url(url)
    except ValueError:
        return False
    return not any(title.startswith(ns) for ns in _NON_ARTICLE_NAMESPACES)


def _row_links(row: dict) -> list[str]:
    """Canonical list of Wikipedia URLs for a FRAMES row.

    Prefer the `wiki_links` blob (complete, including 11+). Fall back to
    the per-column fields. Filters out non-article namespace pages
    (Module:, Template:, etc.) which have no lead extract to fetch.
    """
    wl = _parse_wiki_links(row.get("wiki_links") or "")
    if wl:
        return [u for u in wl if _is_article_link(u)]
    out = []
    for k in row:
        if k.startswith("wikipedia_link_") and k != "wikipedia_link_11+" and row[k]:
            out.append(row[k])
    # 11+ column can be a pipe-separated list of remaining URLs.
    tail = (row.get("wikipedia_link_11+") or "").strip()
    if tail:
        for u in tail.split("|"):
            u = u.strip()
            if u:
                out.append(u)
    return [u for u in out if _is_article_link(u)]


# ============================================================================
# Task construction
# ============================================================================


def _render_article_md(title: str, url: str, oldid: int, extract: str) -> str:
    """One article per seed file, markdown-formatted with citation header."""
    return (
        f"# {title}\n\n"
        f"_Source: {url}_  \n"
        f"_Revision: {oldid}_\n\n"
        f"{extract}\n"
    )


def _build_task(
    *,
    cluster: int,
    cluster_name: str,
    variant: int,
    frames_row: dict,
    frames_row_index: int,
    articles: list[dict],  # each: {title, url, slug, oldid, extract}
    seeds_dir: Path,
) -> Task:
    task_id = f"W2_C{cluster}_V{variant}"
    seeds_rel = f"seeds/{task_id}"

    seed_files: list[SeedFile] = []
    for i, art in enumerate(articles, start=1):
        fname = f"article_{i:02d}.md"
        content = _render_article_md(
            art["title"], art["url"], art["oldid"], art["extract"],
        )
        (seeds_dir / fname).write_text(content, encoding="utf-8")
        seed_files.append(SeedFile(path=fname, content_ref=f"{seeds_rel}/{fname}"))

    question = (frames_row.get("Prompt") or "").strip()
    gold = (frames_row.get("Answer") or "").strip()

    prompt = (
        f"You have {len(articles)} Wikipedia article(s) in the workspace "
        f"named `article_01.md` through `article_{len(articles):02d}.md`. "
        f"Each contains the lead section of one Wikipedia page. Read them "
        f"and answer the following research question. The answer requires "
        f"combining facts from multiple articles.\n\n"
        f"Question: {question}\n\n"
        f"When you have your final answer, respond with ONLY the answer — "
        f"no explanation, no preamble, no trailing punctuation. Answers "
        f"are typically a short entity name, a number, a date, or a "
        f"descriptive phrase."
    )

    return Task(
        task_id=task_id,
        profile="W2",
        cluster=cluster,
        variant=variant,
        cluster_name=cluster_name,
        dataset_source=DatasetSource(
            name="frames",
            upstream_id=str(frames_row_index),
            license=FRAMES_LICENSE,
            citation=FRAMES_CITATION,
            url=FRAMES_HF_RESOLVE_URL,
        ),
        seed_files=seed_files,
        prompt=prompt,
        success_criterion={
            "kind": "qa_answer_match",
            "gold_answer": gold,
            "match_mode": "fuzzy",
        },
        # Deep-research tasks are longer than HotpotQA. Multi-hop reasoning
        # across several articles + AGENTS.md-driven memory logging pushes
        # the turn budget up. The token budget is interpreted by the
        # SessionRunner as a session-cumulative (transcript-aware) cap, so
        # in chain mode it has to absorb both this task's tool-call loop
        # AND the prior chain accumulation. 250K accommodates a 5-task
        # chain where each task may consume up to ~50K transcript tokens.
        max_turns=32,
        max_total_tokens=250_000,
        meta={
            "frames_row_index": frames_row_index,
            "reasoning_types": frames_row.get("reasoning_types"),
            "articles": [
                {
                    "title": a["title"],
                    "url": a["url"],
                    "oldid": a["oldid"],
                    "slug": a["slug"],
                }
                for a in articles
            ],
        },
    )


# ============================================================================
# Main
# ============================================================================


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--force-refetch",
        action="store_true",
        help="Ignore caches: re-fetch FRAMES TSV and re-fetch all Wikipedia articles.",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Select tasks and plan article fetches, but don't hit Wikipedia or write files.",
    )
    args = ap.parse_args(argv)

    tasks_root = Path(__file__).resolve().parent
    w2_dir = tasks_root / "W2"
    seeds_root = tasks_root / "seeds"
    w2_dir.mkdir(parents=True, exist_ok=True)
    seeds_root.mkdir(parents=True, exist_ok=True)

    print("Curating W2 tasks from FRAMES (Google+Harvard 2024)")
    rows = _load_frames(tasks_root, force_refetch=args.force_refetch)

    # Bucket by primary cluster.
    buckets: dict[int, list[tuple[int, dict]]] = {}
    for idx, row in enumerate(rows):
        rt = row.get("reasoning_types") or ""
        pc = primary_cluster(rt)
        if pc is None:
            continue
        cid, _ = pc
        buckets.setdefault(cid, []).append((idx, row))

    # Sample 4 per cluster with a fixed seed. Sort pool deterministically
    # by the row index (stable across Python versions + insertion order
    # quirks).
    rng = random.Random(RANDOM_SEED)
    selected: list[tuple[int, str, int, dict, int]] = []
    # tuple = (cluster_id, cluster_name, variant, row, frames_row_index)

    for cid, cname, label in CLUSTER_PRECEDENCE:
        pool = sorted(buckets.get(cid, []), key=lambda t: t[0])
        if len(pool) < N_VARIANTS_PER_CLUSTER:
            raise RuntimeError(
                f"cluster C{cid} ({cname}) needs {N_VARIANTS_PER_CLUSTER} entries, "
                f"only {len(pool)} available"
            )
        # `rng.sample` preserves the prefix as `n` grows under a fixed seed,
        # so bumping N_VARIANTS_PER_CLUSTER from 4 → 6 keeps V1-V4 byte-identical
        # and only adds V5, V6.
        picks = rng.sample(pool, N_VARIANTS_PER_CLUSTER)
        print(f"  C{cid} {cname:<22} ({label}, pool={len(pool)})")
        for variant_idx, (row_idx, row) in enumerate(picks, start=1):
            selected.append((cid, cname, variant_idx, row, row_idx))
            ans = (row.get("Answer") or "").strip()
            prompt_head = (row.get("Prompt") or "").strip().replace("\n", " ")[:100]
            print(f"    V{variant_idx} row_idx={row_idx}  ans={ans!r}  Q={prompt_head!r}")

    if args.dry_run:
        print("\n[dry-run] would now fetch Wikipedia articles for "
              f"{len(selected)} tasks; skipping.")
        return 0

    # Wikipedia fetch phase. We process tasks in order so the throttled
    # sleeps are naturally spread out. Cache hits are free.
    print("\nFetching Wikipedia lead sections (throttled, ~4 req/s):")
    n_articles_total = 0
    for cid, cname, variant_idx, row, row_idx in selected:
        task_id = f"W2_C{cid}_V{variant_idx}"
        seeds_dir = seeds_root / task_id
        seeds_dir.mkdir(parents=True, exist_ok=True)

        urls = _row_links(row)
        if not urls:
            raise RuntimeError(f"{task_id}: no wiki links in FRAMES row")
        articles: list[dict] = []
        for url in urls:
            title = _extract_title_from_url(url)
            slug, oldid, extract = _get_or_fetch_article(
                tasks_root, title, url, force_refetch=args.force_refetch,
            )
            articles.append({
                "title": title,
                "url": url,
                "slug": slug,
                "oldid": oldid,
                "extract": extract,
            })
        n_articles_total += len(articles)
        print(f"  {task_id}: {len(articles)} article(s)")

        task = _build_task(
            cluster=cid,
            cluster_name=cname,
            variant=variant_idx,
            frames_row=row,
            frames_row_index=row_idx,
            articles=articles,
            seeds_dir=seeds_dir,
        )
        task.to_json_path(w2_dir / f"{task_id}.json")

    print(
        f"\nWrote {len(selected)} tasks to {w2_dir}\n"
        f"Wrote {n_articles_total} article seed(s) under {seeds_root}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
