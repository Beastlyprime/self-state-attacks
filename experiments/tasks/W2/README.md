# W2 — Knowledge workload tasks

**Source:** [FRAMES](https://huggingface.co/datasets/google/frames-benchmark)
(Krishna et al. 2024, "Fact, Fetch, and Reason"). 824 multi-hop
research-style questions whose answers require combining facts from
2–11 Wikipedia articles.

**License:** Apache-2.0.

**Count:** 30 tasks, organized as 5 clusters × 6 variants. V1-V4 are the original sample; V5, V6 added 2026-04-25 to extend chains to 30 unique tasks. `rng.sample` preserves prefix under fixed seed, so V1-V4 selections (and cached Wikipedia oldids) are unchanged.

**Regenerate:** `python3 -m tasks.curate_w2` (idempotent; fixed RNG seed
for reproducible sampling; articles cached by (slug, oldid) so re-runs
produce bit-identical seed bytes).

## Why FRAMES (not HotpotQA)

Earlier W2 drafts used HotpotQA dev-distractor, which stages 10
one-paragraph distractor files per question. That was convenient but
the task shape ("read 10 short paragraphs, answer the question in a
single short string") is unlike the workload profile it was supposed to
represent — a "knowledge assistant" with heavy memory writes across
sessions. HotpotQA tasks don't incentivize any kind of note-taking:
prompt and gold answer are both 1-line.

FRAMES fits W2 better:

- Each question invites agent to read **multiple full-article lead
  sections** (mean 3, up to 11), not short distractor paragraphs.
- Reasoning types naturally produce **intermediate findings worth
  logging** — numerical, tabular, temporal, or multi-constraint
  derivations that the agent can record in `memory/{today}.md` as it
  works. With the w2_knowledge Instruction pack's "write down what
  matters" rule, this produces the memory-layer write traffic the W2
  profile was parameterized against.
- Questions are purposely designed to be non-shortcut-solvable —
  evaluating reasoning across sources, not pattern-matching.

The Instruction pack (`experiments/agent_packs/w2_knowledge/workspace/AGENTS.md`) tells
the agent to log intermediate findings during research-shaped tasks.
Task prompts themselves stay clean ("read the articles, answer the
question"). The memory-write traffic comes from the agent's own
decision that this is research worth tracking.

## Cluster layout

FRAMES rows carry multi-label `reasoning_types` (e.g. `Numerical
reasoning | Tabular reasoning | Multiple constraints`). We assign each
question one primary cluster using this precedence:

```
PostProcessing > Tabular > Numerical > Temporal > MultipleConstraints
```

The most-specific label wins. `Multiple constraints` is the fallback
bucket for questions with no other specific tag. Pool sizes after
primary-label assignment:

| Cluster | FRAMES label          | Pool | Notes |
| :-----: | --------------------- | :--: | ----- |
| C1      | Post processing       | 107  | Rarest type — pinned first so specific wins |
| C2      | Tabular reasoning     | 203  | Table / rank / list lookups |
| C3      | Numerical reasoning   | 155  | Arithmetic, counting, comparison |
| C4      | Temporal reasoning    | 94   | Dates, durations, sequencing |
| C5      | Multi-constraints     | 265  | Composition; residual fallback bucket |

Sampling uses a fixed RNG seed (`RANDOM_SEED = 20260424`) so 4 picks
per cluster are reproducible.

## Task shape

Each task stages a variable number of article files (one per Wikipedia
page the question references):

- `article_01.md` … `article_NN.md` — one Wikipedia article per file.
  Each file contains the **lead section** (plaintext, via
  `prop=extracts&exintro=1&explaintext=1`), plus a header with the
  Wikipedia URL and the pinned revision id.

The revision id is recorded in `meta.articles[].oldid` of each task
JSON. The curator caches one copy per `(slug, oldid)` under
`tasks/seeds/_wiki_cache/`, so re-runs reuse the cached body instead of
re-fetching.

**Prompt:** read the articles, answer the question; final response
must be the answer alone — no explanation or preamble. Prompt
deliberately contains no memory-write directive: the Instruction pack
at `experiments/agent_packs/w2_knowledge/workspace/AGENTS.md` is what instructs the
agent to log intermediate findings.

**Success:** `qa_answer_match` — fuzzy match against
`success_criterion.gold_answer`. Evaluator: `measurement/task_eval.py`.

**Budget:** `max_turns=32`, `max_total_tokens=120_000` — larger than
HotpotQA W2 because multi-source reasoning + memory writes push turn
and token counts up.

## Integrity pins

- FRAMES test.tsv SHA256 is pinned in `curate_w2.py` as
  `FRAMES_EXPECTED_SHA256`. If upstream publishes a new version the
  curator prints a warning with the new hash.
- Each Wikipedia article is pinned by its oldid. The first fetch of a
  title resolves the *current top* oldid; the second and subsequent
  fetches use that pinned oldid. This means the benchmark is stable
  against Wikipedia edits once curated — and any re-curation is
  recorded because the oldid in `meta.articles[]` changes.

## Attribution

FRAMES is released under Apache-2.0. Each task records its original
FRAMES row index in `dataset_source.upstream_id` so reviewers can look
up the exact question in the upstream TSV.

**Citation:** Krishna, S., Krishna, K., Mohananey, A., Schwarcz, S.,
Stambler, A., Upadhyay, S., & Faruqui, M. (2024). *Fact, Fetch, and
Reason: A Unified Evaluation of Retrieval-Augmented Generation*. arXiv
preprint arXiv:2409.12941.
