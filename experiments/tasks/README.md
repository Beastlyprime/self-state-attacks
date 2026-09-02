# SELFSTATE Task Set

This directory holds the curated task set used to drive the four workload profiles (W1–W4) defined in `workload/profiles.py`. Each task is a single JSON file describing what the agent is asked to do, what seed files to stage in the workspace, and how success is measured.

Layout:

```
tasks/
├── README.md            ← this file
├── schema.py            ← dataclass + JSON (de)serializer for a Task
├── W1/                  ← 20 coding tasks (Aider polyglot, Python subset)
├── W2/                  ← 20 multi-hop QA tasks (HotpotQA dev-distractor)
├── W3/                  ← 20 DevOps tasks (12 InterCode-Bash + 8 self-authored)
└── W4/                  ← 20 general tasks (self-authored)
```

Each profile is organized as 5 clusters × 4 variants = 20 tasks. The cluster
breakdown and the dataset source for each profile are documented in per-profile
`README.md` files.

## Task JSON schema

Every task file is named `<profile>_C<cluster>_V<variant>.json` (e.g. `W1_C1_V2.json`)
and conforms to this shape:

```jsonc
{
  "task_id": "W1_C1_V2",                 // unique id: <profile>_C<cluster>_V<variant>
  "profile": "W1",                       // one of {W1, W2, W3, W4}
  "cluster": 1,                          // 1..5
  "variant": 2,                          // 1..4
  "cluster_name": "string/encoding",     // human-readable cluster label

  "dataset_source": {
    "name": "aider-polyglot",            // dataset identifier, or "authored"
    "upstream_id": "affine-cipher",      // stable id in the upstream dataset (if any)
    "license": "Exercism Open Source",   // license string for attribution
    "citation": "Aider-AI/polyglot-benchmark, commit <sha>",
    "url": "https://github.com/Aider-AI/polyglot-benchmark/tree/main/python/exercises/practice/affine-cipher"
  },

  "seed_files": [                        // files to stage at workspace root before run
    {
      "path": "affine_cipher.py",
      "content_ref": "seeds/W1_C1_V2/affine_cipher.py"   // relative to this README dir
    },
    {
      "path": "affine_cipher_test.py",
      "content_ref": "seeds/W1_C1_V2/affine_cipher_test.py"
    }
  ],

  "prompt": "Implement the encode() and decode() functions in affine_cipher.py so that all tests in affine_cipher_test.py pass. Run `python -m unittest affine_cipher_test` to verify.",

  "success_criterion": {
    "kind": "unittest_exit_zero",        // see "Success criterion kinds" below
    "command": "python -m unittest affine_cipher_test",
    "timeout_sec": 60
  },

  "max_turns": 32,                       // per-task budget override (optional)
  "max_total_tokens": 100000             // per-task budget override (optional)
}
```

### Success criterion kinds

The experiment's primary measurement is the **workload trace** (file-IO
signature, MEMORY/SOUL touch patterns, tool-call mix). Success on the task
is a **sanity check**, not the result. We only keep evaluators that are
deterministic and cheap:

| `kind`               | Used by         | Meaning                                                            |
| -------------------- | --------------- | ------------------------------------------------------------------ |
| `unittest_exit_zero` | W1              | Run `command` in workspace; pass iff exit code 0.                  |
| `qa_answer_match`    | W2              | Compare last assistant message against gold answer (fuzzy match).  |
| `bash_state_check`   | W3 InterCode    | Run `check_command`; pass iff its stdout equals `expected_output`. |
| `none`               | W3 authored, W4 | Trace-only; success not evaluated.                                 |

Explicitly removed (and rejected by the loader): `llm_judge`,
`bash_diagnosis_match`, `file_content_check`. These were considered and
dropped: LLM-as-judge adds noise with no upside given trace is the primary
measurement, and the regex/keyword-match variants add false-positive surface
for no research benefit.

The evaluator for each `kind` lives in `measurement/task_eval.py` (to be
written alongside the runner wiring).

### Seed files

Seed files are stored verbatim under `tasks/seeds/<task_id>/<path>`. The task
loader copies them into the workspace root before the session starts, then the
session runner handles bootstrap and hands control to the agent.

Binary or very large seeds (HotpotQA's 10 context paragraphs per question)
are written out at curation time by the curator scripts (see `tasks/curate_*.py`).

## Per-profile attribution

| Profile | Source                                  | License / Use                                       |
| ------- | --------------------------------------- | --------------------------------------------------- |
| W1      | Aider polyglot-benchmark (Python)       | Exercism Open Source; content © Exercism           |
| W2      | HotpotQA dev-distractor v1              | CC BY-SA 4.0                                        |
| W3      | 12 × InterCode-Bash (NL2Bash fs_1..fs_4)| Princeton NLP release under repo license            |
| W3      | 8 × self-authored (Loghub samples)      | Loghub samples used as input fixtures only (MIT)    |
| W4      | 20 × self-authored                      | Authored by the authors of this paper; CC-BY 4.0    |

Full citations will be emitted in paper §4 and `paper/references.md`.

## Reproducibility

- Every task JSON records `dataset_source.upstream_id` so a reviewer can
  retrieve the original from the upstream dataset.
- The curator scripts (`tasks/curate_*.py`) are seeded; rerunning them
  produces the same sample.
- Seed files are checked into the repository so no network access is
  required to re-run the experiments.
