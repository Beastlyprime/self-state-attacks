# W1 — Coding workload tasks

**Source:** [Aider-AI/polyglot-benchmark](https://github.com/Aider-AI/polyglot-benchmark), Python subset, pinned at commit `7e0611e7`.

**License:** Exercism Open Source (content © Exercism).

**Count:** 30 tasks, organized as 5 clusters × 6 variants. V1-V4 are the original sample; V5, V6 added 2026-04-25 to extend chains to 30 unique tasks without repetition.

**Regenerate:** `python -m tasks.curate_w1` (idempotent; rerun after bumping `AIDER_COMMIT` to refresh).

## Cluster layout

| Cluster | Theme           | V1                 | V2              | V3               | V4              | V5                | V6                        |
| :-----: | --------------- | ------------------ | --------------- | ---------------- | --------------- | ----------------- | ------------------------- |
| C1      | string/encoding | affine-cipher      | pig-latin       | phone-number     | proverb         | transpose         | bottle-song               |
| C2      | data-structures | simple-linked-list | zipper          | tree-building    | grade-school    | list-ops          | pov                       |
| C3      | algorithms      | poker              | go-counting     | zebra-puzzle     | two-bucket      | bowling           | dominoes                  |
| C4      | parsing/DSL     | forth              | wordy           | sgf-parsing      | dot-dsl         | scale-generator   | variable-length-quantity  |
| C5      | io/system       | paasio             | grep            | rest-api         | react           | connect           | robot-name                |

## Task shape

Each task stages two files in the agent workspace:

- `<module>.py` — starter stubs the agent must implement.
- `<module>_test.py` — Python stdlib `unittest` suite (not to be modified).

**Success:** `python -m unittest <module>_test` exits 0.

**Budget (override default):** `max_turns=48`, `max_total_tokens=150_000`.

## Attribution

Exercism content is used under the Exercism Open Source licenses. Each
task's upstream Exercism page is recorded in `dataset_source.url`.
