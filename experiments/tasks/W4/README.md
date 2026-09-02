# W4 — General workload tasks

**Source:** self-authored by the SELFSTATE authors. No upstream
benchmark; the tasks are hand-written general-assistant scenarios
(drafting, reading, organizing, planning, light data work) designed to
exercise the kinds of turn-by-turn operations real Cowork / OpenClaw
users do outside a single technical domain.

**License:** CC-BY 4.0.

**Count:** 30 tasks, organized as 5 clusters × 6 variants. V1-V4 are the original sample; V5, V6 added 2026-04-25 to extend chains to 30 unique tasks without repetition.

**Regenerate:** `python -m tasks.curate_w4` (idempotent; tasks are
defined statically in the curator, no sampling).

## Cluster layout

| Cluster | Theme           | V1                | V2                  | V3                   | V4                         | V5                       | V6                            |
| :-----: | --------------- | ----------------- | ------------------- | -------------------- | -------------------------- | ------------------------ | ----------------------------- |
| C1      | email-drafting  | PM roadmap reply  | customer complaint  | 5-msg inbox triage   | 3-msg thread summary       | recruiter outreach reply | rent-renewal counter-offer    |
| C2      | notes-reading   | CAP summary       | meeting → actions   | abstract → plain     | reviews → report           | replication tradeoff     | hiring-debate digest          |
| C3      | file-organize   | downloads sort    | dated notes subdirs | image ext normalize  | old-file cleanup           | mixed-case ext normalize | macOS screenshot rename+sort  |
| C4      | schedule-plan   | find free slot    | SF trip itinerary   | 3-hour todo planning | launch checklist topo-sort | weekly 90-min slot       | family Chicago trip plan      |
| C5      | data-light      | CSV filter + sort | JSON agg → CSV      | TSV outlier detect   | inventory reorder list     | expense category split   | subscription monthly audit    |

## Why self-authored?

No existing public benchmark cleanly covers "general" assistant work
in the way the paper's workload taxonomy needs. HotpotQA (W2) is
knowledge-retrieval, InterCode-Bash (W3) is DevOps, Aider-polyglot
(W1) is coding. The general-purpose bucket — write this email, tidy
this folder, plan this afternoon — is exactly what the existing
benchmarks skip. Rather than stitch together five partial datasets
(a route we previously rejected as a "5-dataset pile"), we hand-wrote
20 realistic scenarios scoped to the agent workspace.

## Task shape

Each task stages a small seed tree in the agent workspace (1–10 files
depending on cluster) and gives the agent a natural-language prompt
describing the scenario. Seed trees use mundane content: fake emails,
notes, inventory CSVs, a cluttered downloads folder, etc.

**Success:** `kind = "none"` — trace-only, no automated scoring. The
workload trace is the measurement; what the agent actually produces
is not graded by the harness. This matches the paper's design that
trace is the primary measurement and success is a sanity check that
only W1/W2/W3 provide (W1 via unit tests, W2 via gold-answer match,
W3 via `bash_state_check` for the 12 InterCode variants).

**Budget (override default):** `max_turns=32`, `max_total_tokens=100_000`.

## Attribution

Tasks are © SELFSTATE authors, released under CC-BY 4.0 so
third parties can reuse or extend the workload without friction.
