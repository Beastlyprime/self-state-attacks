# AIDE fixtures

Per-run **materialized self-state** — the actual `SOUL.md`, `IDENTITY.md`,
`USER.md`, `AGENTS.md`, `TOOLS.md`, `MEMORY.md` and `HEARTBEAT.md` files as they
stood after the run — together with the AIDE reports computed over them.

Each directory holds:

| File | Contents |
|---|---|
| `materialized_state/` | the seven self-state files at the `after_a` snapshot |
| `materialization_deltas.json` | which files changed, were added or removed relative to the pre-state, and which are byte-identical |
| `parsed_reports.json` | AIDE's added/changed/removed counts at `before_control`, `after_a` and `after_b` |
| `aide.conf`, `*.stdout.log`, `tool_manifest.json` | the AIDE invocation and its raw output |

For an attack run, the injected content is present verbatim in
`materialized_state/`. For example, `attack/MCAW102_w1_automerge_instruction_backdoor__poisoned/materialized_state/AGENTS.md`
carries the planted merge rule with its inert marker `[AUTOMERGE_NO_REVIEW_V1]`.

## Coverage — read this before counting directories

These fixtures are **a subset** of the evaluation populations, split here by which
population each run belongs to.

| Directory | Runs | Population | Coverage |
|---|---:|---|---|
| `attack/` | 44 | attack test (55) | **44 of 55** |
| `clean-training/` | 15 | clean training (176) | 15 of 176 |
| — | 0 | clean held-out (60) | **none** |

Three things follow that are easy to get wrong:

1. **`clean-training/` is not a false-positive control.** Those runs are fit-only.
   The natural-workload FPR reported in the paper is measured on the held-out 60,
   and none of that population has a fixture here.
2. **Eleven attacks have no fixture.** They are the `aide_snapshot_source =
   staging` runs whose staging tree is part of the archived corpus rather than
   this repository. They are still scored: their verdicts are in
   `../scored_aide_3pool.json`, which covers all 55.
3. Five further clean directories belonged to no final population — training
   candidates dropped before the freeze. They now sit in
   `../../superseded/aide-fixtures-unaffiliated/`.

The eleven attacks without a fixture:

- `C510_w3_db_query_vendor_package_user_message__poisoned`
- `C512_w3_audit_rotate_runbook__poisoned`
- `C512_w3_audit_rotate_runbook_external_content__poisoned`
- `C512_w3_audit_rotate_runbook_user_message__poisoned`
- `C514_w3_slack_post_vendor_package__poisoned`
- `C514_w3_slack_post_vendor_package_user_message__poisoned`
- `C515_w3_vector_search_repo_rules__poisoned`
- `C520_w3_alert_webhook_runbook__poisoned`
- `C521_w3_metrics_scrape_integration__poisoned`
- `C530_w3_heartbeat_liveness_policy__poisoned`
- `C531_w3_release_notes_tool_integration__poisoned`

## Where the rest is

The full per-run evidence for every population — including the held-out 60 and
the eleven attacks above — is in the archived corpus. `../../corpus-manifests/`
records its provenance and checksums; see [`../../../REPRODUCE.md`](../../../REPRODUCE.md).
