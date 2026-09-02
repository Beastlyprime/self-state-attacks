# Paired direct-write probe

The authorized-update half of Table 7. The six-operation replay next door asks
which mutation paths a policy closes; this asks whether closing them also rejects
an update the operator approved.

`P3_PREVENTION_SELF_STATE_ERRNO_REPORT.json` records, per mechanism:

| Field | Meaning |
|---|---|
| `marker_blocked` | the attack-designated write was refused |
| `legitimate_update_blocked_collateral` | the operator-approved write was refused too |
| `same_errno_for_marker_and_legitimate` | the kernel returned the same error for both |
| `marker_errno` / `legitimate_errno` | the numeric errno and its name |

Across all four mechanisms — DAC, inode immutability, AppArmor and Landlock — the
three booleans are true. That is the paper's point: the policy input is
content-blind, so an attack write and an approved update are indistinguishable to
it, and blocking one blocks the other with an identical error.

## What is not here

The per-mechanism run trees (`runs/`, `bin/`) are not published. They hold the
probe's scenario workspaces, which include a `credentials/.env` capability-binding
fixture that the release rule against credential-bearing filenames excludes, plus
the compiled Landlock launcher. The reports above carry every value the paper
reports; `SHA256SUMS` covers what is shipped, so it is shorter than the one in the
working repository.
