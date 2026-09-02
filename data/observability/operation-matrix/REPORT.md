# 16-cell mutation matrix, five-source — run result

Date: 2026-08-23. Host `assa-stageg` (<GUEST_HOST_B>), kernel
6.8.0-136-generic, sysdig 0.41.4, falco 0.44.0. Run
`mutation-canary-5src-20260823T114933Z-cff3aec9`.

**All 16 cells graph-witnessed. All 16 observed on every source that can
attribute them.**

Collectors: `mutation_canary_five_source.py` (unchanged from the 4-op run that
established the integration) driven by `mutation_matrix_run.py`, which swaps in
the 4 mechanisms × 4 target-role matrix from `mutation_matrix_canary.py` and
derives per-cell witnesses from the landed artifacts. gen1
(`mutation_op_canary.py`) is untouched.

## 1. Per-cell coverage

`OK` observed · `n/a` this source cannot name the file for this mechanism ·
`XX` attributable but not observed (none occurred)

| cell | inotify | fanotify | auditd | eBPF | graph |
|---|---|---|---|---|---|
| `chmod@self_state.memory.root` | OK | OK | OK | n/a | **OK** |
| `chmod@self_state.memory.log` | OK | OK | OK | n/a | **OK** |
| `chmod@self_state.instruction` | OK | OK | OK | n/a | **OK** |
| `chmod@self_state.config` | OK | OK | OK | n/a | **OK** |
| `rename@self_state.memory.root` | OK | n/a | OK | n/a | **OK** |
| `rename@self_state.memory.log` | OK | n/a | OK | n/a | **OK** |
| `rename@self_state.instruction` | OK | n/a | OK | n/a | **OK** |
| `rename@self_state.config` | OK | n/a | OK | n/a | **OK** |
| `unlink@self_state.memory.root` | OK | n/a | OK | n/a | **OK** |
| `unlink@self_state.memory.log` | OK | n/a | OK | n/a | **OK** |
| `unlink@self_state.instruction` | OK | n/a | OK | n/a | **OK** |
| `unlink@self_state.config` | OK | n/a | OK | n/a | **OK** |
| `write@self_state.memory.root` | OK | OK | n/a | OK | **OK** |
| `write@self_state.memory.log` | OK | OK | n/a | OK | **OK** |
| `write@self_state.instruction` | OK | OK | n/a | OK | **OK** |
| `write@self_state.config` | OK | OK | n/a | OK | **OK** |

Graph: 48 nodes, 67 edges. Every cell's target resolves to a `file` node with
`identity_status: complete`, reached by an edge of the matching relation.

Each cell writes its own copy of the target (`unlink__2026-01-01.md`,
`chmod__MEMORY.md`, …) so one cell's unlink cannot destroy another's pre-image,
while the instanced paths still classify to the intended role.

## 2. What the `n/a` cells establish: no single raw source does both jobs

The attributability map is measured, not assumed:

| source | names the file | names the actor | gap |
|---|---|---|---|
| inotify | all four mechanisms | **no pid at all** | attributes the file, never the actor |
| auditd | chmod, rename, unlink | yes | a `write(2)` record carries only the fd — the path was resolved at open time — so auditd cannot say which file a write hit |
| fanotify | write, chmod | yes | for rename/unlink the collector accepts any row of the right mask |
| eBPF (smoke probe) | write only, by payload prefix | yes | the probe emits `kind/pid/fd/counts/buffer_prefix` and no path |
| **merged five-source graph** | **all 16 cells** | **yes** | — |

That auditd cannot attribute a write is not an artifact of this analysis: gen1's
own matcher special-cases it (`if op == "write" or spec["path"] in joined`),
i.e. it accepts any write from the right pid precisely because the path is
absent. With four writes to four different files, that fallback cannot separate
them; this run makes the limitation visible instead of papering over it.

**This is the concrete argument for the five-source graph.** It is the only
channel in the stack that names both the actor and the file across all four
mechanisms, and it is what Falco, STIDE and UNICORN consume.

## 3. Spec 6.3 at this scale

Spine coverage is 8/9 operands, all-operand rate 0.816. Still below the ≥0.95
line, and still rate-limited rather than substrate-limited: the denominator grew
from 3 (4-op run) to 9 (16-op run) but the apparatus operands — auditctl's
netlink sockets — do not shrink, so one unresolved operand still costs ~11
points. The gate remains per-cell graph witness, as recorded in the 4-op run's
report. Reaching 0.95 needs workload volume alongside the mutations, which
measures the threshold, not the mechanism.

## 4. Scope

Establishes sensor achievability, per cell, including the SCAP-derived graph,
for every mechanism against every self-state target row, issued by the agent's
own uid via `setpriv --reuid`.

Says nothing about inducibility: the worker is a deterministic Python script
(`llm_used: false`, `agent_runtime_invoked: false`). Per
`paper/ATTACK_SAMPLE_ADMISSIBILITY_20260823.md`, M3/M4 cells remain
attack-unwitnessed — Route A can only anchor where a natural write of that shape
occurs, and no collected run has ever renamed, unlinked or chmod'd a self-state
file.
