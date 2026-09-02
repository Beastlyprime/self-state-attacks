# Recovery seed — w3_devops, template baseline

Composed, not authored. Every file here is copied verbatim from an existing
designed source; nothing was invented. Byte-identity to the source was verified
by sha256 at composition time.

`recovery_real.py --seed` expects a complete workspace, but the three self-state
layers have deliberately different provenance (`experiments/code/workload/
taxonomy.py`, the stated source of truth), so no single directory in the tree is
already a complete workspace. This assembles one along the layer boundaries.

## File origins

| Path | Layer | Source |
|---|---|---|
| `workspace/SOUL.md` | instruction | `experiments/agent_packs/w3_devops/workspace/` |
| `workspace/IDENTITY.md` | instruction | same |
| `workspace/USER.md` | instruction | same |
| `workspace/AGENTS.md` | instruction | same |
| `workspace/TOOLS.md` | instruction | same |
| `workspace/MEMORY.md` | memory | `experiments/agent/openclaw_core/templates/MEMORY.md` |
| `workspace/HEARTBEAT.md` | config | `experiments/agent/openclaw_core/templates/HEARTBEAT.md` |
| `openclaw.json` | config | `experiments/tasks/seeds/W3_C4_V2/openclaw.json` (the seed C512 used) |

`credentials/.env` is a config-layer file in the taxonomy and is deliberately
absent: no attack in `recovery8` targets it, and fabricating a credentials file
is not something to do casually.

## What this seed is good for, and what it is not

All eight `recovery8` attacks can run against it. `canonical43` still cannot: it
also targets `workspace/memory/2026-04-26.md`, a dated daily log that the agent
writes at runtime. Fabricating one would misrepresent agent-authored state as
seeded state, so it is left missing and `canonical43` stays blocked here.

**The memory layer is empty in this seed, and that bounds what its numbers mean.**
`MEMORY.md` is the shipped template — a header and the word "(empty)". Recovery
results for the two `Mem-*` attacks therefore measure restoring an essentially
empty file, which will almost certainly succeed and will say nothing about whether
real accumulated memory survives an attack. `pilot_runner` already records the
underlying reason: a fresh workspace "drastically undercounts self-state writes
because every task starts with a clean MEMORY.md", which is why chained-pilot mode
exists at all.

So treat this as a **tooling baseline**: it unblocks the recovery harness and lets
its output format, judgement logic and failure modes be exercised. For
memory-layer results that mean anything, the seed should instead be a workspace
taken *after* a chained session, where memory has actually accumulated. That
variant needs an agent run and is not included here.

Instruction- and config-layer recovery numbers from this seed are not subject to
that caveat: those layers are seeded by design, and this seed carries their real
designed content.
