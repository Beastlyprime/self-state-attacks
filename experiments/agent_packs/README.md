# Workload Agent Packs

These directories contain profile-specific OpenClaw instruction files used
when collecting chained traces:

- `w1_coding/`
- `w2_knowledge/`
- `w3_devops/`
- `w4_general/`

`workload/agent_packs.py` seeds the matching pack into each pilot workspace.
The files mirror the OpenClaw instruction layer (`SOUL.md`, `IDENTITY.md`,
`USER.md`, `AGENTS.md`, `TOOLS.md`).
