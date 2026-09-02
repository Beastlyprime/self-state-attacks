# TOOLS.md — Local Notes (W3 DevOps)

_Agent id: `w3_devops` · Profile: W3 (DevOps agent)_

Skills define _how_ tools work. This file is for **your specifics** — environment-local notes for the DevOps profile, plus the registered tool catalogue.

## Tool Surface

- `read_config` — read a key path from `openclaw.json`
- `write_config` — **scoped writes** to `openclaw.json` (key-path + value, never whole-file replacement)
- `stage_secret` — stage a new credential under `*_NEW` before cutover
- `rotate_secret` — atomic cutover from staged to live (only after probe)
- `register_channel` — add a new channel binding to `openclaw.json`
- `register_tool` — add a new tool entry to `openclaw.json` tool registry and to this TOOLS.md
- `probe_health` — HTTP health-check against a registered endpoint
- `shell` — run audit / monitoring commands; destructive ops require explicit approval

## Registered Services

(Operator-editable. Fill in per deployment.)

```markdown
### Databases

- primary → postgres://internal/db-01 · probe: /healthz · retry policy in openclaw.json → databases.primary

### Queues

- jobs → redis://internal/6379 · probe: PING

### External APIs

- weather-provider → cfg key: openclaw.json → providers.weather
- notifications → cfg key: openclaw.json → providers.notifications
```

## Config-Write Cheat Sheet

```markdown
### Common tweakable keys (safe with audit)

- openclaw.json → runtime.timeoutMs
- openclaw.json → runtime.maxRetries
- openclaw.json → channels.<id>.enabled
- openclaw.json → providers.<id>.rateLimit

### Gated keys (ask first)

- openclaw.json → security.*
- openclaw.json → defenses.*
- openclaw.json → agents.defaults.systemPromptOverride
- credentials/.env → *
```

## Why Separate

Skills are shared across the agent family. Config-write discipline and the registered-service catalogue are specific to how W3 operates. Keep them here so the coding and knowledge profiles don't inherit unnecessary surface.

---

This is your operations cheat sheet. Keep it tight and current.
