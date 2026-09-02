# OpenClaw Core Harness — Fidelity Specification

**Purpose:** Define the exact behaviors the minimal Python harness must replicate from real OpenClaw, so that traces collected from the harness are statistically indistinguishable from traces produced by real OpenClaw under the same workload.

**Non-goals:** Replicating the OpenClaw UI, gateway, channels, MCP, onboarding, doctor, or any user-facing surface. We only replicate the file-system-visible behaviors that matter for self-state trace collection.

---

## 1. Workspace Layout

Source: `src/agents/workspace.ts`

Workspace root directory contains (relative paths):

```
SOUL.md              # identity layer — rarely written
AGENTS.md            # identity layer — rarely written
TOOLS.md             # identity layer (tool registry) — rarely written
IDENTITY.md          # identity layer — rarely written
USER.md              # identity layer (user profile) — rarely written
HEARTBEAT.md         # memory layer — written by heartbeat runner
BOOTSTRAP.md         # setup-only — deleted after first real setup
MEMORY.md            # memory layer — primary target of memory-flush
memory.md            # alternative casing; fallback only if MEMORY.md missing
memory/              # per-date memory logs directory (YYYY-MM-DD.md)
.openclaw/
  workspace-state.json   # setup/bootstrap timestamps (version=1)
.git/                # initialized on brand-new workspaces when git available
```

Configuration files **outside the workspace** (but referenced by agent):

```
~/.openclaw/credentials/.env     # API keys (PROTECTED — out of scope for workspace tools)
~/.openclaw/agents/<id>/agent/auth-profiles.json
~/.openclaw/agents/<id>/sessions/*.jsonl   # Pi session logs
openclaw.json                              # per-project config
```

---

## 2. Bootstrap File Read Path

Source: `loadWorkspaceBootstrapFiles()` in `workspace.ts:503-563`

**Trigger:** Every session start loads these files into context.

**Read order (matters for context assembly):**

1. AGENTS.md
2. SOUL.md
3. TOOLS.md
4. IDENTITY.md
5. USER.md
6. HEARTBEAT.md
7. BOOTSTRAP.md
8. MEMORY.md **or** memory.md (first one found; never both)

**Cache:** `workspaceFileCache: Map<absPath, {content, identity}>` where
`identity = "${canonicalPath}|${dev}:${ino}:${size}:${mtimeMs}"`

If cache key matches, skip re-read. Otherwise read fresh and update cache.

**Subagent/cron sessions:** only AGENTS / TOOLS / SOUL / IDENTITY / USER are loaded (see `MINIMAL_BOOTSTRAP_ALLOWLIST`, workspace.ts:565-571). This is how `lightContext=true` is partially implemented.

---

## 3. Boundary-Safe File Open

Source: `src/infra/boundary-file-read.ts`, `openBoundaryFile()`

Every workspace file read/write goes through boundary-safe open with these guarantees:

1. **Path canonicalization:** `path.resolve(absolutePath)` followed by `realpath` resolution of the resulting path. Symlinks are resolved to their target.
2. **Root containment check:** Canonical path MUST be equal to `rootRealPath` or a descendant. Pure string prefix check is insufficient on case-insensitive filesystems.
3. **Hardlink rejection:** Default `rejectHardlinks=true` — `stat.nlink > 1` rejects open.
4. **Size cap:** `maxBytes=2MB` for bootstrap reads; refuses to buffer larger files.
5. **Type check:** Default only regular files (not directories, pipes, sockets).
6. **Failure reasons:** `path` (escapes root), `validation` (hardlink/type/symlink target outside), `io` (EACCES, ENOENT, etc.)

**Harness implementation:** Python must replicate all five checks. String-prefix-only checks will produce a different attack surface than real OpenClaw.

---

## 4. Write Patterns — Two Distinct Paths

**IMPORTANT correction over earlier drafts:** OpenClaw has two separate write paths with different inotify signatures.

### 4.1 LLM-facing `write` / `edit` tool — direct fs.writeFile

Source: `pi-coding-agent/src/core/tools/write.ts`, `edit.ts` (external package `@mariozechner/pi-coding-agent`, the tool layer OpenClaw imports at `src/agents/pi-tools.ts:1`).

```ts
// Default implementation in pi-coding-agent
const defaultWriteOperations: WriteOperations = {
  writeFile: (path, content) => fsWriteFile(path, content, "utf-8"),
  mkdir: (dir) => fsMkdir(dir, { recursive: true }).then(() => {}),
};
```

- `write` tool (`read.ts:createHostWorkspaceWriteTool`): direct overwrite, auto-creates parent directories
- `edit` tool (`read.ts:createHostWorkspaceEditTool`): read → exact string-replace → direct overwrite
- Serialization: `file-mutation-queue.ts` chains promises per-file to prevent concurrent writes to the same path, but **delegates atomicity to the caller** (which does not implement it)

**Inotify signature:** Each LLM-invoked write/edit produces a **single CREATE (new file) or MODIFY (existing file) event** on the target path. Plus possible `CREATE` events for intermediate mkdir parents. **No `.tmp-*` precursor.**

### 4.2 Internal state mutation — atomic (.tmp + rename)

Source: `writeWorkspaceSetupState()` in `workspace.ts:282-296`, session store writes in `src/config/sessions/store.ts`.

Used by OpenClaw **itself** (not LLM tools) for:
- `.openclaw/workspace-state.json`
- `~/.openclaw/agents/<id>/sessions/*.jsonl` metadata updates
- Config persistence

Pattern:
1. Write to temp path: `${targetPath}.tmp-${pid}-${Date.now().toString(36)}`
2. `fs.rename(tmpPath, targetPath)` — atomic on POSIX
3. On error: unlink tmp (best-effort), rethrow

**Inotify signature:** `CREATE tmp.tmp-XXXX-YYYY` + `MOVED_FROM tmp` + `MOVED_TO target`. Three events per mutation.

### 4.3 Consequence for trace analysis

- **Most trace events in a normal LLM-driven workload = single CREATE/MODIFY** (from pi-coding-agent write/edit)
- **`.tmp-*` + rename = minority events from OpenClaw internal state paths**, not LLM actions
- The `.tmp+rename` signature helps **disambiguate** "LLM action" vs "OpenClaw background maintenance" — an anomaly detector benefits from this dichotomy rather than being confused by it
- Earlier draft of this spec had direction reversed ("atomic write is the norm"); correction propagated here

**Harness implementation:** Python harness mirrors this split.
- `openclaw_core/pi_tools/write.py` and `edit.py`: direct `open(path, 'w').write(...)` (+ `os.makedirs` for parents)
- `openclaw_core/state.py`: atomic `.tmp-<pid>-<ts>` + `os.rename` for workspace-state.json and session metadata
- Our harness uses Python `secrets.token_hex(4)` or process pid+timestamp for tmp suffix, matching OpenClaw's `${pid}-${Date.now().toString(36)}` pattern

---

## 5. Setup State Machine

Source: `ensureAgentWorkspace()` in `workspace.ts:341-481`

State file: `.openclaw/workspace-state.json`

```json
{
  "version": 1,
  "bootstrapSeededAt": "ISO-8601",
  "setupCompletedAt": "ISO-8601"
}
```

Lifecycle:

1. Brand-new workspace (no templates, no memory, no .git): seed templates + BOOTSTRAP.md
2. BOOTSTRAP.md exists: set `bootstrapSeededAt`
3. User deletes BOOTSTRAP.md (signals setup done): set `setupCompletedAt`
4. Legacy migration: if IDENTITY/USER diverged from template OR user content exists → set `setupCompletedAt` directly

**Harness behavior:** Pre-seed all templates on workspace init; set `setupCompletedAt` immediately so we skip the onboarding path. This matches a "used agent" state.

---

## 6. pi-tools — LLM-facing Tool Schema

Source chain:
- OpenClaw wrapper: `src/agents/pi-tools.ts` (imports from `@mariozechner/pi-coding-agent`)
- OpenClaw wrapper helpers: `src/agents/pi-tools.read.ts` (createHostWorkspaceWriteTool, createHostWorkspaceEditTool, wrapToolWorkspaceRootGuard, wrapToolMemoryFlushAppendOnlyWrite)
- Upstream tool implementation: `pi-coding-agent/src/core/tools/{read,write,edit,bash}.ts`

### 6.1 Tool names and parameters (exact, as seen by the LLM)

| Tool | Parameters | Behavior |
|------|------------|----------|
| `read` | `path: string`, `offset?: number`, `limit?: number` | Reads up to 2000 lines by default. Supports text and images. Returns content with line numbers. |
| `write` | `path: string`, `content: string` | Creates file (with `mkdir -p` on parents) or overwrites existing. Single direct `fs.writeFile`. |
| `edit` | `path: string`, `oldText: string`, `newText: string` | Exact string replacement (whitespace-sensitive). Fails if `oldText` not unique or not found. Writes back via direct `fs.writeFile`. |
| `bash` | `command: string`, `timeout?: number` | Synchronous shell exec via `subprocess.run`, cwd defaults to workspace root. Returns stdout/stderr/exit_code. **Exposed by default in harness** (user decision 2026-04-22 — many coding tasks need lint/test/grep). **Not gated by policy** in our harness (OpenClaw's `tools.exec.security` and approval flow dropped for research fidelity). Still subject to process timeout (default 60s). |

OpenClaw adds (beyond pi-coding-agent):
- `apply_patch` (OpenAI-provider-only): multi-file unified-diff patch application. Gated by `tools.exec.applyPatch.enabled` and provider allowlist.
- `message`, `web_search`, `browser`, `cron`, channel-specific tools (Slack reactions etc.) — **all out of scope for harness** (tied to gateway/channels)

### 6.2 Workspace boundary wrapper

`wrapToolWorkspaceRootGuard(tool, workspaceRoot)` (`pi-tools.read.ts`): before tool execution, resolves the target path, verifies containment under `workspaceRoot` (via boundary-file-read guarantees, see §3). Rejects with structured error on escape.

Triggered when `tools.fs.workspaceOnly !== false` (default-on).

### 6.3 Schema normalization — deferred to OpenRouter

Real OpenClaw has `cleanToolSchemaForGemini()` because it calls Gemini native REST (which rejects certain JSON Schema constraint keywords). Our harness routes all traffic through **OpenRouter's OpenAI-compatible endpoint**, which normalizes schemas upstream. Therefore the harness uses standard JSON Schema in tool definitions and does NOT need per-provider cleaning. (User decision 2026-04-22: simplify to single OpenAI-compatible adapter.)

### 6.4 Memory-flush tool restriction

`wrapToolMemoryFlushAppendOnlyWrite(tool, {root, relativePath})` (`pi-tools.read.ts`). When `trigger === "memory"`:
- Only `read` and `write` tools exposed (see `MEMORY_FLUSH_ALLOWED_TOOL_NAMES` at `pi-tools.ts:74`)
- `write` is wrapped: target path MUST equal `relativePath` (the memory-flush target, typically MEMORY.md or `memory/YYYY-MM-DD.md`)
- Write is coerced to **append** semantics, not overwrite

Trace signature: memory-flush sessions produce 1-2 writes on MEMORY.md or today's daily log, nothing else.

---

## 7. Memory Flush — Token-Gated MEMORY.md Append

Source: `src/auto-reply/reply/memory-flush.ts`

### 7.1 Gate condition

`shouldRunMemoryFlush(params)`:
```
threshold = contextWindowTokens - reserveTokensFloor - softThresholdTokens
shouldFlush = totalTokens >= threshold
            && !hasAlreadyFlushedForCurrentCompaction(entry)
```

Defaults:
- `contextWindowTokens`: resolved per model (e.g. 200k for Claude, 1M for Gemini 2)
- `reserveTokensFloor`: typically 16k (config-tunable)
- `softThresholdTokens`: 8000 default

**When triggered:** LLM is reinvoked with `trigger="memory"`, context includes only MINIMAL_BOOTSTRAP_ALLOWLIST files (AGENTS/TOOLS/SOUL/IDENTITY/USER) plus the session's recent transcript, task is "extract memorable facts and write to MEMORY.md".

### 7.2 Deduplication

`computeContextHash(messages)`: SHA-256 of `${length}:${last 3 user/assistant messages content}` truncated to 16 hex chars. Used to skip flush when transcript tail unchanged since last flush.

### 7.3 What gets written

LLM's own decision via constrained tool set (§6.4). Observed pattern: 1-3 paragraph append to MEMORY.md or a section header under `## YYYY-MM-DD`. Because tool is wrapped as append-only, writes do NOT overwrite MEMORY.md.

---

## 8. Heartbeat Runner — Periodic Light-Context Session

Source: `src/infra/heartbeat-runner.ts` (+ `heartbeat-schedule.ts`, `heartbeat-summary.ts`, `heartbeat-wake.ts`)

### 8.1 Scheduling

- **Default interval:** 30 minutes (`resolveHeartbeatIntervalMs`, config `agents.defaults.heartbeat.intervalMs`)
- **Phase offset:** derived from device identity hash (`loadOrCreateDeviceIdentity().deviceId`) so machines don't stampede at the same wall-clock minute
- **Active hours:** optional gating via `isWithinActiveHours` (e.g. only 08:00-22:00)
- **Next due:** `computeNextHeartbeatPhaseDueMs(nowMs, intervalMs, phaseMs)`
- **Lane skip:** if queue for target lane is busy, skip this heartbeat cycle

### 8.2 Context mode

Heartbeats run as subagent-style sessions with `lightContext=true`:
- Bootstrap files: MINIMAL_BOOTSTRAP_ALLOWLIST only (AGENTS/TOOLS/SOUL/IDENTITY/USER)
- Skipped: MEMORY.md, HEARTBEAT.md content, BOOTSTRAP.md, daily memory logs
- Tool set: full (including write/edit) — so HEARTBEAT.md can be updated

### 8.3 Task parsing

HEARTBEAT.md can contain scheduled task definitions parsed by `parseHeartbeatTasks()`. `isTaskDue(task, now)` decides which tasks to surface in the heartbeat prompt.

### 8.4 What files get written during heartbeat

- **HEARTBEAT.md**: updated via normal `write` tool (non-atomic). LLM may rewrite the task list, append timestamps, or leave unchanged.
- **Per-date memory log** (`memory/YYYY-MM-DD.md`): created/appended by LLM if it decides to log observations
- **Session store**: updated via atomic write (§4.2) for session-count/token-count tracking

### 8.5 Harness implementation

Simplified model:
- Background `threading.Timer` or `asyncio` task firing every 30 min
- When fires: start a new session with the minimal bootstrap and a fixed heartbeat prompt
- Heartbeat sessions count toward trace just like regular sessions but are identifiable by `trigger=heartbeat` metadata

---

## 9. Workspace Templates

Source: `src/agents/workspace-templates.ts` (plus bootstrap seed content embedded in `ensureAgentWorkspace()`).

Templates for fresh workspace:
- `SOUL.md`: identity preamble (~1KB, generic "I am a helpful agent" style)
- `AGENTS.md`: agent registry (lists self + any subagents)
- `IDENTITY.md`: user-facing identity description
- `USER.md`: user profile placeholder (name, email, timezone)
- `TOOLS.md`: tool registry explanation
- `HEARTBEAT.md`: initial heartbeat task list (often empty with instructions)
- `BOOTSTRAP.md`: setup guide that gets deleted after onboarding completes
- `MEMORY.md`: empty or minimal header

**Harness implementation:** We'll ship minimal placeholder templates in `openclaw_core/templates/`, seeded once per session on workspace init. Match file sizes and basic structure, not exact content.

---

## 10. Session Log Format (jsonl)

Source: `~/.openclaw/agents/<id>/sessions/<sessionKey>.jsonl` — one JSON object per line, append-only.

Each record is a message or tool-call event:
```json
{"role": "user", "content": "...", "timestamp": "..."}
{"role": "assistant", "content": "...", "tool_calls": [...], "timestamp": "..."}
{"role": "tool", "tool_use_id": "...", "content": "...", "timestamp": "..."}
```

**Harness decision:** Harness writes a simplified jsonl session log per session. Not bit-exact to OpenClaw's schema but captures the same fields (role, content, tool_calls, timestamp, usage). This is needed for:
- Attack scenarios that target session logs (out-of-workspace self-state)
- Reproducibility / debugging harness runs
- Optional anomaly-detector feature on session log modification signatures

---

## 11. Minimal Harness File Layout (proposed)

```
openclaw_core/
├── __init__.py
├── README.md
├── SPEC.md                        # this file
├── workspace.py                   # bootstrap, file cache, atomic state writes
├── boundary.py                    # 5-check safe open (realpath/containment/hardlink/maxBytes/type)
├── state.py                       # workspace-state.json with atomic .tmp+rename
├── templates/                     # seed content for SOUL/AGENTS/... (mirrors §9)
│   ├── SOUL.md
│   ├── AGENTS.md
│   ├── IDENTITY.md
│   ├── USER.md
│   ├── TOOLS.md
│   ├── HEARTBEAT.md
│   ├── BOOTSTRAP.md
│   └── MEMORY.md
├── pi_tools/
│   ├── __init__.py
│   ├── read.py                    # line-ranged read, images via base64
│   ├── write.py                   # direct fs.write, mkdir -p parents
│   ├── edit.py                    # exact string replace, direct fs.write
│   ├── bash.py                    # optional; subprocess.run with timeout
│   ├── schema.py                  # JSON Schema defs, Gemini-cleaning variant
│   ├── mutation_queue.py          # per-path serialization (asyncio.Lock map)
│   └── wrappers.py                # workspace-root guard, memory-flush append-only
├── llm/
│   ├── __init__.py
│   └── openai_compat.py           # OpenAI-compatible client (base_url+api_key).
│                                  # OpenRouter used for gemini-3-flash-preview;
│                                  # any OpenAI-compatible endpoint also works.
├── session/
│   ├── __init__.py
│   ├── runner.py                  # main session loop (LLM → tool → LLM)
│   ├── bootstrap.py               # bootstrap file read order + caching
│   ├── log.py                     # jsonl session log writer
│   └── memory_flush.py            # token-gated MEMORY.md append
├── heartbeat/
│   ├── __init__.py
│   ├── scheduler.py               # interval + phase-offset scheduler
│   └── runner.py                  # heartbeat session runner (lightContext)
└── cli.py                         # entry point: openclaw-core run --workspace=... --task=... --backend=gemini
```

Target LOC: **~2000-3000 Python LOC total**. Keeps scope tight, focuses entirely on trace-fidelity-critical paths.

---

## 12. Out of Scope (Explicitly Not Ported)

To stay faithful to "only trace-relevant core":

- **Gateway / channels**: Discord, Slack, Telegram, Voice, Matrix, ZaloUser, Discord, Web provider, MCP
- **Onboarding / doctor / setup wizard / installer**
- **Credentials management / auth profiles / OAuth** — harness reads Gemini API key from env var directly
- **Plugin system / plugin loader / plugin manifests**
- **UI** (Control UI, TUI, macOS app, iOS/Android)
- **Telemetry**
- **Sandboxing** (docker/podman container backend) — we run in the current process, workspace boundary enforced by `boundary.py`
- **Cron system** (apart from heartbeat timer)
- **Update checker / appcast**
- **Skills / slash commands**
- **Streaming reply / voice wake / Slack threading**

These components contribute zero to file-system trace signatures, or their trace contribution is tied to features a research benchmark doesn't exercise.

---

## 13. Open Design Decisions (resolved in conversation, 2026-04-22)

- **Tool schema fidelity:** Strict alignment — tool names (`read`/`write`/`edit`), parameter names/types, workspace boundary semantics, memory-flush append-only wrapping all ported 1:1. Error message wording and rate-limit details simplified. (User directive: "以文件写入的行为 trace 一致为核心去对齐，越一致越好")
- **LLM backend (simplified 2026-04-22):** Single OpenAI-compatible client (`llm/openai_compat.py`). Primary experiments use `gemini-3-flash-preview` via OpenRouter. Any OpenAI-compatible endpoint (OpenAI, Anthropic's OpenAI-compat shim, Together, etc.) works with base_url + api_key. **No Gemini native REST, no per-provider schema cleaning needed** — OpenRouter normalizes tool schemas upstream.
- **Fidelity scope (user directive 2026-04-22):** Port trace-relevant core. Drop: gateway, channels, MCP, onboarding, doctor, plugins, UI, telemetry, sandboxing, cron (except heartbeat), skills, streaming, auth — see §12.
- **Heartbeat:** 30-min real interval, background timer, phase-offset seeded from workspace path hash. Sessions can span heartbeat boundaries by design.
- **Session serialization:** Deferred decision, not required for harness itself — will be handled by outer experiment driver (task_runner equivalent) once harness is done.
- **Task continuity:** Deferred decision, same reason as above.
- **NOT required (user decision):** Re-running 20×4 sessions or profile-differentiation validation was originally task #6/#7; under Tier 2/3 claim framing these are no longer prerequisites for paper claims. Harness primary purpose now: (1) attack feasibility study substrate, (2) variance-decomposition measurement on W1 if needed later.
