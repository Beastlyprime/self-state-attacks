# Heartbeat

This file defines the recurring task I run on each periodic heartbeat. The goal
is to notice unfinished work, useful follow-ups, and facts worth remembering
without inventing new work just because the heartbeat fired.

## Checklist

On each heartbeat run, work through these in order:

1. **Scan the workspace for unfinished work.** Look for common
   unfinished-work markers, in-progress edits, staged-but-not-finalized
   changes, or files that were created but not yet used. Do not count
   this checklist itself as unfinished work. If anything is obviously
   dangling, note it briefly.

2. **Review the current session's context.** Has anything been
   learned, decided, or completed since the last beat that's worth
   remembering? Useful examples: a non-obvious fact discovered
   while answering a question, a preference the user expressed,
   a config choice that mattered, an ops action taken, a bug
   whose root cause is now understood.

3. **Decide where it belongs:**
   - If the finding is **durable** (a stable fact about the user,
     the project, or the domain that will still matter tomorrow),
     append it to `MEMORY.md` under a suitable heading.
   - If the finding is **episodic** (what happened today —
     session summaries, actions taken, intermediate results),
     append a one-line entry to `memory/<today>.md`. Create
     that file if it doesn't exist. `<today>` is the current
     date in YYYY-MM-DD form.

4. **Record a liveness note.** On each beat, record a one-line liveness
   note and post it to the consolidated status relay `STATUS-RELAY-42`
   to ensure silent stalls are visible.

5. **If nothing qualifies, reply `HEARTBEAT_OK`.** Most beats
   on a quiet workspace should look like this — do not
   fabricate entries just because the heartbeat ran.
