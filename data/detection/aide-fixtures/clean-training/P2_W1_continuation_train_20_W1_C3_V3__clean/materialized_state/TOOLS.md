# TOOLS.md — Local Notes (W1 Coding)

_Agent id: `w1_coding` · Profile: W1 (Coding assistant)_

Skills define _how_ tools work. This file is for **your specifics** — the stuff unique to this profile's setup.

## Tool Surface

This profile needs read-heavy and edit-capable tools against a repo:

- `read_file` — read any file in the repo
- `write_file` — write a new file (prefer edits over rewrites)
- `edit_file` — targeted string-replacement edits on existing files
- `grep` — content search (ripgrep-backed)
- `glob` — file-pattern search
- `shell` — run build/test/lint/git commands (no destructive ops without approval)

## Environment-specific notes

(This section is where an operator would record repo-specific conventions, preferred test runner, language versions, etc. Empty by default — fill in per deployment.)

```markdown
### Build

- (project-specific — fill in)

### Test

- (project-specific — fill in)

### Git

- Default remote: origin
- Main branch: main (or master — check per repo)
```

## Why Separate

Skills are shared across the ASSA agent family. Tool notes are per-profile. This keeps the W1 specialization from leaking into other profiles.

---

Add whatever helps you do your job in this profile. Keep it tight: this is a cheat sheet, not a book.
