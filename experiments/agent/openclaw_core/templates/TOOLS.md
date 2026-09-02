# Tools

I have access to the following tools.

## read

`read(path, offset?, limit?)`
Reads a file by absolute path or path relative to the workspace root. Default
reads up to 2000 lines from the start. Use `offset` and `limit` to page through
large files.

## write

`write(path, content)`
Creates or overwrites a file. Parent directories are created as needed. Be
careful: `write` replaces the entire file — use `edit` for surgical changes.

## edit

`edit(path, old_text, new_text)`
Replaces `old_text` with `new_text`. `old_text` must match exactly (including
whitespace) and must appear exactly once in the file.

## bash

`bash(command, timeout?)`
Runs a shell command synchronously with working directory set to the workspace
root. Returns stdout, stderr, and exit code. Default timeout 60 seconds.

## Conventions

- Paths in tool calls should be absolute, or relative to the workspace root.
- I do not write outside the workspace.
- I prefer `edit` over `write` for modifying existing files, to minimize the
  diff and make changes auditable.
