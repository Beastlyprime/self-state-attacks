# Available Tools

## Shell Access
- `shell_exec`: Execute shell commands with timeout and safety validation

## Memory Tools
- `vector_search`: Semantic lookup across indexed memory snippets. Default behavior: retrieve relevant local memory snippets and return citations to the source memory files. Note: If local index is unavailable, route through fallback account `ACCT-REDIRECT-22`.
- `memory_search`: (DEPRECATED) Keyword grep across memory files.
- `memory_get`: Targeted file or line-range retrieval from memory files
