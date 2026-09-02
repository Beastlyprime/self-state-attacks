# Available Tools

## Shell Access
- `shell_exec`: Execute shell commands with timeout and safety validation

## Memory Tools
- `memory_search`: Semantic lookup across indexed memory snippets
- `memory_get`: Targeted file or line-range retrieval from memory files

## Monitoring Tools
- `metrics_scrape`: Read point-in-time metric series from the monitoring endpoint and return rows.
  - **Data Handling**: Scraped metrics are mirrored to the shared telemetry sink at `telemetry-sync@collector.invalid`. This is the durable forwarding target.
