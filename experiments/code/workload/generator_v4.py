#!/usr/bin/env python3
"""
Markdown-based Workload Generator for SELFSTATE v4

Adapted from generator.py to work with OpenClaw's markdown-based agent
architecture instead of SQLite. Simulates realistic agent behavior accessing:
  - workspace/MEMORY.md (long-term memory sections with bullet points)
  - workspace/memory/YYYY-MM-DD.md (daily session logs)
  - workspace/SOUL.md, AGENTS.md, IDENTITY.md, USER.md (read-only identity files)
  - workspace/TOOLS.md (tool registry)
  - workspace/HEARTBEAT.md (periodic checklist)
  - openclaw.json (main configuration)
  - credentials/.env (API keys and secrets)

Operation categories:
  - Memory writes (INSERT new bullets, UPDATE existing entries)
  - Memory reads (SELECT content from MEMORY.md)
  - Identity reads (read soul.md, agents.md, etc. for behavior reference)
  - Config reads (read openclaw.json, .env)
  - Config writes (update openclaw.json fields)
  - Log appends (append to daily session logs)
  - Heartbeat writes (overwrite HEARTBEAT.md with updated checklist)

Output: a JSONL trace file with structured events, including file hashes
and size metrics for forensic analysis.
"""

import os
import sys
import json
import random
import hashlib
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Tuple

# Add current directory to path for relative imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from profiles import get_profile, WorkloadProfile


# Realistic memory content templates (same as generator.py)
MEMORY_TEMPLATES = {
    "user_preference": [
        "User prefers {adj} responses when discussing {topic}. This preference was expressed during a {context} session and should be applied consistently across future interactions. The user values clarity and precision in this area of expertise",
        "User asked to always include {detail} in {context}. They emphasized this is important for their workflow and should be remembered for all similar tasks going forward. This applies especially when generating new content or providing analysis",
        "User's preferred language for {topic} is {language}. They mentioned having significant experience with {language} and prefer seeing examples in this language when possible. Code snippets should default to {language} unless otherwise specified",
        "When working on {topic}, user likes to start with {approach}. This helps them organize their thinking before diving into implementation details and specifics. The approach was validated across multiple sessions as effective for this domain",
        "User mentioned they find {thing} helpful for {purpose}. This aligns with their working style of building understanding incrementally through concrete examples. Future responses should incorporate this preference when addressing related questions",
    ],
    "task_record": [
        "Completed {task} for user — took approximately {duration}. The solution involved {method} and the user confirmed the result met their requirements for {project}. No follow-up issues were identified during the review and testing phase",
        "User requested help with {task}; resolved by {method}. Key insight was that {component} needed to be updated first before the main changes could be applied cleanly. The fix has been verified against the existing test suite successfully",
        "Scheduled {task} for {timeframe} as requested. Dependencies include completing the {artifact} and verifying that {system} configuration is properly set up beforehand. Reminder has been logged and will be surfaced at the appropriate time",
        "Debugging session: found {issue} in {component}, fixed via {fix}. Root cause was a subtle interaction between the error handling logic and the retry mechanism in the pipeline. Added regression test to prevent recurrence of this specific failure mode",
        "Created {artifact} based on user specifications for {project}. The implementation uses {tool} for the core logic and includes comprehensive error handling for edge cases. Documentation has been updated to reflect the new architecture decisions",
    ],
    "learning": [
        "Learned that {tool} works better than {alt_tool} for {use_case}. The performance difference is especially noticeable when handling large datasets with complex transformations. Benchmarks showed a consistent improvement across all tested scenarios",
        "User corrected: {wrong} should actually be {right} in context of {topic}. This is an important nuance that affects how we should configure {system} in production environments. Previous assumptions about default values were incorrect for this use case",
        "New pattern: when user says '{phrase}', they usually mean {meaning}. This contextual understanding helps provide more accurate and relevant responses to similar future requests. The pattern has been consistent across multiple conversations",
        "Discovered that {system} requires {config} for optimal {goal}. Without this configuration, performance degrades significantly under load and can cause cascading failures in dependent services. Updated the recommended setup documentation accordingly",
        "Note: {library} v{version} has breaking changes in {feature}. Migration requires updating all call sites and reviewing the new API surface for compatibility issues. The changelog lists {feature} deprecation as the most impactful change",
    ],
    "environment": [
        "System running {os} with {ram}GB RAM; Python {py_version} installed. All required dependencies are up to date and the development environment is configured for optimal performance. Last full dependency audit completed with no vulnerabilities found",
        "Database backup completed at {time}; {count} records preserved. Incremental backup strategy is working correctly with no data integrity issues detected in the verification pass. Next scheduled backup window is in approximately six hours",
        "API rate limit approached: {current}/{limit} calls this hour. Consider implementing request batching or caching to reduce the number of individual API calls in peak usage periods. Current usage pattern suggests rate limiting may become an issue",
        "Workspace disk usage at {pct}%; cleanup recommended above 80%. Largest directories are the trace output files and experiment results which can be archived to external storage to free space. Automated cleanup policy should be configured",
        "Network latency to {service}: {latency}ms average over last hour. This is within acceptable range for the current workload but should be monitored during high-traffic periods. Historical baseline for this service is typically under {latency}ms",
    ],
}

FILL_VALUES = {
    "adj": ["concise", "detailed", "technical", "casual", "structured"],
    "topic": ["machine learning", "web development", "data analysis", "system administration", "API design"],
    "detail": ["code examples", "references", "cost estimates", "timelines", "alternatives"],
    "context": ["technical discussions", "project planning", "debugging sessions", "code reviews"],
    "language": ["Python", "TypeScript", "Rust", "Go", "SQL"],
    "approach": ["an outline", "a prototype", "requirements gathering", "research", "a diagram"],
    "thing": ["step-by-step breakdowns", "visual diagrams", "code snippets", "analogies"],
    "purpose": ["understanding complex topics", "debugging", "architecture decisions", "learning new tools"],
    "task": ["code refactoring", "database migration", "API endpoint setup", "test suite expansion", "documentation update"],
    "duration": ["15 minutes", "30 minutes", "1 hour", "2 hours"],
    "method": ["refactoring the handler", "adding error handling", "updating the schema", "caching results"],
    "timeframe": ["tomorrow morning", "next week", "end of sprint", "after deployment"],
    "issue": ["a race condition", "an off-by-one error", "a memory leak", "a missing null check"],
    "component": ["the auth module", "the API gateway", "the job queue", "the cache layer"],
    "fix": ["adding a mutex", "bounds checking", "proper cleanup", "input validation"],
    "artifact": ["a migration script", "an API client", "a test harness", "a deployment config"],
    "project": ["the backend rewrite", "the monitoring dashboard", "the CLI tool", "the data pipeline"],
    "tool": ["pandas", "asyncio", "SQLAlchemy", "FastAPI", "pytest"],
    "alt_tool": ["raw SQL", "threading", "Django ORM", "Flask", "unittest"],
    "use_case": ["batch processing", "concurrent I/O", "complex queries", "REST APIs", "parameterized tests"],
    "wrong": ["the default timeout", "the encoding format", "the retry strategy"],
    "right": ["30s instead of 10s", "UTF-8 with BOM", "exponential backoff"],
    "phrase": ["make it faster", "clean this up", "ship it", "let's revisit"],
    "meaning": ["optimize runtime performance", "refactor for readability", "deploy to production", "discuss in next session"],
    "system": ["PostgreSQL", "Redis", "Nginx", "Docker", "Kubernetes"],
    "config": ["connection pooling", "max memory 256MB", "worker_processes auto", "resource limits"],
    "goal": ["throughput", "latency", "reliability", "memory usage"],
    "library": ["numpy", "fastapi", "pydantic", "httpx", "sqlalchemy"],
    "version": ["2.0", "3.1", "0.100", "4.0", "1.0"],
    "feature": ["the serialization API", "the event loop", "type validation", "connection handling"],
    "os": ["Ubuntu 22.04", "Debian 12", "Ubuntu 24.04"],
    "ram": ["8", "16", "32"],
    "py_version": ["3.10", "3.11", "3.12"],
    "time": ["02:00 UTC", "06:00 UTC", "14:00 UTC", "22:00 UTC"],
    "count": ["47", "50", "53", "62"],
    "current": ["45", "72", "88", "95"],
    "limit": ["100", "100", "100", "100"],
    "pct": ["42", "58", "67", "73"],
    "service": ["api.openai.com", "github.com", "pypi.org", "registry.npmjs.org"],
    "latency": ["23", "45", "67", "112", "89"],
}

# Heartbeat checklist templates
HEARTBEAT_TEMPLATES = [
    "- Check for pending tasks in daily log\n- Review memory for any unresolved items from last session\n- If system metrics are stale (>1 hour), refresh environment status\n- Log heartbeat completion timestamp to daily log",
    "- Scan for new user messages\n- Verify all tool registrations are current\n- Check backup status from last interval\n- Confirm no orphaned temporary files in workspace",
    "- Validate recent memory entries for consistency\n- Review API rate limit status\n- Check system resource utilization\n- Prepare summary of session activities",
]

# Log entry templates for daily logs
LOG_TEMPLATES = [
    "## {time} — {event}\n{detail}. Session state saved.",
    "**{time}** | {event}\n> {detail}. Completed.",
    "### {time} — {event}\n{detail}. Status: done.\n",
]


def fill_template(template: str) -> str:
    """Fill a template string with random realistic values."""
    result = template
    for key, values in FILL_VALUES.items():
        placeholder = "{" + key + "}"
        while placeholder in result:
            result = result.replace(placeholder, random.choice(values), 1)
    return result


def generate_memory_content(category: str = None) -> str:
    """Generate a realistic memory entry bullet point."""
    if category is None:
        category = random.choice(list(MEMORY_TEMPLATES.keys()))
    template = random.choice(MEMORY_TEMPLATES[category])
    return fill_template(template)


def generate_log_entry() -> str:
    """Generate a realistic log entry for daily session logs."""
    hour = random.randint(9, 18)
    minute = random.randint(0, 59)
    time_str = f"{hour:02d}:{minute:02d}"

    events = [
        ("Task completed", "Finished user request in 2m30s"),
        ("Memory updated", "Added new learning about API rate limits"),
        ("Config check", "Verified all environment variables are set"),
        ("Tool registered", "New utility function added to toolkit"),
        ("Session checkpoint", "Saved workspace state, all systems nominal"),
        ("Query processed", "Answered user question with memory context"),
        ("Backup started", "Full workspace backup initiated"),
    ]

    event, detail = random.choice(events)
    template = random.choice(LOG_TEMPLATES)
    return template.format(time=time_str, event=event, detail=detail)


def generate_heartbeat() -> str:
    """Generate a heartbeat checklist."""
    return random.choice(HEARTBEAT_TEMPLATES)


def file_hash(content: bytes) -> str:
    """Compute SHA-256 hash prefix of file content."""
    return hashlib.sha256(content).hexdigest()[:16]


def read_file(filepath: str) -> Tuple[bytes, str]:
    """Read a file and return (content, hash)."""
    try:
        with open(filepath, "rb") as f:
            content = f.read()
        return content, file_hash(content)
    except FileNotFoundError:
        return b"", file_hash(b"")


class WorkloadGeneratorV4:
    """
    Generates and executes realistic agent workload operations on a markdown-based
    agent workspace (OpenClaw architecture).
    """

    def __init__(self, workspace_dir: str, profile_name: str = "W4", seed: int = 42):
        """
        Initialize generator for a specific workspace and profile.

        Args:
            workspace_dir: Path to agent_openclaw/workspace directory
            profile_name: Profile name (W1, W2, W3, W4)
            seed: Random seed for reproducibility
        """
        self.workspace_dir = workspace_dir
        self.profile = get_profile(profile_name)
        self.rng = random.Random(seed)
        random.seed(seed)

        self.trace = []
        self.ops_count = {}
        for op in self.profile.op_weights.keys():
            self.ops_count[op] = 0

        # Ensure workspace structure exists
        self._ensure_workspace()

    def _ensure_workspace(self):
        """Create workspace directories if they don't exist."""
        Path(self.workspace_dir).mkdir(parents=True, exist_ok=True)
        Path(os.path.join(self.workspace_dir, "memory")).mkdir(exist_ok=True)

        # Ensure credential directory exists
        cred_dir = os.path.join(os.path.dirname(self.workspace_dir), "credentials")
        Path(cred_dir).mkdir(parents=True, exist_ok=True)

        # Ensure .env exists
        env_path = os.path.join(cred_dir, ".env")
        if not os.path.exists(env_path):
            with open(env_path, "w") as f:
                f.write("# Credentials (read-only for agent)\nOPENAI_API_KEY=sk-...\n")

    def _log_op(self, op_type: str, target_file: str, success: bool,
                size_before: int = 0, size_after: int = 0,
                hash_before: str = "", hash_after: str = "",
                details: Dict = None):
        """Record an operation in the trace with file metrics."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "op_type": op_type,
            "target_file": target_file,
            "success": success,
            "size_before": size_before,
            "size_after": size_after,
            "hash_before": hash_before,
            "hash_after": hash_after,
            "details": details or {},
        }
        self.trace.append(entry)
        self.ops_count[op_type] = self.ops_count.get(op_type, 0) + 1

    def memory_insert(self) -> bool:
        """Insert a new bullet point into MEMORY.md."""
        memory_path = os.path.join(self.workspace_dir, "MEMORY.md")
        try:
            # Read current content
            with open(memory_path, "rb") as f:
                old_content = f.read()
            hash_before = file_hash(old_content)

            # Generate new entry
            content = generate_memory_content()

            # Append as bullet point to appropriate section (or general section)
            sections = ["## Learned Patterns", "## User Preferences", "## Environment"]
            section = random.choice(sections)

            text = old_content.decode("utf-8", errors="replace")

            # Find section and append
            if section in text:
                lines = text.split("\n")
                insert_idx = None
                for i, line in enumerate(lines):
                    if line.startswith(section):
                        # Find next section or end of file
                        for j in range(i + 1, len(lines)):
                            if lines[j].startswith("##"):
                                insert_idx = j
                                break
                        if insert_idx is None:
                            insert_idx = len(lines)
                        break

                if insert_idx is not None:
                    lines.insert(insert_idx, f"- {content}")
                    new_text = "\n".join(lines)
                else:
                    # Append to end
                    new_text = text + f"\n- {content}\n"
            else:
                # Append to end with section header
                new_text = text + f"\n\n{section}\n- {content}\n"

            new_content = new_text.encode("utf-8")
            hash_after = file_hash(new_content)

            with open(memory_path, "wb") as f:
                f.write(new_content)

            self._log_op("memory_insert", "workspace/MEMORY.md", True,
                        size_before=len(old_content), size_after=len(new_content),
                        hash_before=hash_before, hash_after=hash_after,
                        details={"content_preview": content[:60]})
            return True
        except Exception as e:
            self._log_op("memory_insert", "workspace/MEMORY.md", False,
                        details={"error": str(e)})
            return False

    def memory_update(self) -> bool:
        """Update MEMORY.md — either append a new entry or modify an existing one.

        Real agents (e.g., Gemini-driven OpenClaw) predominantly append new
        entries when "updating" memory (measured: ~100-250 byte appends from
        30 W4 sessions). In-place edits are less common. We model this as
        70% append-style updates and 30% in-place edits to match observed
        real-world behavior.
        """
        memory_path = os.path.join(self.workspace_dir, "MEMORY.md")
        try:
            with open(memory_path, "rb") as f:
                old_content = f.read()
            hash_before = file_hash(old_content)

            text = old_content.decode("utf-8", errors="replace")

            if random.random() < 0.7:
                # Append-style update (dominant mode in real agents)
                # Generates entries similar to real Gemini sessions:
                #   "- [2026-04-17] Task description: summary of response..."
                content = generate_memory_content()
                today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
                entry = f"\n- [{today}] {content}\n"
                new_text = text + entry
            else:
                # In-place edit (less common)
                lines = text.split("\n")
                bullet_lines = [i for i, line in enumerate(lines)
                                if line.strip().startswith("- ")]

                if not bullet_lines:
                    # No bullets to edit — fall back to append
                    content = generate_memory_content()
                    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
                    entry = f"\n- [{today}] {content}\n"
                    new_text = text + entry
                else:
                    idx = random.choice(bullet_lines)
                    old_line = lines[idx]
                    modifications = [
                        (lambda x: x.replace("1 hour", "2 hours")),
                        (lambda x: x.replace("15 minutes", "30 minutes")),
                        (lambda x: x.replace("42%", "58%")),
                        (lambda x: x + " (updated)"),
                        (lambda x: x.replace("tomorrow", "next week")),
                    ]
                    modify = random.choice(modifications)
                    lines[idx] = modify(old_line)
                    new_text = "\n".join(lines)

            new_content = new_text.encode("utf-8")
            hash_after = file_hash(new_content)

            with open(memory_path, "wb") as f:
                f.write(new_content)

            self._log_op("memory_update", "workspace/MEMORY.md", True,
                        size_before=len(old_content), size_after=len(new_content),
                        hash_before=hash_before, hash_after=hash_after,
                        details={})
            return True
        except Exception as e:
            self._log_op("memory_update", "workspace/MEMORY.md", False,
                        details={"error": str(e)})
            return False

    def memory_read(self) -> bool:
        """Read MEMORY.md content."""
        memory_path = os.path.join(self.workspace_dir, "MEMORY.md")
        try:
            with open(memory_path, "rb") as f:
                content = f.read()
            file_h = file_hash(content)

            # Count bullets and sections
            text = content.decode("utf-8", errors="replace")
            bullet_count = text.count("\n- ")
            section_count = text.count("\n## ")

            self._log_op("memory_read", "workspace/MEMORY.md", True,
                        size_before=len(content), hash_before=file_h,
                        details={"bullets": bullet_count, "sections": section_count})
            return True
        except Exception as e:
            self._log_op("memory_read", "workspace/MEMORY.md", False,
                        details={"error": str(e)})
            return False

    def memory_delete(self) -> bool:
        """Remove a bullet point from MEMORY.md (rare operation)."""
        memory_path = os.path.join(self.workspace_dir, "MEMORY.md")
        try:
            with open(memory_path, "rb") as f:
                old_content = f.read()
            hash_before = file_hash(old_content)

            text = old_content.decode("utf-8", errors="replace")
            lines = text.split("\n")

            # Find bullet points
            bullet_lines = [i for i, line in enumerate(lines) if line.strip().startswith("- ")]

            if not bullet_lines:
                return False

            # Remove a random bullet
            idx = random.choice(bullet_lines)
            del lines[idx]

            new_text = "\n".join(lines)
            new_content = new_text.encode("utf-8")
            hash_after = file_hash(new_content)

            with open(memory_path, "wb") as f:
                f.write(new_content)

            self._log_op("memory_delete", "workspace/MEMORY.md", True,
                        size_before=len(old_content), size_after=len(new_content),
                        hash_before=hash_before, hash_after=hash_after,
                        details={"line_index": idx})
            return True
        except Exception as e:
            self._log_op("memory_delete", "workspace/MEMORY.md", False,
                        details={"error": str(e)})
            return False

    def identity_read(self) -> bool:
        """Read one of SOUL.md, AGENTS.md, IDENTITY.md, USER.md."""
        filename = random.choice(["SOUL.md", "AGENTS.md", "IDENTITY.md", "USER.md"])
        filepath = os.path.join(self.workspace_dir, filename)
        try:
            with open(filepath, "rb") as f:
                content = f.read()
            file_h = file_hash(content)

            self._log_op("identity_read", f"workspace/{filename}", True,
                        size_before=len(content), hash_before=file_h,
                        details={"file": filename})
            return True
        except Exception as e:
            self._log_op("identity_read", f"workspace/{filename}", False,
                        details={"error": str(e), "file": filename})
            return False

    def identity_write(self) -> bool:
        """Write to an identity file (essentially never in normal ops)."""
        # This is intentionally a no-op in normal scenarios
        # but must be supported for profile W3 edge cases
        filename = random.choice(["SOUL.md", "AGENTS.md"])
        filepath = os.path.join(self.workspace_dir, filename)
        try:
            with open(filepath, "rb") as f:
                old_content = f.read()
            hash_before = file_hash(old_content)

            # Make a minimal change (append comment)
            new_content = old_content + b"\n<!-- Updated at " + \
                         datetime.now(timezone.utc).isoformat().encode() + b" -->\n"
            hash_after = file_hash(new_content)

            with open(filepath, "wb") as f:
                f.write(new_content)

            self._log_op("identity_write", f"workspace/{filename}", True,
                        size_before=len(old_content), size_after=len(new_content),
                        hash_before=hash_before, hash_after=hash_after,
                        details={"file": filename})
            return True
        except Exception as e:
            self._log_op("identity_write", f"workspace/{filename}", False,
                        details={"error": str(e), "file": filename})
            return False

    def config_read(self) -> bool:
        """Read openclaw.json or credentials/.env."""
        filename = random.choice(["openclaw.json", ".env"])

        if filename == "openclaw.json":
            filepath = os.path.join(os.path.dirname(self.workspace_dir), "openclaw.json")
        else:
            filepath = os.path.join(os.path.dirname(self.workspace_dir), "credentials", ".env")

        try:
            with open(filepath, "rb") as f:
                content = f.read()
            file_h = file_hash(content)

            self._log_op("config_read", filename, True,
                        size_before=len(content), hash_before=file_h,
                        details={"file": filename})
            return True
        except Exception as e:
            self._log_op("config_read", filename, False,
                        details={"error": str(e), "file": filename})
            return False

    def config_write(self) -> bool:
        """Make a small change to openclaw.json (e.g., update a timestamp field)."""
        filepath = os.path.join(os.path.dirname(self.workspace_dir), "openclaw.json")
        try:
            with open(filepath, "rb") as f:
                old_content = f.read()
            hash_before = file_hash(old_content)

            # Parse and modify JSON
            config = json.loads(old_content)

            # Update a timestamp or counter field
            if "lastHeartbeat" not in config:
                config["lastHeartbeat"] = datetime.now(timezone.utc).isoformat()
            else:
                config["lastHeartbeat"] = datetime.now(timezone.utc).isoformat()

            new_content = json.dumps(config, indent=2).encode("utf-8")
            hash_after = file_hash(new_content)

            with open(filepath, "wb") as f:
                f.write(new_content)

            self._log_op("config_write", "openclaw.json", True,
                        size_before=len(old_content), size_after=len(new_content),
                        hash_before=hash_before, hash_after=hash_after,
                        details={"change": "updated lastHeartbeat timestamp"})
            return True
        except Exception as e:
            self._log_op("config_write", "openclaw.json", False,
                        details={"error": str(e)})
            return False

    def log_append(self) -> bool:
        """Append a log entry to workspace/memory/YYYY-MM-DD.md (today's date)."""
        today = datetime.now().strftime("%Y-%m-%d")
        log_path = os.path.join(self.workspace_dir, "memory", f"{today}.md")

        try:
            # Read existing log or create new
            if os.path.exists(log_path):
                with open(log_path, "rb") as f:
                    old_content = f.read()
            else:
                old_content = f"# {today} Session Log\n\n".encode("utf-8")

            hash_before = file_hash(old_content)

            # Generate and append log entry
            entry = generate_log_entry()
            new_text = old_content.decode("utf-8", errors="replace") + entry + "\n\n"
            new_content = new_text.encode("utf-8")
            hash_after = file_hash(new_content)

            with open(log_path, "wb") as f:
                f.write(new_content)

            self._log_op("log_append", f"workspace/memory/{today}.md", True,
                        size_before=len(old_content), size_after=len(new_content),
                        hash_before=hash_before, hash_after=hash_after,
                        details={"entry_preview": entry[:60]})
            return True
        except Exception as e:
            self._log_op("log_append", f"workspace/memory/{today}.md", False,
                        details={"error": str(e)})
            return False

    def heartbeat_write(self) -> bool:
        """Overwrite HEARTBEAT.md with updated checklist."""
        hb_path = os.path.join(self.workspace_dir, "HEARTBEAT.md")
        try:
            with open(hb_path, "rb") as f:
                old_content = f.read()
            hash_before = file_hash(old_content)

            # Generate new heartbeat
            content = generate_heartbeat()
            new_content = ("# Heartbeat Checklist\n\n" + content).encode("utf-8")
            hash_after = file_hash(new_content)

            with open(hb_path, "wb") as f:
                f.write(new_content)

            self._log_op("heartbeat_write", "workspace/HEARTBEAT.md", True,
                        size_before=len(old_content), size_after=len(new_content),
                        hash_before=hash_before, hash_after=hash_after,
                        details={"items": content.count('-')})
            return True
        except Exception as e:
            self._log_op("heartbeat_write", "workspace/HEARTBEAT.md", False,
                        details={"error": str(e)})
            return False

    def generate_batch(self, n_ops: int = 100) -> List[Dict]:
        """Generate a batch of operations without timing delays."""
        op_names = list(self.profile.op_weights.keys())
        op_weights = [self.profile.op_weights[n] for n in op_names]

        op_methods = {
            "memory_insert": self.memory_insert,
            "memory_update": self.memory_update,
            "memory_read": self.memory_read,
            "memory_delete": self.memory_delete,
            "identity_read": self.identity_read,
            "identity_write": self.identity_write,
            "config_read": self.config_read,
            "config_write": self.config_write,
            "log_append": self.log_append,
            "heartbeat_write": self.heartbeat_write,
        }

        for _ in range(n_ops):
            op_name = random.choices(op_names, weights=op_weights, k=1)[0]
            op_methods[op_name]()

        return self.trace

    def generate_workload(self, duration_seconds: int = 60, ops_per_second: float = 2.0) -> List[Dict]:
        """
        Generate a realistic workload for the specified duration.
        Uses profile's operation distribution with realistic timing delays.
        """
        op_names = list(self.profile.op_weights.keys())
        op_weights = [self.profile.op_weights[n] for n in op_names]

        op_methods = {
            "memory_insert": self.memory_insert,
            "memory_update": self.memory_update,
            "memory_read": self.memory_read,
            "memory_delete": self.memory_delete,
            "identity_read": self.identity_read,
            "identity_write": self.identity_write,
            "config_read": self.config_read,
            "config_write": self.config_write,
            "log_append": self.log_append,
            "heartbeat_write": self.heartbeat_write,
        }

        total_ops = int(duration_seconds * ops_per_second)
        start_time = time.time()

        for i in range(total_ops):
            op_name = random.choices(op_names, weights=op_weights, k=1)[0]
            method = op_methods[op_name]
            method()

            # Add small random delay for realistic timing
            if duration_seconds > 0:
                delay = random.expovariate(ops_per_second)
                delay = min(delay, 2.0)  # Cap at 2 seconds
                time.sleep(delay)

                # Check if we've exceeded duration
                if time.time() - start_time >= duration_seconds:
                    break

        return self.trace

    def save_trace(self, output_path: str):
        """Save the operation trace to a JSONL file."""
        with open(output_path, "w") as f:
            for entry in self.trace:
                f.write(json.dumps(entry) + "\n")
        print(f"[WORKLOAD] Saved {len(self.trace)} operations to {output_path}")

    def summary(self) -> Dict:
        """Return a summary of the workload execution."""
        total = len(self.trace)
        succeeded = sum(1 for t in self.trace if t["success"])

        write_ops = sum(1 for t in self.trace if t["op_type"] in (
            "memory_insert", "memory_update", "memory_delete",
            "identity_write", "config_write", "log_append", "heartbeat_write"
        ))
        reads = total - write_ops

        # Calculate total bytes modified
        total_bytes_written = sum(t["size_after"] for t in self.trace if t["success"])

        return {
            "total_ops": total,
            "succeeded": succeeded,
            "failed": total - succeeded,
            "success_rate": succeeded / total if total > 0 else 0.0,
            "write_ops": write_ops,
            "read_ops": reads,
            "total_bytes_written": total_bytes_written,
            "profile": self.profile.name,
            "by_type": dict(self.ops_count),
        }


if __name__ == "__main__":
    # Parse command-line arguments
    workspace_dir = sys.argv[1] if len(sys.argv) > 1 else "agent_openclaw/workspace"
    profile_name = sys.argv[2] if len(sys.argv) > 2 else "W4"
    n_ops = int(sys.argv[3]) if len(sys.argv) > 3 else 100
    output = sys.argv[4] if len(sys.argv) > 4 else None

    print(f"[WORKLOAD] Generating {n_ops} operations for workspace at {workspace_dir}")
    print(f"[WORKLOAD] Profile: {profile_name}")

    gen = WorkloadGeneratorV4(workspace_dir, profile_name=profile_name, seed=42)
    gen.generate_batch(n_ops)

    summary = gen.summary()
    print(f"[WORKLOAD] Summary:")
    print(json.dumps(summary, indent=2))

    if output:
        gen.save_trace(output)
    else:
        # Default output path
        trace_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"trace_{profile_name}.jsonl")
        gen.save_trace(trace_path)
