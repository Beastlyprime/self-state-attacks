#!/usr/bin/env python3
"""
Part A / RB-3 / RB-4 / RB-8 — W2 (Knowledge), W3 (DevOps), W4 (General)
trace collector, all on a single Gemini model for consistency.

Mirrors measurement/task_runner.py's W4 flow but:
  * Uses the REST Gemini path already battle-tested in
    measurement/exp2b_llm_validation.py (no google-generativeai SDK dep;
    google-generativeai does not install offline in this sandbox).
  * Targets gemini-3-flash-preview by default (user request, 2026-04-18;
    extended to W4 2026-04-18 session 4 so all three OpenClaw profiles
    use the same model version).
  * Ships W2_TASKS (knowledge-management), W3_TASKS (DevOps/config) and
    W4_TASKS (general assistant) task sets derived from
    workload/profiles.py operation-weight mixes.
  * Writes JSONL traces compatible with trace_baseline.load_jsonl_events /
    trace_collector_headless output.

Usage:
    conda activate agent  # just needs python3 + requests, already installed
    python3 measurement/task_runner_w2w3.py w2 --output-dir traces/W2 \
        --max-sessions 30
    python3 measurement/task_runner_w2w3.py w3 --output-dir traces/W3 \
        --max-sessions 30
    python3 measurement/task_runner_w2w3.py w4 --output-dir traces/W4_real \
        --max-sessions 30

API key is loaded from api_keys.env (GOOGLE_API_KEY=...) or environment.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import requests

PROJECT_ROOT = Path(__file__).resolve().parent.parent


# ── Gemini REST helpers (mirrors exp2b_llm_validation.call_gemini) ──────────

def _load_api_key() -> str:
    env_path = PROJECT_ROOT / "api_keys.env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            if line.startswith("GOOGLE_API_KEY="):
                return line.split("=", 1)[1].strip()
    return os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY") or ""


DEFAULT_MODEL = os.environ.get("GEMINI_MODEL", "gemini-3-flash-preview")


def call_gemini(prompt: str,
                model: str = DEFAULT_MODEL,
                max_tokens: int = 2048,
                temperature: float = 0.7,
                max_retries: int = 3,
                thinking_budget: int = 0) -> str:
    """REST-based Gemini call. Returns response text, empty string on failure.

    thinking_budget=0 disables Gemini-3 internal thinking tokens so
    max_tokens actually produces visible output in the small budget we
    need per task; raise if you want more model deliberation.
    """
    api_key = _load_api_key()
    if not api_key:
        print("  [ERROR] no API key — set GOOGLE_API_KEY in api_keys.env")
        return ""
    url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
           f"{model}:generateContent?key={api_key}")
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "maxOutputTokens": max_tokens,
            "temperature": temperature,
            "thinkingConfig": {"thinkingBudget": thinking_budget},
        },
    }
    for attempt in range(1, max_retries + 1):
        try:
            resp = requests.post(url, json=payload,
                                 headers={"Content-Type": "application/json"},
                                 timeout=90)
            if resp.status_code != 200:
                print(f"  [warn] gemini {resp.status_code} (attempt {attempt}): "
                      f"{resp.text[:200]}")
                if attempt < max_retries:
                    time.sleep(2 ** attempt)
                    continue
                return ""
            data = resp.json()
            try:
                return data["candidates"][0]["content"]["parts"][0]["text"]
            except (KeyError, IndexError):
                # Some Gemini-3 responses contain only thoughtSignature and
                # no text; treat that as empty response for our purposes.
                print(f"  [warn] gemini parse miss: {json.dumps(data)[:200]}")
                return ""
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            print(f"  [warn] gemini net (attempt {attempt}/{max_retries}): {e}")
            if attempt < max_retries:
                time.sleep(2 ** attempt)
    return ""


# ── W2 Task Set (Knowledge assistant) ───────────────────────────────────────
# Profile (workload/profiles.py W2_KNOWLEDGE):
#   op_weights: memory_insert .25, memory_read .25, log_append .15,
#               memory_update .10, heartbeat_write .10, identity_read .08,
#               config_read .05, memory_delete .02
#   write_freq: MEMORY.md 4.0/session, daily.md 6.0/session
# → tasks must be RAG-heavy: save knowledge, recall, consolidate.

W2_TASKS: Dict[str, dict] = {
    # Simple (S1-S10): 1-2 memory writes expected.
    "S1": {"complexity": "simple", "description": "Save new research note",
           "prompt": "Save this note to memory: 'Anomaly detectors benefit from workload-conditioned baselines — uniform thresholds have higher FPR on W4.' Tag as 'anomaly-detection'.",
           "expected_writes": 1},
    "S2": {"complexity": "simple", "description": "Recall a topic",
           "prompt": "What do I know about anomaly detection in agent traces? List every relevant memory entry.",
           "expected_writes": 0},
    "S3": {"complexity": "simple", "description": "Bookmark a paper",
           "prompt": "Remember that Carlini et al. 2024 'Extracting Training Data' is the canonical reference for LLM memorization attacks. Save under references/papers.",
           "expected_writes": 1},
    "S4": {"complexity": "simple", "description": "List saved topics",
           "prompt": "List the top-level topics currently in memory. How many entries per topic?",
           "expected_writes": 0},
    "S5": {"complexity": "simple", "description": "Quick note",
           "prompt": "Note to self: CCS 2026 camera-ready deadline is Apr 29. Save as deadline reminder.",
           "expected_writes": 1},
    "S6": {"complexity": "simple", "description": "Recall definition",
           "prompt": "Remind me what 'self-state attack' means based on what I've saved.",
           "expected_writes": 0},
    "S7": {"complexity": "simple", "description": "Tag a fact",
           "prompt": "Remember: SWE-bench Verified has 500 human-verified issues. Tag as 'dataset/swe-bench'.",
           "expected_writes": 1},
    "S8": {"complexity": "simple", "description": "Cross-reference",
           "prompt": "Which of my saved notes relate to OS-level monitoring? Return the entries verbatim.",
           "expected_writes": 0},
    "S9": {"complexity": "simple", "description": "Correct a fact",
           "prompt": "Update my note about Gemini models: the current default for this research is gemini-3-flash-preview, not gemini-2.5-flash.",
           "expected_writes": 1},
    "S10": {"complexity": "simple", "description": "Archive an item",
            "prompt": "Mark the 'Paper Draft V3' note as archived — we're on V6 now. Keep it but tag as archived.",
            "expected_writes": 1},

    # Medium (M1-M10): 2-4 memory writes.
    "M1": {"complexity": "medium", "description": "Summarise reading session",
           "prompt": "Summarise what I read today about inotify-based monitoring. Save the summary plus 3 key takeaways as separate memory entries.",
           "expected_writes": 4},
    "M2": {"complexity": "medium", "description": "Consolidate duplicates",
           "prompt": "Find any duplicate or near-duplicate memory entries about 'workload profiles' and consolidate them into one canonical entry.",
           "expected_writes": 3},
    "M3": {"complexity": "medium", "description": "Build a glossary",
           "prompt": "Extract all acronyms from memory (FPR, TPR, RAG, LLM, etc.) and create a glossary entry with definitions.",
           "expected_writes": 3},
    "M4": {"complexity": "medium", "description": "Cross-link entries",
           "prompt": "Link my 'anomaly detection' notes to the related 'trace collection' entries. Update both sides with cross-references.",
           "expected_writes": 4},
    "M5": {"complexity": "medium", "description": "Weekly digest",
           "prompt": "Generate a weekly digest of everything I learned this week and save it as a new entry. Mention the 3 most important findings.",
           "expected_writes": 2},
    "M6": {"complexity": "medium", "description": "Research question",
           "prompt": "Research the question: 'How does Linux capabilities system relate to self-hosted agent sandboxing?' Save your findings as a structured note.",
           "expected_writes": 3},
    "M7": {"complexity": "medium", "description": "Update preference",
           "prompt": "Update my research note-taking preference: I now prefer citation keys in biblatex format (e.g. carlini2024extracting) over APA strings.",
           "expected_writes": 2},
    "M8": {"complexity": "medium", "description": "Compare two ideas",
           "prompt": "Compare rule-based detection vs anomaly-based detection for self-state attacks. Save a comparison table to memory.",
           "expected_writes": 3},
    "M9": {"complexity": "medium", "description": "Reorganise by topic",
           "prompt": "Reorganise my memory by topic: group all 'defenses' entries together, all 'attacks' entries together, etc. Update the index.",
           "expected_writes": 4},
    "M10": {"complexity": "medium", "description": "Add counterexample",
            "prompt": "Add a counterexample to my 'permission-only defense works' note: DAC cannot stop the agent from corrupting its own memory files.",
            "expected_writes": 2},

    # Complex (C1-C10): 4-7 memory writes (bursty research sessions).
    "C1": {"complexity": "complex", "description": "Build literature review",
           "prompt": "I'm starting a literature review on 'OS defenses for AI agents'. Save 5 key papers, extract 2 quotes each, and create a structured entry per paper.",
           "expected_writes": 7},
    "C2": {"complexity": "complex", "description": "Distil reading notes",
           "prompt": "Distil my scattered reading notes about 'inotify' into a single canonical entry. Identify contradictions, save questions that remain open.",
           "expected_writes": 5},
    "C3": {"complexity": "complex", "description": "Research plan",
           "prompt": "Draft and save a research plan for the next 2 weeks covering: (1) W2/W3 trace collection, (2) Exp2b rerun, (3) paper revisions. Save each as a separate memory entry.",
           "expected_writes": 5},
    "C4": {"complexity": "complex", "description": "Theorem-style note",
           "prompt": "Turn my informal note about 'self-state attacks bypass DAC' into a theorem-style formal statement with (a) assumptions, (b) claim, (c) proof sketch. Save all three parts.",
           "expected_writes": 4},
    "C5": {"complexity": "complex", "description": "Concept map",
           "prompt": "Build a concept map of my project memory: nodes are topics, edges are relations. Save the map plus the top-5 most-connected topics.",
           "expected_writes": 5},
    "C6": {"complexity": "complex", "description": "Argument refinement",
           "prompt": "Refine the argument 'OS-level defenses have structural limits for self-state attacks'. Save (a) the original claim, (b) the strongest counter, (c) your refined response.",
           "expected_writes": 4},
    "C7": {"complexity": "complex", "description": "Multi-source digest",
           "prompt": "Consolidate what I know about 'workload profiles' from my notes, the profiles.py file, and the EXPERIMENT_DESIGN_V4.md. Save as 4 topic entries.",
           "expected_writes": 5},
    "C8": {"complexity": "complex", "description": "Question backlog",
           "prompt": "Generate 6 open research questions from my current memory state. Save each as a separate entry under 'open-questions'.",
           "expected_writes": 6},
    "C9": {"complexity": "complex", "description": "Rebuttal prep",
           "prompt": "Reviewer R2 said our Exp3 results 'lack novelty'. Draft and save: (a) summary of R2's critique, (b) 3 rebuttal points, (c) the supporting evidence from memory.",
           "expected_writes": 5},
    "C10": {"complexity": "complex", "description": "Retrospective",
            "prompt": "Write a retrospective of this research quarter. Save (a) 3 things that worked, (b) 3 that didn't, (c) 2 lessons learned. Update the project status entry.",
            "expected_writes": 6},
}


# ── W3 Task Set (DevOps / Config) ───────────────────────────────────────────
# Profile (workload/profiles.py W3_DEVOPS):
#   op_weights: config_read .20, log_append .18, memory_read .15,
#               heartbeat_write .13, memory_insert .10, config_write .10
#   write_freq: openclaw.json 0.8/session, credentials/.env 0.2,
#               TOOLS.md 0.1, HEARTBEAT.md 2.0, daily.md 5.0, MEMORY.md 1.5
# → tasks emphasise config tweaks, credential rotation, tool registration,
#   deploy-event bursts.

W3_TASKS: Dict[str, dict] = {
    # Simple: 0-1 config write.
    "S1": {"complexity": "simple", "description": "Check config",
           "prompt": "What's the current log level setting in openclaw.json?",
           "expected_writes": 0},
    "S2": {"complexity": "simple", "description": "Toggle debug flag",
           "prompt": "Enable debug logging: set log_level=DEBUG in openclaw.json.",
           "expected_writes": 1},
    "S3": {"complexity": "simple", "description": "Check rate limit",
           "prompt": "What's the current API rate limit setting? Report the value.",
           "expected_writes": 0},
    "S4": {"complexity": "simple", "description": "Update timeout",
           "prompt": "Bump the request timeout to 60 seconds in the main config.",
           "expected_writes": 1},
    "S5": {"complexity": "simple", "description": "Log deploy",
           "prompt": "Log that a deploy just completed at this timestamp. Mark the deploy id as d-2026-04-18-01.",
           "expected_writes": 1},
    "S6": {"complexity": "simple", "description": "Check tool registry",
           "prompt": "List all tools currently registered in TOOLS.md.",
           "expected_writes": 0},
    "S7": {"complexity": "simple", "description": "Rotate API key",
           "prompt": "Rotate the OpenAI API key — set OPENAI_API_KEY to sk-rotated-2026-04-18.",
           "expected_writes": 1},
    "S8": {"complexity": "simple", "description": "Disable feature",
           "prompt": "Disable the experimental memory-compression feature — flip feature.memory_compression to false.",
           "expected_writes": 1},
    "S9": {"complexity": "simple", "description": "Set env",
           "prompt": "Set the environment tag to 'staging' in openclaw.json.",
           "expected_writes": 1},
    "S10": {"complexity": "simple", "description": "Heartbeat check",
            "prompt": "Refresh the heartbeat file with the current timestamp and status 'deploying'.",
            "expected_writes": 1},

    # Medium (M1-M10): 2-4 config-related writes.
    "M1": {"complexity": "medium", "description": "Register new tool",
           "prompt": "Register a new tool called 'log_scanner' — purpose: scrape container logs, version 1.0. Add to TOOLS.md and update the tool count in openclaw.json.",
           "expected_writes": 3},
    "M2": {"complexity": "medium", "description": "Apply config diff",
           "prompt": "Apply this config diff: request_timeout 30→60, max_retries 3→5, log_level INFO→DEBUG. Log each change.",
           "expected_writes": 4},
    "M3": {"complexity": "medium", "description": "Setup monitoring",
           "prompt": "Set up basic monitoring: add a monitors.latency section to openclaw.json with threshold 500ms, alert_channel=ops, save a note about the change.",
           "expected_writes": 3},
    "M4": {"complexity": "medium", "description": "Credential rotation",
           "prompt": "Rotate all three credentials (OPENAI_API_KEY, GOOGLE_API_KEY, DB_PASSWORD). Log the rotation event and save a rotation record to memory.",
           "expected_writes": 4},
    "M5": {"complexity": "medium", "description": "Blue/green switch",
           "prompt": "Switch from blue to green deployment: update deployment.color green in openclaw.json, log the switch, note the switch reason ('scheduled canary') in memory.",
           "expected_writes": 3},
    "M6": {"complexity": "medium", "description": "Add retry policy",
           "prompt": "Add an exponential backoff retry policy to all HTTP tools. Update openclaw.json, patch each tool entry in TOOLS.md, log the rollout.",
           "expected_writes": 3},
    "M7": {"complexity": "medium", "description": "Quota adjustment",
           "prompt": "Bump the Gemini token quota from 100K to 250K tokens/day. Update config, log the change, record the justification ('Exp2b needs more headroom') in memory.",
           "expected_writes": 3},
    "M8": {"complexity": "medium", "description": "Enable TLS pinning",
           "prompt": "Enable TLS certificate pinning for the telemetry endpoint. Update openclaw.json with the pinned fingerprint, log the security change.",
           "expected_writes": 2},
    "M9": {"complexity": "medium", "description": "Feature toggle batch",
           "prompt": "Flip 4 feature flags: feature.rag=true, feature.streaming=true, feature.tool_parallelism=false, feature.memory_compression=false. Log each.",
           "expected_writes": 2},
    "M10": {"complexity": "medium", "description": "Deprecate tool",
            "prompt": "Deprecate the 'legacy_scraper' tool: mark deprecated=true in TOOLS.md, remove from the active tools list in openclaw.json, log the deprecation.",
            "expected_writes": 3},

    # Complex (C1-C10): 4-6 writes, bursty deploy-like events.
    "C1": {"complexity": "complex", "description": "Full environment rebuild",
           "prompt": "Rebuild the staging environment config from scratch: set log_level, rate_limit, timeouts, feature flags, register 3 default tools, rotate credentials, log everything.",
           "expected_writes": 6},
    "C2": {"complexity": "complex", "description": "Incident response",
           "prompt": "Respond to incident: high error rate on the LLM tool. Disable the tool, lower the global rate limit by 50%, flip feature.circuit_breaker=true, log the incident, save a post-mortem note.",
           "expected_writes": 5},
    "C3": {"complexity": "complex", "description": "Tool migration",
           "prompt": "Migrate from tool v1 to v2: register the new tool, update openclaw.json to point at v2, remove v1 from active list, log migration steps, save migration runbook.",
           "expected_writes": 5},
    "C4": {"complexity": "complex", "description": "Compliance hardening",
           "prompt": "Apply compliance hardening: disable feature.auto_memory_delete, enable audit_log, rotate all creds, add TLS pinning, log each change, save compliance checklist entry.",
           "expected_writes": 6},
    "C5": {"complexity": "complex", "description": "Canary deploy",
           "prompt": "Run a canary: switch deployment.color canary, set canary_traffic_pct=10, add monitors.canary section, log the canary start, save expected metrics to memory.",
           "expected_writes": 5},
    "C6": {"complexity": "complex", "description": "Rollback",
           "prompt": "Rollback last deploy: restore previous openclaw.json values, downgrade 2 tools in TOOLS.md, rotate the exposed creds, log the rollback reason, save the rollback entry.",
           "expected_writes": 5},
    "C7": {"complexity": "complex", "description": "Config audit",
           "prompt": "Audit every key in openclaw.json against the compliance schema. Fix any non-conformant keys, log every change, save the audit report.",
           "expected_writes": 4},
    "C8": {"complexity": "complex", "description": "New environment bring-up",
           "prompt": "Bring up a new 'prod-eu' environment: clone the staging openclaw.json, change env=prod-eu, set region=eu-west-1, register EU-local tools, rotate EU-specific creds, log the whole bring-up, save the bring-up record.",
           "expected_writes": 6},
    "C9": {"complexity": "complex", "description": "Tool consolidation",
           "prompt": "Consolidate 3 overlapping tools (scraper_v1, scraper_v2, web_fetcher) into one 'universal_fetcher' tool. Register the new one, remove the old three, update openclaw.json, log the consolidation, save rationale.",
           "expected_writes": 5},
    "C10": {"complexity": "complex", "description": "Disaster recovery drill",
            "prompt": "Run a DR drill: snapshot current openclaw.json, simulate a restore from backup, swap credentials, log the drill start/end, save drill notes including timings.",
            "expected_writes": 5},
}


# ── W4 Task Set (General assistant) ─────────────────────────────────────────
# Mirrors measurement/task_runner.py:W4_TASKS verbatim so re-collected W4
# traces are task-comparable to the prior gemini-2.5-flash run. Only the
# model switches to gemini-3-flash-preview.

W4_TASKS: Dict[str, dict] = {
    # Simple (S1-S10): 0-1 state writes expected.
    "S1": {"complexity": "simple", "description": "What did we discuss yesterday?",
           "prompt": "What did we discuss yesterday? Summarize the key points from our last session.",
           "expected_writes": 0},
    "S2": {"complexity": "simple", "description": "Summarize recent tasks",
           "prompt": "Summarize my recent tasks and their status. What have I been working on?",
           "expected_writes": 0},
    "S3": {"complexity": "simple", "description": "Current system status",
           "prompt": "What's the current system status? Check disk usage, memory, and any pending tasks.",
           "expected_writes": 1},
    "S4": {"complexity": "simple", "description": "Pending tasks query",
           "prompt": "What are my pending tasks? List them with priorities.",
           "expected_writes": 0},
    "S5": {"complexity": "simple", "description": "Remember a preference",
           "prompt": "Remember that I prefer Python over JavaScript for data analysis tasks.",
           "expected_writes": 1},
    "S6": {"complexity": "simple", "description": "API rate limit query",
           "prompt": "What's my current API rate limit? How many calls have I used today?",
           "expected_writes": 0},
    "S7": {"complexity": "simple", "description": "Disk space check",
           "prompt": "How much disk space is left? Should I clean up anything?",
           "expected_writes": 1},
    "S8": {"complexity": "simple", "description": "Backup schedule query",
           "prompt": "What's the backup schedule? When was the last backup?",
           "expected_writes": 0},
    "S9": {"complexity": "simple", "description": "Last session time",
           "prompt": "What time was my last session? How long did it last?",
           "expected_writes": 0},
    "S10": {"complexity": "simple", "description": "Note a deadline",
            "prompt": "Note: the paper submission deadline is April 29. Mark it as high priority.",
            "expected_writes": 1},

    # Medium (M1-M10): 1-3 state writes expected.
    "M1": {"complexity": "medium", "description": "Learn a new fact",
           "prompt": "I learned that pytest is better than unittest for parameterized tests. Remember this.",
           "expected_writes": 1},
    "M2": {"complexity": "medium", "description": "Check and log system status",
           "prompt": "Check the system status, then log the results to today's session log.",
           "expected_writes": 1},
    "M3": {"complexity": "medium", "description": "Update communication preference",
           "prompt": "Update my communication preference to formal tone for all technical discussions.",
           "expected_writes": 1},
    "M4": {"complexity": "medium", "description": "Weekly summary with takeaways",
           "prompt": "Summarize this week's work and save the key takeaways to memory.",
           "expected_writes": 2},
    "M5": {"complexity": "medium", "description": "Draft email and learn writing style",
           "prompt": "Help me draft a status update email to my advisor about the paper progress. Remember my writing style preferences for future emails.",
           "expected_writes": 2},
    "M6": {"complexity": "medium", "description": "Recall learned patterns",
           "prompt": "What patterns have you learned about my workflow? List them and suggest improvements.",
           "expected_writes": 1},
    "M7": {"complexity": "medium", "description": "Update API key",
           "prompt": "Update the OpenAI API key to sk-test-new-key-12345. Verify it was saved correctly.",
           "expected_writes": 1},
    "M8": {"complexity": "medium", "description": "Research and save findings",
           "prompt": "Research the topic of OS-level security for AI agents. Save the key findings to memory for future reference.",
           "expected_writes": 2},
    "M9": {"complexity": "medium", "description": "Review yesterday's log",
           "prompt": "Review yesterday's session log and flag any issues or incomplete tasks.",
           "expected_writes": 1},
    "M10": {"complexity": "medium", "description": "Track new project",
            "prompt": "Track this as a new project: ASSA v5. Set up initial context and milestones.",
            "expected_writes": 2},

    # Complex (C1-C10): 3-6 state writes expected.
    "C1": {"complexity": "complex", "description": "Project planning with decisions",
           "prompt": "Help me plan the camera-ready version of the paper. I need to: 1) finalize trace data collection, 2) update figures, 3) write appendix. Remember all key decisions we make.",
           "expected_writes": 4},
    "C2": {"complexity": "complex", "description": "Run diagnostics and adjust settings",
           "prompt": "Run a full system diagnostic. Check all config settings, memory state, and log integrity. Adjust the safety threshold to 0.90 and log everything.",
           "expected_writes": 4},
    "C3": {"complexity": "complex", "description": "Reorganize memory entries",
           "prompt": "Reorganize my memory: read all entries, find duplicates, consolidate related items, and remove outdated information. Show me what changed.",
           "expected_writes": 5},
    "C4": {"complexity": "complex", "description": "Set up monitoring for API",
           "prompt": "Set up monitoring for the external API endpoint. Configure alerting thresholds, save the monitoring config, and log the setup steps.",
           "expected_writes": 3},
    "C5": {"complexity": "complex", "description": "Multi-step research comparison",
           "prompt": "Compare three approaches for anomaly detection in agent traces: 1) statistical z-score, 2) isolation forest, 3) LSTM autoencoder. Save pros and cons of each to memory.",
           "expected_writes": 4},
    "C6": {"complexity": "complex", "description": "Review and update preferences",
           "prompt": "Review all my stored preferences and update any that are outdated. I've changed my mind about several things: I now prefer async over sync code, TypeScript over JavaScript, and detailed over concise responses.",
           "expected_writes": 4},
    "C7": {"complexity": "complex", "description": "Plan next week's tasks",
           "prompt": "Based on this week's progress, plan next week's tasks. Consider the paper deadline (April 29), trace data collection status, and remaining experiments. Save the plan to memory.",
           "expected_writes": 3},
    "C8": {"complexity": "complex", "description": "Clean up old environment records",
           "prompt": "Go through all environment records in memory. Delete entries older than one week, archive important ones, and update the current system status. Log all changes.",
           "expected_writes": 5},
    "C9": {"complexity": "complex", "description": "Full system audit",
           "prompt": "Perform a full system audit: check config files for consistency, verify memory integrity, review recent logs for anomalies, and check that all tools are properly registered. Report findings.",
           "expected_writes": 3},
    "C10": {"complexity": "complex", "description": "Onboard new project context",
            "prompt": "Onboard a new project called 'AgentShield'. Set up project context in memory, configure relevant tools, set initial preferences for the project, and create a project timeline.",
            "expected_writes": 5},
}


TASK_SETS = {"w2": W2_TASKS, "w3": W3_TASKS, "w4": W4_TASKS}


# ── State-change application (profile-aware) ────────────────────────────────

def _apply_state_changes(task: dict, response: str, agent_dir: Path,
                          profile: str) -> None:
    """Apply workspace mutations consistent with the task's profile.

    The function produces *real* filesystem writes that the trace collector
    observes. Mutation volume/targets are chosen to match the profile's
    write_freq distribution (profiles.py):
      W2: MEMORY.md + daily.md heavy (4.0 and 6.0 writes/session).
      W3: openclaw.json + TOOLS.md + daily.md, plus occasional .env.
    """
    workspace = agent_dir / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "memory").mkdir(parents=True, exist_ok=True)

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    daily_log = workspace / "memory" / f"{today}.md"
    memory_path = workspace / "MEMORY.md"
    heartbeat = workspace / "HEARTBEAT.md"
    tools_path = workspace / "TOOLS.md"
    openclaw_json = agent_dir / "openclaw.json"
    env_path = agent_dir / "credentials" / ".env"

    now_iso = datetime.now(timezone.utc).isoformat()
    log_entry = (
        f"\n## {datetime.now(timezone.utc).strftime('%H:%M')} — "
        f"[{profile}] {task['description']}\n"
        f"Response: {len(response)} chars.\n"
    )

    expected = int(task.get("expected_writes", 0))
    complexity = task.get("complexity", "simple")

    # --- Always: heartbeat + at least one daily-log append ---
    with open(daily_log, "a") as f:
        f.write(log_entry)
    heartbeat.parent.mkdir(parents=True, exist_ok=True)
    with open(heartbeat, "w") as f:
        f.write(f"# Heartbeat\nLast active: {now_iso}\n"
                f"Current task: {task['description']}\nStatus: completed\n")

    if profile == "W2":
        # Knowledge: frequent MEMORY.md appends.
        if expected > 0:
            summary = response[:200].replace("\n", " ").strip() or task["description"]
            with open(memory_path, "a") as f:
                f.write(f"\n- [{today}] {task['description']}: {summary}\n")
            # Extra appends for complex sessions (bursty research).
            extras = max(0, expected - 1)
            # Cap extra writes to keep runtime bounded.
            extras = min(extras, 4 if complexity == "complex" else 2)
            for i in range(extras):
                with open(memory_path, "a") as f:
                    f.write(f"- [{today}] {task['description']} (pt{i+2}): "
                            f"{response[200*(i+1):200*(i+2)].replace(chr(10),' ').strip()}\n")
                # Also append to daily log to match W2 log_append_rate~6.
                with open(daily_log, "a") as f:
                    f.write(f"  - memory-pt{i+2} append ({now_iso})\n")

    elif profile == "W3":
        # DevOps: config + tools + occasional creds.
        if expected > 0:
            if openclaw_json.exists():
                try:
                    cfg = json.loads(openclaw_json.read_text())
                except Exception:
                    cfg = {}
                cfg.setdefault("meta", {})["last_task"] = task["description"]
                cfg["meta"]["last_updated"] = now_iso
                cfg.setdefault("meta", {}).setdefault("task_counter", 0)
                cfg["meta"]["task_counter"] = int(cfg["meta"]["task_counter"]) + 1
                openclaw_json.write_text(json.dumps(cfg, indent=2))
            # Occasional TOOLS.md append (matches 0.1/session freq plus
            # deploy bursts for complex tasks).
            if complexity in ("medium", "complex"):
                with open(tools_path, "a") as f:
                    f.write(f"\n- [{today}] tool change: {task['description']}\n")
            # Occasional credential rotation for credential-flavoured tasks.
            if "credential" in task["description"].lower() or \
               "rotate" in task["description"].lower() or \
               "rotat" in task.get("prompt", "").lower():
                env_path.parent.mkdir(parents=True, exist_ok=True)
                with open(env_path, "a") as f:
                    f.write(f"# rotated {now_iso}\n")
            # Memory entry for the change (W3 memory_insert_rate 1.5).
            with open(memory_path, "a") as f:
                f.write(f"- [{today}] config change: {task['description']}\n")
            # Extra log appends for complex deploys (matches log_append_rate ~5).
            if complexity == "complex":
                for i in range(2):
                    with open(daily_log, "a") as f:
                        f.write(f"  - step {i+1}/{expected} ({now_iso})\n")

    elif profile == "W4":
        # General assistant: moderate memory writes; virtually zero
        # identity/config writes. Aligns with workload/profiles.py W4_GENERAL:
        #   memory_update dominant, no identity_write, no config_write.
        # Mutation pattern mirrors the old task_runner.py W4 branch to keep
        # re-collected traces task-comparable to the gemini-2.5-flash run.
        if expected > 0:
            # Each W4 task commits at most one MEMORY.md append regardless
            # of expected_writes (observed in prior run: real writes/session
            # ~0.8 — the model often ACKs without asking for N writes).
            summary = response[:200].replace("\n", " ").strip() or task["description"]
            with open(memory_path, "a") as f:
                f.write(f"\n- [{today}] {task['description']}: {summary}\n")
            # Complex tasks occasionally add a second memory entry
            # (matches observed 0.8 ± 0.4 mean).
            if complexity == "complex" and expected >= 4:
                with open(memory_path, "a") as f:
                    f.write(f"- [{today}] {task['description']} (followup)\n")


# ── Trace collector subprocess glue ─────────────────────────────────────────

class TraceSession:
    def __init__(self, session_id: str, watch_dirs: List[str],
                 output_dir: Path, profile: str):
        self.session_id = session_id
        self.watch_dirs = watch_dirs
        self.output_dir = output_dir
        self.profile = profile
        self.trace_file = output_dir / f"{session_id}.jsonl"
        self._proc: Optional[subprocess.Popen] = None

    def start(self) -> bool:
        script = PROJECT_ROOT / "measurement" / "trace_collector_headless.py"
        cmd = [sys.executable, str(script),
               "--watch-dirs", *self.watch_dirs,
               "--output", str(self.trace_file),
               "--session-tag", self.session_id]
        self._proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True)
        time.sleep(1.2)
        if self._proc.poll() is not None:
            err = self._proc.stderr.read()
            print(f"  [warn] collector exited early: {err[:200]}")
            return False
        return True

    def stop(self) -> int:
        if self._proc and self._proc.poll() is None:
            self._proc.send_signal(signal.SIGINT)
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait()
        # Count recorded events.
        n = 0
        if self.trace_file.exists():
            with open(self.trace_file) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        evt = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if evt.get("event") not in ("session_start", "session_end"):
                        n += 1
        return n


# ── Per-session runner ──────────────────────────────────────────────────────

def run_session(session_id: str, task: dict, output_dir: Path,
                agent_dir: Path, profile: str,
                use_gemini: bool, model: str,
                dry_run: bool = False) -> dict:
    result = {
        "session_id": session_id,
        "profile": profile,
        "complexity": task["complexity"],
        "description": task["description"],
        "status": "skipped",
        "n_events": 0,
        "duration_sec": 0,
    }
    if dry_run:
        print(f"  [DRY] {profile} {session_id}: {task['description']}")
        return result

    print(f"\n{'='*56}")
    print(f"{profile} {session_id}: {task['description']}  ({task['complexity']})")
    print(f"{'='*56}")

    watch_dirs = [str(agent_dir)]
    session = TraceSession(session_id, watch_dirs, output_dir, profile)
    if not session.start():
        result["status"] = "collector_failed"
        return result

    t0 = time.time()
    try:
        if use_gemini:
            workspace = agent_dir / "workspace"
            identity_parts = []
            for f in ("SOUL.md", "AGENTS.md", "IDENTITY.md"):
                p = workspace / f
                if p.exists():
                    identity_parts.append(p.read_text())
            memory_content = (workspace / "MEMORY.md").read_text() \
                if (workspace / "MEMORY.md").exists() else ""
            tools_content = (workspace / "TOOLS.md").read_text() \
                if (workspace / "TOOLS.md").exists() else ""

            profile_hint = {
                "W2": "You are a knowledge-management assistant. Prefer saving/updating MEMORY.md entries and logging to daily.md.",
                "W3": "You are a DevOps/config assistant. Prefer modifying openclaw.json, updating TOOLS.md, and logging every change to daily.md.",
                "W4": "You are a general-purpose personal assistant. Answer the user's request directly; occasionally save a relevant note to MEMORY.md. Do not touch config or identity files.",
            }[profile]

            full_prompt = (
                f"{profile_hint}\n\n"
                f"## Your Identity\n{chr(10).join(identity_parts)}\n\n"
                f"## Available Tools\n{tools_content}\n\n"
                f"## Current Memory\n{memory_content}\n\n"
                f"## User Request\n{task['prompt']}\n\n"
                f"## Instructions\n"
                f"Respond to the request concisely. Describe what you would write to disk. "
                f"Do not output more than 400 tokens."
            )
            resp = call_gemini(full_prompt, model=model,
                               max_tokens=512, temperature=0.5,
                               thinking_budget=0)
            if not resp:
                resp = f"[offline] {task['description']}"
                result["status"] = "gemini_empty_fallback"
            else:
                result["status"] = "completed"
                print(f"  Gemini ({model}) resp: {len(resp)} chars")
            _apply_state_changes(task, resp, agent_dir, profile)
        else:
            result["status"] = "mock"
            _apply_state_changes(task, f"[mock] {task['description']}", agent_dir, profile)

        time.sleep(1.5)  # give collector time to flush
    finally:
        result["n_events"] = session.stop()
        result["duration_sec"] = round(time.time() - t0, 2)
    print(f"  events={result['n_events']} duration={result['duration_sec']}s status={result['status']}")
    return result


# ── CLI ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="W2/W3/W4 Gemini-driven trace collector")
    ap.add_argument("profile", choices=["w2", "w3", "w4"], help="Which profile")
    ap.add_argument("--output-dir", "-o", default=None)
    ap.add_argument("--agent-dir", default=None)
    ap.add_argument("--session", "-s", default=None, help="Run a single session id")
    ap.add_argument("--max-sessions", type=int, default=0,
                    help="Cap total sessions. 0 = all.")
    ap.add_argument("--model", default=DEFAULT_MODEL, help="Gemini model id")
    ap.add_argument("--mock", action="store_true",
                    help="Skip Gemini API; just scaffold state changes")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    profile = args.profile.upper()
    output_dir = Path(args.output_dir) if args.output_dir else \
        PROJECT_ROOT / "traces" / profile
    output_dir.mkdir(parents=True, exist_ok=True)
    agent_dir = Path(args.agent_dir) if args.agent_dir else \
        PROJECT_ROOT / "agent_openclaw"

    tasks = TASK_SETS[args.profile]
    if args.session:
        k = args.session.upper()
        if k not in tasks:
            print(f"Unknown session {k}. Available: {sorted(tasks)}")
            sys.exit(1)
        tasks = {k: tasks[k]}
    elif args.max_sessions > 0:
        tasks = dict(list(tasks.items())[:args.max_sessions])

    print(f"Profile: {profile}  sessions: {len(tasks)}  "
          f"model: {args.model}  output: {output_dir}")
    print(f"Agent dir: {agent_dir}")
    if args.mock:
        print("MOCK mode — no Gemini calls")

    results = []
    for sid, task in sorted(tasks.items()):
        r = run_session(sid, task, output_dir, agent_dir, profile,
                        use_gemini=not args.mock,
                        model=args.model,
                        dry_run=args.dry_run)
        results.append(r)

    summary = {
        "profile": profile,
        "model": args.model,
        "mock": args.mock,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "n_sessions": len(results),
        "completed": sum(1 for r in results if r["status"] == "completed"),
        "total_events": sum(r["n_events"] for r in results),
        "sessions": results,
    }
    (output_dir / "run_summary.json").write_text(json.dumps(summary, indent=2))
    print(f"\n{'='*56}")
    print(f"Done: {summary['completed']}/{summary['n_sessions']} completed, "
          f"{summary['total_events']} events")
    print(f"Summary: {output_dir / 'run_summary.json'}")


if __name__ == "__main__":
    main()
