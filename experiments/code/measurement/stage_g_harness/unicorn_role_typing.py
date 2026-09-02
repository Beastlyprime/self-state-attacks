#!/usr/bin/env python3
"""Role-based node typing for UNICORN (gen5 candidate).

Preregistered in paper/P2_UNICORN_GEN5_ROLE_TYPING_PREREGISTRATION_20260823.md.

Motivation: the gen4 adapter types a node by its resolved path, and self-state
files live under a run-specific prefix that carries the run id and the
`__poisoned` / `__clean` arm label. The two arms therefore hold disjoint type
vocabularies by construction. This module types a node by its *role* in a
committed pattern table applied to the run-relative path, so the vocabulary is
stable across runs and blind to the arm.

Two variants are provided:

  ROLE_ONLY  node type = H(role)                   -- node-intrinsic
  ROLE_OP    node type = H(role, op_class)         -- richer, but makes the
                                                      node type depend on which
                                                      edge it is seen on

This module computes types and runs the fairness gates. It does not invoke
UNICORN; scoring needs the pinned parser/modeler/analyzer and is out of scope
here.
"""
from __future__ import annotations

import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

ROLE_TABLE_VERSION = "assa.unicorn_role_table.v1"

# --- canonicalization -------------------------------------------------------

_RUN_ROOT = re.compile(r"^.*?/runs/[^/]+/")
_AGENT_INSTANCE = re.compile(r"(\.openclaw/agents/)[^/]+/")
_SESSION_LEAF = re.compile(r"session-\d{8}T\d{6}-[0-9a-f]+\.jsonl$")
_DATE_LEAF = re.compile(r"\d{4}-\d{2}-\d{2}\.md$")
_WORKSPACE_ROOT = re.compile(r"^.*?/workspace/")

# Tokens that must never reach a type string. G1 checks these.
BANNED_TOKEN_PATTERNS = [
    re.compile(r"__poisoned"),
    re.compile(r"__clean"),
    re.compile(r"\bp[0-9]_[a-z0-9_]*20\d{6}"),      # collection namespace
    re.compile(r"\d{8}T\d{6}"),                      # UTC timestamp
    re.compile(r"\d{4}-\d{2}-\d{2}"),                # date stamp
    re.compile(r"/runs/"),
    re.compile(r"C\d{3}_w\d_"),                      # case/run id
]


def canonical_path(raw: str) -> str:
    """Reduce an absolute path to a run-relative, run-stable form."""
    if not raw:
        return ""
    p = _RUN_ROOT.sub("", raw)
    if p == raw and "/workspace/" in raw:
        # workspace reached by a different prefix (e.g. a stageg repo root)
        p = "workspace/" + _WORKSPACE_ROOT.sub("", raw)
    p = _AGENT_INSTANCE.sub(r"\1<INSTANCE>/", p)
    p = _SESSION_LEAF.sub("session-<SESSION>.jsonl", p)
    p = _DATE_LEAF.sub("<DATE>.md", p)
    return p


# --- role table -------------------------------------------------------------

SELF_STATE_INSTRUCTION = {"SOUL.md", "AGENTS.md", "IDENTITY.md", "USER.md", "TOOLS.md"}
SELF_STATE_CONFIG = {"openclaw.json", "HEARTBEAT.md"}

APPARATUS_EXE = {
    "auditctl", "ausearch", "auditd", "sysdig", "falco", "aide", "strace",
    "inotifywait", "bpftool", "scap", "sysdig-probe",
}
TOOL_EXE = {
    "dash", "sh", "bash", "ls", "mv", "rm", "mkdir", "date", "cat", "grep",
    "sed", "awk", "cp", "touch", "chmod", "find", "head", "tail", "unshare",
    "ldconfig.real", "ldconfig", "env", "which",
}
AGENT_WORKER_HINT = re.compile(r"python3(\.\d+)?$")

EXTERNAL_INPUT_HINTS = (
    "delivered_carrier", "carrier_quarantine/", "carrier.bin",
)


def assign_role(node: dict[str, Any]) -> str:
    """Map a provenance node to a role. Ordered; first match wins."""
    base = node.get("node_type") or "unknown"
    attrs = node.get("attributes") or {}
    raw = attrs.get("resolved_path") or attrs.get("exe") or attrs.get("raw_path") or ""
    p = canonical_path(raw)

    if base == "process":
        exe = (attrs.get("exe") or "").rsplit("/", 1)[-1]
        if exe in APPARATUS_EXE:
            return "process.apparatus"
        if AGENT_WORKER_HINT.search(exe or ""):
            return "process.agent_worker"
        if exe in TOOL_EXE:
            return "process.tool_subprocess"
        return "process.other"

    if base.startswith("socket"):
        local = str(attrs.get("local_address") or "")
        if local.startswith("127.") or local == "::1":
            return "socket.loopback"
        return "socket.external"

    # file-like nodes
    if any(h in p for h in EXTERNAL_INPUT_HINTS):
        return "external_input"
    if p.startswith("workspace/"):
        leaf = p.split("/", 1)[1] if "/" in p else ""
        if leaf == "MEMORY.md":
            return "self_state.memory.root"
        if leaf.startswith("memory/"):
            return "self_state.memory.log"
        if leaf in SELF_STATE_INSTRUCTION:
            return "self_state.instruction"
        if leaf in SELF_STATE_CONFIG:
            return "self_state.config"
        return "workspace.other"
    if p.startswith(".openclaw/agents/<INSTANCE>/sessions/"):
        return "apparatus.session_log"
    if p.startswith(".openclaw/"):
        return "apparatus.agent_state"
    if (p.startswith(("semantic/", "raw/", "graph/", "health/", "control/",
                      "state_snapshots/", "bin/"))
            or p.endswith("_attestation.json")
            or p.endswith((".start.json", ".stop.json"))):
        return "apparatus.collection"
    for prefix, role in (
        ("/usr/lib/", "system.library"), ("/lib/", "system.library"),
        ("/usr/bin/", "system.binary"), ("/usr/sbin/", "system.binary"),
        ("/bin/", "system.binary"), ("/sbin/", "system.binary"),
        ("/usr/share/", "system.share"), ("/etc/", "system.config"),
        ("/proc/", "system.pseudo"), ("/sys/", "system.pseudo"),
        ("/dev/", "system.pseudo"), ("/tmp/", "system.temp"),
        ("/var/tmp/", "system.temp"), ("/var/", "system.var"),
        ("/opt/", "system.opt"), ("/home/", "system.home"),
    ):
        if p.startswith(prefix):
            return role
    if not p:
        return f"unclassified.{base}"
    # NO raw-path fallback: collapse to the first segment only.
    return "unclassified." + (p.split("/", 1)[0] or "root")


OP_CLASS = {
    "read": "read", "write": "write", "chmod": "attrib", "exec": "exec",
    "unlink": "unlink", "rename": "rename", "fork": "fork",
    "send": "net", "recv": "net", "transfer": "net",
}


def op_class(relation: str) -> str:
    return OP_CLASS.get(relation, "other")


# --- typing -----------------------------------------------------------------

def read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def type_strings(graph_dir: Path, variant: str) -> tuple[list[str], dict[str, str]]:
    """Return (per-edge-endpoint type strings, node_id -> role)."""
    nodes = {r["node_id"]: r for r in read_jsonl(graph_dir / "provenance.nodes.jsonl")}
    roles = {nid: assign_role(n) for nid, n in nodes.items()}
    emitted: list[str] = []
    for edge in read_jsonl(graph_dir / "provenance.edges.jsonl"):
        oc = op_class(edge.get("relation") or "")
        for key in ("source_node_id", "destination_node_id"):
            role = roles.get(edge[key], "unclassified.missing")
            emitted.append(role if variant == "ROLE_ONLY" else f"{role}|{oc}")
    return emitted, roles


# --- fairness gates ---------------------------------------------------------

def g1_arm_blind(types: Iterable[str]) -> dict[str, Any]:
    violations: Counter[str] = Counter()
    for t in set(types):
        for pat in BANNED_TOKEN_PATTERNS:
            if pat.search(t):
                violations[pat.pattern] += 1
    return {"passed": not violations, "violations": dict(violations)}


def g3_non_degenerate(types: list[str], min_distinct: int = 12,
                      min_entropy: float = 0.35) -> dict[str, Any]:
    hist = Counter(types)
    k, n = len(hist), sum(hist.values())
    if k <= 1 or n == 0:
        return {"passed": False, "distinct": k, "normalized_entropy": 0.0,
                "min_distinct": min_distinct, "min_entropy": min_entropy}
    h = -sum((c / n) * math.log2(c / n) for c in hist.values())
    norm = h / math.log2(k)
    return {"passed": k >= min_distinct and norm >= min_entropy,
            "distinct": k, "shannon_bits": round(h, 4),
            "normalized_entropy": round(norm, 4),
            "min_distinct": min_distinct, "min_entropy": min_entropy}


def jaccard(a: set[str], b: set[str]) -> float:
    return len(a & b) / len(a | b) if (a or b) else 1.0


def g2_run_stability(vocabs: dict[str, set[str]], floor: float = 0.95) -> dict[str, Any]:
    keys = sorted(vocabs)
    pairs = [(x, y, round(jaccard(vocabs[x], vocabs[y]), 4))
             for i, x in enumerate(keys) for y in keys[i + 1:]]
    worst = min((p[2] for p in pairs), default=1.0)
    return {"passed": worst >= floor, "worst_jaccard": worst, "floor": floor,
            "n_runs": len(keys),
            "worst_pair": min(pairs, key=lambda p: p[2])[:2] if pairs else None}


def arm_role_parity(clean: set[str], poisoned: set[str]) -> dict[str, Any]:
    """The (b) question: do the two arms expose the same role vocabulary?"""
    return {"identical": clean == poisoned,
            "jaccard": round(jaccard(clean, poisoned), 4),
            "clean_only": sorted(clean - poisoned),
            "poisoned_only": sorted(poisoned - clean)}
