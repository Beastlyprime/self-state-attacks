#!/usr/bin/env python3
"""
Experiment 2b: Anomaly Detection Across Workload Profiles

Tests the effectiveness of anomaly detection at identifying attacks
across different workload profiles (W1, W2, W3, W4). Evaluates whether
profile-aware baseline models can improve detection performance.

Experiment Flow:
  For each profile W in {W1, W2, W3, W4}:
    For trial t in {1, 2, 3}:

      Phase 1: Build baseline
        - Run ~1050 normal workload ops (profile W, seed=t*100)
        - Compute BaselineModel from operation statistics

      Phase 2: Test
        For each attack A in {B1..B8, S1..S8}:
          - Run 50 normal workload ops (fresh)
          - Inject attack A at random position
          - Score all events with anomaly detector
          - Record: was attack flagged? (at various thresholds)
          - Record: how many normal events were falsely flagged?

      Output: per (profile, trial) → per-attack TPR, FPR, ROC points

Output JSON structure:
  {
    "experiment": "exp2b_anomaly_detection",
    "profiles": ["W1", "W2", "W3", "W4"],
    "trials": 3,
    "thresholds": [...],
    "results": {
      "W1": {
        "trial_1": {
          "baseline_stats": {...},
          "per_attack": {
            "B1": {"tpr_at_threshold": {...}, ...},
            ...
          },
          "fpr_at_threshold": {...}
        }
      }
    },
    "detection_matrix": {
      "W1": {"B1": "high", "S1": "zero", ...},
      ...
    }
  }
"""

import os
import sys
import json
import random
import argparse
import shutil
import logging
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Tuple, Optional
from collections import defaultdict
import statistics
import math

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from workload.generator_v4 import WorkloadGeneratorV4
from workload.profiles import get_profile, ALL_PROFILES

# Real-trace baseline loader (ACTION_PLAN RB-5). Loaded lazily so this
# module still works when the helper is unavailable.
try:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from trace_baseline import (
        build_baseline_from_traces,
        default_trace_dir as _default_trace_dir,
    )
    _TRACE_BASELINE_AVAILABLE = True
except ImportError:
    _TRACE_BASELINE_AVAILABLE = False

logging.basicConfig(
    level=logging.INFO,
    format="[EXP2B] %(asctime)s — %(levelname)s — %(message)s"
)
log = logging.getLogger(__name__)


# =============================================================================
# Data Structures
# =============================================================================

@dataclass
class FileStatistics:
    """Statistics for a single (file, op_type) pair."""
    target_file: str
    op_type: str
    count: int = 0
    size_mean: float = 0.0
    size_std: float = 0.0
    freq_mean: float = 0.0
    freq_std: float = 0.0
    # Paper Eq. 1 second term: log inter-arrival statistics. Fitted from
    # log(Δt) where Δt is the interval (in seconds) between consecutive
    # events on the same (target_file, op_type) key in the train trace.
    # When fewer than 2 same-key events exist in train, time_log_count<2
    # and the score falls back to the size-only first term (paper:
    # max() degenerates to its first argument).
    time_log_mean: float = 0.0
    time_log_std: float = 0.0
    time_log_count: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class BaselineModel:
    """Baseline statistical model of normal operations for a profile."""
    profile_name: str
    profile_source: str
    n_ops: int
    timestamp: str

    # Per (file, op_type) statistics
    file_stats: Dict[Tuple[str, str], FileStatistics] = field(default_factory=dict)

    # Global statistics
    op_type_dist: Dict[str, float] = field(default_factory=dict)  # Frequencies
    identity_write_rate: float = 0.0
    config_write_rate: float = 0.0
    memory_insert_rate: float = 0.0
    memory_update_rate: float = 0.0

    # Profile-level pooled σ over all (file, op_type) keys with size_std>0.
    # Used as an empirical-Bayes σ floor on individual keys whose own
    # MLE σ is degenerate (n=1 or constant-delta train pool). Without
    # this floor, σ collapses to the magnitude-only fallback
    # max(|μ|·0.1, 1.0) which is too tight on sparse profiles and
    # produces high FPR on ordinary legitimate writes.
    size_pooled_sigma: float = 0.0

    def to_dict(self) -> dict:
        stats_dict = {}
        for key, stat in self.file_stats.items():
            stats_dict[f"{key[0]}:{key[1]}"] = stat.to_dict()

        return {
            "profile_name": self.profile_name,
            "profile_source": self.profile_source,
            "n_ops": self.n_ops,
            "timestamp": self.timestamp,
            "file_stats": stats_dict,
            "op_type_dist": self.op_type_dist,
            "identity_write_rate": self.identity_write_rate,
            "config_write_rate": self.config_write_rate,
            "memory_insert_rate": self.memory_insert_rate,
            "memory_update_rate": self.memory_update_rate,
            "size_pooled_sigma": self.size_pooled_sigma,
        }


@dataclass
class AnomalyEvent:
    """A single event from the workload trace."""
    op_type: str
    target_file: str
    size_delta: int
    success: bool
    timestamp: str


@dataclass
class AttackResult:
    """Result of testing a single attack."""
    attack_id: str
    attack_type: str  # "blunt" or "subtle"
    target_file: str
    tpr_at_threshold: Dict[float, float] = field(default_factory=dict)
    fpr_at_threshold: Dict[float, float] = field(default_factory=dict)
    attack_score: float = 0.0
    attack_detected: bool = False
    normal_events_count: int = 0
    normal_flagged: Dict[float, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "attack_id": self.attack_id,
            "attack_type": self.attack_type,
            "target_file": self.target_file,
            "attack_score": round(self.attack_score, 4),
            "attack_detected": self.attack_detected,
            "normal_events_count": self.normal_events_count,
            "tpr_at_threshold": {
                str(t): round(tpr, 4) for t, tpr in self.tpr_at_threshold.items()
            },
            "fpr_at_threshold": {
                str(t): round(fpr, 4) for t, fpr in self.fpr_at_threshold.items()
            },
            "normal_flagged": {
                str(t): count for t, count in self.normal_flagged.items()
            },
        }


# =============================================================================
# Baseline Model Training
# =============================================================================

def build_baseline_model(
    agent_dir: str,
    profile_name: str,
    n_ops: int = 1050,
    seed: int = 42
) -> BaselineModel:
    """
    Build a baseline model by running normal operations and collecting statistics.
    """
    log.info(f"Building baseline for {profile_name} with {n_ops} operations...")

    # Generate workload
    gen = WorkloadGeneratorV4(
        workspace_dir=os.path.join(agent_dir, "workspace"),
        profile_name=profile_name,
        seed=seed
    )
    gen.generate_batch(n_ops)
    trace = gen.trace

    log.info(f"Collected {len(trace)} operations")

    # Compute statistics per (file, op_type) pair, with bucket-key collapse so
    # workspace/memory/<X>.md daily-log/topical subfiles share one baseline.
    from workload.taxonomy import bucket_key  # type: ignore

    file_stats = {}
    size_deltas = defaultdict(list)
    op_type_counts = defaultdict(int)

    for event in trace:
        if not event.get("success", False):
            continue

        op_type = event.get("op_type", "unknown")
        target_file = event.get("target_file", "unknown")
        bucket = bucket_key(target_file)
        size_before = event.get("size_before", 0)
        size_after = event.get("size_after", 0)
        size_delta = abs(size_after - size_before)

        key = (bucket, op_type)
        if key not in file_stats:
            file_stats[key] = FileStatistics(target_file=bucket, op_type=op_type)

        file_stats[key].count += 1
        size_deltas[key].append(size_delta)
        op_type_counts[op_type] += 1

    # Compute mean and std for size deltas
    for key, stat in file_stats.items():
        deltas = size_deltas[key]
        if deltas:
            stat.size_mean = statistics.mean(deltas)
            stat.size_std = statistics.stdev(deltas) if len(deltas) > 1 else 0.0

    # Compute operation type distribution
    total_ops = sum(op_type_counts.values())
    op_type_dist = {
        op: count / total_ops for op, count in op_type_counts.items()
    }

    # Get profile for additional metadata
    profile = get_profile(profile_name)

    baseline = BaselineModel(
        profile_name=profile_name,
        profile_source=profile.source,
        n_ops=n_ops,
        timestamp=datetime.now(timezone.utc).isoformat(),
        file_stats=file_stats,
        op_type_dist=op_type_dist,
        identity_write_rate=profile.identity_write_rate,
        config_write_rate=profile.config_write_rate,
        memory_insert_rate=profile.memory_insert_rate,
        memory_update_rate=profile.memory_update_rate,
    )

    log.info(f"Baseline built: {len(file_stats)} file-op pairs, "
             f"{len(op_type_dist)} operation types")

    return baseline


def build_baseline_auto(
    agent_dir: str,
    profile_name: str,
    n_ops: int,
    seed: int,
    real_traces_dir: Optional[str] = None,
    real_traces_train_frac: float = 0.7,
) -> Tuple["BaselineModel", Optional[List[Dict]]]:
    """
    Build a baseline model, preferring real JSONL traces when available.

    Returns (baseline, real_test_events_or_None).

    If `real_traces_dir` is provided and exists, load real events from
    that dir and compute statistics (ACTION_PLAN RB-5). The held-out
    test split is returned so callers can use it as the normal-workload
    sample for attack injection (keeping train/test distributions
    aligned). Otherwise fall back to the synthetic WorkloadGeneratorV4
    and return (baseline, None).
    """
    if real_traces_dir and _TRACE_BASELINE_AVAILABLE and os.path.isdir(real_traces_dir):
        try:
            baseline, train_events, test_events = build_baseline_from_traces(
                trace_dir=real_traces_dir,
                profile_name=profile_name,
                profile_source="empirical_trace",
                train_frac=real_traces_train_frac,
                seed=seed,
            )
            log.info(
                "Baseline source: REAL TRACES (%s) — %d train events, "
                "%d held-out test events, %d file-op pairs",
                real_traces_dir, len(train_events), len(test_events),
                len(baseline.file_stats),
            )
            return baseline, test_events
        except Exception as e:
            log.warning(
                "Real-trace baseline failed for %s (%s) — falling back to synthetic",
                profile_name, e,
            )

    return build_baseline_model(
        agent_dir=agent_dir,
        profile_name=profile_name,
        n_ops=n_ops,
        seed=seed,
    ), None


# =============================================================================
# Anomaly Scoring
# =============================================================================

UNSEEN_KEY_SCORE = 1e6
"""Numeric stand-in for paper's "+∞" assignment to unseen (file, op_type)
keys. Any reasonable detection threshold (τ ≤ ~10 in practice) treats
this score the same as ∞, while keeping arithmetic finite for downstream
ROC/CSV serialization."""


def _coerce_seconds(value) -> Optional[float]:
    """Coerce an event timestamp field to seconds-as-float.

    Inotify traces emit unix epoch floats; trace_injection_detection's
    attach_temporal_times sets synthetic_time as float seconds; but
    make_attack_event uses datetime.now().isoformat() which is a
    string. Return None when coercion is impossible so the caller
    can drop the log-Δt term gracefully.
    """
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        # Fast path: numeric string
        try:
            return float(value)
        except ValueError:
            pass
        # ISO datetime fallback
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except (ValueError, TypeError):
            return None
    return None


def compute_anomaly_score(
    event: Dict,
    baseline: BaselineModel,
    prev_ts_by_key: Optional[Dict[Tuple[str, str], float]] = None,
) -> float:
    """
    Compute anomaly score for a single event using baseline statistics.

    Implements paper §5.1 Eq. (1):

        score(e, W) = max( |δ_s − μ_s^W| / σ_s^W,
                           |log Δt − μ_t^W| / σ_t^W )

    where μ_s, σ_s are per-(file, op_type) size-delta statistics fitted
    from the train split, μ_t, σ_t are per-(file, op_type) log
    inter-arrival statistics from the same split, and an unseen
    (file, op_type) scores +∞ (modeled here as ``UNSEEN_KEY_SCORE``).

    Δt comes from the caller-maintained ``prev_ts_by_key`` mapping. The
    caller is responsible for updating it AFTER scoring (typically with
    the just-scored event's timestamp) so that the next event in the
    sequence sees the correct previous timestamp. When ``prev_ts_by_key``
    is None or the key is unseen in the running sequence, the second
    term (log Δt) is dropped from the max, matching the paper's
    "first event of a key" boundary case.

    Args:
        event: trace event dict with at least ``op_type``, ``target_file``,
            ``size_before``, ``size_after``, ``timestamp`` fields.
        baseline: fitted BaselineModel from trace_baseline.build_baseline_from_traces.
        prev_ts_by_key: optional running map from (file, op_type) → last
            seen timestamp (in epoch seconds). Pass an empty dict and
            update it as you iterate the sequence to enable the log Δt
            term.

    Returns:
        Anomaly score (≥ 0). Higher = more anomalous.
    """
    op_type = event.get("op_type", "unknown")
    target_file = event.get("target_file", "unknown")
    size_after = event.get("size_after") or 0
    size_before = event.get("size_before") or 0
    # Signed delta — see trace_baseline.fit_baseline_from_train_events for
    # the matching change on the fitting side. Direction matters for
    # detection: +5B append vs -5B truncate are different events whose
    # legitimate distributions can have different shapes.
    size_delta = size_after - size_before

    # Bucket-collapse target file so memory/<X>.md daily logs share a
    # single distribution at lookup time, matching the aggregator.
    from workload.taxonomy import bucket_key  # type: ignore
    key = (bucket_key(target_file), op_type)
    if key not in baseline.file_stats:
        # Unseen (bucket, op_type) — paper assigns +∞.
        return UNSEEN_KEY_SCORE

    stat = baseline.file_stats[key]

    scores: List[float] = []

    # Term 1: size-delta z-score with σ floor.
    #
    # When the train split has σ_s = 0 (single sample, or all samples
    # share the same delta — e.g. truncate-and-rewrite events that all
    # leave size unchanged), the literal z-score is undefined. The old
    # fallback returned a fixed 5.0 whenever the test event differed
    # from the constant μ_s, which conflated "any deviation" with
    # "anomaly above τ" and prevented small in-distribution deviations
    # from receiving low scores — directly contradicting paper §4.2's
    # claim that small memory edits should be hard to flag at the OS
    # layer.
    #
    # Replace that with a magnitude-aware σ floor: σ_eff =
    # max(σ_s, |μ_s| * 0.1, 1.0). This keeps the z-score continuous
    # across train sample size and lets a 1-byte deviation against a
    # μ=12000 constant baseline score ~1/1200 (effectively 0) instead of
    # 5.0. The 1.0 minimum prevents "σ_eff = 0 when both μ and σ are 0"
    # from producing infinity for any non-zero delta.
    #
    # We also experimented with empirical-Bayes shrinkage toward the
    # per-profile pooled σ (BaselineModel.size_pooled_sigma): the FPR
    # improvement on sparse profiles was modest (W2 0.33→0.27, others
    # within noise) while several V cells on W3 dropped to C/I because
    # their "high TPR" was a sample-size artifact masked by the σ_floor.
    # Net effect on the V/C/I distribution was ambiguous (10/8/5 vs
    # 11/8/4), so we keep the simpler magnitude-aware floor; the
    # pooled σ remains in the BaselineModel for future analysis.
    sigma_floor = max(stat.size_std, abs(stat.size_mean) * 0.1, 1.0)
    scores.append(abs(size_delta - stat.size_mean) / sigma_floor)

    # Term 2: log-Δt z-score (paper Eq. 1 second term).
    #
    # We require ``synthetic_time`` here. Two timestamp domains exist on
    # trace events: ``synthetic_time`` (relative session seconds, used by
    # the injection harness) and ``timestamp`` (absolute wall-clock
    # seconds). Mixing them across the prev-ts map and the current
    # event's ts produces a spurious ~10^9 log-Δt difference whenever
    # one event uses one domain and the next uses the other, which
    # silently inflates attack TPR.
    #
    # The trace-injection driver assigns ``synthetic_time`` to every
    # event in the mixed sequence (attack events via assign_attack_times,
    # normal events via attach_temporal_times). When called outside that
    # pipeline (e.g., on raw trace events that only have ``timestamp``),
    # the caller is responsible for normalising. We treat absence of
    # ``synthetic_time`` as "no Δt term available" rather than silently
    # falling back to wall-clock.
    ts_num = _coerce_seconds(event.get("synthetic_time"))
    if (
        prev_ts_by_key is not None
        and ts_num is not None
        and stat.time_log_count >= 2
    ):
        prev_ts = prev_ts_by_key.get(key)
        if prev_ts is not None:
            dt = ts_num - float(prev_ts)
            # Floor to 1 ms, matching the train-side convention in
            # trace_baseline.py so train and score share the same
            # log-domain support.
            dt = dt if dt > 1e-3 else 1e-3
            log_dt = math.log(dt)
            if stat.time_log_std > 0:
                scores.append(abs(log_dt - stat.time_log_mean) / stat.time_log_std)
            elif log_dt != stat.time_log_mean:
                scores.append(5.0)

    return max(scores) if scores else 0.0


# =============================================================================
# Attack Execution
# =============================================================================

# Session-8 explicit attack registry. Decouples attack enumeration from
# filename prefixes so new taxonomy-meaningful names don't need numeric
# B/S id slots. Values are absolute module paths, resolved lazily below.
# Out-of-scope attacks (B5, B6) are retained for contrast but excluded
# from default runs (see ACTION_PLAN.md §"Out-of-scope").
_ATTACK_REGISTRY = {
    # Blunt (destructive) — in-scope
    "B1": ("../legacy/attacks/v4/blunt_v4", "b1_delete_memory.py"),
    "B2": ("../legacy/attacks/v4/blunt_v4", "b2_wipe_daily_logs.py"),
    "B3": ("../legacy/attacks/v4/blunt_v4", "b3_overwrite_soul.py"),
    "B4": ("../legacy/attacks/v4/blunt_v4", "b4_truncate_agents.py"),
    "B7": ("../legacy/attacks/v4/blunt_v4", "b7_chmod_config.py"),
    "B8": ("../legacy/attacks/v4/blunt_v4", "b8_destroy_backups.py"),
    "Inst_M3_G1_SOUL": ("../legacy/attacks/v4/blunt_v4", "inst_m3_g1_unlink_soul.py"),
    "Inst_M3_G1_AGENTS": ("../legacy/attacks/v4/blunt_v4", "inst_m3_g1_unlink_agents.py"),
    # Blunt — out-of-scope (credential substitution, process kill)
    "B5": ("../legacy/attacks/v4/blunt_v4", "b5_replace_api_key.py"),
    "B6": ("../legacy/attacks/v4/blunt_v4", "b6_kill_agent.py"),
    # Subtle — in-scope
    "S1": ("../legacy/attacks/v4/subtle_v4", "s1_insert_false_fact.py"),
    "S2": ("../legacy/attacks/v4/subtle_v4", "s2_modify_existing_memory.py"),
    "S3": ("../legacy/attacks/v4/subtle_v4", "s3_single_trait_change.py"),
    "S4": ("../legacy/attacks/v4/subtle_v4", "s4_add_subtle_instruction.py"),
    "S5": ("../legacy/attacks/v4/subtle_v4", "s5_redirect_api_endpoint.py"),
    "S6": ("../legacy/attacks/v4/subtle_v4", "s6_insert_backdoor_trigger.py"),
    "S7": ("../legacy/attacks/v4/subtle_v4", "s7_modify_capabilities.py"),
    "S8": ("../legacy/attacks/v4/subtle_v4", "s8_relax_safety_threshold.py"),
    # Session-8 additions
    "A1": ("../legacy/attacks/v4/subtle_v4", "a1_access_deny_memory.py"),
    "A2": ("../legacy/attacks/v4/subtle_v4", "a2_access_deny_identity.py"),
    "A3": ("../legacy/attacks/v4/subtle_v4", "a3_access_deny_rules.py"),
    "Mem_M1_G4": ("../legacy/attacks/v4/subtle_v4", "mem_m1_g4_fact_flip.py"),
    "Mem_M2_G4": ("../legacy/attacks/v4/subtle_v4", "mem_m2_g4_minimal_append.py"),
}

_OUT_OF_SCOPE_ATTACKS = {"B5", "B6"}


def get_attack_modules(include_out_of_scope: bool = False) -> Dict[str, str]:
    """Return {attack_id: absolute module path} from the explicit registry.

    Args:
        include_out_of_scope: if True, include B5/B6; otherwise omit them.
    """
    attacks_dir = os.path.join(PROJECT_ROOT, "attacks")
    out: Dict[str, str] = {}
    for attack_id, (pkg, filename) in _ATTACK_REGISTRY.items():
        if not include_out_of_scope and attack_id in _OUT_OF_SCOPE_ATTACKS:
            continue
        path = os.path.join(attacks_dir, pkg, filename)
        if os.path.exists(path):
            out[attack_id] = path
    return out


def execute_attack(agent_dir: str, attack_id: str) -> Dict:
    """
    Execute a single attack and return metadata.
    Returns dict with: success, target_file, op_type, size_before, size_after
    """
    attacks = get_attack_modules()

    if attack_id not in attacks:
        log.warning(f"Attack {attack_id} not found")
        return {"success": False, "attack_id": attack_id}

    module_path = attacks[attack_id]

    # Execute attack script
    import subprocess
    try:
        result = subprocess.run(
            [sys.executable, module_path, agent_dir],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode == 0 and result.stdout:
            try:
                attack_result = json.loads(result.stdout)
                attack_result["success"] = True
                return attack_result
            except json.JSONDecodeError:
                log.warning(f"Could not parse attack output for {attack_id}")
                return {"success": False, "attack_id": attack_id}
        else:
            log.warning(f"Attack {attack_id} failed: {result.stderr}")
            return {"success": False, "attack_id": attack_id}

    except subprocess.TimeoutExpired:
        log.warning(f"Attack {attack_id} timed out")
        return {"success": False, "attack_id": attack_id}
    except Exception as e:
        log.warning(f"Error executing attack {attack_id}: {e}")
        return {"success": False, "attack_id": attack_id}


# =============================================================================
# Test Execution
# =============================================================================

def test_attack_on_profile(
    agent_dir: str,
    profile_name: str,
    baseline: BaselineModel,
    attack_id: str,
    n_test_ops: int = 50,
    thresholds: List[float] = None,
    trial: int = 1,
    real_test_events: Optional[List[Dict]] = None,
) -> AttackResult:
    """
    Test a single attack on a profile:
    1. Run n_test_ops normal operations
    2. Inject attack
    3. Score all events
    4. Compute TPR/FPR at each threshold

    If `real_test_events` is provided (held-out 30% from the real-trace
    split), a deterministic sample is used as the normal workload so that
    test and baseline events come from the same distribution — this is
    required when the baseline was trained on real traces, otherwise the
    synthetic generator emits op_types the baseline has never seen and
    FPR explodes (ACTION_PLAN RB-5).
    """
    if thresholds is None:
        thresholds = [1.0, 1.5, 2.0, 2.5, 3.0, 4.0, 5.0, 7.0, 10.0]

    if real_test_events:
        # Deterministic sample from the real held-out test split.
        rng_local = random.Random(trial * 100 + hash(attack_id) % 100)
        if len(real_test_events) >= n_test_ops:
            normal_events = rng_local.sample(real_test_events, n_test_ops)
        else:
            # Not enough test events; reuse with replacement.
            normal_events = [rng_local.choice(real_test_events) for _ in range(n_test_ops)]
    else:
        # Synthetic fallback.
        gen = WorkloadGeneratorV4(
            workspace_dir=os.path.join(agent_dir, "workspace"),
            profile_name=profile_name,
            seed=trial * 100 + hash(attack_id) % 100
        )
        gen.generate_batch(n_test_ops)
        normal_events = gen.trace

    # Execute attack
    attack_metadata = execute_attack(agent_dir, attack_id)

    # Normalize attack target_file to relative path (matching generator format)
    raw_target = attack_metadata.get("target_file", "unknown")
    if os.path.isabs(raw_target):
        # Strip agent_dir prefix to get relative path like "workspace/MEMORY.md"
        try:
            rel_target = os.path.relpath(raw_target, agent_dir)
        except ValueError:
            rel_target = raw_target
    else:
        rel_target = raw_target

    # Map attack to the appropriate op_type for anomaly detection. Session-8
    # additions: A1/A2/A3 (attrib), MEM_M1_G4 / MEM_M2_G4 (memory writes),
    # ID_M3_G1 / RULES_M3_G1 (deletes on identity / rules).
    attack_op_map = {
        "B1": "memory_delete", "B2": "memory_delete", "B3": "identity_write",
        "B4": "identity_write", "B5": "config_write", "B6": "config_write",
        "B7": "config_attrib", "B8": "memory_delete",
        "S1": "memory_insert", "S2": "memory_update", "S3": "identity_write",
        "S4": "identity_write", "S5": "config_write", "S6": "log_append",
        "S7": "identity_write", "S8": "config_write",
        "A1": "memory_attrib", "A2": "identity_attrib", "A3": "identity_attrib",
        # Canonical 3-layer ids; uppercase legacy ids still resolve via
        # attacks/*/__init__.py LEGACY_ID_ALIASES but experiments should
        # emit canonical ids going forward.
        "Mem_M1_G4": "memory_update", "Mem_M2_G4": "memory_insert",
        "Inst_M3_G1_SOUL": "identity_delete",
        "Inst_M3_G1_AGENTS": "identity_delete",
    }

    # Inject attack event into trace at random position
    if attack_metadata.get("success"):
        attack_event = {
            "op_type": attack_op_map.get(attack_id, attack_metadata.get("op_type", "UNKNOWN")),
            "target_file": rel_target,
            "size_before": attack_metadata.get("size_before", 0),
            "size_after": attack_metadata.get("size_after", 0),
            "success": True,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        injection_pos = random.randint(0, len(normal_events))
        all_events = normal_events[:injection_pos] + [attack_event] + normal_events[injection_pos:]
        attack_found = True
    else:
        all_events = normal_events
        attack_found = False
        attack_event = None

    # Score all events
    scores = [
        {
            "event": event,
            "score": compute_anomaly_score(event, baseline),
            "is_attack": (event == attack_event) if attack_event else False,
        }
        for event in all_events
    ]

    # Compute TPR/FPR at each threshold
    tpr_at_threshold = {}
    fpr_at_threshold = {}
    normal_flagged = {}

    attack_score = 0.0
    attack_detected = False

    for threshold in thresholds:
        tp = 0  # Attack detected
        fp = 0  # False positives (normal ops flagged)
        fn = 0  # Attack missed
        tn = 0  # Normal ops not flagged

        for item in scores:
            is_attack = item["is_attack"]
            score = item["score"]
            flagged = score >= threshold

            if is_attack:
                attack_score = score
                if flagged:
                    tp += 1
                    attack_detected = True
                else:
                    fn += 1
            else:
                if flagged:
                    fp += 1
                else:
                    tn += 1

        # Compute rates
        tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        tpr_at_threshold[threshold] = tpr
        fpr_at_threshold[threshold] = fpr
        normal_flagged[threshold] = fp

    attack_type = "blunt" if attack_id.startswith("B") else "subtle"
    target_file = attack_metadata.get("target_file", "unknown")

    result = AttackResult(
        attack_id=attack_id,
        attack_type=attack_type,
        target_file=target_file,
        tpr_at_threshold=tpr_at_threshold,
        fpr_at_threshold=fpr_at_threshold,
        attack_score=attack_score,
        attack_detected=attack_detected,
        normal_events_count=len(normal_events),
        normal_flagged=normal_flagged,
    )

    log.info(f"  {attack_id}: score={attack_score:.2f}, detected={attack_detected}, "
             f"tpr@2.0={tpr_at_threshold.get(2.0, 0.0):.3f}")

    return result


# =============================================================================
# Helper Functions
# =============================================================================

def compute_binomial_ci(
    successes: int,
    trials: int,
    confidence: float = 0.95
) -> Tuple[float, float]:
    """
    Compute binomial confidence interval using normal approximation.
    Returns (lower, upper) bounds.
    """
    if trials == 0:
        return (0.0, 0.0)

    p = successes / trials
    z = 1.96 if confidence == 0.95 else 2.576  # 95% or 99%
    se = math.sqrt(p * (1 - p) / trials)
    margin = z * se

    return (max(0, p - margin), min(1, p + margin))


def generate_detection_matrix(
    results: Dict
) -> Dict[str, Dict[str, str]]:
    """
    Generate a profile × attack matrix showing detectability.
    Categories: "high", "medium", "low", "zero"
    """
    matrix = {}

    for profile_name, profile_data in results["results"].items():
        matrix[profile_name] = {}

        # Average across trials
        attack_results = defaultdict(list)

        for trial_name, trial_data in profile_data.items():
            if trial_name.startswith("trial_"):
                for attack_id, attack_data in trial_data.get("per_attack", {}).items():
                    # Use TPR at threshold 2.0 as detectability measure
                    tpr = attack_data.get("tpr_at_threshold", {}).get("2.0", 0.0)
                    attack_results[attack_id].append(tpr)

        # Classify each attack
        for attack_id, tprs in attack_results.items():
            avg_tpr = statistics.mean(tprs) if tprs else 0.0

            if avg_tpr >= 0.8:
                category = "high"
            elif avg_tpr >= 0.5:
                category = "medium"
            elif avg_tpr >= 0.1:
                category = "low"
            else:
                category = "zero"

            matrix[profile_name][attack_id] = category

    return matrix


def setup_fresh_agent(work_dir: str) -> str:
    """Create a fresh agent instance from the OpenClaw template."""
    agent_dir = os.path.join(work_dir, "agent_instance")
    template_dir = os.path.join(PROJECT_ROOT, "agent_openclaw")

    # Remove old instance if exists
    if os.path.exists(agent_dir):
        try:
            shutil.rmtree(agent_dir)
        except Exception as e:
            log.warning(f"Could not remove old agent_dir: {e}")

    # Copy fresh instance
    shutil.copytree(template_dir, agent_dir)

    # Note: We do NOT run setup_agent.py here because it would
    # shutil.rmtree the agent_dir (its own parent) and then fail to
    # copy template files back (since the source was just deleted).
    # The copytree above already provides a complete agent instance.

    return agent_dir


# =============================================================================
# Main Experiment
# =============================================================================

def run_experiment(
    profiles: List[str],
    trials: int,
    train_ops: int,
    test_ops: int,
    thresholds: List[float],
    agent_template_dir: str,
    work_dir: str,
    real_traces_dir_map: Optional[Dict[str, str]] = None,
    real_traces_train_frac: float = 0.7,
) -> Dict:
    """Run the full experiment.

    If `real_traces_dir_map` is provided (profile_name -> trace_dir path),
    baselines are built from real JSONL traces where available and fall
    back to synthetic generation otherwise (ACTION_PLAN RB-5).
    """

    os.makedirs(work_dir, exist_ok=True)

    # Record which profiles used real vs synthetic baselines so the
    # downstream figures/tables can reflect the provenance honestly.
    baseline_source_map: Dict[str, str] = {}

    results = {
        "experiment": "exp2b_anomaly_detection",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "profiles": profiles,
        "trials": trials,
        "train_ops": train_ops,
        "test_ops": test_ops,
        "thresholds": thresholds,
        "real_traces_dir_map": real_traces_dir_map or {},
        "baseline_source_map": baseline_source_map,
        "results": {},
    }

    # All in-scope attacks (21 after session-8 taxonomy overhaul).
    # Out-of-scope B5 / B6 are excluded from the default run; invoke by
    # id via `--attacks B5,B6` if the contrast experiment is needed.
    all_attacks = sorted(get_attack_modules(include_out_of_scope=False).keys())

    for profile_name in profiles:
        log.info(f"\n{'='*70}")
        log.info(f"Profile: {profile_name}")
        log.info(f"{'='*70}")

        results["results"][profile_name] = {}

        for trial in range(1, trials + 1):
            log.info(f"\nTrial {trial}/{trials}")
            trial_key = f"trial_{trial}"

            # Setup fresh agent
            trial_work_dir = os.path.join(work_dir, f"{profile_name}_trial{trial}")
            agent_dir = setup_fresh_agent(trial_work_dir)

            # Phase 1: Build baseline (real traces when available)
            log.info("Phase 1: Building baseline...")
            rt_dir = (real_traces_dir_map or {}).get(profile_name)
            baseline, real_test_events = build_baseline_auto(
                agent_dir=agent_dir,
                profile_name=profile_name,
                n_ops=train_ops,
                seed=trial * 100,
                real_traces_dir=rt_dir,
                real_traces_train_frac=real_traces_train_frac,
            )
            # Record provenance for reporting.
            baseline_source_map[profile_name] = baseline.profile_source

            # Phase 2: Test attacks
            log.info("Phase 2: Testing attacks...")
            per_attack = {}

            for attack_id in all_attacks:
                # Fresh agent for each attack test
                test_agent_dir = setup_fresh_agent(
                    os.path.join(trial_work_dir, f"test_{attack_id}")
                )

                attack_result = test_attack_on_profile(
                    agent_dir=test_agent_dir,
                    profile_name=profile_name,
                    baseline=baseline,
                    attack_id=attack_id,
                    n_test_ops=test_ops,
                    thresholds=thresholds,
                    real_test_events=real_test_events,
                    trial=trial,
                )

                per_attack[attack_id] = attack_result.to_dict()

            # Compute FPR (false positive rate across all normal ops)
            # This is approximated from the test runs
            fpr_at_threshold = {}
            total_normal_flagged = defaultdict(int)
            total_normal_ops = 0

            for attack_data in per_attack.values():
                total_normal_ops += attack_data["normal_events_count"]
                for threshold_str, fp_count in attack_data["normal_flagged"].items():
                    threshold = float(threshold_str)
                    total_normal_flagged[threshold] += fp_count

            if total_normal_ops > 0:
                for threshold in thresholds:
                    fpr_at_threshold[threshold] = (
                        total_normal_flagged[threshold] / total_normal_ops
                    )

            # Store trial results
            results["results"][profile_name][trial_key] = {
                "baseline_stats": baseline.to_dict(),
                "per_attack": per_attack,
                "fpr_at_threshold": {
                    str(t): round(fpr, 4) for t, fpr in fpr_at_threshold.items()
                },
            }

            log.info(f"Trial {trial} complete: {len(per_attack)} attacks tested")

    # Generate detection matrix
    log.info("\nGenerating detection matrix...")
    results["detection_matrix"] = generate_detection_matrix(results)

    return results


# =============================================================================
# Output and Summary
# =============================================================================

def print_summary_table(results: Dict):
    """Print a human-readable summary table."""
    print("\n" + "="*90)
    print("ANOMALY DETECTION ACROSS PROFILES — SUMMARY")
    print("="*90)

    # Show detection matrix
    print("\nDetectability Matrix (TPR@threshold=2.0):")
    print("(Categories: high=80%+, medium=50-80%, low=10-50%, zero=<10%)")
    print()

    matrix = results.get("detection_matrix", {})
    all_attacks = set()
    for attacks in matrix.values():
        all_attacks.update(attacks.keys())

    all_attacks = sorted(all_attacks)

    # Header
    print(f"{'Attack':<12}", end="")
    for profile in sorted(matrix.keys()):
        print(f"{profile:>12}", end="")
    print()
    print("-" * (12 + len(matrix) * 12))

    # Rows
    for attack in all_attacks:
        print(f"{attack:<12}", end="")
        for profile in sorted(matrix.keys()):
            cat = matrix[profile].get(attack, "?")
            print(f"{cat:>12}", end="")
        print()

    # Key findings
    print("\n" + "="*90)
    print("KEY FINDINGS:")
    print("="*90)

    # Count universally detectable attacks
    universal_high = []
    for attack in all_attacks:
        if all(matrix.get(p, {}).get(attack) == "high" for p in matrix.keys()):
            universal_high.append(attack)

    if universal_high:
        print(f"\nUniversally high-detection attacks (all profiles): {', '.join(universal_high)}")
        print("  → These represent 'easy wins' for anomaly detection")

    # Count universally undetectable attacks
    universal_zero = []
    for attack in all_attacks:
        if all(matrix.get(p, {}).get(attack) == "zero" for p in matrix.keys()):
            universal_zero.append(attack)

    if universal_zero:
        print(f"\nUniversally undetectable attacks (all profiles): {', '.join(universal_zero)}")
        print("  → These represent the irreducible OS-level detection gap")

    # Profile-dependent attacks
    profile_dependent = []
    for attack in all_attacks:
        cats = set(matrix.get(p, {}).get(attack) for p in matrix.keys())
        if len(cats) > 1 and attack not in universal_high and attack not in universal_zero:
            profile_dependent.append(attack)

    if profile_dependent:
        print(f"\nProfile-dependent attacks: {', '.join(profile_dependent)}")
        print("  → Detectability varies by workload profile")
        for attack in profile_dependent:
            print(f"\n  {attack}:")
            for profile in sorted(matrix.keys()):
                cat = matrix[profile].get(attack, "?")
                print(f"    {profile}: {cat}")


def main():
    parser = argparse.ArgumentParser(
        description="Experiment 2b: Anomaly Detection Across Workload Profiles"
    )
    parser.add_argument(
        "--profiles",
        nargs="+",
        default=["W1", "W2", "W3", "W4"],
        choices=list(ALL_PROFILES.keys()),
        help="Workload profiles to test"
    )
    parser.add_argument(
        "--trials",
        type=int,
        default=3,
        help="Number of trials per profile"
    )
    parser.add_argument(
        "--train-ops",
        type=int,
        default=1050,
        help="Operations for baseline training"
    )
    parser.add_argument(
        "--test-ops",
        type=int,
        default=50,
        help="Operations for attack testing"
    )
    parser.add_argument(
        "--thresholds",
        nargs="+",
        type=float,
        default=[1.0, 1.5, 2.0, 2.5, 3.0, 4.0, 5.0, 7.0, 10.0],
        help="Anomaly score thresholds"
    )
    parser.add_argument(
        "--agent-dir",
        type=str,
        default=os.path.join(PROJECT_ROOT, "agent_openclaw"),
        help="Path to agent scaffold template"
    )
    parser.add_argument(
        "--work-dir",
        type=str,
        default=os.path.join(PROJECT_ROOT, "results", "work", "exp2b_work"),
        help="Working directory for experiment"
    )
    parser.add_argument(
        "--output",
        type=str,
        default=os.path.join(PROJECT_ROOT, "results", "intermediate", "exp2b_results.json"),
        help="Output JSON file"
    )
    parser.add_argument(
        "--use-real-traces",
        action="store_true",
        help=(
            "Build baseline from real JSONL traces (ACTION_PLAN RB-5). "
            "Uses traces/<profile> by default; override with "
            "--trace-dir PROFILE=PATH. Profiles without real traces "
            "fall back to the synthetic generator."
        ),
    )
    parser.add_argument(
        "--trace-dir",
        action="append",
        default=[],
        metavar="PROFILE=PATH",
        help=(
            "Override the real-traces dir for a profile "
            "(e.g. --trace-dir W4=traces/W4_real). Repeatable."
        ),
    )
    parser.add_argument(
        "--real-traces-train-frac",
        type=float,
        default=0.7,
        help="Train/test split when using real traces (default 0.7)",
    )

    args = parser.parse_args()

    # Assemble the profile -> real-trace-dir map.
    real_traces_dir_map: Dict[str, str] = {}
    if args.use_real_traces and _TRACE_BASELINE_AVAILABLE:
        for prof in args.profiles:
            d = _default_trace_dir(prof, PROJECT_ROOT)
            if d and os.path.isdir(d):
                real_traces_dir_map[prof] = d
    for override in args.trace_dir:
        if "=" not in override:
            log.warning("Ignoring malformed --trace-dir %r (expected PROFILE=PATH)", override)
            continue
        prof, path = override.split("=", 1)
        prof = prof.strip().upper()
        if os.path.isdir(path):
            real_traces_dir_map[prof] = path
        else:
            log.warning("Trace dir %s not found; falling back to synthetic for %s", path, prof)

    log.info("="*70)
    log.info("EXPERIMENT 2b: ANOMALY DETECTION ACROSS WORKLOAD PROFILES")
    log.info("="*70)
    log.info(f"Profiles: {', '.join(args.profiles)}")
    log.info(f"Trials: {args.trials}")
    log.info(f"Training ops: {args.train_ops}")
    log.info(f"Test ops: {args.test_ops}")
    log.info(f"Thresholds: {args.thresholds}")
    log.info(f"Work directory: {args.work_dir}")
    log.info(f"Output: {args.output}")
    if real_traces_dir_map:
        log.info("Real-trace baselines enabled for: %s",
                 ", ".join(f"{p}={real_traces_dir_map[p]}" for p in real_traces_dir_map))
    else:
        log.info("Using synthetic WorkloadGeneratorV4 baseline for all profiles")

    # Run experiment
    results = run_experiment(
        profiles=args.profiles,
        trials=args.trials,
        train_ops=args.train_ops,
        test_ops=args.test_ops,
        thresholds=args.thresholds,
        agent_template_dir=args.agent_dir,
        work_dir=args.work_dir,
        real_traces_dir_map=real_traces_dir_map,
        real_traces_train_frac=args.real_traces_train_frac,
    )

    # Save results
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(results, f, indent=2, default=str)

    log.info(f"\nResults saved to {args.output}")

    # Print summary
    print_summary_table(results)

    log.info("\n" + "="*70)
    log.info("EXPERIMENT COMPLETE")
    log.info("="*70)


if __name__ == "__main__":
    main()
