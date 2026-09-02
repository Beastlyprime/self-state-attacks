#!/usr/bin/env python3
"""C1 benign-splice indistinguishability check.

C1 is a precondition for injection-mode templating: after re-anchoring a benign
self-state write template into a held-out clean session, a classifier should not
be able to separate spliced benign events from native benign events.  This script
builds the templating mechanism and evaluates that failure mode.
"""

from __future__ import annotations

import argparse
import copy
import json
import math
import random
import statistics
import sys
from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

SOURCES = ("inotify", "fanotify", "auditd", "ebpf")
SCHEMA_VERSION = "assa.c1.benign_splice.v1"
SESSION_REANCHOR_FIELDS = ("run_id", "timestamp_realtime_ns", "timestamp_monotonic_ns", "process", "path", "logical_path", "inode", "fd")
# Field-level positive controls cover every field family the templater rewrites.
# Process subfields are listed explicitly because auditd/eBPF provenance leaks
# often live in auid/ses/exe/start-time rather than in the top-level process key.
DEFAULT_REANCHOR_FIELD_SPECS = (
    "run_id",
    "timestamp_realtime_ns",
    "timestamp_monotonic_ns",
    "path",
    "logical_path",
    "inode",
    "fd",
    "process.pid",
    "process.tid",
    "process.ppid",
    "process.exe",
    "process.comm",
    "process.cwd",
    "process.auid",
    "process.ses",
    "process.process_start_time_ticks",
    "ingestion_join_key.run_id",
    "ingestion_join_key.pid",
    "ingestion_join_key.process_start_time_ticks",
    "ingestion_join_key.fd",
    "ingestion_join_key.path",
    "ingestion_join_key.inode",
    "ingestion_join_key.timestamp_monotonic_ns",
    "auditd.syscall_arguments_raw",
)
TEMPORAL_FIELD_SPECS = {"timestamp_realtime_ns", "timestamp_monotonic_ns", "ingestion_join_key.timestamp_monotonic_ns"}
LONG_STRING_HASH_THRESHOLD = 128


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    if not path.is_file():
        return rows
    for line in path.read_text(encoding="utf-8", errors="strict").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def _logical_path(row: dict[str, Any]) -> str | None:
    value = row.get("logical_path")
    return value if isinstance(value, str) and value else None


def _path_basename(value: object) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    return PurePosixPath(value.replace("\\", "/")).name


# Equivalent names for the SAME OS-visible session-A poisoned-carrier read
# observation, across collector schema versions.  Older paired-live bundles
# (e.g. pilot_006 w3fix) use ``carrier_read_observed``; batch3/batch4 bundles
# renamed it to ``carrier_read_observed_in_session_a``.  Recognising both is a
# schema-compatibility fix, not a relaxation of the admissibility standard:
# each flag denotes a real carrier read observed in the OS trace.  Non-OS
# ingestion attestations (``user_message_provenance_observed``,
# ``external_content_provenance_observed``) are deliberately NOT included here,
# because they are not OS-visible carrier reads and would overclaim OS-layer
# provenance admissibility.
OS_VISIBLE_CARRIER_READ_KEYS = (
    "carrier_read_observed",
    "carrier_read_observed_in_session_a",
)


def _os_visible_carrier_read_key(checks: dict[str, Any]) -> str | None:
    for key in OS_VISIBLE_CARRIER_READ_KEYS:
        if checks.get(key):
            return key
    return None


# Channels whose carrier is ingested through a filesystem read the four OS
# monitors can see with path/inode identity.  user_message and external_content
# are delivered over the model/HTTP path and produce no OS-visible carrier read.
_NON_OS_CARRIER_READ_CHANNELS = ("user_message", "external_content")


def _is_os_carrier_read_channel(channel: object) -> bool:
    return channel not in _NON_OS_CARRIER_READ_CHANNELS


def _channel_ingestion_evidence_key(channel: object, checks: dict[str, Any]) -> str | None:
    """Ground-truth ingestion evidence for a sample's known carrier channel.

    The carrier is declared at construction time, so admission is a lookup, not
    an inference: a file carrier must show its OS-visible read; a user_message /
    external_content carrier must show its delivered-ingestion attestation.
    """
    if channel == "user_message":
        return "user_message_provenance_observed" if checks.get("user_message_provenance_observed") else None
    if channel == "external_content":
        return "external_content_provenance_observed" if checks.get("external_content_provenance_observed") else None
    return _os_visible_carrier_read_key(checks)


def _channel_ingestion_observed(channel: object, checks: dict[str, Any]) -> bool:
    return _channel_ingestion_evidence_key(channel, checks) is not None


def _load_run_groups(run_dir: Path, *, host_mode: str = "clean") -> list[dict[str, Any]]:
    """Load write groups while retaining whether the host had real poisoned ingestion.

    Production Route-B hosts use ``poisoned_attack_failed``: valid poisoned
    paired-live runs whose carrier was observed but whose attack did not realize.
    ``clean`` is retained only for historical C1/legacy-L3 artifacts.
    """
    if host_mode not in {"clean", "poisoned_attack_failed"}:
        raise ValueError("unknown host_mode: %s" % host_mode)
    truth_path = run_dir / "ground_truth.json"
    truth: dict[str, Any] = {}
    if truth_path.is_file():
        truth = _read_json(truth_path)
        if truth.get("pipeline_status") != "valid_attempt":
            return []
        if host_mode == "clean" and truth.get("variant") not in {None, "clean"}:
            return []
        if host_mode == "poisoned_attack_failed":
            if truth.get("variant") != "poisoned":
                return []
            if not str(truth.get("branch_outcome", "")).startswith("attack_failed"):
                return []
            checks = truth.get("checks") if isinstance(truth.get("checks"), dict) else {}
            delivery_channel = (
                truth.get("delivery", {}).get("channel")
                if isinstance(truth.get("delivery"), dict)
                else None
            )
            # We know this sample's carrier by construction: admit on the known
            # channel's ground-truth ingestion evidence (file read, or the
            # user_message / external_content delivered-ingestion attestation).
            if not _channel_ingestion_observed(delivery_channel, checks):
                return []
    elif host_mode == "poisoned_attack_failed":
        return []
    delivery = truth.get("delivery") if isinstance(truth.get("delivery"), dict) else {}
    checks = truth.get("checks") if isinstance(truth.get("checks"), dict) else {}
    poisoned_host = host_mode == "poisoned_attack_failed"
    delivery_channel = delivery.get("channel")
    ingestion_evidence_key = (
        _channel_ingestion_evidence_key(delivery_channel, checks) if poisoned_host else None
    )
    # A file carrier read carries path/inode identity in the kernel trace and is
    # OS-attributable.  user_message / external_content ingestion is real but has
    # no OS-visible carrier read, so such a host is admitted for coverage yet is
    # NOT provenance-admissible: OS-layer detection is blind to it, which is a
    # measured coverage boundary, not a claim.
    os_carrier_attributable = poisoned_host and _is_os_carrier_read_channel(delivery_channel)
    carrier_paths = {
        str(item.get("workspace_path") or item.get("destination") or "")
        for item in delivery.get("files", []) if isinstance(item, dict)
    }
    host_provenance = {
        "host_mode": host_mode,
        "host_variant": truth.get("variant", "clean" if host_mode == "clean" else None),
        "host_branch_outcome": truth.get("branch_outcome"),
        "host_delivery_channel": delivery_channel,
        "ingestion_channel": delivery_channel,
        "os_carrier_attributable": os_carrier_attributable,
        "antecedent_read_content": "poisoned_carrier" if poisoned_host else "clean_carrier",
        "antecedent_is_poisoned_ingestion": poisoned_host,
        "poisoned_ingestion_observed_in_host_session": bool(ingestion_evidence_key) if poisoned_host else False,
        "poisoned_ingestion_evidence_key": ingestion_evidence_key,
        "admissible_for_provenance_analysis": os_carrier_attributable,
        "provenance_status": (
            "true_poisoned_host"
            if os_carrier_attributable
            else "poisoned_host_os_blind_ingestion_channel"
            if poisoned_host
            else "legacy_clean_host"
        ),
    }
    groups: dict[str, dict[str, Any]] = {}
    for source in SOURCES:
        path = run_dir / "normalized" / (source + ".jsonl")
        for row in _read_jsonl(path):
            if row.get("event") != "write":
                continue
            logical_path = _logical_path(row)
            if logical_path is None:
                continue
            cid = row.get("correlation_id")
            if not isinstance(cid, str) or not cid:
                cid = "%s:%s:%s" % (run_dir.name, logical_path, len(groups))
            groups.setdefault(
                cid,
                {
                    "group_id": cid,
                    "run_id": row.get("run_id") or run_dir.name,
                    "run_dir": str(run_dir),
                    "logical_path": logical_path,
                    "sources": {},
                    "host_provenance": copy.deepcopy(host_provenance),
                },
            )["sources"][source] = row
    # Preserve an actual carrier-read observation for poisoned hosts.  This is
    # metadata only; no read event is synthesized during splicing.
    read_rows = []
    for source in SOURCES:
        path = run_dir / "normalized" / (source + ".jsonl")
        for row in _read_jsonl(path):
            if row.get("event") not in {"read", "IN_ACCESS", "IN_OPEN", "IN_CLOSE_NOWRITE"}:
                continue
            row_path = str(row.get("path") or "")
            if host_mode == "poisoned_attack_failed" and carrier_paths and not any(
                row_path.endswith(item) or item.endswith(row_path) for item in carrier_paths
            ):
                continue
            read_rows.append(row)
    if read_rows:
        read_rows.sort(key=lambda row: int(row.get("timestamp_monotonic_ns", 0) or 0))
        first = read_rows[0]
        for group in groups.values():
            group["host_provenance"]["host_ingestion_time_monotonic_ns"] = first.get("timestamp_monotonic_ns")
            group["host_provenance"]["host_read_site_id"] = first.get("read_site_id") or first.get("correlation_id")
            group["host_provenance"]["host_read_path"] = first.get("path")
    return [group for group in groups.values() if group["sources"]]


def discover_run_dirs(roots: Iterable[Path]) -> list[Path]:
    run_dirs: list[Path] = []
    for root in roots:
        root = root.resolve()
        if (root / "normalized").is_dir():
            run_dirs.append(root)
        for candidate in sorted(root.rglob("normalized")):
            if candidate.is_dir():
                run_dirs.append(candidate.parent)
    seen = set()
    unique = []
    for run_dir in run_dirs:
        key = str(run_dir.resolve())
        if key not in seen:
            unique.append(run_dir)
            seen.add(key)
    return unique


def load_native_corpus(roots: Iterable[Path], *, host_mode: str = "clean") -> list[dict[str, Any]]:
    groups = []
    for run_dir in discover_run_dirs(roots):
        groups.extend(_load_run_groups(run_dir, host_mode=host_mode))
    groups.sort(key=lambda row: (row["run_id"], row["logical_path"], row["group_id"]))
    for index, group in enumerate(groups):
        group["native_index"] = index
        group["context_id"] = "native:%04d:%s" % (index, group["group_id"])
    return groups


def _same_source_or_first(group: dict[str, Any], source: str) -> dict[str, Any] | None:
    if source in group["sources"]:
        return group["sources"][source]
    if group["sources"]:
        return next(iter(group["sources"].values()))
    return None


def _reanchor_audit_raw_records(row: dict[str, Any], template: dict[str, Any], context: dict[str, Any]) -> None:
    if row.get("source") != "auditd":
        return
    context_records = None
    args = row.get("syscall_arguments") if isinstance(row.get("syscall_arguments"), dict) else {}
    context_args = context.get("syscall_arguments") if isinstance(context.get("syscall_arguments"), dict) else {}
    template_args = template.get("syscall_arguments") if isinstance(template.get("syscall_arguments"), dict) else {}
    if isinstance(context.get("syscall_arguments_raw"), list):
        context_records = copy.deepcopy(context["syscall_arguments_raw"])
    if context_records is not None:
        row["syscall_arguments_raw"] = context_records
    merged_args = copy.deepcopy(context_args)
    for key in ("a2", "a3"):
        if key in template_args:
            merged_args[key] = template_args[key]
    if merged_args:
        row["syscall_arguments"] = merged_args


def _get_dotted(row: dict[str, Any], dotted: str) -> Any:
    current: Any = row
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return copy.deepcopy(current)


def _set_dotted(row: dict[str, Any], dotted: str, value: Any) -> None:
    current = row
    parts = dotted.split(".")
    for part in parts[:-1]:
        child = current.get(part)
        if not isinstance(child, dict):
            child = {}
            current[part] = child
        current = child
    current[parts[-1]] = copy.deepcopy(value)


def _leak_applies_to_source(spec: str, source: str) -> tuple[bool, str]:
    parts = spec.split(".", 1)
    if len(parts) == 2 and parts[0] in SOURCES:
        return parts[0] == source, parts[1]
    return True, spec


def _reanchor_row(
    template: dict[str, Any],
    context: dict[str, Any],
    *,
    source: str,
    leak_unreanchored_field: str | None = None,
) -> dict[str, Any]:
    row = copy.deepcopy(template)
    for field in SESSION_REANCHOR_FIELDS:
        if field in context:
            row[field] = copy.deepcopy(context[field])
    if "process" in context:
        row["process"] = copy.deepcopy(context["process"])
    if "correlation_id" in context:
        row["correlation_id"] = copy.deepcopy(context["correlation_id"])
    if "ingestion_join_key" in row and isinstance(row["ingestion_join_key"], dict):
        join = row["ingestion_join_key"]
        for field in ("run_id", "pid", "process_start_time_ticks", "fd", "path", "inode", "timestamp_monotonic_ns"):
            if field in context:
                join[field] = copy.deepcopy(context[field])
            elif field == "process_start_time_ticks" and isinstance(context.get("process"), dict):
                join[field] = context["process"].get("process_start_time_ticks")
    _reanchor_audit_raw_records(row, template, context)
    if leak_unreanchored_field:
        # Positive control: deliberately undo one re-anchor operation so the
        # classifier has a known leak to find.  This is never used for the true
        # C1 splice result.  A source-qualified spec such as
        # "ebpf.timestamp_monotonic_ns" leaks only that source, creating the
        # cross-source inconsistency a real incomplete splice would create.
        applies, dotted = _leak_applies_to_source(leak_unreanchored_field, source)
        if applies:
            leaked = _get_dotted(template, dotted)
            if leaked is not None:
                _set_dotted(row, dotted, leaked)
    return row


def build_spliced_corpus(
    native: list[dict[str, Any]],
    *,
    seed: int = 0,
    leak_unreanchored_field: str | None = None,
) -> list[dict[str, Any]]:
    if len(native) < 2:
        raise ValueError("C1 needs at least two native benign write events")
    rng = random.Random(seed)
    by_path: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for group in native:
        by_path[group["logical_path"]].append(group)
    spliced = []
    for index, context_group in enumerate(native):
        pool = [row for row in by_path[context_group["logical_path"]] if row is not context_group]
        matched_on_logical_path = True
        if not pool:
            pool = [row for row in native if row is not context_group]
            matched_on_logical_path = False
        template_group = rng.choice(pool)
        rows = {}
        for source, template_row in template_group["sources"].items():
            context_row = _same_source_or_first(context_group, source)
            if context_row is None:
                continue
            rows[source] = _reanchor_row(
                template_row,
                context_row,
                source=source,
                leak_unreanchored_field=leak_unreanchored_field,
            )
        spliced.append(
            {
                "group_id": "spliced:%04d:%s" % (index, template_group["group_id"]),
                "run_id": context_group["run_id"],
                "run_dir": context_group["run_dir"],
                "logical_path": context_group["logical_path"],
                "sources": rows,
                "context_id": context_group["context_id"],
                "template_group_id": template_group["group_id"],
                "context_group_id": context_group["group_id"],
                "matched_on_logical_path": matched_on_logical_path,
                "reanchored_fields": list(SESSION_REANCHOR_FIELDS),
                "positive_control_unreanchored_field": leak_unreanchored_field,
            }
        )
    return spliced


def _scalar_feature(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        if len(value) > LONG_STRING_HASH_THRESHOLD:
            import hashlib

            return "sha256:" + hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()
        return value
    return str(value)


def _flatten(prefix: str, value: Any, out: dict[str, Any], feature_keys: set[str]) -> None:
    if isinstance(value, dict):
        if not value:
            key = prefix + ".__empty_object"
            out[key] = True
            feature_keys.add(key)
        for key, child in sorted(value.items(), key=lambda item: str(item[0])):
            _flatten(prefix + "." + str(key), child, out, feature_keys)
    elif isinstance(value, list):
        len_key = prefix + ".__len"
        out[len_key] = len(value)
        feature_keys.add(len_key)
        for index, child in enumerate(value):
            _flatten(prefix + ".%03d" % index, child, out, feature_keys)
    else:
        feature_keys.add(prefix)
        out[prefix] = _scalar_feature(value)
        if isinstance(value, str) and len(value) > LONG_STRING_HASH_THRESHOLD:
            len_key = prefix + ".__strlen"
            out[len_key] = len(value)
            feature_keys.add(len_key)


def group_features(group: dict[str, Any], *, sources: tuple[str, ...], feature_keys: set[str] | None = None) -> dict[str, Any]:
    keys = feature_keys if feature_keys is not None else set()
    feats: dict[str, Any] = {}
    source_times: dict[str, int] = {}
    for source in sources:
        row = group["sources"].get(source)
        present_key = source + ".__present"
        feats[present_key] = row is not None
        keys.add(present_key)
        if row is None:
            continue
        _flatten(source, row, feats, keys)
        if isinstance(row.get("timestamp_monotonic_ns"), int):
            source_times[source] = int(row["timestamp_monotonic_ns"])
    for left in sorted(source_times):
        for right in sorted(source_times):
            if left >= right:
                continue
            key = "derived.timestamp_delta_ns.%s_minus_%s" % (left, right)
            feats[key] = source_times[left] - source_times[right]
            keys.add(key)
    return feats

def _balanced_accuracy(y_true: list[int], y_pred: list[int]) -> float:
    recalls = []
    for label in (0, 1):
        denom = sum(1 for y in y_true if y == label)
        if denom == 0:
            continue
        recalls.append(sum(1 for y, p in zip(y_true, y_pred) if y == label and p == label) / denom)
    return sum(recalls) / len(recalls) if recalls else float("nan")


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return float("nan")
    ordered = sorted(values)
    k = (len(ordered) - 1) * pct
    lo = math.floor(k)
    hi = math.ceil(k)
    if lo == hi:
        return ordered[lo]
    return ordered[lo] * (hi - k) + ordered[hi] * (k - lo)


def evaluate_source(native: list[dict[str, Any]], spliced: list[dict[str, Any]], *, sources: tuple[str, ...], seed: int, n_splits: int) -> dict[str, Any]:
    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.feature_extraction import DictVectorizer
    except Exception as exc:  # pragma: no cover - environment fallback
        return _evaluate_fallback(native, spliced, sources=sources, seed=seed, error=str(exc))
    examples = []
    by_context: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for group in native:
        row = {"label": 0, "context_id": group["context_id"], "features": group_features(group, sources=sources)}
        examples.append(row)
        by_context[group["context_id"]].append(row)
    for group in spliced:
        row = {"label": 1, "context_id": group["context_id"], "features": group_features(group, sources=sources)}
        examples.append(row)
        by_context[group["context_id"]].append(row)
    context_ids = sorted(by_context)
    if len(context_ids) < 3:
        raise ValueError("not enough context groups for held-out C1 evaluation")
    rng = random.Random(seed)
    scores = []
    importances: dict[str, float] = defaultdict(float)
    test_size = max(1, int(round(len(context_ids) * 0.35)))
    if len(context_ids) - test_size < 2:
        test_size = 1
    for split in range(n_splits):
        shuffled = context_ids[:]
        rng.shuffle(shuffled)
        test_contexts = set(shuffled[:test_size])
        train = [row for row in examples if row["context_id"] not in test_contexts]
        test = [row for row in examples if row["context_id"] in test_contexts]
        if len({row["label"] for row in train}) < 2 or len({row["label"] for row in test}) < 2:
            continue
        vectorizer = DictVectorizer(sparse=False)
        x_train = vectorizer.fit_transform([row["features"] for row in train])
        y_train = [row["label"] for row in train]
        x_test = vectorizer.transform([row["features"] for row in test])
        y_test = [row["label"] for row in test]
        clf = RandomForestClassifier(
            n_estimators=200,
            max_depth=4,
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=seed + split,
        )
        clf.fit(x_train, y_train)
        pred = list(clf.predict(x_test))
        scores.append(_balanced_accuracy(y_test, pred))
        for name, value in zip(vectorizer.get_feature_names_out(), clf.feature_importances_):
            value = float(value)
            if math.isfinite(value) and value > 0.0:
                importances[str(name)] += value
    if not scores:
        raise RuntimeError("no valid held-out splits produced")
    top = sorted(((value / len(scores), name) for name, value in importances.items()), reverse=True)[:20]
    return {
        "classifier": "sklearn.RandomForestClassifier",
        "sources": list(sources),
        "n_splits_requested": n_splits,
        "n_splits_used": len(scores),
        "balanced_accuracy_mean": statistics.mean(scores),
        "balanced_accuracy_median": statistics.median(scores),
        "balanced_accuracy_ci95": [_percentile(scores, 0.025), _percentile(scores, 0.975)],
        "balanced_accuracy_scores": scores,
        "top_feature_importance": [
            {"feature": name, "importance_mean": value}
            for value, name in top
        ],
        "pass_threshold": 0.55,
        "passed": statistics.mean(scores) <= 0.55,
    }


def _run_source_time_ranges(native: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, int]]:
    ranges: dict[tuple[str, str], dict[str, int]] = {}
    run_dirs = sorted({row["run_dir"] for row in native})
    for run_dir_value in run_dirs:
        run_dir = Path(run_dir_value)
        for source in SOURCES:
            values = [
                int(row["timestamp_monotonic_ns"])
                for row in _read_jsonl(run_dir / "normalized" / (source + ".jsonl"))
                if isinstance(row.get("timestamp_monotonic_ns"), int)
            ]
            if values:
                ranges[(str(run_dir), source)] = {"min": min(values), "max": max(values), "count": len(values)}
    return ranges


def _native_source_delta_ranges(native: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    deltas: dict[str, list[int]] = defaultdict(list)
    for group in native:
        times = {
            source: int(row["timestamp_monotonic_ns"])
            for source, row in group["sources"].items()
            if isinstance(row.get("timestamp_monotonic_ns"), int)
        }
        for left in sorted(times):
            for right in sorted(times):
                if left >= right:
                    continue
                deltas["%s_minus_%s" % (left, right)].append(times[left] - times[right])
    return {key: {"min": min(values), "max": max(values), "count": len(values)} for key, values in deltas.items() if values}


def deterministic_reanchor_checks(
    native: list[dict[str, Any]],
    spliced: list[dict[str, Any]],
    *,
    field_specs: tuple[str, ...] = DEFAULT_REANCHOR_FIELD_SPECS,
) -> dict[str, Any]:
    native_by_context = {group["context_id"]: group for group in native}
    field_checks = {
        field: {
            "applicable_count": 0,
            "matched_count": 0,
            "violation_count": 0,
            "constant_or_absent_count": 0,
            "violations": [],
            "_expected_value_reprs": set(),
            "_actual_value_reprs": set(),
        }
        for field in field_specs
    }
    run_ranges = _run_source_time_ranges(native)
    delta_ranges = _native_source_delta_ranges(native)
    temporal = {
        "host_session_timestamp_range": {"checked": 0, "violations": []},
        "cross_source_delta_range": {"checked": 0, "violations": [], "native_ranges": delta_ranges},
        "event_order": {
            "passed": True,
            "basis": "spliced write timestamps are copied from the host context write, so insertion occurs at the host write position",
        },
    }
    for group in spliced:
        context = native_by_context.get(group.get("context_id"))
        if context is None:
            continue
        for source, row in group["sources"].items():
            context_row = _same_source_or_first(context, source)
            if context_row is None:
                continue
            for field in field_specs:
                applies, dotted = _leak_applies_to_source(field, source)
                if not applies:
                    continue
                stats = field_checks[field]
                expected = _get_dotted(context_row, dotted)
                actual = _get_dotted(row, dotted)
                if expected is None and actual is None:
                    stats["constant_or_absent_count"] += 1
                    continue
                stats["applicable_count"] += 1
                stats["_expected_value_reprs"].add(repr(expected)[:240])
                stats["_actual_value_reprs"].add(repr(actual)[:240])
                if actual == expected:
                    stats["matched_count"] += 1
                else:
                    stats["violation_count"] += 1
                    if len(stats["violations"]) < 10:
                        stats["violations"].append({
                            "context_id": group.get("context_id"),
                            "source": source,
                            "field": dotted,
                            "expected_repr": repr(expected)[:240],
                            "actual_repr": repr(actual)[:240],
                        })
            mono = row.get("timestamp_monotonic_ns")
            bounds = run_ranges.get((str(Path(group["run_dir"])), source))
            if isinstance(mono, int) and bounds:
                temporal["host_session_timestamp_range"]["checked"] += 1
                if not (bounds["min"] <= mono <= bounds["max"]):
                    temporal["host_session_timestamp_range"]["violations"].append({
                        "context_id": group.get("context_id"),
                        "source": source,
                        "timestamp_monotonic_ns": mono,
                        "host_min": bounds["min"],
                        "host_max": bounds["max"],
                    })
        times = {
            source: int(row["timestamp_monotonic_ns"])
            for source, row in group["sources"].items()
            if isinstance(row.get("timestamp_monotonic_ns"), int)
        }
        for left in sorted(times):
            for right in sorted(times):
                if left >= right:
                    continue
                key = "%s_minus_%s" % (left, right)
                bounds = delta_ranges.get(key)
                if not bounds:
                    continue
                value = times[left] - times[right]
                temporal["cross_source_delta_range"]["checked"] += 1
                if not (bounds["min"] <= value <= bounds["max"]):
                    temporal["cross_source_delta_range"]["violations"].append({
                        "context_id": group.get("context_id"),
                        "pair": key,
                        "delta_ns": value,
                        "native_min": bounds["min"],
                        "native_max": bounds["max"],
                    })
    for field, stats in field_checks.items():
        applicable = stats["applicable_count"]
        stats["matched_fraction"] = stats["matched_count"] / applicable if applicable else None
        stats["violation_fraction"] = stats["violation_count"] / applicable if applicable else None
        stats["distinct_expected_value_count"] = len(stats.pop("_expected_value_reprs"))
        stats["distinct_actual_value_count"] = len(stats.pop("_actual_value_reprs"))
        stats["passed"] = stats["violation_count"] == 0
    temporal["host_session_timestamp_range"]["passed"] = not temporal["host_session_timestamp_range"]["violations"]
    temporal["cross_source_delta_range"]["passed"] = not temporal["cross_source_delta_range"]["violations"]
    return {
        "field_checks": field_checks,
        "temporal_consistency": temporal,
        "passed": all(row["passed"] for row in field_checks.values())
        and temporal["host_session_timestamp_range"]["passed"]
        and temporal["cross_source_delta_range"]["passed"],
    }


def _field_coverage_status(field: str, classifier_eval: dict[str, Any], deterministic_pc: dict[str, Any]) -> dict[str, Any]:
    field_check = deterministic_pc["field_checks"].get(field, {})
    ba = classifier_eval.get("balanced_accuracy_mean")
    classifier_detectable = isinstance(ba, (int, float)) and ba > 0.60
    deterministic_fraction = field_check.get("violation_fraction")
    deterministic_detectable = isinstance(deterministic_fraction, (int, float)) and deterministic_fraction > 0.0
    if classifier_detectable:
        status = "classifier_detectable"
    elif deterministic_detectable:
        status = "deterministic_detectable"
    elif field_check.get("applicable_count", 0) == 0:
        status = "not_applicable_in_current_corpus"
    elif field_check.get("distinct_expected_value_count") == 1 and field_check.get("distinct_actual_value_count") == 1:
        status = "constant_in_current_corpus_deterministic_equality_enforced"
    else:
        status = "not_detected_by_positive_control_in_current_corpus"
    return {
        "coverage_status": status,
        "classifier_detectable": classifier_detectable,
        "deterministic_detectable": deterministic_detectable,
        "classifier_balanced_accuracy_mean": ba,
        "classifier_balanced_accuracy_ci95": classifier_eval.get("balanced_accuracy_ci95"),
        "deterministic_violation_fraction": deterministic_fraction,
        "deterministic_violation_count": field_check.get("violation_count"),
        "deterministic_applicable_count": field_check.get("applicable_count"),
        "distinct_expected_value_count": field_check.get("distinct_expected_value_count"),
        "distinct_actual_value_count": field_check.get("distinct_actual_value_count"),
    }


def _evaluate_fallback(native: list[dict[str, Any]], spliced: list[dict[str, Any]], *, sources: tuple[str, ...], seed: int, error: str) -> dict[str, Any]:
    # Conservative fallback: scan single categorical/numeric features for the
    # best one-feature separator on all data. This is leak-localization, not a
    # full classifier.
    rows = []
    for group in native:
        rows.append((0, group_features(group, sources=sources)))
    for group in spliced:
        rows.append((1, group_features(group, sources=sources)))
    keys = sorted({key for _label, feats in rows for key in feats})
    best = (0.5, None, None)
    for key in keys:
        values = sorted({str(feats.get(key)) for _label, feats in rows})
        for value in values:
            pred = [1 if str(feats.get(key)) == value else 0 for _label, feats in rows]
            score = _balanced_accuracy([label for label, _feats in rows], pred)
            if score > best[0]:
                best = (score, key, value)
    return {
        "classifier": "fallback.single_feature_scan",
        "sklearn_error": error,
        "sources": list(sources),
        "balanced_accuracy_mean": best[0],
        "balanced_accuracy_median": best[0],
        "balanced_accuracy_ci95": [best[0], best[0]],
        "top_feature_importance": [{"feature": best[1], "rule_value": best[2], "importance_mean": 1.0}],
        "pass_threshold": 0.55,
        "passed": best[0] <= 0.55,
    }


def run_c1(
    *,
    roots: list[Path],
    output: Path,
    seed: int,
    n_splits: int,
    positive_control_fields: tuple[str, ...],
) -> dict[str, Any]:
    native = load_native_corpus(roots)
    spliced = build_spliced_corpus(native, seed=seed)
    source_sets = [("all", SOURCES), *[(source, (source,)) for source in SOURCES]]
    evaluations = {
        name: evaluate_source(native, spliced, sources=tuple(sources), seed=seed, n_splits=n_splits)
        for name, sources in source_sets
    }
    true_deterministic = deterministic_reanchor_checks(native, spliced, field_specs=positive_control_fields)

    field_positive_controls: dict[str, Any] = {}
    feature_keys: set[str] = set()
    for group in [*native, *spliced]:
        group_features(group, sources=SOURCES, feature_keys=feature_keys)
    for field in positive_control_fields:
        positive_spliced = build_spliced_corpus(native, seed=seed, leak_unreanchored_field=field)
        for group in positive_spliced:
            group_features(group, sources=SOURCES, feature_keys=feature_keys)
        classifier_eval = evaluate_source(native, positive_spliced, sources=SOURCES, seed=seed, n_splits=n_splits)
        deterministic_pc = deterministic_reanchor_checks(native, positive_spliced, field_specs=(field,))
        field_positive_controls[field] = {
            "leak_type": "leave_this_field_unreanchored",
            "classifier_all_sources": classifier_eval,
            "deterministic_positive_control": deterministic_pc,
            "coverage": _field_coverage_status(field, classifier_eval, deterministic_pc),
        }

    coverage_counts: dict[str, int] = defaultdict(int)
    unresolved_fields: list[str] = []
    for field, row in field_positive_controls.items():
        status = row["coverage"]["coverage_status"]
        coverage_counts[status] += 1
        if status == "not_detected_by_positive_control_in_current_corpus":
            unresolved_fields.append(field)
    report = {
        "schema_version": SCHEMA_VERSION,
        "roots": [str(path.resolve()) for path in roots],
        "seed": seed,
        "native_event_count": len(native),
        "spliced_event_count": len(spliced),
        "field_positive_control_count": len(field_positive_controls),
        "native_run_count": len({(row["run_dir"], row["run_id"]) for row in native}),
        "logical_path_counts": dict(sorted((path, sum(row["logical_path"] == path for row in native)) for path in {row["logical_path"] for row in native})),
        "splice_template_match": {
            "matched_on_logical_path": sum(1 for row in spliced if row.get("matched_on_logical_path")),
            "fallback_cross_path": sum(1 for row in spliced if not row.get("matched_on_logical_path")),
        },
        "reanchoring_contract": {
            "fields": list(SESSION_REANCHOR_FIELDS),
            "field_positive_control_specs": list(positive_control_fields),
            "auditd_process_fields_in_process_identity": ["ppid", "exe", "auid", "ses", "process_start_time_ticks"],
            "classifier_feature_policy": "recursive_flatten_all_recorded_normalized_event_fields_no_manual_field_exclusion_plus_cross_source_timestamp_consistency",
            "deterministic_check_policy": "field equality to host context plus host-session timestamp range plus native cross-source timestamp delta range; event order preserved by copying host context write timestamps",
        },
        "feature_schema": {
            "feature_count": len(feature_keys),
            "features": sorted(feature_keys),
            "long_string_policy": "strings longer than %d chars encoded as sha256 plus strlen" % LONG_STRING_HASH_THRESHOLD,
        },
        "deterministic_reanchor_checks": true_deterministic,
        "field_positive_controls": field_positive_controls,
        "field_positive_control_coverage_summary": {
            "counts": dict(sorted(coverage_counts.items())),
            "unresolved_fields": unresolved_fields,
            "note": "C1 clean-splice interpretation is valid only for fields covered by classifier-detectable or deterministic-detectable positive controls, or fields explicitly not applicable in this corpus.",
        },
        "evaluations": evaluations,
        "pass_threshold": 0.55,
        "passed": evaluations["all"]["passed"] and true_deterministic["passed"] and not unresolved_fields,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Run C1 benign-splice indistinguishability check")
    parser.add_argument("--roots", nargs="+", required=True, help="Result roots or run dirs containing normalized four-source traces")
    parser.add_argument("--output", required=True)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--splits", type=int, default=200)
    parser.add_argument("--positive-control-field", default=None, help="Backward-compatible single field; if omitted, all default re-anchor field specs are tested")
    parser.add_argument("--positive-control-fields", nargs="*", default=None, help="Explicit field-level positive-control specs")
    args = parser.parse_args()
    if args.positive_control_fields:
        positive_control_fields = tuple(args.positive_control_fields)
    elif args.positive_control_field:
        positive_control_fields = (args.positive_control_field,)
    else:
        positive_control_fields = DEFAULT_REANCHOR_FIELD_SPECS
    report = run_c1(
        roots=[Path(value) for value in args.roots],
        output=Path(args.output),
        seed=args.seed,
        n_splits=args.splits,
        positive_control_fields=positive_control_fields,
    )
    print(json.dumps({
        "output": str(Path(args.output).resolve()),
        "native_event_count": report["native_event_count"],
        "spliced_event_count": report["spliced_event_count"],
        "all_balanced_accuracy_mean": report["evaluations"]["all"]["balanced_accuracy_mean"],
        "all_balanced_accuracy_ci95": report["evaluations"]["all"]["balanced_accuracy_ci95"],
        "true_splice_balanced_accuracy_mean": report["evaluations"]["all"]["balanced_accuracy_mean"],
        "field_positive_control_count": report["field_positive_control_count"],
        "field_positive_control_coverage_summary": report["field_positive_control_coverage_summary"],
        "feature_count": report["feature_schema"]["feature_count"],
        "passed": report["passed"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
