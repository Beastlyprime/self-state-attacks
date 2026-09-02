#!/usr/bin/env python3
"""Build Route-B attack-arrival policy from threat-model and realization rates.

This is intentionally separate from clean read-to-write measurement.  Clean
read-to-write rates describe legitimate support/FPR populations; they do not set
attack-arrival probability.  Route-B attack selection is controlled by explicit
threat-model prevalence and measured P(realized write | poisoned ingestion).
"""

from __future__ import annotations

import argparse
import copy
import json
import random
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[3]
CODE_ROOT = PROJECT_ROOT / "experiments" / "code"
if str(CODE_ROOT) not in sys.path:
    sys.path.insert(0, str(CODE_ROOT))

try:
    from .injection_routes import measure_clean_read_sites
except ImportError:  # pragma: no cover
    from injection_routes import measure_clean_read_sites

SCHEMA_VERSION = "assa.route_b_attack_arrival_policy.v1"
DEFAULT_CHANNEL_WEIGHTS = {
    "user_message": 0.435,
    "supply_chain": 0.200,
    "workspace_file": 0.190,
    "external_content": 0.174,
}


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load_json(path: Path | None, default: Any) -> Any:
    if path is None:
        return copy.deepcopy(default)
    return json.loads(path.read_text(encoding="utf-8"))


def _rate_key(target_class: str, tier: str) -> str:
    return "%s:%s" % (target_class, tier)


def _site_channel(site: dict[str, Any]) -> str:
    """Recover a read site's ingestion channel.

    ``measure_clean_read_sites`` now propagates ``ingestion_channel`` to the top
    level; the ``read_event`` fallbacks keep older site records working.
    """
    read = site.get("read_event") if isinstance(site.get("read_event"), dict) else {}
    channel = (
        site.get("ingestion_channel")
        or read.get("ingestion_channel")
        or read.get("channel")
    )
    if isinstance(channel, str) and channel:
        return channel
    return "workspace_file"


def _channel_weight(channel_weights: dict[str, float], channel: str) -> float:
    """Weight the arrival prevalence of a channel; unknown channels are 1.0.

    A missing channel is not thinned (weight 1.0) so file-carrier corpora that
    predate channel tagging keep their previous arrival behaviour.  A weight of
    0 removes a channel from the attack-arrival distribution entirely.
    """
    weight = channel_weights.get(channel, 1.0)
    try:
        weight = float(weight)
    except (TypeError, ValueError):
        raise ValueError("channel weight for %s is not a number" % channel)
    if weight < 0:
        raise ValueError("channel weight for %s must be non-negative" % channel)
    return weight


def _rate_index(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        target = row.get("target_class")
        tier = row.get("tier")
        if not isinstance(target, str) or not isinstance(tier, str):
            raise ValueError("realization-rate rows require target_class and tier")
        trials = int(row.get("trials") or 0)
        successes = int(row.get("successes") or 0)
        if trials <= 0 or successes < 0 or successes > trials:
            raise ValueError("invalid realization-rate successes/trials")
        record = copy.deepcopy(row)
        record["realization_rate"] = successes / trials
        out[_rate_key(target, tier)] = record
    return out


def build_policy(
    *,
    clean_runs: list[dict[str, Any]],
    realization_rates: list[dict[str, Any]],
    target_class: str,
    tier: str,
    threat_prevalence: float,
    channel_weights: dict[str, float],
    rng_seed: int,
    max_selected: int,
    clean_corpus_label: str = "unreported_clean_runs",
    clean_corpus_role: str = "unspecified",
) -> dict[str, Any]:
    if not 0 <= threat_prevalence <= 1:
        raise ValueError("threat prevalence must be in [0, 1]")
    if max_selected < 0:
        raise ValueError("max-selected must be non-negative")
    read_sites = measure_clean_read_sites(clean_runs)
    rates = _rate_index(realization_rates)
    key = _rate_key(target_class, tier)
    if key not in rates:
        raise ValueError("missing realization rate for %s" % key)
    realization = rates[key]
    expected_attack_write_rate_given_read = threat_prevalence * float(realization["realization_rate"])
    rng = random.Random(rng_seed)
    decisions = []
    selected_count = 0
    realization_rate = float(realization["realization_rate"])
    # Channel weights express the RELATIVE channel mixture of poisoned arrivals,
    # not an absolute rate cut (the absolute rate is threat_prevalence).  Weights
    # are normalized by the largest weight among channels actually present, so a
    # single-channel corpus is never thinned while a multi-channel mixture is
    # shaped toward the declared distribution.
    present_channels = {_site_channel(site) for site in read_sites}
    present_weights = {
        channel: _channel_weight(channel_weights, channel) for channel in present_channels
    }
    max_present_weight = max(present_weights.values(), default=0.0)
    for site in read_sites:
        channel = _site_channel(site)
        channel_weight = present_weights[channel]
        channel_relative_weight = (
            channel_weight / max_present_weight if max_present_weight > 0 else 0.0
        )
        channel_weighted_prevalence = threat_prevalence * channel_relative_weight
        arrival_draw = rng.random()
        realization_draw = rng.random()
        arrival_selected = arrival_draw < channel_weighted_prevalence
        realized_after_arrival = arrival_selected and realization_draw < realization_rate
        selected = realized_after_arrival and selected_count < max_selected
        if selected:
            selected_count += 1
        if selected:
            not_selected_reason = None
        elif not arrival_selected:
            not_selected_reason = "arrival_draw_ge_channel_weighted_threat_prevalence"
        elif not realized_after_arrival:
            not_selected_reason = "poisoned_arrival_not_realized_by_measured_rate"
        else:
            not_selected_reason = "max_selected_reached"
        decisions.append(
            {
                "read_site_id": site["read_site_id"],
                "run_id": site.get("run_id"),
                "workload_profile": site.get("workload_profile") or site.get("profile"),
                "read_event": copy.deepcopy(site.get("read_event") or site),
                "ingestion_channel": channel,
                "channel_weight": channel_weight,
                "channel_relative_weight": channel_relative_weight,
                "channel_weighted_arrival_prevalence": channel_weighted_prevalence,
                "selected": selected,
                "selection_basis": "explicit_threat_arrival_prevalence_x_channel_weight_x_measured_realization_rate",
                "arrival_draw": arrival_draw,
                "realization_draw": realization_draw,
                "rng_draw": arrival_draw,
                "arrival_selected": arrival_selected,
                "realized_after_arrival": realized_after_arrival,
                "threat_prevalence": threat_prevalence,
                "not_selected_reason": not_selected_reason,
                "target_class": target_class,
                "tier": tier,
                "realization_rate_record": copy.deepcopy(realization),
                "expected_attack_write_rate_given_read": expected_attack_write_rate_given_read,
                "legitimate_support_observation": {
                    "followed_by_natural_self_state_write": site.get("followed_by_natural_self_state_write"),
                    "clean_outcome": site.get("clean_outcome"),
                    "clean_corpus_label": clean_corpus_label,
                    "clean_corpus_role": clean_corpus_role,
                    "frequency_or_base_rate_estimation_allowed": clean_corpus_label == "unbiased_frequency_corpus",
                    "role": "support_and_host_context_characterization_only_not_attack_arrival_selection",
                },
            }
        )
    followed = [site["followed_by_natural_self_state_write"] for site in read_sites]
    channels = sorted({row["ingestion_channel"] for row in decisions})
    channel_breakdown = {
        channel: {
            "read_sites": sum(row["ingestion_channel"] == channel for row in decisions),
            "arrival_selected": sum(
                row["ingestion_channel"] == channel and row["arrival_selected"]
                for row in decisions
            ),
            "selected": sum(
                row["ingestion_channel"] == channel and row["selected"]
                for row in decisions
            ),
            "channel_weight": _channel_weight(channel_weights, channel),
        }
        for channel in channels
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "policy_type": "attack_arrival_x_realization_rate",
        "rng_algorithm": "python.random.MT19937",
        "rng_seed": rng_seed,
        "target_class": target_class,
        "tier": tier,
        "realization_rate_record": realization,
        "threat_model": {
            "arrival_prevalence": threat_prevalence,
            "arrival_prevalence_role": "explicit_threat_model_parameter_not_empirically_calibrated_from_clean_workload",
            "channel_weights": channel_weights,
            "channel_weights_source": "MemSecBench carrier distribution as cited in benchmark_design.md section 4.1",
            "channel_weights_applied_to_arrival": True,
            "channel_weights_role": "channel weights are the relative ingestion-channel mixture; user_message is a first-class ingestion channel, not only a file carrier read",
            "channel_weight_normalization": "normalized by the largest weight among channels present, so a single-channel corpus is not thinned",
            "max_present_channel_weight": max_present_weight,
            "unlisted_channel_weight_default": 1.0,
            "expected_attack_write_rate_given_read": expected_attack_write_rate_given_read,
            "formula": "arrival_prevalence * relative_channel_weight(channel) * P(write | poisoned ingestion, target_class, tier)",
        },
        "clean_corpus": {
            "label": clean_corpus_label,
            "role": clean_corpus_role,
            "frequency_or_base_rate_estimation_allowed": clean_corpus_label == "unbiased_frequency_corpus",
            "warning": (
                "Do not use selected host-context corpora to estimate legitimate write frequency, base rates, or FPR denominators."
                if clean_corpus_label != "unbiased_frequency_corpus"
                else "This corpus is marked as unbiased for frequency/base-rate use."
            ),
        },
        "legitimate_support_summary": {
            "role": "support_shape_and_host_availability_characterization_only_not_attack_arrival_selection",
            "natural_read_sites": len(read_sites),
            "natural_read_then_write_sites": sum(followed),
            "natural_read_without_write_sites": len(read_sites) - sum(followed),
            "mixed_rate_diagnostic": sum(followed) / len(read_sites) if read_sites else None,
        },
        "selected_read_sites": [row for row in decisions if row["selected"]],
        "unselected_read_sites": [row for row in decisions if not row["selected"]],
        "all_read_site_decisions": decisions,
        "channel_breakdown": channel_breakdown,
        "counts": {
            "read_sites": len(read_sites),
            "selected_read_sites": sum(row["selected"] for row in decisions),
            "unselected_read_sites": sum(not row["selected"] for row in decisions),
            "arrival_selected_before_cap": sum(row["arrival_selected"] for row in decisions),
            "realized_after_arrival_before_cap": sum(row["realized_after_arrival"] for row in decisions),
            "max_selected": max_selected,
            "channels": {channel: row["read_sites"] for channel, row in channel_breakdown.items()},
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Route-B attack-arrival policy")
    parser.add_argument("--clean-runs", required=True, type=Path)
    parser.add_argument("--realization-rates", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--target-class", required=True)
    parser.add_argument("--tier", required=True)
    parser.add_argument("--threat-prevalence", type=float, default=1.0)
    parser.add_argument("--channel-weights", type=Path, default=None)
    parser.add_argument("--seed", required=True, type=int)
    parser.add_argument("--max-selected", type=int, default=10)
    parser.add_argument("--clean-corpus-label", default="unreported_clean_runs")
    parser.add_argument("--clean-corpus-role", default="unspecified")
    args = parser.parse_args()
    clean_runs = json.loads(args.clean_runs.read_text(encoding="utf-8"))
    realization_rates = json.loads(args.realization_rates.read_text(encoding="utf-8"))
    if isinstance(realization_rates, dict):
        realization_rates = realization_rates.get("rates", [])
    if not isinstance(realization_rates, list):
        raise ValueError("realization rates must be a JSON list or {rates: [...]}")
    channel_weights = _load_json(args.channel_weights, DEFAULT_CHANNEL_WEIGHTS)
    policy = build_policy(
        clean_runs=clean_runs,
        realization_rates=realization_rates,
        target_class=args.target_class,
        tier=args.tier,
        threat_prevalence=args.threat_prevalence,
        channel_weights=channel_weights,
        rng_seed=args.seed,
        max_selected=args.max_selected,
        clean_corpus_label=args.clean_corpus_label,
        clean_corpus_role=args.clean_corpus_role,
    )
    output = args.output_dir
    output.mkdir(parents=True, exist_ok=True)
    _write_json(output / "route_b_attack_arrival_policy.json", policy)
    print(json.dumps({"policy": str((output / "route_b_attack_arrival_policy.json").resolve()), **policy["counts"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
