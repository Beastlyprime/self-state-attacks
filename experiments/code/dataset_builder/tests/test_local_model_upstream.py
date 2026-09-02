from __future__ import annotations

import copy
from pathlib import Path

import pytest

from dataset_builder.paired_live_four_source import _model_upstream_policy
from dataset_builder.run_safety import evaluate_prelaunch_controls
from dataset_builder.tests.test_injection_binding import _prelaunch_payload


def test_private_local_model_upstream_is_exact() -> None:
    policy = _model_upstream_policy(
        "http://10.0.0.2:11434/v1/chat/completions"
    )
    assert policy["allowlist"] == ["tcp:10.0.0.2:11434"]
    assert policy["nft_rules"] == [
        "meta skuid 0 ip daddr 10.0.0.2 tcp dport 11434 accept"
    ]


@pytest.mark.parametrize(
    "upstream",
    [
        "https://10.0.0.2:11434/v1/chat/completions",
        "http://ollama.internal:11434/v1/chat/completions",
        "http://8.8.8.8:11434/v1/chat/completions",
        "http://10.0.0.2:443/v1/chat/completions",
    ],
)
def test_local_model_upstream_rejects_non_scoped_forms(upstream: str) -> None:
    with pytest.raises(ValueError):
        _model_upstream_policy(upstream)


def test_prelaunch_accepts_exact_private_endpoint_and_rejects_mismatch(
    tmp_path: Path,
) -> None:
    payload = _prelaunch_payload(tmp_path)
    payload["network"].update(
        {
            "routes": ["default via 10.0.0.1"],
            "routes_restricted_by_default_deny": True,
            "worker_egress_allowlist": ["loopback:model_proxy"],
            "proxy_egress_allowlist": ["tcp:10.0.0.2:11434"],
            "nft_ruleset": (
                "chain output { type filter hook output priority 0; policy drop; "
                "meta skuid 0 ip daddr 10.0.0.2 tcp dport 11434 accept; }"
            ),
        }
    )
    assert evaluate_prelaunch_controls(
        payload, planned_worker_env={"PATH": "/usr/bin"}
    )["preflight_passed"] is True

    mismatched = copy.deepcopy(payload)
    mismatched["network"]["proxy_egress_allowlist"] = [
        "tcp:10.0.0.3:11434"
    ]
    result = evaluate_prelaunch_controls(
        mismatched, planned_worker_env={"PATH": "/usr/bin"}
    )
    assert result["preflight_passed"] is False
    assert "egress_default_deny_installed" in result["failed_checks"]
