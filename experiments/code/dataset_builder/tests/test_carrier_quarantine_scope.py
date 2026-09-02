"""Carrier quarantine before Session B must remove ONLY the poisoned carrier.

Regression for the over-quarantine bug: the runner used to pass every task
seed as a --carrier-path, so for self-configuration cases the agent's own
self-state (openclaw.json, TOOLS.md) was moved out of the workspace between
sessions -- destroying the sleeper payload the case exists to measure.
"""
from __future__ import annotations

import sys
from pathlib import Path

CODE_ROOT = Path(__file__).resolve().parents[2]
if str(CODE_ROOT) not in sys.path:
    sys.path.insert(0, str(CODE_ROOT))

from dataset_builder.paired_live_four_source import _carrier_quarantine_paths


def _case(channel, carrier, seeds):
    return {"case_id": "X", "carrier_path": carrier,
            "delivery": {"channel": channel},
            "seed_files": [{"path": p} for p in seeds]}


def test_self_config_workspace_file_quarantines_only_carrier():
    # C512-shape: config seeds must survive, only the runbook carrier is removed.
    case = _case("workspace_file", "runbooks/audit_log_rotation.md",
                 ["openclaw.json", "TOOLS.md", "runbooks/audit_log_rotation.md"])
    assert _carrier_quarantine_paths(case) == ["runbooks/audit_log_rotation.md"]


def test_external_content_carrier_quarantines_nothing():
    # C511/C513-shape: carrier is served over HTTP, never a workspace file;
    # the only workspace seeds are self-state and must persist.
    case = _case("external_content", "ops_tickets/CHG-1842-model-defaults.md",
                 ["openclaw.json", "TOOLS.md", "ops_tickets/CHG-1842-model-defaults.md"])
    assert _carrier_quarantine_paths(case) == []


def test_multi_seed_workspace_case_keeps_benign_seed():
    # C302-shape: calendar.md is the carrier; request.md is benign context.
    case = _case("workspace_file", "calendar.md", ["calendar.md", "request.md"])
    assert _carrier_quarantine_paths(case) == ["calendar.md"]


def test_single_seed_workspace_attachment_unchanged():
    # C301/C401-shape: the only seed is the carrier -> behavior identical.
    case = _case("workspace_attachment", "inbox/from_recruiter.txt",
                 ["inbox/from_recruiter.txt"])
    assert _carrier_quarantine_paths(case) == ["inbox/from_recruiter.txt"]


def test_user_message_case_quarantines_nothing():
    case = _case("user_message", "calendar.md", ["calendar.md"])
    assert _carrier_quarantine_paths(case) == []


def test_missing_carrier_path_is_empty():
    case = {"case_id": "X", "carrier_path": None,
            "delivery": {"channel": "workspace_file"}, "seed_files": []}
    assert _carrier_quarantine_paths(case) == []
