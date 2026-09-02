import json
from pathlib import Path

from measurement.stage_g_harness.unicorn_adapter_role import adapt_records, assign_role_final


def _node(node_id: str, node_type: str, **attributes):
    return {
        "node_id": node_id,
        "node_type": node_type,
        "run_id": "C001_w1_example__poisoned",
        "identity_status": "complete",
        "attributes": attributes,
    }


def test_role_adapter_is_arm_blind_and_keeps_topology(tmp_path: Path) -> None:
    nodes = [
        _node("p1", "process", exe="/usr/bin/python3.10"),
        _node(
            "f1",
            "file",
            resolved_path=(
                "/collection/runs/C001_w1_example__poisoned/workspace/MEMORY.md"
            ),
        ),
    ]
    edges = [{
        "edge_id": "e1",
        "source_node_id": "p1",
        "destination_node_id": "f1",
        "relation": "write",
        "order": {"merged": 9},
    }]
    coverage = {
        "provenance_evaluable": True,
        "fd_path_resolved_rate": 1.0,
        "fd_path_resolved_threshold": 0.95,
    }
    report = adapt_records(nodes, edges, tmp_path, coverage, source_description="test")
    assert report["g1_arm_blindness"]["passed"] is True
    assert set(report["role_vocabulary"]) == {
        "process.agent_worker", "self_state.memory.root",
    }
    assert report["output_edges"] == 1
    line = (tmp_path / "assa.edgelist").read_text().strip()
    assert len(line.split("\t")) == 3
    assert "poisoned" not in line
    persisted = json.loads((tmp_path / "adapter_report.json").read_text())
    assert persisted["typing_variant"] == "ROLE_ONLY"


def test_role_adapter_rejects_failed_coverage_without_dropping_graph(tmp_path: Path) -> None:
    nodes = [
        _node("p1", "process", exe="/usr/bin/python3.10"),
        _node("f1", "file", resolved_path="/tmp/x"),
    ]
    edges = [{
        "edge_id": "e1",
        "source_node_id": "p1",
        "destination_node_id": "f1",
        "relation": "write",
        "order": {"merged": 1},
    }]
    report = adapt_records(
        nodes,
        edges,
        tmp_path,
        {"provenance_evaluable": False, "fd_path_resolved_rate": 0.5},
        source_description="test",
    )
    assert report["status"] == "data_insufficient"
    assert report["output_edges"] == 1


def test_final_table_completion_is_path_blind() -> None:
    assert assign_role_final(_node("f1", "file", resolved_path="/lib64/ld-linux.so.2")) == "system.library"
    assert assign_role_final(_node("f2", "file", resolved_path="stage_g_v6/workload.stdout.log")) == "apparatus.collection"
    assert assign_role_final(_node("f3", "file", resolved_path="engineers.csv")) == "external_input"
    assert assign_role_final(_node("f4", "file", resolved_path="customers.csv")) == "external_input"
