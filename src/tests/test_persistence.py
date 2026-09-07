"""
test_persistence.py - Unit tests for the SQLite persistence layer.

Tests that AeroDriftDB correctly stores and retrieves scan runs,
findings, and graph snapshots using the real graph_engine output.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from persistence.database import AeroDriftDB
from graph.graph_engine import build_graph, diagnose_drift
from aws.mock_data import MOCK_AWS_STATE


# ── Fixtures ──


@pytest.fixture
def db(tmp_path):
    """Create a temporary database for each test."""
    db_path = tmp_path / "test.db"
    database = AeroDriftDB(db_path=db_path)
    database.connect()
    yield database
    database.close()


@pytest.fixture
def graph():
    """Build a real graph from mock AWS data."""
    return build_graph(MOCK_AWS_STATE)


@pytest.fixture
def findings(graph):
    """Detect drift from the real graph."""
    return diagnose_drift(graph)


# ── Tests ──


class TestAeroDriftDB:

    def test_connect_creates_db(self, db):
        assert db.conn is not None

    def test_context_manager(self, tmp_path):
        db_path = tmp_path / "ctx.db"
        with AeroDriftDB(db_path=db_path) as database:
            assert database.conn is not None
        assert database.conn is None

    def test_save_scan_returns_id(self, db, graph, findings):
        scan_id = db.save_scan(graph, findings)
        assert isinstance(scan_id, int)
        assert scan_id > 0

    def test_list_scans_after_save(self, db, graph, findings):
        db.save_scan(graph, findings)
        scans = db.list_scans()
        assert len(scans) == 1

    def test_list_scans_multiple(self, db, graph, findings):
        db.save_scan(graph, findings)
        db.save_scan(graph, findings)
        scans = db.list_scans()
        assert len(scans) == 2

    def test_list_scans_ordered_by_id_desc(self, db, graph, findings):
        id1 = db.save_scan(graph, findings)
        id2 = db.save_scan(graph, findings)
        scans = db.list_scans()
        assert scans[0]["id"] == id2
        assert scans[1]["id"] == id1

    def test_get_findings_after_save(self, db, graph, findings):
        scan_id = db.save_scan(graph, findings)
        saved = db.get_findings(scan_id)
        assert len(saved) == len(findings)

    def test_get_findings_contains_correct_data(self, db, graph, findings):
        scan_id = db.save_scan(graph, findings)
        saved = db.get_findings(scan_id)
        assert saved[0]["resource_id"] == findings[0]["resource_id"]
        assert saved[0]["drift_type"] == findings[0]["drift_type"]

    def test_get_snapshot_after_save(self, db, graph, findings):
        scan_id = db.save_scan(graph, findings)
        snapshot = db.get_snapshot(scan_id)
        assert snapshot is not None
        assert "nodes" in snapshot
        assert "edges" in snapshot

    def test_snapshot_node_count(self, db, graph, findings):
        scan_id = db.save_scan(graph, findings)
        snapshot = db.get_snapshot(scan_id)
        assert len(snapshot["nodes"]) == graph.number_of_nodes()

    def test_snapshot_edge_count(self, db, graph, findings):
        scan_id = db.save_scan(graph, findings)
        snapshot = db.get_snapshot(scan_id)
        assert len(snapshot["edges"]) == graph.number_of_edges()

    def test_snapshot_contains_internet_node(self, db, graph, findings):
        scan_id = db.save_scan(graph, findings)
        snapshot = db.get_snapshot(scan_id)
        node_ids = {n["id"] for n in snapshot["nodes"]}
        assert "internet" in node_ids

    def test_get_nonexistent_snapshot(self, db):
        result = db.get_snapshot(9999)
        assert result is None

    def test_diff_snapshots_same_scan(self, db, graph, findings):
        scan_id = db.save_scan(graph, findings)
        diff = db.diff_snapshots(scan_id, scan_id)
        assert diff["nodes_added"] == []
        assert diff["nodes_removed"] == []
        assert diff["edges_added"] == []
        assert diff["edges_removed"] == []

    def test_diff_snapshots_different(self, db, graph, findings):
        id1 = db.save_scan(graph, findings)
        id2 = db.save_scan(graph, findings)
        diff = db.diff_snapshots(id1, id2)
        assert diff is not None
        assert isinstance(diff, dict)

    def test_diff_with_nonexistent_returns_none(self, db, graph, findings):
        scan_id = db.save_scan(graph, findings)
        diff = db.diff_snapshots(scan_id, 9999)
        assert diff is None

    def test_save_scan_with_no_findings(self, db, graph):
        scan_id = db.save_scan(graph, [])
        saved = db.get_findings(scan_id)
        assert len(saved) == 0

    def test_scan_metadata_correct(self, db, graph, findings):
        scan_id = db.save_scan(graph, findings, state_file="test.json")
        scans = db.list_scans()
        scan = scans[0]
        assert scan["state_file"] == "test.json"
        assert scan["finding_count"] == len(findings)
        assert scan["node_count"] == graph.number_of_nodes()
        assert scan["edge_count"] == graph.number_of_edges()
