import pytest

from app.ingestion.aws_ingestion import CloudStateLoader
from app.topology.graph import CloudTopology
from app.detection.drift_detector import DriftDetector
from app.persistence.database import AeroDriftDB
from pathlib import Path


DATA_DIR = Path(__file__).resolve().parents[1] / "data"
STATE_FILE = DATA_DIR / "mock_aws_state.json"


@pytest.fixture
def db(tmp_path):
    db_path = tmp_path / "test.db"
    database = AeroDriftDB(db_path=db_path)
    database.connect()
    yield database
    database.close()


@pytest.fixture
def topology():
    loader = CloudStateLoader(STATE_FILE)
    state = loader.load()
    topo = CloudTopology()
    topo.build_from_state(state)
    return topo


@pytest.fixture
def findings(topology):
    detector = DriftDetector(topology)
    return detector.detect_public_database_exposure()


class TestAeroDriftDB:

    def test_connect_creates_db(self, db):
        assert db.conn is not None

    def test_save_scan_returns_id(self, db, topology, findings):
        scan_id = db.save_scan(topology, findings)
        assert isinstance(scan_id, int)

    def test_list_scans_after_save(self, db, topology, findings):
        db.save_scan(topology, findings)
        scans = db.list_scans()
        assert len(scans) == 1

    def test_get_findings_after_save(self, db, topology, findings):
        scan_id = db.save_scan(topology, findings)
        saved_findings = db.get_findings(scan_id)
        assert len(saved_findings) == len(findings)

    def test_get_snapshot_after_save(self, db, topology, findings):
        scan_id = db.save_scan(topology, findings)
        snapshot = db.get_snapshot(scan_id)
        assert snapshot is not None
        assert "nodes" in snapshot
        assert "edges" in snapshot

    def test_snapshot_node_count(self, db, topology, findings):
        scan_id = db.save_scan(topology, findings)
        snapshot = db.get_snapshot(scan_id)
        assert len(snapshot["nodes"]) == 4

    def test_snapshot_edge_count(self, db, topology, findings):
        scan_id = db.save_scan(topology, findings)
        snapshot = db.get_snapshot(scan_id)
        assert len(snapshot["edges"]) == 3

    def test_diff_snapshots_same_scan(self, db, topology, findings):
        scan_id = db.save_scan(topology, findings)
        diff = db.diff_snapshots(scan_id, scan_id)
        assert diff["nodes_added"] == []
        assert diff["nodes_removed"] == []
        assert diff["edges_added"] == []
        assert diff["edges_removed"] == []

    def test_diff_snapshots_different(self, db, topology, findings):
        id1 = db.save_scan(topology, findings)
        id2 = db.save_scan(topology, findings)
        diff = db.diff_snapshots(id1, id2)
        assert diff is not None

    def test_get_nonexistent_snapshot(self, db):
        result = db.get_snapshot(9999)
        assert result is None
