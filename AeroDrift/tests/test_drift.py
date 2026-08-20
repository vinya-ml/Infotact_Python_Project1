import pytest

from app.ingestion.aws_ingestion import CloudStateLoader
from app.topology.graph import CloudTopology
from app.detection.drift_detector import DriftDetector, DriftFinding
from pathlib import Path


DATA_DIR = Path(__file__).resolve().parents[1] / "data"
STATE_FILE = DATA_DIR / "mock_aws_state.json"


@pytest.fixture
def detector():
    loader = CloudStateLoader(STATE_FILE)
    state = loader.load()
    topology = CloudTopology()
    topology.build_from_state(state)
    return DriftDetector(topology)


class TestDriftDetector:

    def test_detect_returns_list(self, detector):
        findings = detector.detect_public_database_exposure()
        assert isinstance(findings, list)

    def test_detect_finds_drift(self, detector):
        findings = detector.detect_public_database_exposure()
        assert len(findings) > 0

    def test_finding_is_drift_finding(self, detector):
        findings = detector.detect_public_database_exposure()
        assert isinstance(findings[0], DriftFinding)

    def test_finding_target(self, detector):
        findings = detector.detect_public_database_exposure()
        assert findings[0].target == "production-database"

    def test_finding_security_group(self, detector):
        findings = detector.detect_public_database_exposure()
        assert findings[0].security_group == "sg-database"

    def test_finding_protocol(self, detector):
        findings = detector.detect_public_database_exposure()
        assert findings[0].protocol == "tcp"

    def test_finding_port(self, detector):
        findings = detector.detect_public_database_exposure()
        assert findings[0].port == 22

    def test_finding_source(self, detector):
        findings = detector.detect_public_database_exposure()
        assert findings[0].source == "0.0.0.0/0"

    def test_finding_path_starts_with_internet(self, detector):
        findings = detector.detect_public_database_exposure()
        assert findings[0].path[0] == "internet"

    def test_finding_path_ends_with_ec2(self, detector):
        findings = detector.detect_public_database_exposure()
        assert findings[0].path[-1] == "ec2-database"
