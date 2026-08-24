import pytest

from app.ingestion.aws_ingestion import CloudStateLoader
from app.topology.graph import CloudTopology
from app.detection.drift_detector import DriftDetector
from app.remediation.generator import RemediationGenerator
from pathlib import Path


DATA_DIR = Path(__file__).resolve().parents[1] / "data"
STATE_FILE = DATA_DIR / "mock_aws_state.json"


@pytest.fixture
def findings():
    loader = CloudStateLoader(STATE_FILE)
    state = loader.load()
    topology = CloudTopology()
    topology.build_from_state(state)
    detector = DriftDetector(topology)
    return detector.detect_public_database_exposure()


@pytest.fixture
def generator(tmp_path):
    return RemediationGenerator(output_dir=tmp_path)


class TestRemediationGenerator:

    def test_render_code_returns_string(self, generator, findings):
        code = generator.render_code(findings[0])
        assert isinstance(code, str)

    def test_code_contains_import(self, generator, findings):
        code = generator.render_code(findings[0])
        assert "boto3" in code

    def test_code_contains_revoke(self, generator, findings):
        code = generator.render_code(findings[0])
        assert "revoke_security_group_ingress" in code

    def test_code_contains_group_id(self, generator, findings):
        code = generator.render_code(findings[0])
        assert "sg-001" in code

    def test_code_contains_protocol(self, generator, findings):
        code = generator.render_code(findings[0])
        assert "tcp" in code

    def test_code_contains_port(self, generator, findings):
        code = generator.render_code(findings[0])
        assert "22" in code

    def test_save_script_creates_file(self, generator, findings):
        path = generator.save_script(findings[0])
        assert path.exists()

    def test_save_script_has_correct_name(self, generator, findings):
        path = generator.save_script(findings[0])
        assert path.name == "remediate_sg-001_22.py"

    def test_generate_all_returns_paths(self, generator, findings):
        scripts = generator.generate_all(findings)
        assert len(scripts) == len(findings)
        for script in scripts:
            assert script.exists()
