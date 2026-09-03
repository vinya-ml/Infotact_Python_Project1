import pytest

from app.ingestion.aws_ingestion import CloudStateLoader
from app.topology.graph import CloudTopology
from app.detection.drift_detector import DriftDetector
from app.remediation.generator import RemediationGenerator
from app.remediation.sandbox import RemediationSandbox, ExecutionResult
from pathlib import Path


DATA_DIR = Path(__file__).resolve().parents[1] / "data"
STATE_FILE = DATA_DIR / "mock_aws_state.json"


@pytest.fixture
def remediation_script(tmp_path):
    loader = CloudStateLoader(STATE_FILE)
    state = loader.load()
    topology = CloudTopology()
    topology.build_from_state(state)
    detector = DriftDetector(topology)
    findings = detector.detect_public_database_exposure()
    generator = RemediationGenerator(output_dir=tmp_path)
    scripts = generator.generate_all(findings)
    return scripts


class TestExecutionSandbox:

    def test_dry_run_succeeds(self, remediation_script):
        sandbox = RemediationSandbox(dry_run=True)
        results = sandbox.execute_all(remediation_script)
        assert all(r.success for r in results)

    def test_dry_run_output_contains_dry_run(self, remediation_script):
        sandbox = RemediationSandbox(dry_run=True)
        results = sandbox.execute_all(remediation_script)
        assert "DRY-RUN" in results[0].output

    def test_result_is_execution_result(self, remediation_script):
        sandbox = RemediationSandbox(dry_run=True)
        results = sandbox.execute_all(remediation_script)
        assert isinstance(results[0], ExecutionResult)

    def test_summary_counts(self, remediation_script):
        sandbox = RemediationSandbox(dry_run=True)
        sandbox.execute_all(remediation_script)
        summary = sandbox.summary()
        assert summary["total"] == 1
        assert summary["succeeded"] == 1
        assert summary["failed"] == 0

    def test_nonexistent_script_fails(self):
        sandbox = RemediationSandbox(dry_run=True)
        result = sandbox.execute_script("/nonexistent/script.py")
        assert not result.success

    def test_execute_all_returns_list(self, remediation_script):
        sandbox = RemediationSandbox(dry_run=True)
        results = sandbox.execute_all(remediation_script)
        assert isinstance(results, list)
