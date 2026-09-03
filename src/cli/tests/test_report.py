import pytest

from app.ingestion.aws_ingestion import CloudStateLoader
from app.topology.graph import CloudTopology
from app.detection.drift_detector import DriftDetector
from app.remediation.generator import RemediationGenerator
from app.remediation.sandbox import RemediationSandbox
from app.cli.report import ReportGenerator
from pathlib import Path


DATA_DIR = Path(__file__).resolve().parents[1] / "data"
STATE_FILE = DATA_DIR / "mock_aws_state.json"


@pytest.fixture
def report_data(tmp_path):
    loader = CloudStateLoader(STATE_FILE)
    state = loader.load()
    topology = CloudTopology()
    topology.build_from_state(state)
    detector = DriftDetector(topology)
    findings = detector.detect_public_database_exposure()
    generator = RemediationGenerator(output_dir=tmp_path)
    scripts = generator.generate_all(findings)
    sandbox = RemediationSandbox(dry_run=True)
    results = sandbox.execute_all(scripts)
    return findings, topology, results


class TestReportGenerator:

    def test_generate_creates_pdf(self, report_data, tmp_path):
        findings, topology, results = report_data
        gen = ReportGenerator(output_dir=tmp_path)
        path = gen.generate(findings, topology, results)
        assert path.exists()
        assert path.suffix == ".pdf"

    def test_generate_pdf_has_content(self, report_data, tmp_path):
        findings, topology, results = report_data
        gen = ReportGenerator(output_dir=tmp_path)
        path = gen.generate(findings, topology, results)
        assert path.stat().st_size > 0

    def test_generate_no_findings(self, tmp_path):
        topology = CloudTopology()
        topology.add_resource("test", "EC2")
        gen = ReportGenerator(output_dir=tmp_path)
        path = gen.generate([], topology, None)
        assert path.exists()

    def test_generate_with_scan_id(self, report_data, tmp_path):
        findings, topology, results = report_data
        gen = ReportGenerator(output_dir=tmp_path)
        path = gen.generate(
            findings, topology, results, scan_id=42
        )
        assert path.exists()
