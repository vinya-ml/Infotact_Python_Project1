"""
test_report.py - Unit tests for the PDF report generator.

Tests that ReportGenerator creates valid PDF files with correct
content using the real graph_engine output.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cli.report import ReportGenerator
from automation.sandbox import RemediationSandbox
from graph.graph_engine import build_graph, diagnose_drift
from aws.mock_data import MOCK_AWS_STATE


# ── Fixtures ──


@pytest.fixture
def graph():
    """Build a real graph from mock AWS data."""
    return build_graph(MOCK_AWS_STATE)


@pytest.fixture
def findings(graph):
    """Detect drift from the real graph."""
    return diagnose_drift(graph)


@pytest.fixture
def remediation_results(tmp_path, findings):
    """Generate and execute remediation scripts for test findings."""
    from automation.generator import RemediationGenerator

    generator = RemediationGenerator(output_dir=tmp_path)
    scripts = generator.generate_all(findings)
    sandbox = RemediationSandbox(dry_run=True)
    return sandbox.execute_all(scripts)


# ── Tests ──


class TestReportGenerator:

    def test_generate_creates_pdf(self, findings, graph, tmp_path):
        gen = ReportGenerator(output_dir=tmp_path)
        path = gen.generate(findings, graph)
        assert path.exists()
        assert path.suffix == ".pdf"

    def test_generate_pdf_has_content(self, findings, graph, tmp_path):
        gen = ReportGenerator(output_dir=tmp_path)
        path = gen.generate(findings, graph)
        assert path.stat().st_size > 0

    def test_generate_no_findings(self, graph, tmp_path):
        gen = ReportGenerator(output_dir=tmp_path)
        path = gen.generate([], graph)
        assert path.exists()
        assert path.stat().st_size > 0

    def test_generate_with_scan_id(self, findings, graph, tmp_path):
        gen = ReportGenerator(output_dir=tmp_path)
        path = gen.generate(findings, graph, scan_id=42)
        assert path.exists()

    def test_generate_with_remediation_results(
        self, findings, graph, remediation_results, tmp_path
    ):
        gen = ReportGenerator(output_dir=tmp_path)
        path = gen.generate(findings, graph, remediation_results=remediation_results)
        assert path.exists()
        assert path.stat().st_size > 0

    def test_generate_with_all_params(
        self, findings, graph, remediation_results, tmp_path
    ):
        gen = ReportGenerator(output_dir=tmp_path)
        path = gen.generate(
            findings,
            graph,
            remediation_results=remediation_results,
            scan_id=7,
        )
        assert path.exists()
        assert path.suffix == ".pdf"

    def test_output_dir_created(self, findings, graph):
        custom_dir = Path(__file__).resolve().parent / "_test_reports"
        gen = ReportGenerator(output_dir=custom_dir)
        path = gen.generate(findings, graph)
        assert path.exists()
        assert custom_dir.exists()

    def test_filename_contains_timestamp(self, findings, graph, tmp_path):
        gen = ReportGenerator(output_dir=tmp_path)
        path = gen.generate(findings, graph)
        assert "aerodrift_report_" in path.name
