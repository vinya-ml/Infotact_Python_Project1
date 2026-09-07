"""
test_sandbox.py - Unit tests for the execution sandbox.

Tests that RemediationSandbox correctly executes scripts, captures output,
handles dry-run mocking, and reports errors for bad scripts.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from automation.sandbox import RemediationSandbox, ExecutionResult


# ── Fixtures ──


@pytest.fixture
def valid_script(tmp_path):
    """Create a simple valid Python script."""
    script = tmp_path / "good_script.py"
    script.write_text(
        'import boto3\n'
        'ec2 = boto3.client("ec2")\n'
        'response = ec2.revoke_security_group_ingress(\n'
        '    GroupId="sg-001",\n'
        '    IpPermissions=[{\n'
        '        "IpProtocol": "tcp",\n'
        '        "FromPort": 22,\n'
        '        "ToPort": 22,\n'
        '        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]\n'
        '    }]\n'
        ')\n'
        'print("Revoked tcp/22 from 0.0.0.0/0 on sg-001")\n',
        encoding="utf-8",
    )
    return script


@pytest.fixture
def failing_script(tmp_path):
    """Create a script that raises an error."""
    script = tmp_path / "bad_script.py"
    script.write_text(
        'raise ValueError("intentional failure")\n',
        encoding="utf-8",
    )
    return script


@pytest.fixture
def output_script(tmp_path):
    """Create a script that prints output."""
    script = tmp_path / "output_script.py"
    script.write_text(
        'print("hello from sandbox")\n'
        'print("line two")\n',
        encoding="utf-8",
    )
    return script


# ── Tests ──


class TestExecutionResult:

    def test_repr_success(self):
        r = ExecutionResult("script.py", True, "ok")
        assert "OK" in repr(r)

    def test_repr_failure(self):
        r = ExecutionResult("script.py", False, "", "err")
        assert "FAIL" in repr(r)

    def test_attributes(self):
        r = ExecutionResult("/tmp/x.py", True, "output", None)
        assert r.script_path == "/tmp/x.py"
        assert r.success is True
        assert r.output == "output"
        assert r.error is None


class TestRemediationSandbox:

    def test_dry_run_succeeds(self, valid_script):
        sandbox = RemediationSandbox(dry_run=True)
        result = sandbox.execute_script(valid_script)
        assert result.success is True

    def test_dry_run_output_contains_dry_run(self, valid_script):
        sandbox = RemediationSandbox(dry_run=True)
        result = sandbox.execute_script(valid_script)
        assert "DRY-RUN" in result.output

    def test_dry_run_output_contains_revoked(self, valid_script):
        sandbox = RemediationSandbox(dry_run=True)
        result = sandbox.execute_script(valid_script)
        assert "Revoked" in result.output

    def test_result_is_execution_result(self, valid_script):
        sandbox = RemediationSandbox(dry_run=True)
        result = sandbox.execute_script(valid_script)
        assert isinstance(result, ExecutionResult)

    def test_captures_stdout(self, output_script):
        sandbox = RemediationSandbox(dry_run=True)
        result = sandbox.execute_script(output_script)
        assert "hello from sandbox" in result.output
        assert "line two" in result.output

    def test_nonexistent_script_fails(self):
        sandbox = RemediationSandbox(dry_run=True)
        result = sandbox.execute_script("/nonexistent/path.py")
        assert result.success is False
        assert "not found" in result.error.lower()

    def test_failing_script_returns_error(self, failing_script):
        sandbox = RemediationSandbox(dry_run=True)
        result = sandbox.execute_script(failing_script)
        assert result.success is False
        assert "intentional failure" in result.error

    def test_execute_all_returns_list(self, valid_script):
        sandbox = RemediationSandbox(dry_run=True)
        results = sandbox.execute_all([valid_script])
        assert isinstance(results, list)
        assert len(results) == 1

    def test_execute_all_multiple_scripts(self, valid_script, output_script):
        sandbox = RemediationSandbox(dry_run=True)
        results = sandbox.execute_all([valid_script, output_script])
        assert len(results) == 2
        assert all(r.success for r in results)

    def test_summary_counts_success(self, valid_script):
        sandbox = RemediationSandbox(dry_run=True)
        sandbox.execute_script(valid_script)
        summary = sandbox.summary()
        assert summary["total"] == 1
        assert summary["succeeded"] == 1
        assert summary["failed"] == 0

    def test_summary_counts_failure(self, failing_script):
        sandbox = RemediationSandbox(dry_run=True)
        sandbox.execute_script(failing_script)
        summary = sandbox.summary()
        assert summary["total"] == 1
        assert summary["succeeded"] == 0
        assert summary["failed"] == 1

    def test_summary_mixed(self, valid_script, failing_script):
        sandbox = RemediationSandbox(dry_run=True)
        sandbox.execute_all([valid_script, failing_script])
        summary = sandbox.summary()
        assert summary["total"] == 2
        assert summary["succeeded"] == 1
        assert summary["failed"] == 1

    def test_results_accumulate(self, valid_script, output_script):
        sandbox = RemediationSandbox(dry_run=True)
        sandbox.execute_script(valid_script)
        sandbox.execute_script(output_script)
        assert len(sandbox.results) == 2
