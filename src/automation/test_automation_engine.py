from unittest.mock import patch

from src.automation.automation_engine import remediate


def test_remediate_empty_findings():
    """Empty drift findings should return an empty list."""
    result = remediate([])

    assert result == []


@patch("src.automation.automation_engine.RemediationSandbox")
@patch("src.automation.automation_engine.RemediationGenerator")
def test_remediate_runs_pipeline(mock_generator_class, mock_sandbox_class):
    """remediate should run the automation pipeline."""

    drift_findings = [
        {
            "drift_type": "open_ingress",
            "resource_id": "sg-001",
            "bad_rule": {
                "port": 22,
                "cidr": "0.0.0.0/0",
            },
            "path": ["internet", "sg-001", "i-001"],
        }
    ]

    mock_generator = mock_generator_class.return_value
    mock_generator.generate_all.return_value = ["script1.py"]

    mock_sandbox = mock_sandbox_class.return_value
    mock_sandbox.execute_all.return_value = ["result1"]

    result = remediate(drift_findings, dry_run=True)

    assert result == ["result1"]

    mock_generator.generate_all.assert_called_once()
    mock_sandbox_class.assert_called_once_with(dry_run=True)
    mock_sandbox.execute_all.assert_called_once_with(["script1.py"])


@patch("src.automation.automation_engine.RemediationSandbox")
@patch("src.automation.automation_engine.RemediationGenerator")
def test_remediate_respects_dry_run(
    mock_generator_class,
    mock_sandbox_class,
):
    """dry_run=False should be passed to the sandbox."""

    drift_findings = [
        {
            "drift_type": "open_ingress",
            "resource_id": "sg-001",
            "bad_rule": {
                "port": 22,
                "cidr": "0.0.0.0/0",
            },
            "path": ["internet", "sg-001", "i-001"],
        }
    ]

    mock_generator = mock_generator_class.return_value
    mock_generator.generate_all.return_value = ["script.py"]

    mock_sandbox = mock_sandbox_class.return_value
    mock_sandbox.execute_all.return_value = []

    remediate(drift_findings, dry_run=False)

    mock_sandbox_class.assert_called_once_with(dry_run=False)
