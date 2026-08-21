from pathlib import Path

from src.cli.sandbox import RemediationSandbox


def test_execute_script_success(tmp_path):
    script = tmp_path / "success.py"
    script.write_text("print('hello')", encoding="utf-8")

    sandbox = RemediationSandbox()

    result = sandbox.execute_script(script)

    assert result.success is True
    assert "hello" in result.output


def test_execute_script_not_found(tmp_path):
    script = tmp_path / "missing.py"

    sandbox = RemediationSandbox()

    result = sandbox.execute_script(script)

    assert result.success is False
    assert "Script not found" in result.error


def test_execute_script_failure(tmp_path):
    script = tmp_path / "error.py"
    script.write_text(
        "raise ValueError('test error')",
        encoding="utf-8",
    )

    sandbox = RemediationSandbox(dry_run=False)

    result = sandbox.execute_script(script)

    assert result.success is False
    assert "ValueError" in result.error


def test_execute_all(tmp_path):
    script1 = tmp_path / "one.py"
    script2 = tmp_path / "two.py"

    script1.write_text("print('one')", encoding="utf-8")
    script2.write_text("print('two')", encoding="utf-8")

    sandbox = RemediationSandbox(dry_run=False)

    results = sandbox.execute_all([script1, script2])

    assert len(results) == 2
    assert all(result.success for result in results)


def test_summary(tmp_path):
    success_script = tmp_path / "success.py"
    error_script = tmp_path / "error.py"

    success_script.write_text("print('ok')", encoding="utf-8")
    error_script.write_text(
        "raise ValueError('error')",
        encoding="utf-8",
    )

    sandbox = RemediationSandbox(dry_run=False)

    sandbox.execute_script(success_script)
    sandbox.execute_script(error_script)

    summary = sandbox.summary()

    assert summary["total"] == 2
    assert summary["succeeded"] == 1
    assert summary["failed"] == 1
