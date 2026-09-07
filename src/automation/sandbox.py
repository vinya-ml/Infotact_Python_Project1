"""
sandbox.py - Execution Sandbox for Remediation Scripts

Runs generated boto3 remediation scripts in a restricted local scope.
In dry-run mode, replaces boto3 with a mock client that logs actions
without making real AWS API calls.

Public API:
    ExecutionResult(script_path, success, output, error)
    RemediationSandbox(dry_run=True)
        .execute_script(path)   -> ExecutionResult
        .execute_all(paths)     -> list[ExecutionResult]
        .summary()              -> dict
"""

import io
import sys
import traceback
from pathlib import Path


class ExecutionResult:
    """Holds the outcome of a single sandboxed script execution."""

    def __init__(self, script_path, success, output, error=None):
        self.script_path = str(script_path)
        self.success = success
        self.output = output
        self.error = error

    def __repr__(self):
        status = "OK" if self.success else "FAIL"
        return f"ExecutionResult({status}, {self.script_path})"


class RemediationSandbox:
    """Executes generated remediation scripts in a restricted local scope.

    Args:
        dry_run: If True, boto3 calls are replaced with a mock client
                 that prints actions without touching AWS.
    """

    _DRY_RUN_MOCK = (
        "class _MockEC2Client:\n"
        "    def revoke_security_group_ingress(self, **kwargs):\n"
        "        print(f'[DRY-RUN] Would revoke: {kwargs}')\n"
        "        return {'ResponseMetadata': {'HTTPStatusCode': 200}}\n"
        "\n"
        "class _MockBoto3:\n"
        "    @staticmethod\n"
        "    def client(service):\n"
        "        return _MockEC2Client()\n"
        "\n"
        "boto3 = _MockBoto3()\n"
        "\n"
    )

    def __init__(self, dry_run=True):
        self.dry_run = dry_run
        self.results = []

    def execute_script(self, script_path):
        """Run a single Python script inside the sandbox.

        Captures stdout/stderr, returns an ExecutionResult.
        In dry-run mode, patches boto3 imports before execution.
        """
        script_path = Path(script_path)

        if not script_path.exists():
            result = ExecutionResult(
                script_path=script_path,
                success=False,
                output="",
                error=f"Script not found: {script_path}",
            )
            self.results.append(result)
            return result

        source = script_path.read_text(encoding="utf-8")

        if self.dry_run:
            source = self._patch_for_dry_run(source)

        old_stdout = sys.stdout
        old_stderr = sys.stderr
        sys.stdout = io.StringIO()
        sys.stderr = io.StringIO()

        sandbox_globals = {"__builtins__": __builtins__}

        try:
            compiled = compile(source, str(script_path), "exec")
            exec(compiled, sandbox_globals)

            output = sys.stdout.getvalue()
            error_output = sys.stderr.getvalue()
            if error_output:
                output = output + "\n" + error_output

            result = ExecutionResult(
                script_path=script_path,
                success=True,
                output=output.strip(),
            )

        except Exception:
            output = sys.stdout.getvalue()
            error_detail = traceback.format_exc()

            result = ExecutionResult(
                script_path=script_path,
                success=False,
                output=output.strip(),
                error=error_detail,
            )

        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr

        self.results.append(result)
        return result

    def execute_all(self, script_paths):
        """Execute multiple remediation scripts sequentially."""
        for path in script_paths:
            self.execute_script(path)
        return self.results

    def _patch_for_dry_run(self, source):
        """Replace boto3 import with a mock client for safe dry-run."""
        source = source.replace(
            "import boto3",
            "# import boto3 (replaced by mock)",
        )
        return self._DRY_RUN_MOCK + source

    def summary(self):
        """Return counts of total, succeeded, and failed executions."""
        total = len(self.results)
        succeeded = sum(1 for r in self.results if r.success)
        return {
            "total": total,
            "succeeded": succeeded,
            "failed": total - succeeded,
        }
