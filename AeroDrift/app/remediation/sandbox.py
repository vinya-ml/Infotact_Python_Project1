import io
import sys
import traceback
from pathlib import Path


class ExecutionResult:
    """Holds the outcome of a sandboxed script execution."""

    def __init__(self, script_path, success, output, error=None):
        self.script_path = script_path
        self.success = success
        self.output = output
        self.error = error

    def __repr__(self):
        status = "OK" if self.success else "FAIL"
        return f"ExecutionResult({status}, {self.script_path})"


class RemediationSandbox:
    """Executes generated remediation scripts in a restricted local scope."""

    def __init__(self, dry_run=True):
        self.dry_run = dry_run
        self.results = []

    def execute_script(self, script_path):
        """Run a single Python script inside the sandbox."""

        script_path = Path(script_path)

        if not script_path.exists():
            result = ExecutionResult(
                script_path=str(script_path),
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

        sandbox_globals = {
            "__builtins__": __builtins__,
        }

        try:
            compiled = compile(source, str(script_path), "exec")
            exec(compiled, sandbox_globals)

            output = sys.stdout.getvalue()
            error_output = sys.stderr.getvalue()

            if error_output:
                output = output + "\n" + error_output

            result = ExecutionResult(
                script_path=str(script_path),
                success=True,
                output=output.strip(),
            )

        except Exception:
            output = sys.stdout.getvalue()
            error_detail = traceback.format_exc()

            result = ExecutionResult(
                script_path=str(script_path),
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
        """Replace boto3 client creation with a mock in dry-run mode."""

        source = source.replace(
            "import boto3",
            "# import boto3 (replaced by mock)",
        )

        mock_code = (
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

        return mock_code + source

    def summary(self):
        """Return a summary of all execution results."""

        total = len(self.results)
        succeeded = sum(1 for r in self.results if r.success)
        failed = total - succeeded

        return {
            "total": total,
            "succeeded": succeeded,
            "failed": failed,
        }
