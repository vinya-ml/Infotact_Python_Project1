"""
automation_engine.py - Ties the Automation module together into one
simple function that other modules (like the CLI) can call.

Public function:
    remediate(drift_findings, dry_run=True) -> list[ExecutionResult]

This is the single entry point the rest of the project should use -
nobody outside this module needs to know about adapter.py, generator.py,
or sandbox.py individually.
"""

from .adapter import convert_all
from .generator import RemediationGenerator
from .sandbox import RemediationSandbox


def remediate(drift_findings: list[dict], dry_run: bool = True):
    """
    Full pipeline: takes raw diagnose_drift() findings, generates fix
    scripts for each, and safely executes them.

    Args:
        drift_findings: the list of dicts produced by graph_engine.diagnose_drift()
        dry_run: if True (default), scripts run against a mock AWS client -
                 nothing real is ever touched. Set to False only in a real,
                 intentional deployment scenario.

    Returns:
        A list of ExecutionResult objects (one per finding), each with
        .success, .output, and .error attributes.
    """
    if not drift_findings:
        # Nothing to do - this is a normal, valid case, not an error.
        return []

    converted = convert_all(drift_findings)

    generator = RemediationGenerator()
    scripts = generator.generate_all(converted)

    sandbox = RemediationSandbox(dry_run=dry_run)
    results = sandbox.execute_all(scripts)

    return results


if __name__ == "__main__":
    # End-to-end manual test using a realistic example finding
    example_findings = [
        {
            "drift_type": "open_ingress",
            "resource_id": "sg-001",
            "bad_rule": {"port": 22, "cidr": "0.0.0.0/0"},
            "path": ["internet", "sg-001", "i-001"],
        }
    ]

    results = remediate(example_findings, dry_run=True)

    for r in results:
        status = "SUCCESS" if r.success else "FAILED"
        print(f"[{status}] {r.script_path}")
        print(f"  Output: {r.output}")
        if r.error:
            print(f"  Error: {r.error}")