"""
agent.py - The AeroDrift "agent" cycle: a single run of the full
detect -> remediate loop, matching the project brief's description of
AeroDrift as a daemon that "intercepts configuration drift" continuously.

This module wraps the EXISTING, already-tested pieces together:
    src.aws.mock_data        -> raw AWS state
    src.graph.graph_engine   -> build_graph(), diagnose_drift()
    src.automation.*         -> adapter, generator, sandbox

Public function:
    run_cycle(dry_run=True) -> CycleResult
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from src.aws.mock_data import MOCK_AWS_STATE
from src.graph.graph_engine import build_graph, diagnose_drift
from src.automation.automation_engine import remediate

logger = logging.getLogger("aerodrift.agent")


@dataclass
class CycleResult:
    """The outcome of one full detect-and-remediate cycle."""
    timestamp: str
    nodes: int
    edges: int
    findings_count: int
    remediation_results: list = field(default_factory=list)


def run_cycle(dry_run: bool = True) -> CycleResult:
    """
    Runs ONE full cycle:
        1. Get current AWS state
        2. Build the topology graph
        3. Detect drift
        4. Remediate anything found (dry-run by default)
        5. Log what happened

    This does not loop - see loop.py for the continuously-running version.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    logger.info(f"[{timestamp}] Starting detection cycle")

    graph = build_graph(MOCK_AWS_STATE)
    findings = diagnose_drift(graph)

    logger.info(
        f"[{timestamp}] Graph built: {graph.number_of_nodes()} nodes, "
        f"{graph.number_of_edges()} edges. Findings: {len(findings)}"
    )

    remediation_results = []
    if findings:
        remediation_results = remediate(findings, dry_run=dry_run)
        for r in remediation_results:
            status = "SUCCESS" if r.success else "FAILED"
            logger.info(f"[{timestamp}] Remediation [{status}]: {r.output}")
    else:
        logger.info(f"[{timestamp}] No drift detected - nothing to remediate")

    return CycleResult(
        timestamp=timestamp,
        nodes=graph.number_of_nodes(),
        edges=graph.number_of_edges(),
        findings_count=len(findings),
        remediation_results=remediation_results,
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    result = run_cycle(dry_run=True)

    print()
    print("Cycle complete:")
    print(f"  Timestamp:  {result.timestamp}")
    print(f"  Graph:      {result.nodes} nodes, {result.edges} edges")
    print(f"  Findings:   {result.findings_count}")
    print(f"  Remediated: {len(result.remediation_results)}")