"""
agent.py - The AeroDrift "agent" cycle: a single run of the full
detect -> remediate loop, matching the project brief's description of
AeroDrift as a daemon that "intercepts configuration drift" continuously.

This module wraps the EXISTING, already-tested pieces together:
    src.aws.mock_data        -> raw AWS state
    src.graph.graph_engine   -> build_graph(), diagnose_drift()
    src.automation.*         -> adapter, generator, sandbox

Public function:
    run_cycle(dry_run=True, seen_findings=None) -> CycleResult

Tracks which findings have already been remediated (by a stable key),
so a long-running daemon doesn't re-fix the exact same issue on every
single cycle - only genuinely NEW drift triggers a new remediation.
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
    new_findings_count: int
    remediation_results: list = field(default_factory=list)


def _finding_key(finding: dict) -> str:
    """
    Builds a stable, unique identifier for a finding, so we can tell if
    we've already seen (and remediated) this exact issue before.

    Based on the resource and the specific bad rule - if the SAME port
    on the SAME security group is still open, it's the same issue. If a
    DIFFERENT port opens up later, that's correctly treated as new.
    """
    bad_rule = finding.get("bad_rule", {})
    return f"{finding.get('resource_id')}:{bad_rule.get('port')}:{bad_rule.get('cidr')}"


def run_cycle(dry_run: bool = True, seen_findings: set | None = None) -> CycleResult:
    """
    Runs ONE full cycle:
        1. Get current AWS state
        2. Build the topology graph
        3. Detect drift
        4. Remediate only NEW findings (not already in seen_findings)
        5. Log what happened

    Args:
        dry_run: passed through to remediate()
        seen_findings: a set of finding keys already remediated in
                       previous cycles. Pass the SAME set object across
                       multiple calls (e.g. from loop.py) so the agent
                       remembers what it's already handled. If None,
                       every finding is treated as new (single-run mode).

    This function itself does not loop - see loop.py for that.
    """
    if seen_findings is None:
        seen_findings = set()

    timestamp = datetime.now(timezone.utc).isoformat()
    logger.info(f"[{timestamp}] Starting detection cycle")

    graph = build_graph(MOCK_AWS_STATE)
    all_findings = diagnose_drift(graph)

    new_findings = [f for f in all_findings if _finding_key(f) not in seen_findings]
    already_known_count = len(all_findings) - len(new_findings)

    logger.info(
        f"[{timestamp}] Graph built: {graph.number_of_nodes()} nodes, "
        f"{graph.number_of_edges()} edges. "
        f"Findings: {len(all_findings)} total, {len(new_findings)} new, "
        f"{already_known_count} already handled"
    )

    remediation_results = []
    if new_findings:
        remediation_results = remediate(new_findings, dry_run=dry_run)
        for finding, r in zip(new_findings, remediation_results):
            status = "SUCCESS" if r.success else "FAILED"
            logger.info(f"[{timestamp}] Remediation [{status}]: {r.output}")
            seen_findings.add(_finding_key(finding))
    else:
        logger.info(f"[{timestamp}] No NEW drift detected - nothing to do this cycle")

    return CycleResult(
        timestamp=timestamp,
        nodes=graph.number_of_nodes(),
        edges=graph.number_of_edges(),
        findings_count=len(all_findings),
        new_findings_count=len(new_findings),
        remediation_results=remediation_results,
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    print("Running the SAME cycle twice, to show duplicate-detection working:\n")

    seen = set()

    print("--- Cycle 1 ---")
    result1 = run_cycle(dry_run=True, seen_findings=seen)
    print(f"  New findings remediated: {result1.new_findings_count}\n")

    print("--- Cycle 2 (same data, should skip - already handled) ---")
    result2 = run_cycle(dry_run=True, seen_findings=seen)
    print(f"  New findings remediated: {result2.new_findings_count}")