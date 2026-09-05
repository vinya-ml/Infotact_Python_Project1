"""
test_agent_and_loop.py - Tests for the Week 4 agent cycle and daemon
loop: single-cycle behavior, duplicate-finding tracking across cycles,
and the live-mode safety gate.
"""

import asyncio
import os
import pytest

from src.automation.agent import run_cycle, _finding_key
from src.automation.loop import run_daemon, LiveModeNotConfirmedError, LIVE_MODE_CONFIRM_ENV_VAR


class TestRunCycle:

    def test_run_cycle_returns_result(self):
        result = run_cycle(dry_run=True)
        assert result is not None
        assert result.findings_count >= 0

    def test_run_cycle_detects_the_known_finding(self):
        # Based on the real mock data, we expect exactly 1 finding
        result = run_cycle(dry_run=True)
        assert result.findings_count == 1
        assert result.new_findings_count == 1

    def test_run_cycle_with_no_seen_findings_treats_everything_as_new(self):
        result = run_cycle(dry_run=True, seen_findings=None)
        assert result.new_findings_count == result.findings_count


class TestDuplicateTracking:

    def test_second_cycle_with_shared_set_skips_known_finding(self):
        seen = set()

        first = run_cycle(dry_run=True, seen_findings=seen)
        second = run_cycle(dry_run=True, seen_findings=seen)

        assert first.new_findings_count == 1
        assert second.new_findings_count == 0, (
            "Second cycle should recognize the SAME finding and skip it"
        )

    def test_seen_findings_set_actually_gets_populated(self):
        seen = set()
        assert len(seen) == 0

        run_cycle(dry_run=True, seen_findings=seen)

        assert len(seen) == 1, "seen_findings should contain 1 key after remediating 1 finding"

    def test_finding_key_is_stable_for_identical_findings(self):
        finding = {
            "resource_id": "sg-001",
            "bad_rule": {"port": 22, "cidr": "0.0.0.0/0"},
        }
        assert _finding_key(finding) == _finding_key(finding)

    def test_finding_key_differs_for_different_ports(self):
        finding_a = {"resource_id": "sg-001", "bad_rule": {"port": 22, "cidr": "0.0.0.0/0"}}
        finding_b = {"resource_id": "sg-001", "bad_rule": {"port": 3389, "cidr": "0.0.0.0/0"}}
        assert _finding_key(finding_a) != _finding_key(finding_b)


class TestRunDaemon:

    def test_daemon_runs_exact_number_of_cycles(self):
        results = asyncio.run(run_daemon(interval_seconds=0, dry_run=True, max_cycles=3))
        assert len(results) == 3

    def test_daemon_only_remediates_once_across_multiple_cycles(self):
        results = asyncio.run(run_daemon(interval_seconds=0, dry_run=True, max_cycles=3))
        total_new_findings = sum(r.new_findings_count for r in results)
        assert total_new_findings == 1, (
            "Across 3 cycles of unchanged data, only 1 finding should ever be 'new'"
        )


class TestLiveModeSafety:

    def test_live_mode_blocked_without_env_var(self):
        # Make sure the env var is definitely not set for this test
        os.environ.pop(LIVE_MODE_CONFIRM_ENV_VAR, None)

        with pytest.raises(LiveModeNotConfirmedError):
            asyncio.run(run_daemon(interval_seconds=0, dry_run=False, max_cycles=1))

    def test_dry_run_never_requires_confirmation(self):
        os.environ.pop(LIVE_MODE_CONFIRM_ENV_VAR, None)
        # Should NOT raise, since dry_run=True is always safe
        results = asyncio.run(run_daemon(interval_seconds=0, dry_run=True, max_cycles=1))
        assert len(results) == 1