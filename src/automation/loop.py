"""
loop.py - Wraps agent.run_cycle() in a continuously-running loop, using
asyncio - matching the project brief's description of AeroDrift as a
daemon that continuously watches for and heals configuration drift.

Public function:
    run_daemon(interval_seconds=10, dry_run=True, max_cycles=None)

max_cycles is for TESTING - pass None (default) to run forever, or a
number to stop after that many cycles (used by the test suite so tests
don't hang forever).
"""

import asyncio
import logging

from src.automation.agent import run_cycle

logger = logging.getLogger("aerodrift.daemon")


async def run_daemon(interval_seconds: int = 10, dry_run: bool = True, max_cycles: int | None = None):
    """
    Runs run_cycle() repeatedly, waiting `interval_seconds` between runs.

    Args:
        interval_seconds: how long to wait between each detection cycle
        dry_run: passed straight through to run_cycle()/remediate()
        max_cycles: if set, stops after this many cycles (for testing).
                    If None, runs forever until manually stopped (Ctrl+C).

    Returns:
        A list of all CycleResult objects from every cycle run - mainly
        useful for tests. In a real long-running daemon this list would
        grow unboundedly, so max_cycles should always be set outside tests.
    """
    logger.info(
        f"Starting AeroDrift daemon: checking every {interval_seconds}s "
        f"(dry_run={dry_run})"
    )

    results = []
    cycle_count = 0

    try:
        while max_cycles is None or cycle_count < max_cycles:
            result = run_cycle(dry_run=dry_run)
            results.append(result)
            cycle_count += 1

            if max_cycles is None or cycle_count < max_cycles:
                await asyncio.sleep(interval_seconds)

    except asyncio.CancelledError:
        logger.info("Daemon stopped.")
        raise

    return results


def start(interval_seconds: int = 10, dry_run: bool = True):
    """Synchronous entry point - what you'd actually run from the CLI."""
    asyncio.run(run_daemon(interval_seconds=interval_seconds, dry_run=dry_run))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    print("Starting AeroDrift daemon (Ctrl+C to stop)...")
    print("Running 3 cycles for this demo, 3 seconds apart.\n")

    # For a real daemon, you'd call start() with max_cycles=None (runs forever).
    # Here we cap it at 3 cycles so the demo actually finishes.
    asyncio.run(run_daemon(interval_seconds=3, dry_run=True, max_cycles=3))

    print("\nDemo complete - daemon ran 3 cycles and stopped.")