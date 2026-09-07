"""
loop.py - Wraps agent.run_cycle() in a continuously-running loop, using
asyncio - matching the project brief's description of AeroDrift as a
daemon that continuously watches for and heals configuration drift.

Tracks already-remediated findings across cycles (via a shared set
passed into run_cycle), so the daemon only acts on genuinely NEW drift,
not the same unchanged issue over and over.

SAFETY: live (non-dry-run) mode is deliberately hard to enable by
accident. Passing dry_run=False alone is NOT enough - you must also set
the environment variable AERODRIFT_CONFIRM_LIVE=YES. This is intentional:
an unattended daemon that can make REAL AWS changes on its own is
dangerous, and should never turn on from a default, a typo, or a copied
command someone didn't fully read.

Public function:
    run_daemon(interval_seconds=10, dry_run=True, max_cycles=None)

max_cycles is for TESTING - pass None (default) to run forever, or a
number to stop after that many cycles (used by the test suite so tests
don't hang forever).
"""

import asyncio
import logging
import os

from src.automation.agent import run_cycle

logger = logging.getLogger("aerodrift.daemon")

LIVE_MODE_CONFIRM_ENV_VAR = "AERODRIFT_CONFIRM_LIVE"
LIVE_MODE_CONFIRM_VALUE = "YES"


class LiveModeNotConfirmedError(RuntimeError):
    """
    Raised when someone tries to start the daemon in live (non-dry-run)
    mode without explicitly confirming it via environment variable.

    This exists so live mode can NEVER turn on silently - not from a
    default value, not from a copy-pasted command, not from a typo.
    """
    pass


def _check_live_mode_allowed(dry_run: bool) -> None:
    if dry_run:
        return  # dry-run is always safe, no confirmation needed

    confirmed = os.environ.get(LIVE_MODE_CONFIRM_ENV_VAR) == LIVE_MODE_CONFIRM_VALUE
    if not confirmed:
        raise LiveModeNotConfirmedError(
            "Refusing to start in LIVE mode (dry_run=False) without explicit "
            f"confirmation. This would make REAL changes to AWS.\n"
            f"To confirm you understand this and want live mode, set the "
            f"environment variable {LIVE_MODE_CONFIRM_ENV_VAR}={LIVE_MODE_CONFIRM_VALUE} "
            f"and try again."
        )

    logger.warning(
        "!!! LIVE MODE CONFIRMED - this daemon WILL make real AWS changes !!!"
    )


async def run_daemon(interval_seconds: int = 10, dry_run: bool = True, max_cycles: int | None = None):
    """
    Runs run_cycle() repeatedly, waiting `interval_seconds` between runs.
    Remembers what's already been remediated across the whole run, so
    the same issue doesn't get "fixed" again every cycle.

    Raises LiveModeNotConfirmedError if dry_run=False without the safety
    environment variable set - see module docstring for why.
    """
    _check_live_mode_allowed(dry_run)

    mode_label = "DRY-RUN (safe)" if dry_run else "LIVE (real changes will be made)"
    logger.info(
        f"Starting AeroDrift daemon: checking every {interval_seconds}s [{mode_label}]"
    )

    results = []
    cycle_count = 0
    seen_findings = set()

    try:
        while max_cycles is None or cycle_count < max_cycles:
            result = run_cycle(dry_run=dry_run, seen_findings=seen_findings)
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

    print("Demo 1: Trying to start in LIVE mode WITHOUT confirmation (should be blocked)\n")
    try:
        asyncio.run(run_daemon(interval_seconds=1, dry_run=False, max_cycles=1))
    except LiveModeNotConfirmedError as e:
        print(f"Correctly blocked: {e}\n")

    print("Demo 2: Running in normal DRY-RUN mode (always allowed)\n")
    asyncio.run(run_daemon(interval_seconds=1, dry_run=True, max_cycles=1))