"""
Scan Queue Manager
==================
Prevents system crashes by enforcing hard concurrency limits and providing
automatic memory cleanup, watchdog recovery, and optional resource throttling.

Exports used by backend/main.py:
  get_semaphore()        → asyncio.Semaphore  (lazy-init, call inside event loop)
  bounded_executor       → ThreadPoolExecutor(max_workers=10)
  scan_queue_manager     → ScanQueueManager singleton
  cleanup_old_scans()    → background coroutine (start via asyncio.create_task)
  scan_watchdog()        → background coroutine (start via asyncio.create_task)
  resource_monitor()     → background coroutine (start via asyncio.create_task)
"""

import asyncio
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Configuration constants
# ──────────────────────────────────────────────────────────────────────────────

MAX_GLOBAL_SCANS: int = 5           # hard cap on simultaneous scan executions
MAX_SCANS_PER_USER: int = 2         # per-user active scan limit
SCAN_TTL_SECONDS: int = 3600        # 1 hour — remove completed scans from memory
CLEANUP_INTERVAL_SECONDS: int = 1800  # sweep every 30 minutes

WATCHDOG_CHECK_INTERVAL: int = 30   # check every 30 seconds
WATCHDOG_STUCK_THRESHOLD: int = 120  # mark as failed if no progress for 120s

RESOURCE_CHECK_INTERVAL: int = 15   # check CPU/RAM every 15 seconds
CPU_THROTTLE_THRESHOLD: float = 80.0
RAM_THROTTLE_THRESHOLD: float = 75.0

# ──────────────────────────────────────────────────────────────────────────────
# Bounded thread pool — replaces FastAPI's default unbounded executor
# ──────────────────────────────────────────────────────────────────────────────

bounded_executor = ThreadPoolExecutor(
    max_workers=10,
    thread_name_prefix="quantara-scan",
)

# ──────────────────────────────────────────────────────────────────────────────
# Global semaphore (lazy-initialized inside the running event loop)
# ──────────────────────────────────────────────────────────────────────────────

_global_semaphore: Optional[asyncio.Semaphore] = None


def get_semaphore() -> asyncio.Semaphore:
    """
    Return (and lazily create) the global scan semaphore.
    Must be called from within a running asyncio event loop.
    """
    global _global_semaphore
    if _global_semaphore is None:
        _global_semaphore = asyncio.Semaphore(MAX_GLOBAL_SCANS)
        logger.info(f"Scan semaphore initialised: max {MAX_GLOBAL_SCANS} concurrent scans")
    return _global_semaphore


# ──────────────────────────────────────────────────────────────────────────────
# ScanQueueManager
# ──────────────────────────────────────────────────────────────────────────────

class ScanQueueManager:
    """
    Manages global concurrency limits and per-user scan caps.

    Typical usage in main.py:
        # Before starting a scan:
        acquired = await scan_queue_manager.acquire_slot(scan_id, user_id, scans, db)
        if not acquired:
            # scan is queued — execute_scan() will wait_for_slot() itself

        # Inside execute_scan(), try/finally:
        try:
            if scans[scan_id]["status"] == "queued":
                await scan_queue_manager.wait_for_slot(scan_id, scans)
            ... run the scan ...
        finally:
            await scan_queue_manager.release_slot(scan_id)
    """

    def _count_user_active(self, user_id: str, scans_dict: dict) -> int:
        """Count active/queued scans for a specific user in the in-memory dict."""
        count = 0
        for scan in scans_dict.values():
            if (
                scan.get("user_id") == user_id
                and scan.get("status") in ("running", "initializing", "queued", "starting")
            ):
                count += 1
        return count

    async def acquire_slot(
        self,
        scan_id: str,
        user_id: str,
        scans_dict: dict,
        db: Any = None,
    ) -> bool:
        """
        Attempt to acquire a global scan slot for scan_id.

        Raises ValueError if the user is already at MAX_SCANS_PER_USER.
        Returns True  if the slot was acquired and the scan can start immediately.
        Returns False if the global cap is reached — scan is queued.
        """
        sem = get_semaphore()

        # Hard per-user limit — reject immediately, don't queue
        user_active = self._count_user_active(user_id, scans_dict)
        if user_active >= MAX_SCANS_PER_USER:
            raise ValueError(
                f"You already have {user_active} active scan(s). "
                f"Maximum {MAX_SCANS_PER_USER} concurrent scans per user allowed."
            )

        # Try to acquire without blocking
        acquired = sem._value > 0
        if acquired:
            await sem.acquire()
            scans_dict[scan_id]["status"] = "running"
            logger.info(
                f"Scan {scan_id} acquired slot immediately "
                f"(slots remaining: {sem._value})"
            )
            return True
        else:
            scans_dict[scan_id]["status"] = "queued"
            logger.info(
                f"Scan {scan_id} queued — global limit of {MAX_GLOBAL_SCANS} reached"
            )
            return False

    async def wait_for_slot(self, scan_id: str, scans_dict: dict) -> None:
        """
        Block (async, non-CPU) until a global slot becomes available.
        Call at the START of execute_scan() when scan["status"] == "queued".
        """
        sem = get_semaphore()
        logger.info(f"Scan {scan_id} waiting for a free slot…")
        await sem.acquire()
        scans_dict[scan_id]["status"] = "running"
        logger.info(f"Scan {scan_id} acquired slot after waiting, starting now")

    async def release_slot(self, scan_id: str) -> None:
        """
        Release one slot back to the global semaphore.
        Call in execute_scan()'s finally block.
        """
        try:
            get_semaphore().release()
            logger.debug(f"Scan {scan_id} released its semaphore slot")
        except Exception as exc:
            logger.warning(f"release_slot for {scan_id} failed: {exc}")


# Module-level singleton
scan_queue_manager = ScanQueueManager()


# ──────────────────────────────────────────────────────────────────────────────
# Background coroutines — start all three in startup_event()
# ──────────────────────────────────────────────────────────────────────────────

async def cleanup_old_scans(scans_dict: dict) -> None:
    """
    Background task: sweep the global `scans` dict every 30 minutes.
    Evicts entries whose scan completed/failed more than SCAN_TTL_SECONDS ago.

    This prevents the permanent memory leak where completed scans pile up
    in the in-memory dict indefinitely.
    """
    logger.info("Scan cleanup task started (interval: 30 min, TTL: 1 hr)")
    while True:
        try:
            await asyncio.sleep(CLEANUP_INTERVAL_SECONDS)
            now = datetime.now(timezone.utc)
            to_remove: list[str] = []

            for scan_id, scan in list(scans_dict.items()):
                if scan.get("status") not in ("completed", "error", "cancelled", "failed"):
                    continue
                completed_at_str = scan.get("completed_at")
                if not completed_at_str:
                    continue
                try:
                    completed_at = datetime.fromisoformat(completed_at_str)
                    if completed_at.tzinfo is None:
                        completed_at = completed_at.replace(tzinfo=timezone.utc)
                    age_seconds = (now - completed_at).total_seconds()
                    if age_seconds > SCAN_TTL_SECONDS:
                        to_remove.append(scan_id)
                except (ValueError, TypeError):
                    pass  # malformed timestamp — skip

            for scan_id in to_remove:
                scans_dict.pop(scan_id, None)

            if to_remove:
                logger.info(
                    f"Cleanup: evicted {len(to_remove)} stale scan(s) from memory: "
                    f"{to_remove[:5]}{'…' if len(to_remove) > 5 else ''}"
                )
        except asyncio.CancelledError:
            logger.info("Scan cleanup task cancelled")
            break
        except Exception as exc:
            logger.error(f"Scan cleanup error: {exc}", exc_info=True)


async def scan_watchdog(scans_dict: dict) -> None:
    """
    Background task: check every 30 seconds for scans that are frozen.

    A scan is considered stuck if it has been in "running" status for more than
    WATCHDOG_STUCK_THRESHOLD seconds with no new events appended.

    Stuck scans are marked "failed" and their semaphore slot is released so
    queued scans can proceed without hanging the server.
    """
    logger.info(
        f"Scan watchdog started "
        f"(check: {WATCHDOG_CHECK_INTERVAL}s, threshold: {WATCHDOG_STUCK_THRESHOLD}s)"
    )
    while True:
        try:
            await asyncio.sleep(WATCHDOG_CHECK_INTERVAL)
            now = time.monotonic()

            for scan_id, scan in list(scans_dict.items()):
                if scan.get("status") != "running":
                    continue

                last_event = scan.get("_last_event_time")
                if last_event is None:
                    # No events yet — use scan start time as baseline
                    scan["_last_event_time"] = now
                    continue

                stuck_seconds = now - last_event
                if stuck_seconds > WATCHDOG_STUCK_THRESHOLD:
                    logger.warning(
                        f"Watchdog: scan {scan_id} stuck for {stuck_seconds:.0f}s — "
                        f"marking as failed"
                    )
                    scan["status"] = "failed"
                    scan["completed_at"] = datetime.now(timezone.utc).isoformat()
                    scan["error"] = f"Scan timed out after {WATCHDOG_STUCK_THRESHOLD}s with no progress"

                    # Emit a visible error event to the SSE stream
                    scan.setdefault("events", []).append({
                        "type": "log",
                        "data": {
                            "level": "error",
                            "message": (
                                f"Scan watchdog: no progress for {stuck_seconds:.0f}s — "
                                f"scan terminated to protect server stability"
                            ),
                            "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                            "module": "watchdog",
                        },
                    })
                    scan.setdefault("events", []).append({
                        "type": "complete",
                        "data": {
                            "status": "failed",
                            "message": "Scan timed out",
                        },
                    })

                    # Release the semaphore so queued scans can proceed
                    try:
                        get_semaphore().release()
                        logger.info(f"Watchdog released semaphore slot for {scan_id}")
                    except Exception as exc:
                        logger.warning(f"Watchdog semaphore release failed: {exc}")

        except asyncio.CancelledError:
            logger.info("Scan watchdog cancelled")
            break
        except Exception as exc:
            logger.error(f"Scan watchdog error: {exc}", exc_info=True)


async def resource_monitor(scans_dict: dict) -> None:
    """
    Optional background task: monitor system CPU and RAM.
    Emits a health event to active scans when thresholds are exceeded.

    Requires psutil. Gracefully exits if psutil is not installed — the rest
    of the system continues working normally without it.
    """
    try:
        import psutil
    except ImportError:
        logger.warning(
            "psutil not installed — resource throttling disabled. "
            "Install with: pip install psutil>=5.9.0"
        )
        return

    logger.info(
        f"Resource monitor started "
        f"(CPU threshold: {CPU_THROTTLE_THRESHOLD}%, RAM threshold: {RAM_THROTTLE_THRESHOLD}%)"
    )
    _throttle_active = False

    while True:
        try:
            await asyncio.sleep(RESOURCE_CHECK_INTERVAL)
            cpu = psutil.cpu_percent(interval=1)
            mem = psutil.virtual_memory().percent

            if cpu > CPU_THROTTLE_THRESHOLD or mem > RAM_THROTTLE_THRESHOLD:
                if not _throttle_active:
                    logger.warning(
                        f"Resource pressure detected: CPU={cpu:.1f}% MEM={mem:.1f}% — "
                        f"emitting throttle events to active scans"
                    )
                    _throttle_active = True

                # Emit health change event to all running scans so the UI can show it
                for scan_id, scan in list(scans_dict.items()):
                    if scan.get("status") == "running":
                        scan.setdefault("events", []).append({
                            "type": "scan_health_change",
                            "data": {
                                "old_mode": "NORMAL",
                                "new_mode": "THROTTLED",
                                "reason": (
                                    f"Host resource pressure — "
                                    f"CPU: {cpu:.0f}%  RAM: {mem:.0f}%"
                                ),
                            },
                        })
            else:
                if _throttle_active:
                    logger.info(
                        f"Resource pressure relieved: CPU={cpu:.1f}% MEM={mem:.1f}%"
                    )
                    _throttle_active = False

        except asyncio.CancelledError:
            logger.info("Resource monitor cancelled")
            break
        except Exception as exc:
            logger.error(f"Resource monitor error: {exc}", exc_info=True)
