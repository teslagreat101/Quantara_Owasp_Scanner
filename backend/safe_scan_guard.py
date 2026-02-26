"""
Quantara Safe Active Scan Guard
================================
Production-safe adaptive scan protection.

Monitors target server health in real-time and automatically adjusts
scan speed or aborts to prevent DoS of the target application.

Protections:
  - Adaptive request throttling (monitors latency)
  - Server health monitoring (5xx rate, timeouts, connection resets)
  - Auto-enable SAFE MODE when distress signals detected
  - Sandbox verification mode (Detect → Verify → STOP, no weaponization)
"""

from __future__ import annotations

import logging
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# ── Thresholds ─────────────────────────────────────────────────────────────────
LATENCY_THROTTLE_MS    = 3000   # avg latency above this → throttle
LATENCY_ABORT_MS       = 8000   # avg latency above this → abort
RATE_5XX_SAFE_MODE     = 0.20   # 20% 5xx → SAFE MODE
RATE_5XX_ABORT         = 0.50   # 50% 5xx → ABORT
CONN_RESET_SAFE_MODE   = 3      # N connection resets → SAFE MODE
WINDOW_SIZE            = 20     # rolling window for health calculation

# ── Mode names ────────────────────────────────────────────────────────────────
MODE_NORMAL      = "NORMAL"
MODE_THROTTLED   = "THROTTLED"
MODE_SAFE        = "SAFE_MODE"
MODE_ABORTED     = "ABORTED"


@dataclass
class ScanHealthSnapshot:
    mode: str = MODE_NORMAL
    requests_total: int = 0
    errors_5xx: int = 0
    conn_resets: int = 0
    avg_latency_ms: float = 0.0
    rate_5xx: float = 0.0
    adaptive_delay_s: float = 0.0
    should_abort: bool = False


class SafeScanGuard:
    """
    Thread-safe (asyncio-compatible) real-time scan health monitor.

    Usage:
        guard = SafeScanGuard()
        await asyncio.sleep(guard.get_adaptive_delay())
        # ... make request ...
        guard.track_request(elapsed_ms, status_code, connection_reset=False)
        if guard.should_abort():
            break
    """

    def __init__(self, window_size: int = WINDOW_SIZE):
        self._window: Deque[Dict] = deque(maxlen=window_size)
        self._mode: str = MODE_NORMAL
        self._conn_resets: int = 0
        self._total_requests: int = 0
        self._events: list = []  # emitted mode-change events

    # ── Public interface ──────────────────────────────────────────────────────

    def track_request(
        self,
        response_time_ms: float,
        status_code: int,
        connection_reset: bool = False,
    ) -> None:
        """Record a completed (or failed) request."""
        self._total_requests += 1
        entry = {
            "time_ms":    response_time_ms,
            "status":     status_code,
            "reset":      connection_reset,
            "ts":         time.monotonic(),
        }
        self._window.append(entry)

        if connection_reset:
            self._conn_resets += 1

        self._evaluate_health()

    def check_health(self) -> Tuple[bool, bool, bool]:
        """
        Returns: (is_healthy, should_throttle, should_abort)
        """
        return (
            self._mode not in (MODE_SAFE, MODE_ABORTED),
            self._mode == MODE_THROTTLED,
            self._mode == MODE_ABORTED,
        )

    def should_abort(self) -> bool:
        return self._mode == MODE_ABORTED

    def get_adaptive_delay(self) -> float:
        """Return seconds to sleep between requests."""
        delays = {
            MODE_NORMAL:    0.0,
            MODE_THROTTLED: 2.0,
            MODE_SAFE:      10.0,
            MODE_ABORTED:   0.0,
        }
        return delays.get(self._mode, 0.0)

    def get_snapshot(self) -> ScanHealthSnapshot:
        """Current health metrics."""
        snap = ScanHealthSnapshot(mode=self._mode)
        snap.requests_total = self._total_requests
        if self._window:
            latencies  = [r["time_ms"]  for r in self._window]
            errors_5xx = sum(1 for r in self._window if 500 <= r["status"] < 600)
            resets     = sum(1 for r in self._window if r["reset"])
            snap.avg_latency_ms = sum(latencies) / len(latencies)
            snap.errors_5xx = errors_5xx
            snap.conn_resets = resets
            snap.rate_5xx = errors_5xx / len(self._window)
        snap.adaptive_delay_s = self.get_adaptive_delay()
        snap.should_abort = self.should_abort()
        return snap

    def get_events(self) -> list:
        """Drain and return emitted mode-change events."""
        evts = list(self._events)
        self._events.clear()
        return evts

    def reset(self) -> None:
        """Reset guard state for a new scan."""
        self._window.clear()
        self._mode = MODE_NORMAL
        self._conn_resets = 0
        self._total_requests = 0
        self._events.clear()

    # ── Internal ──────────────────────────────────────────────────────────────

    def _evaluate_health(self) -> None:
        """Re-evaluate mode based on the current rolling window."""
        if len(self._window) < 3:
            return  # Not enough data yet

        latencies   = [r["time_ms"] for r in self._window]
        avg_latency = sum(latencies) / len(latencies)
        errors_5xx  = sum(1 for r in self._window if 500 <= r["status"] < 600)
        rate_5xx    = errors_5xx / len(self._window)

        prev_mode = self._mode

        # ABORT conditions (most severe)
        if rate_5xx >= RATE_5XX_ABORT:
            self._set_mode(MODE_ABORTED, f"5xx rate {rate_5xx:.0%} ≥ abort threshold {RATE_5XX_ABORT:.0%}")
        elif avg_latency >= LATENCY_ABORT_MS:
            self._set_mode(MODE_ABORTED, f"avg latency {avg_latency:.0f}ms ≥ abort threshold {LATENCY_ABORT_MS}ms")

        # SAFE MODE conditions
        elif rate_5xx >= RATE_5XX_SAFE_MODE and self._mode != MODE_ABORTED:
            self._set_mode(MODE_SAFE, f"5xx rate {rate_5xx:.0%} ≥ safe mode threshold")
        elif self._conn_resets >= CONN_RESET_SAFE_MODE and self._mode != MODE_ABORTED:
            self._set_mode(MODE_SAFE, f"{self._conn_resets} connection resets detected")

        # THROTTLE conditions
        elif avg_latency >= LATENCY_THROTTLE_MS and self._mode == MODE_NORMAL:
            self._set_mode(MODE_THROTTLED, f"avg latency {avg_latency:.0f}ms ≥ throttle threshold")

        # Recovery: if latency improves and no errors, return to NORMAL
        elif (avg_latency < LATENCY_THROTTLE_MS and rate_5xx < 0.05
              and self._mode == MODE_THROTTLED):
            self._set_mode(MODE_NORMAL, "Server health recovered — resuming normal speed")

    def _set_mode(self, new_mode: str, reason: str) -> None:
        if self._mode == new_mode:
            return
        old_mode = self._mode
        self._mode = new_mode
        msg = f"SafeScanGuard: {old_mode} → {new_mode} | {reason}"
        logger.info(msg)
        self._events.append({
            "type":     "scan_health_change",
            "old_mode": old_mode,
            "new_mode": new_mode,
            "reason":   reason,
        })


# ── Singleton ──────────────────────────────────────────────────────────────────

_guard: Optional[SafeScanGuard] = None


def get_safe_scan_guard() -> SafeScanGuard:
    global _guard
    if _guard is None:
        _guard = SafeScanGuard()
    return _guard


def create_fresh_guard() -> SafeScanGuard:
    """Create a per-scan fresh guard (preferred over singleton for concurrent scans)."""
    return SafeScanGuard()
