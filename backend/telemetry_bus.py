"""
Quantara Telemetry Bus
======================
Real-time internal event bus for exploit verification telemetry.

Events are emitted at every stage of the verification pipeline and
streamed to dashboard consumers via Server-Sent Events (SSE) or
WebSocket subscriptions without requiring a page refresh.

Architecture:
    ExploitVerificationEngine
        └─ emits events → TelemetryBus
                              ├─ SSE generator (FastAPI StreamingResponse)
                              ├─ WebSocket broadcast
                              └─ in-memory rolling event log
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ── Event types ───────────────────────────────────────────────────────────────

class TelemetryEvent(str, Enum):
    # Lifecycle
    VERIFICATION_STARTED     = "VERIFICATION_STARTED"
    VERIFICATION_CONFIRMED   = "VERIFICATION_CONFIRMED"
    VERIFICATION_FAILED      = "VERIFICATION_FAILED"
    VERIFICATION_INCONCLUSIVE = "VERIFICATION_INCONCLUSIVE"
    VERIFICATION_ERROR       = "VERIFICATION_ERROR"

    # Request / Response
    BASELINE_REQUEST_SENT    = "BASELINE_REQUEST_SENT"
    PAYLOAD_INJECTED         = "PAYLOAD_INJECTED"
    RESPONSE_RECEIVED        = "RESPONSE_RECEIVED"

    # Analysis
    DIFFERENTIAL_DETECTED    = "DIFFERENTIAL_DETECTED"
    STATISTICAL_SAMPLING     = "STATISTICAL_SAMPLING"
    CONFIDENCE_COMPUTED      = "CONFIDENCE_COMPUTED"

    # Evidence
    EVIDENCE_HASH_CREATED    = "EVIDENCE_HASH_CREATED"

    # Safety
    SAFETY_CHECK_PASSED      = "SAFETY_CHECK_PASSED"
    SAFETY_CHECK_FAILED      = "SAFETY_CHECK_FAILED"

    # Session
    SESSION_REFRESHED        = "SESSION_REFRESHED"
    SESSION_EXPIRED          = "SESSION_EXPIRED"

    # AI
    AI_CONTRACT_APPROVED     = "AI_CONTRACT_APPROVED"
    AI_CONTRACT_REJECTED     = "AI_CONTRACT_REJECTED"

    # Batch
    BATCH_STARTED            = "BATCH_STARTED"
    BATCH_COMPLETE           = "BATCH_COMPLETE"


# ── Telemetry payload schema ──────────────────────────────────────────────────

def _build_event(
    event: TelemetryEvent,
    finding_id: str = "",
    data: Optional[Dict[str, Any]] = None,
    scan_id: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "event": event.value,
        "finding_id": finding_id,
        "scan_id": scan_id or "",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "running",
        "data": data or {},
    }


# ═══════════════════════════════════════════════════════════════════════════════
# TelemetryBus
# ═══════════════════════════════════════════════════════════════════════════════

class TelemetryBus:
    """
    Central event bus for verification telemetry.

    Consumers:
        - SSE stream  → sse_generator(finding_id=...)
        - WebSocket   → ws_generator(finding_id=...)
        - In-process  → get_event_log()

    Thread-safe for asyncio environments.
    """

    def __init__(self, max_log_size: int = 2000):
        self._queues: List[asyncio.Queue] = []
        self._event_log: List[Dict[str, Any]] = []
        self._max_log_size = max_log_size
        # scan_id → list of event dicts (per-scan isolation)
        self._scan_logs: Dict[str, List[Dict[str, Any]]] = {}

    # ── Subscription management ───────────────────────────────────────────────

    def subscribe(self) -> asyncio.Queue:
        """Create and register a new subscriber queue."""
        q: asyncio.Queue = asyncio.Queue(maxsize=200)
        self._queues.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        try:
            self._queues.remove(q)
        except ValueError:
            pass

    # ── Core emit ────────────────────────────────────────────────────────────

    async def emit(
        self,
        event: TelemetryEvent,
        finding_id: str = "",
        data: Optional[Dict[str, Any]] = None,
        scan_id: Optional[str] = None,
    ) -> None:
        """Broadcast an event to all active subscribers and log it."""
        payload = _build_event(event, finding_id, data, scan_id)

        # Rolling global log
        self._event_log.append(payload)
        if len(self._event_log) > self._max_log_size:
            self._event_log = self._event_log[-self._max_log_size:]

        # Per-scan log
        if scan_id:
            self._scan_logs.setdefault(scan_id, []).append(payload)

        # Fan-out to subscribers (drop slow consumers)
        dead: List[asyncio.Queue] = []
        for q in list(self._queues):
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            self.unsubscribe(q)

        logger.debug(
            f"[Telemetry] {event.value} | finding={finding_id!r} scan={scan_id!r}"
        )

    def emit_sync(
        self,
        event: TelemetryEvent,
        finding_id: str = "",
        data: Optional[Dict[str, Any]] = None,
        scan_id: Optional[str] = None,
    ) -> None:
        """Synchronous emit — schedules on the current event loop if available."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(self.emit(event, finding_id, data, scan_id))
            else:
                loop.run_until_complete(self.emit(event, finding_id, data, scan_id))
        except RuntimeError:
            # No event loop — just log
            payload = _build_event(event, finding_id, data, scan_id)
            self._event_log.append(payload)

    # ── Convenience emitters ──────────────────────────────────────────────────

    async def emit_started(self, finding_id: str, strategy: str, scan_id: str = "") -> None:
        await self.emit(
            TelemetryEvent.VERIFICATION_STARTED,
            finding_id=finding_id,
            scan_id=scan_id,
            data={"strategy": strategy},
        )

    async def emit_baseline_sent(self, finding_id: str, url: str, scan_id: str = "") -> None:
        await self.emit(
            TelemetryEvent.BASELINE_REQUEST_SENT,
            finding_id=finding_id,
            scan_id=scan_id,
            data={"url": url},
        )

    async def emit_payload_injected(
        self, finding_id: str, payload: str, url: str, scan_id: str = ""
    ) -> None:
        await self.emit(
            TelemetryEvent.PAYLOAD_INJECTED,
            finding_id=finding_id,
            scan_id=scan_id,
            data={"payload": payload[:200], "url": url},
        )

    async def emit_response_received(
        self,
        finding_id: str,
        status: int,
        elapsed_ms: float,
        length: int,
        scan_id: str = "",
    ) -> None:
        await self.emit(
            TelemetryEvent.RESPONSE_RECEIVED,
            finding_id=finding_id,
            scan_id=scan_id,
            data={"status": status, "elapsed_ms": elapsed_ms, "length": length},
        )

    async def emit_differential(
        self, finding_id: str, delta_ms: float, len_diff: int, scan_id: str = ""
    ) -> None:
        await self.emit(
            TelemetryEvent.DIFFERENTIAL_DETECTED,
            finding_id=finding_id,
            scan_id=scan_id,
            data={"timing_delta_ms": delta_ms, "length_diff": len_diff},
        )

    async def emit_confirmed(
        self, finding_id: str, confidence: float, notes: str, scan_id: str = ""
    ) -> None:
        await self.emit(
            TelemetryEvent.VERIFICATION_CONFIRMED,
            finding_id=finding_id,
            scan_id=scan_id,
            data={"confidence": confidence, "notes": notes},
        )

    async def emit_failed(self, finding_id: str, reason: str, scan_id: str = "") -> None:
        await self.emit(
            TelemetryEvent.VERIFICATION_FAILED,
            finding_id=finding_id,
            scan_id=scan_id,
            data={"reason": reason},
        )

    async def emit_evidence_hash(
        self, finding_id: str, sha256: str, scan_id: str = ""
    ) -> None:
        await self.emit(
            TelemetryEvent.EVIDENCE_HASH_CREATED,
            finding_id=finding_id,
            scan_id=scan_id,
            data={"sha256": sha256},
        )

    async def emit_safety_blocked(self, finding_id: str, url: str, scan_id: str = "") -> None:
        await self.emit(
            TelemetryEvent.SAFETY_CHECK_FAILED,
            finding_id=finding_id,
            scan_id=scan_id,
            data={"blocked_url": url, "reason": "SSRF/internal target"},
        )

    async def emit_statistical_sample(
        self,
        finding_id: str,
        sample_num: int,
        elapsed_ms: float,
        phase: str,
        scan_id: str = "",
    ) -> None:
        await self.emit(
            TelemetryEvent.STATISTICAL_SAMPLING,
            finding_id=finding_id,
            scan_id=scan_id,
            data={"sample": sample_num, "elapsed_ms": elapsed_ms, "phase": phase},
        )

    # ── Streaming generators ──────────────────────────────────────────────────

    async def sse_generator(
        self,
        finding_id: Optional[str] = None,
        scan_id: Optional[str] = None,
        keepalive_seconds: float = 15.0,
    ):
        """
        Async generator that yields SSE-formatted strings.

        Usage in FastAPI:
            from fastapi.responses import StreamingResponse
            return StreamingResponse(
                bus.sse_generator(finding_id=fid),
                media_type="text/event-stream",
            )
        """
        q = self.subscribe()
        try:
            while True:
                try:
                    event = await asyncio.wait_for(q.get(), timeout=keepalive_seconds)
                    # Filter by finding_id and/or scan_id if provided
                    if finding_id and event.get("finding_id") != finding_id:
                        continue
                    if scan_id and event.get("scan_id") != scan_id:
                        continue
                    yield f"data: {json.dumps(event)}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"  # prevent connection drop
        except asyncio.CancelledError:
            pass
        finally:
            self.unsubscribe(q)

    async def ws_generator(
        self,
        finding_id: Optional[str] = None,
        scan_id: Optional[str] = None,
        keepalive_seconds: float = 15.0,
    ):
        """
        Async generator for WebSocket broadcast.

        Usage:
            async for msg in bus.ws_generator(scan_id=sid):
                await websocket.send_text(msg)
        """
        q = self.subscribe()
        try:
            while True:
                try:
                    event = await asyncio.wait_for(q.get(), timeout=keepalive_seconds)
                    if finding_id and event.get("finding_id") != finding_id:
                        continue
                    if scan_id and event.get("scan_id") != scan_id:
                        continue
                    yield json.dumps(event)
                except asyncio.TimeoutError:
                    yield json.dumps({"event": "keepalive", "timestamp": datetime.now(timezone.utc).isoformat()})
        except asyncio.CancelledError:
            pass
        finally:
            self.unsubscribe(q)

    # ── Log accessors ─────────────────────────────────────────────────────────

    def get_event_log(
        self,
        finding_id: Optional[str] = None,
        scan_id: Optional[str] = None,
        limit: int = 200,
    ) -> List[Dict[str, Any]]:
        """Return recent events, optionally filtered."""
        if scan_id and scan_id in self._scan_logs:
            logs = self._scan_logs[scan_id]
        else:
            logs = self._event_log

        if finding_id:
            logs = [e for e in logs if e.get("finding_id") == finding_id]

        return logs[-limit:]

    def clear_scan_log(self, scan_id: str) -> None:
        self._scan_logs.pop(scan_id, None)

    def subscriber_count(self) -> int:
        return len(self._queues)


# ── Singleton ─────────────────────────────────────────────────────────────────

_bus: Optional[TelemetryBus] = None


def get_telemetry_bus() -> TelemetryBus:
    global _bus
    if _bus is None:
        _bus = TelemetryBus(max_log_size=2000)
    return _bus
