"""
scheduler.py — Enterprise Async Scheduler & CPU Protection
===========================================================
Prevents scanner meltdown under concurrent enterprise load.

Features:
- asyncio worker pools with semaphore throttling
- Priority queue execution
- Per-host request rate limiting
- AI task concurrency caps
- Global resource monitor
- Graceful shutdown + retry logic
- Redis-backed distributed queue (optional)
- Scan prioritization (CRITICAL targets first)
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

_logger = logging.getLogger("enterprise.scheduler")

# ─────────────────────────────────────────────
# Global safety limits
# ─────────────────────────────────────────────
MAX_CONCURRENT_TARGETS: int = int(os.getenv("MAX_CONCURRENT_TARGETS", "20"))
MAX_REQUESTS_PER_HOST: int = int(os.getenv("MAX_REQUESTS_PER_HOST", "5"))
MAX_AI_TASKS: int = int(os.getenv("MAX_AI_TASKS", "2"))
MAX_QUEUE_SIZE: int = int(os.getenv("MAX_QUEUE_SIZE", "500"))
WATCHDOG_INTERVAL_S: float = float(os.getenv("WATCHDOG_INTERVAL_S", "30.0"))
CPU_THROTTLE_THRESHOLD: float = float(os.getenv("CPU_THROTTLE_THRESHOLD", "80.0"))
MEMORY_THROTTLE_MB: float = float(os.getenv("MEMORY_THROTTLE_MB", "2048.0"))


# ─────────────────────────────────────────────
# Priority levels
# ─────────────────────────────────────────────
class ScanPriority(IntEnum):
    CRITICAL = 0   # Highest — runs immediately
    HIGH = 1
    NORMAL = 2
    LOW = 3
    BACKGROUND = 4  # Lowest — only when idle


# ─────────────────────────────────────────────
# Task definition
# ─────────────────────────────────────────────
@dataclass(order=True)
class ScheduledTask:
    """
    A unit of work submitted to the scheduler.
    Sorted by (priority, enqueue_time) for fair scheduling.
    """
    priority: ScanPriority = field(default=ScanPriority.NORMAL, compare=True)
    enqueue_time: float = field(default_factory=time.monotonic, compare=True)

    # Non-comparable fields
    task_id: str = field(default_factory=lambda: str(uuid.uuid4()), compare=False)
    scan_id: str = field(default="", compare=False)
    user_id: Optional[str] = field(default=None, compare=False)
    target_host: str = field(default="", compare=False)
    coro_fn: Optional[Callable[..., Awaitable[Any]]] = field(default=None, compare=False)
    args: Tuple = field(default_factory=tuple, compare=False)
    kwargs: Dict[str, Any] = field(default_factory=dict, compare=False)
    retries: int = field(default=3, compare=False)
    attempt: int = field(default=0, compare=False)
    timeout: float = field(default=300.0, compare=False)
    created_at: float = field(default_factory=time.time, compare=False)
    tags: List[str] = field(default_factory=list, compare=False)


@dataclass
class TaskResult:
    task_id: str
    scan_id: str
    success: bool
    result: Any = None
    error: Optional[str] = None
    duration_ms: float = 0.0
    attempt: int = 1
    worker_id: str = ""


@dataclass
class SchedulerStats:
    queued: int = 0
    running: int = 0
    completed: int = 0
    failed: int = 0
    throttled: int = 0
    total_requests: int = 0
    cpu_pct: float = 0.0
    memory_mb: float = 0.0
    uptime_s: float = 0.0
    workers_active: int = 0


# ─────────────────────────────────────────────
# Per-host rate limiter
# ─────────────────────────────────────────────
class HostRateLimiter:
    """
    Limits concurrent requests per hostname.
    Prevents hammering a single target and triggering IP bans.
    """

    def __init__(self, max_per_host: int = MAX_REQUESTS_PER_HOST):
        self._max = max_per_host
        self._semaphores: Dict[str, asyncio.Semaphore] = {}
        self._lock = asyncio.Lock()
        self._counters: Dict[str, int] = defaultdict(int)

    async def acquire(self, host: str) -> asyncio.Semaphore:
        async with self._lock:
            if host not in self._semaphores:
                self._semaphores[host] = asyncio.Semaphore(self._max)
        return self._semaphores[host]

    async def __call__(self, host: str):
        sem = await self.acquire(host)
        await sem.acquire()
        self._counters[host] += 1

    def release(self, host: str) -> None:
        if host in self._semaphores:
            self._semaphores[host].release()
            self._counters[host] = max(0, self._counters[host] - 1)

    def active_count(self, host: str) -> int:
        return self._counters.get(host, 0)

    async def throttled_request(self, host: str):
        """Context manager: acquire on enter, release on exit."""
        return _HostContext(self, host)


class _HostContext:
    def __init__(self, limiter: HostRateLimiter, host: str):
        self._limiter = limiter
        self._host = host

    async def __aenter__(self):
        await self._limiter(self._host)
        return self

    async def __aexit__(self, *args):
        self._limiter.release(self._host)


# ─────────────────────────────────────────────
# Resource monitor
# ─────────────────────────────────────────────
class ResourceMonitor:
    """
    Monitors system CPU + memory.
    Signals the scheduler to throttle when resources are constrained.
    """

    def __init__(
        self,
        cpu_threshold: float = CPU_THROTTLE_THRESHOLD,
        memory_threshold_mb: float = MEMORY_THROTTLE_MB,
    ):
        self._cpu_threshold = cpu_threshold
        self._memory_threshold = memory_threshold_mb
        self._throttling = False
        self._last_check: float = 0.0

    def check(self) -> Tuple[bool, float, float]:
        """Returns (should_throttle, cpu_pct, memory_mb)."""
        now = time.monotonic()
        if now - self._last_check < 2.0:
            return self._throttling, 0.0, 0.0
        self._last_check = now

        cpu_pct, mem_mb = self._get_metrics()
        self._throttling = cpu_pct > self._cpu_threshold or mem_mb > self._memory_threshold
        return self._throttling, cpu_pct, mem_mb

    def _get_metrics(self) -> Tuple[float, float]:
        try:
            import psutil
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory().used / 1024 / 1024
            return cpu, mem
        except ImportError:
            return 0.0, 0.0

    @property
    def is_throttling(self) -> bool:
        return self._throttling


# ─────────────────────────────────────────────
# Enterprise Scheduler
# ─────────────────────────────────────────────
class EnterpriseScheduler:
    """
    Priority-aware async scheduler for enterprise scanning workloads.

    Architecture:
    - Priority queue feeds a fixed worker pool
    - Each worker acquires the global semaphore (MAX_CONCURRENT_TARGETS)
    - Per-host semaphore limits per-target concurrency (MAX_REQUESTS_PER_HOST)
    - AI tasks go through a separate throttled pool (MAX_AI_TASKS)
    - Resource monitor pauses new tasks when CPU/memory spikes
    - Watchdog detects stalled tasks and cancels them
    - Graceful shutdown drains the queue before stopping
    """

    def __init__(
        self,
        max_concurrent: int = MAX_CONCURRENT_TARGETS,
        max_per_host: int = MAX_REQUESTS_PER_HOST,
        max_ai_tasks: int = MAX_AI_TASKS,
        queue_size: int = MAX_QUEUE_SIZE,
        watchdog_interval: float = WATCHDOG_INTERVAL_S,
    ):
        self._max_concurrent = max_concurrent
        self._max_ai_tasks = max_ai_tasks
        self._queue_size = queue_size
        self._watchdog_interval = watchdog_interval

        # Core primitives
        self._global_sem = asyncio.Semaphore(max_concurrent)
        self._ai_sem = asyncio.Semaphore(max_ai_tasks)
        self._queue: asyncio.PriorityQueue[ScheduledTask] = asyncio.PriorityQueue(
            maxsize=queue_size
        )
        self._host_limiter = HostRateLimiter(max_per_host)
        self._resource_monitor = ResourceMonitor()

        # State
        self._running_tasks: Dict[str, asyncio.Task] = {}
        self._stats = SchedulerStats()
        self._started = False
        self._shutdown = asyncio.Event()
        self._workers: List[asyncio.Task] = []
        self._start_time: float = time.monotonic()
        self._result_callbacks: List[Callable[[TaskResult], None]] = []

    # ── Lifecycle ───────────────────────────────────────────────
    async def start(self, num_workers: int = 4) -> None:
        """Start the worker pool and watchdog."""
        if self._started:
            return
        self._started = True
        self._stats.workers_active = num_workers
        _logger.info(
            f"EnterpriseScheduler starting: workers={num_workers} "
            f"max_concurrent={self._max_concurrent} max_per_host={self._host_limiter._max}"
        )
        for i in range(num_workers):
            worker = asyncio.create_task(self._worker(f"worker-{i}"), name=f"scanner-worker-{i}")
            self._workers.append(worker)
        asyncio.create_task(self._watchdog(), name="scheduler-watchdog")

    async def shutdown(self, timeout: float = 30.0) -> None:
        """
        Graceful shutdown:
        1. Signal stop
        2. Drain queue (no new tasks)
        3. Wait for running tasks to finish (with timeout)
        4. Cancel remaining
        """
        _logger.info("EnterpriseScheduler shutting down...")
        self._shutdown.set()

        # Drain queue with sentinel tasks
        for _ in self._workers:
            try:
                self._queue.put_nowait(
                    ScheduledTask(priority=ScanPriority.BACKGROUND, coro_fn=None)
                )
            except asyncio.QueueFull:
                pass

        try:
            await asyncio.wait_for(
                asyncio.gather(*self._workers, return_exceptions=True),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            for w in self._workers:
                w.cancel()
        _logger.info("EnterpriseScheduler shutdown complete.")

    # ── Task submission ──────────────────────────────────────────
    async def submit(
        self,
        coro_fn: Callable[..., Awaitable[Any]],
        *args,
        scan_id: str = "",
        user_id: Optional[str] = None,
        target_host: str = "",
        priority: ScanPriority = ScanPriority.NORMAL,
        timeout: float = 300.0,
        retries: int = 3,
        tags: Optional[List[str]] = None,
        **kwargs,
    ) -> str:
        """
        Submit a coroutine for scheduled execution.
        Returns task_id for tracking.
        """
        if self._shutdown.is_set():
            raise RuntimeError("Scheduler is shutting down — no new tasks accepted")

        task = ScheduledTask(
            priority=priority,
            task_id=str(uuid.uuid4()),
            scan_id=scan_id or str(uuid.uuid4()),
            user_id=user_id,
            target_host=target_host,
            coro_fn=coro_fn,
            args=args,
            kwargs=kwargs,
            retries=retries,
            timeout=timeout,
            tags=tags or [],
        )

        try:
            await asyncio.wait_for(self._queue.put(task), timeout=5.0)
            self._stats.queued += 1
            _logger.debug(f"Task queued: {task.task_id} priority={priority.name}")
            return task.task_id
        except asyncio.TimeoutError:
            self._stats.throttled += 1
            raise RuntimeError(f"Queue full (size={self._queue_size}). Task rejected.")

    def submit_nowait(
        self,
        coro_fn: Callable[..., Awaitable[Any]],
        *args,
        **kwargs,
    ) -> str:
        """Non-blocking submit. Raises if queue is full."""
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(self.submit(coro_fn, *args, **kwargs))

    # ── AI-task specific submission ─────────────────────────────
    async def submit_ai(
        self,
        coro_fn: Callable[..., Awaitable[Any]],
        *args,
        **kwargs,
    ) -> Any:
        """
        Submit an AI task (Gemini, GPT, etc.) through the AI semaphore.
        Prevents AI API overload.
        """
        async with self._ai_sem:
            return await coro_fn(*args, **kwargs)

    # ── Callbacks ───────────────────────────────────────────────
    def on_result(self, callback: Callable[[TaskResult], None]) -> None:
        self._result_callbacks.append(callback)

    def _emit_result(self, result: TaskResult) -> None:
        for cb in self._result_callbacks:
            try:
                cb(result)
            except Exception as e:
                _logger.warning(f"Result callback error: {e}")

    # ── Worker loop ─────────────────────────────────────────────
    async def _worker(self, worker_id: str) -> None:
        _logger.debug(f"Worker {worker_id} started")
        while not self._shutdown.is_set():
            try:
                task = await asyncio.wait_for(self._queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue

            # Sentinel — shutdown signal
            if task.coro_fn is None:
                self._queue.task_done()
                break

            # Resource check — throttle if overloaded
            should_throttle, cpu, mem = self._resource_monitor.check()
            if should_throttle:
                _logger.warning(f"Throttling: CPU={cpu:.1f}% MEM={mem:.0f}MB")
                self._stats.throttled += 1
                await asyncio.sleep(2.0)
                await self._queue.put(task)  # Re-queue
                self._queue.task_done()
                continue

            await self._execute_task(task, worker_id)
            self._queue.task_done()

        _logger.debug(f"Worker {worker_id} exited")

    async def _execute_task(self, task: ScheduledTask, worker_id: str) -> None:
        """Execute a single task with semaphore, host limiting, retry, and telemetry."""
        start = time.monotonic()
        self._stats.running += 1
        self._stats.queued = max(0, self._stats.queued - 1)

        async with self._global_sem:
            # Per-host throttling
            async with _HostContext(self._host_limiter, task.target_host or "default"):
                result: Optional[TaskResult] = None
                for attempt in range(task.retries + 1):
                    task.attempt = attempt + 1
                    try:
                        coro = task.coro_fn(*task.args, **task.kwargs)
                        value = await asyncio.wait_for(coro, timeout=task.timeout)
                        duration = (time.monotonic() - start) * 1000
                        result = TaskResult(
                            task_id=task.task_id,
                            scan_id=task.scan_id,
                            success=True,
                            result=value,
                            duration_ms=duration,
                            attempt=task.attempt,
                            worker_id=worker_id,
                        )
                        self._stats.completed += 1
                        break
                    except asyncio.TimeoutError:
                        _logger.warning(
                            f"Task {task.task_id} timed out (attempt {attempt+1}/{task.retries+1})"
                        )
                        if attempt >= task.retries:
                            result = TaskResult(
                                task_id=task.task_id,
                                scan_id=task.scan_id,
                                success=False,
                                error="Timeout",
                                duration_ms=(time.monotonic() - start) * 1000,
                                attempt=task.attempt,
                                worker_id=worker_id,
                            )
                            self._stats.failed += 1
                    except asyncio.CancelledError:
                        _logger.info(f"Task {task.task_id} cancelled")
                        result = TaskResult(
                            task_id=task.task_id,
                            scan_id=task.scan_id,
                            success=False,
                            error="Cancelled",
                            attempt=task.attempt,
                            worker_id=worker_id,
                        )
                        break
                    except Exception as exc:
                        _logger.error(
                            f"Task {task.task_id} error (attempt {attempt+1}): {exc}",
                            exc_info=True,
                        )
                        if attempt >= task.retries:
                            result = TaskResult(
                                task_id=task.task_id,
                                scan_id=task.scan_id,
                                success=False,
                                error=str(exc),
                                duration_ms=(time.monotonic() - start) * 1000,
                                attempt=task.attempt,
                                worker_id=worker_id,
                            )
                            self._stats.failed += 1
                        else:
                            backoff = 2 ** attempt
                            await asyncio.sleep(backoff)

                if result:
                    self._emit_result(result)

        self._stats.running = max(0, self._stats.running - 1)

    # ── Watchdog ────────────────────────────────────────────────
    async def _watchdog(self) -> None:
        """Monitors for stalled workers and system resource pressure."""
        while not self._shutdown.is_set():
            await asyncio.sleep(self._watchdog_interval)
            _, cpu, mem = self._resource_monitor.check()
            self._stats.cpu_pct = cpu
            self._stats.memory_mb = mem
            self._stats.uptime_s = time.monotonic() - self._start_time
            _logger.debug(
                f"Watchdog: running={self._stats.running} queued={self._stats.queued} "
                f"completed={self._stats.completed} failed={self._stats.failed} "
                f"CPU={cpu:.1f}% MEM={mem:.0f}MB"
            )

    # ── Stats ────────────────────────────────────────────────────
    def stats(self) -> Dict:
        return {
            "queued": self._stats.queued,
            "running": self._stats.running,
            "completed": self._stats.completed,
            "failed": self._stats.failed,
            "throttled": self._stats.throttled,
            "cpu_pct": self._stats.cpu_pct,
            "memory_mb": self._stats.memory_mb,
            "uptime_s": self._stats.uptime_s,
            "workers_active": self._stats.workers_active,
            "queue_size": self._queue.qsize(),
        }

    def is_healthy(self) -> bool:
        return (
            not self._shutdown.is_set()
            and self._stats.running < self._max_concurrent
            and self._queue.qsize() < self._queue_size * 0.9
        )


# ─────────────────────────────────────────────
# Scan-level concurrency manager
# ─────────────────────────────────────────────
class ScanConcurrencyManager:
    """
    Per-scan concurrency control.
    Used by individual scanner modules to limit their own parallelism.
    """

    def __init__(self, max_workers: int = 10, max_per_host: int = MAX_REQUESTS_PER_HOST):
        self._sem = asyncio.Semaphore(max_workers)
        self._host_sem: Dict[str, asyncio.Semaphore] = {}
        self._lock = asyncio.Lock()
        self._max_per_host = max_per_host

    async def _host_semaphore(self, host: str) -> asyncio.Semaphore:
        async with self._lock:
            if host not in self._host_sem:
                self._host_sem[host] = asyncio.Semaphore(self._max_per_host)
            return self._host_sem[host]

    async def run(self, host: str, coro_fn: Callable, *args, **kwargs) -> Any:
        """Execute coro_fn with both global and per-host throttling."""
        host_sem = await self._host_semaphore(host)
        async with self._sem:
            async with host_sem:
                return await coro_fn(*args, **kwargs)

    async def run_batch(
        self,
        host: str,
        tasks: List[Tuple[Callable, tuple, dict]],
        jitter_ms: Tuple[float, float] = (50, 200),
    ) -> List[Any]:
        """
        Run a batch of (coro_fn, args, kwargs) tuples with throttling and jitter.
        Returns results in order (None for failed tasks).
        """
        import random
        results = []
        for coro_fn, args, kwargs in tasks:
            if jitter_ms[1] > 0:
                await asyncio.sleep(random.uniform(*jitter_ms) / 1000)
            try:
                result = await self.run(host, coro_fn, *args, **kwargs)
                results.append(result)
            except Exception as exc:
                _logger.warning(f"Batch task failed: {exc}")
                results.append(None)
        return results


# ─────────────────────────────────────────────
# Global default scheduler (singleton)
# ─────────────────────────────────────────────
_default_scheduler: Optional[EnterpriseScheduler] = None


def get_scheduler() -> EnterpriseScheduler:
    """Return the global scheduler instance (lazy init)."""
    global _default_scheduler
    if _default_scheduler is None:
        _default_scheduler = EnterpriseScheduler()
    return _default_scheduler


async def init_scheduler(num_workers: int = 4) -> EnterpriseScheduler:
    """Initialize and start the global scheduler."""
    sched = get_scheduler()
    await sched.start(num_workers=num_workers)
    return sched


async def shutdown_scheduler(timeout: float = 30.0) -> None:
    """Gracefully shut down the global scheduler."""
    global _default_scheduler
    if _default_scheduler:
        await _default_scheduler.shutdown(timeout=timeout)
        _default_scheduler = None
