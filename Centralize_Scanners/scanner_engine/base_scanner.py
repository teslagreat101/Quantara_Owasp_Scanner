"""
base_scanner.py — Enterprise BaseScanner Abstract Framework
============================================================
All scanners in Centralize_Scanners MUST inherit from BaseScanner.
Provides: hot-plug support, distributed execution, orchestration compatibility,
telemetry, structured evidence generation, and SARIF-ready output.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncIterator, Callable, Dict, List, Optional, Tuple

# ─────────────────────────────────────────────
# Telemetry / structured logging
# ─────────────────────────────────────────────
_logger = logging.getLogger("enterprise.scanner")
if not _logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(
        logging.Formatter(
            '{"time":"%(asctime)s","level":"%(levelname)s","scanner":"%(name)s","msg":"%(message)s"}'
        )
    )
    _logger.addHandler(_handler)
    _logger.setLevel(logging.INFO)


# ─────────────────────────────────────────────
# Core enumerations
# ─────────────────────────────────────────────
class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def score(self) -> float:
        return {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.5}[
            self.value
        ]


class ScanPhase(str, Enum):
    DISCOVERY = "discovery"
    PROBING = "probing"
    VERIFICATION = "verification"
    ESCALATION = "escalation"
    REPORTING = "reporting"


class VerificationStatus(str, Enum):
    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    POSSIBLE = "possible"
    FALSE_POSITIVE = "false_positive"
    UNVERIFIED = "unverified"


# ─────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────
@dataclass
class ScanTarget:
    """Normalized input for any scanner module."""
    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    params: Dict[str, Any] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    auth: Optional[Dict[str, str]] = None
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)
    timeout: float = 30.0
    follow_redirects: bool = True
    max_retries: int = 3
    tags: List[str] = field(default_factory=list)

    @property
    def host(self) -> str:
        from urllib.parse import urlparse
        return urlparse(self.url).netloc

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "headers": self.headers,
            "body": self.body,
            "params": self.params,
            "scan_id": self.scan_id,
        }


@dataclass
class EvidenceBundle:
    """Forensic evidence attached to every finding."""
    request_method: str = ""
    request_url: str = ""
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body: Optional[str] = None
    response_status: int = 0
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: Optional[str] = None
    response_time_ms: float = 0.0
    payload_used: Optional[str] = None
    proof_snippet: Optional[str] = None
    screenshot_path: Optional[str] = None
    diff_summary: Optional[str] = None
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request": {
                "method": self.request_method,
                "url": self.request_url,
                "headers": self.request_headers,
                "body": self.request_body,
            },
            "response": {
                "status": self.response_status,
                "headers": self.response_headers,
                "body": self.response_body[:2000] if self.response_body else None,
                "time_ms": self.response_time_ms,
            },
            "payload": self.payload_used,
            "proof": self.proof_snippet,
            "diff": self.diff_summary,
            "timestamp": self.timestamp,
        }


@dataclass
class NormalizedFinding:
    """
    Universal finding format — compatible across all scanner modules,
    SARIF export, Neo4j ingestion, DFIR bundles, and API responses.
    """
    # Identity
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    fingerprint: str = ""

    # Classification
    scanner_name: str = ""
    category: str = ""
    severity: SeverityLevel = SeverityLevel.MEDIUM
    title: str = ""
    description: str = ""
    cwe: str = ""
    owasp: str = ""

    # Location
    file: Optional[str] = None
    line_number: Optional[int] = None
    url: Optional[str] = None
    endpoint: Optional[str] = None
    parameter: Optional[str] = None

    # Quality
    confidence: float = 0.5
    verification_status: VerificationStatus = VerificationStatus.UNVERIFIED
    false_positive_score: float = 0.0

    # Evidence
    evidence: EvidenceBundle = field(default_factory=EvidenceBundle)
    matched_content: Optional[str] = None
    payload_used: Optional[str] = None

    # Context
    remediation: str = ""
    remediation_effort: str = "medium"  # low|medium|high
    attack_vector: str = ""
    tags: List[str] = field(default_factory=list)

    # Metadata
    scan_id: Optional[str] = None
    user_id: Optional[str] = None
    scanner_source: str = ""
    phase: ScanPhase = ScanPhase.DISCOVERY
    timestamp: float = field(default_factory=time.time)

    # Attack chain
    attack_chain_id: Optional[str] = None
    related_findings: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.fingerprint:
            raw = f"{self.file}:{self.line_number}:{self.cwe}:{self.title}:{self.url}"
            self.fingerprint = hashlib.sha256(raw.encode()).hexdigest()

    @property
    def risk_score(self) -> float:
        base = self.severity.score
        return round(base * self.confidence, 2)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "fingerprint": self.fingerprint,
            "scanner": self.scanner_name,
            "category": self.category,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "file": self.file,
            "line_number": self.line_number,
            "url": self.url,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "confidence": self.confidence,
            "risk_score": self.risk_score,
            "verification": self.verification_status.value,
            "false_positive_score": self.false_positive_score,
            "evidence": self.evidence.to_dict(),
            "matched_content": self.matched_content,
            "payload": self.payload_used,
            "remediation": self.remediation,
            "remediation_effort": self.remediation_effort,
            "attack_vector": self.attack_vector,
            "tags": self.tags,
            "scan_id": self.scan_id,
            "scanner_source": self.scanner_source,
            "phase": self.phase.value,
            "timestamp": self.timestamp,
            "attack_chain_id": self.attack_chain_id,
            "related_findings": self.related_findings,
        }

    def to_sarif(self) -> Dict[str, Any]:
        """SARIF 2.1.0 compatible result."""
        return {
            "ruleId": self.cwe or self.category,
            "level": {
                "critical": "error",
                "high": "error",
                "medium": "warning",
                "low": "note",
                "info": "none",
            }.get(self.severity.value, "warning"),
            "message": {"text": self.description},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": self.file or self.url or ""},
                        "region": {"startLine": self.line_number or 1},
                    }
                }
            ],
            "properties": {
                "confidence": self.confidence,
                "owasp": self.owasp,
                "remediation": self.remediation,
                "tags": self.tags,
            },
        }


@dataclass
class ScanTelemetry:
    """Per-scan runtime metrics for observability."""
    scan_id: str
    scanner_name: str
    target: str
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    findings_count: int = 0
    requests_made: int = 0
    payloads_tested: int = 0
    cpu_usage_pct: float = 0.0
    memory_mb: float = 0.0
    error_count: int = 0
    phase: ScanPhase = ScanPhase.DISCOVERY
    user_id: Optional[str] = None

    @property
    def duration_ms(self) -> float:
        end = self.end_time or time.time()
        return round((end - self.start_time) * 1000, 2)

    def finish(self) -> None:
        self.end_time = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "scanner": self.scanner_name,
            "target": self.target,
            "duration_ms": self.duration_ms,
            "findings": self.findings_count,
            "requests": self.requests_made,
            "payloads_tested": self.payloads_tested,
            "cpu_pct": self.cpu_usage_pct,
            "memory_mb": self.memory_mb,
            "errors": self.error_count,
            "phase": self.phase.value,
            "user_id": self.user_id,
        }


# ─────────────────────────────────────────────
# Abstract Base Scanner
# ─────────────────────────────────────────────
class BaseScanner(ABC):
    """
    Enterprise abstract base class for all scanner modules.

    Features:
    - Hot-plug registration via ScannerRegistry
    - Async-first scan/verify pipeline
    - Structured telemetry + logging
    - SARIF-ready NormalizedFinding output
    - CPU-safe semaphore throttling
    - Distributed execution compatibility
    - Finding deduplication via fingerprints
    - Graceful shutdown support
    """

    # Subclasses MUST define these
    name: str = "base"
    category: str = "general"
    severity: str = "medium"
    owasp_category: str = ""
    cwe_ids: List[str] = []
    version: str = "1.0.0"

    # Operational limits (override per scanner)
    max_concurrent: int = 10
    request_timeout: float = 30.0
    max_retries: int = 3
    confidence_threshold: float = 0.3

    def __init__(self):
        self._telemetry: Optional[ScanTelemetry] = None
        self._seen_fingerprints: set = set()
        self._shutdown_event = asyncio.Event()
        self._logger = logging.getLogger(f"enterprise.scanner.{self.name}")
        self._callbacks: List[Callable[[NormalizedFinding], None]] = []

    # ── Required interface ──────────────────────────────────────
    @abstractmethod
    async def scan(self, target: ScanTarget) -> List[NormalizedFinding]:
        """
        Primary scan entrypoint. Receives a normalized ScanTarget,
        returns a list of NormalizedFinding objects.
        """
        ...

    # ── Optional overrides ──────────────────────────────────────
    async def verify(self, finding: NormalizedFinding) -> NormalizedFinding:
        """
        Multi-stage verification pipeline:
        Detect → Retest → Variant replay → Confirm → Score
        Default: mark as PROBABLE (subclasses should override for confirmation).
        """
        if finding.confidence >= 0.8:
            finding.verification_status = VerificationStatus.CONFIRMED
        elif finding.confidence >= 0.5:
            finding.verification_status = VerificationStatus.PROBABLE
        else:
            finding.verification_status = VerificationStatus.POSSIBLE
        return finding

    def normalize(self, result: Any) -> Optional[NormalizedFinding]:
        """
        Convert any raw scanner output into a NormalizedFinding.
        Override this in each subclass to handle module-specific formats.
        """
        if isinstance(result, NormalizedFinding):
            return result
        if isinstance(result, dict):
            return self._from_dict(result)
        return None

    async def stream(self, target: ScanTarget) -> AsyncIterator[NormalizedFinding]:
        """Streaming variant of scan() for real-time SSE/WebSocket delivery."""
        findings = await self.scan(target)
        for f in findings:
            yield f

    # ── Telemetry ───────────────────────────────────────────────
    def start_telemetry(self, scan_id: str, target: str, user_id: Optional[str] = None) -> ScanTelemetry:
        self._telemetry = ScanTelemetry(
            scan_id=scan_id,
            scanner_name=self.name,
            target=target,
            user_id=user_id,
        )
        self._log("info", "Scan started", scan_id=scan_id, target=target)
        return self._telemetry

    def finish_telemetry(self) -> Optional[Dict[str, Any]]:
        if self._telemetry:
            self._telemetry.finish()
            data = self._telemetry.to_dict()
            self._log("info", "Scan finished", **data)
            return data
        return None

    # ── Deduplication ───────────────────────────────────────────
    def deduplicate(self, findings: List[NormalizedFinding]) -> List[NormalizedFinding]:
        unique: List[NormalizedFinding] = []
        for f in findings:
            if f.fingerprint not in self._seen_fingerprints:
                self._seen_fingerprints.add(f.fingerprint)
                unique.append(f)
        return unique

    # ── Callbacks ───────────────────────────────────────────────
    def on_finding(self, callback: Callable[[NormalizedFinding], None]) -> None:
        """Register a callback invoked for each finding (for real-time streaming)."""
        self._callbacks.append(callback)

    def _emit(self, finding: NormalizedFinding) -> None:
        """Emit finding to all registered callbacks."""
        for cb in self._callbacks:
            try:
                cb(finding)
            except Exception as exc:
                self._log("warning", f"Callback error: {exc}")

    # ── Graceful shutdown ────────────────────────────────────────
    def request_shutdown(self) -> None:
        self._shutdown_event.set()

    @property
    def should_stop(self) -> bool:
        return self._shutdown_event.is_set()

    # ── Helpers ──────────────────────────────────────────────────
    def _log(self, level: str, msg: str, **extra) -> None:
        log_fn = getattr(self._logger, level, self._logger.info)
        log_fn(f"{msg} | {json.dumps(extra)}" if extra else msg)

    def _make_finding(self, **kwargs) -> NormalizedFinding:
        """Helper to quickly build a NormalizedFinding with scanner defaults."""
        kwargs.setdefault("scanner_name", self.name)
        kwargs.setdefault("category", self.category)
        kwargs.setdefault("owasp", self.owasp_category)
        if "severity" in kwargs and isinstance(kwargs["severity"], str):
            try:
                kwargs["severity"] = SeverityLevel(kwargs["severity"])
            except ValueError:
                kwargs["severity"] = SeverityLevel.MEDIUM
        return NormalizedFinding(**kwargs)

    def _from_dict(self, d: Dict[str, Any]) -> NormalizedFinding:
        """Convert a legacy dict finding to NormalizedFinding."""
        sev_raw = d.get("severity", "medium")
        try:
            sev = SeverityLevel(str(sev_raw).lower())
        except ValueError:
            sev = SeverityLevel.MEDIUM
        return NormalizedFinding(
            id=d.get("id", str(uuid.uuid4())),
            scanner_name=d.get("module", d.get("scanner_source", self.name)),
            category=d.get("category", self.category),
            severity=sev,
            title=d.get("title", ""),
            description=d.get("description", ""),
            cwe=d.get("cwe", ""),
            owasp=d.get("owasp", self.owasp_category),
            file=d.get("file"),
            line_number=d.get("line_number"),
            url=d.get("url"),
            endpoint=d.get("endpoint"),
            parameter=d.get("parameter"),
            confidence=float(d.get("confidence", 0.5)),
            matched_content=d.get("matched_content"),
            remediation=d.get("remediation", ""),
            tags=d.get("tags", []),
            scan_id=d.get("scan_id"),
            scanner_source=d.get("scanner_source", self.name),
        )

    async def _safe_request(
        self,
        session: Any,
        method: str,
        url: str,
        retries: int = 3,
        **kwargs,
    ) -> Tuple[Optional[Any], float]:
        """
        Retry-aware HTTP request wrapper.
        Returns (response, elapsed_ms). Returns (None, 0) on failure.
        """
        for attempt in range(retries):
            try:
                start = time.monotonic()
                resp = await session.request(method, url, **kwargs)
                elapsed = (time.monotonic() - start) * 1000
                if self._telemetry:
                    self._telemetry.requests_made += 1
                return resp, elapsed
            except Exception as exc:
                self._log("warning", f"Request failed (attempt {attempt+1}/{retries}): {exc}")
                if attempt < retries - 1:
                    await asyncio.sleep(0.5 * (attempt + 1))
                if self._telemetry:
                    self._telemetry.error_count += 1
        return None, 0.0

    # ── Class info ───────────────────────────────────────────────
    @classmethod
    def info(cls) -> Dict[str, Any]:
        return {
            "name": cls.name,
            "category": cls.category,
            "owasp": cls.owasp_category,
            "cwe_ids": cls.cwe_ids,
            "version": cls.version,
            "max_concurrent": cls.max_concurrent,
        }

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r} category={self.category!r}>"


# ─────────────────────────────────────────────
# Scanner Registry — hot-plug support
# ─────────────────────────────────────────────
class ScannerRegistry:
    """
    Central registry for all BaseScanner subclasses.
    Supports hot-plugging: scanners register themselves on import.
    """

    _registry: Dict[str, type[BaseScanner]] = {}

    @classmethod
    def register(cls, scanner_cls: type[BaseScanner]) -> type[BaseScanner]:
        """Decorator or direct call to register a scanner class."""
        cls._registry[scanner_cls.name] = scanner_cls
        _logger.debug(f"Registered scanner: {scanner_cls.name}")
        return scanner_cls

    @classmethod
    def get(cls, name: str) -> Optional[type[BaseScanner]]:
        return cls._registry.get(name)

    @classmethod
    def all_scanners(cls) -> List[type[BaseScanner]]:
        return list(cls._registry.values())

    @classmethod
    def instantiate_all(cls) -> List[BaseScanner]:
        return [s() for s in cls._registry.values()]

    @classmethod
    def list_names(cls) -> List[str]:
        return list(cls._registry.keys())

    @classmethod
    def info_all(cls) -> List[Dict[str, Any]]:
        return [s.info() for s in cls._registry.values()]


def register_scanner(cls: type[BaseScanner]) -> type[BaseScanner]:
    """Class decorator for auto-registration."""
    return ScannerRegistry.register(cls)


# ─────────────────────────────────────────────
# Mixin: HTTP Scanner capability
# ─────────────────────────────────────────────
class HttpScannerMixin:
    """
    Adds aiohttp session management, connection pooling, and
    human-like timing to any BaseScanner subclass.
    """

    _session: Optional[Any] = None
    _session_lock: Optional[asyncio.Lock] = None

    async def _get_session(self) -> Any:
        try:
            import aiohttp
        except ImportError:
            raise RuntimeError("aiohttp is required for HTTP scanning: pip install aiohttp")

        if self._session_lock is None:
            self._session_lock = asyncio.Lock()

        async with self._session_lock:
            if self._session is None or self._session.closed:
                connector = aiohttp.TCPConnector(
                    limit=100,
                    limit_per_host=10,
                    ssl=False,
                    enable_cleanup_closed=True,
                )
                timeout = aiohttp.ClientTimeout(total=30)
                headers = {
                    "User-Agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/122.0.0.0 Safari/537.36"
                    ),
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Accept-Encoding": "gzip, deflate",
                }
                self._session = aiohttp.ClientSession(
                    connector=connector,
                    timeout=timeout,
                    headers=headers,
                )
        return self._session

    async def _close_session(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    @staticmethod
    async def _human_delay(min_ms: float = 50, max_ms: float = 300) -> None:
        """Mimic human-like request timing to evade WAF rate detection."""
        import random
        delay = random.uniform(min_ms, max_ms) / 1000.0
        await asyncio.sleep(delay)


# ─────────────────────────────────────────────
# Mixin: Code Scanner capability
# ─────────────────────────────────────────────
class CodeScannerMixin:
    """
    Adds file-traversal helpers for code-based scanners.
    """

    SKIP_DIRS = {
        ".git", "__pycache__", "node_modules", ".venv", "venv",
        "dist", "build", ".next", ".cache", "coverage",
    }
    SKIP_EXTENSIONS = {
        ".pyc", ".pyo", ".so", ".dll", ".exe", ".bin",
        ".jpg", ".jpeg", ".png", ".gif", ".ico", ".svg",
        ".zip", ".tar", ".gz", ".7z", ".rar",
        ".min.js", ".min.css",
    }

    def _iter_files(self, root: str, extensions: Optional[List[str]] = None) -> List[str]:
        """Walk directory, yielding scannable files."""
        result = []
        for dirpath, dirnames, filenames in os.walk(root):
            # Prune skip dirs
            dirnames[:] = [
                d for d in dirnames
                if d not in self.SKIP_DIRS and not d.startswith(".")
            ]
            for fname in filenames:
                if any(fname.endswith(ext) for ext in self.SKIP_EXTENSIONS):
                    continue
                if extensions:
                    if not any(fname.endswith(ext) for ext in extensions):
                        continue
                result.append(os.path.join(dirpath, fname))
        return result

    def _read_file(self, path: str, max_bytes: int = 2_000_000) -> Optional[str]:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                return fh.read(max_bytes)
        except Exception:
            return None
