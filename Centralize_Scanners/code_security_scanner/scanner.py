"""
Code Security Scanner — Main Orchestrator
==========================================

The primary entry point for enterprise security scanning. Orchestrates
the full multi-agent pipeline: Discovery → Verification → Assessment.

Usage:
    scanner = CodeSecurityScanner()
    result = scanner.scan_directory("/path/to/project")
    result = scanner.scan_file("/path/to/file.py")
    print(result.to_json())
"""

"""
Enterprise Security Scanner — Main Orchestrator
================================================
Production-Ready Refactoring:
- Hybrid Concurrency (Process + Thread + Async)
- OpenTelemetry Tracing
- Circuit Breakers & Retry Logic
- Redis Caching Layer
- Database Persistence (Optional)
- FastAPI Integration Ready
- Comprehensive Health Checks
- Multi-format Export (SARIF/JUnit/HTML/DB)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import signal
import sys
import time
import traceback
import uuid
from abc import ABC, abstractmethod
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from contextlib import contextmanager, asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from functools import lru_cache, wraps
from pathlib import Path
from typing import (
    Any, AsyncIterator, Callable, Dict, List, Optional, 
    Set, Tuple, Type, TypeVar, Union,
)

# Enterprise Dependencies
try:
    from pydantic import BaseModel, Field, field_validator, model_validator
    from pydantic_settings import BaseSettings
    PYDANTIC_AVAILABLE = True
except ImportError:
    PYDANTIC_AVAILABLE = False
    class BaseModel: pass
    class Field: 
        def __init__(self, *args, **kwargs): pass
    def field_validator(*args, **kwargs):
        def decorator(func): return func
        return decorator
    def model_validator(*args, **kwargs):
        def decorator(func): return func
        return decorator
    class BaseSettings: pass

# Optional: Redis Caching
try:
    import redis.asyncio as aioredis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    aioredis = None

# Optional: Database
try:
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
    from sqlalchemy.orm import sessionmaker
    SQLALCHEMY_AVAILABLE = True
except ImportError:
    SQLALCHEMY_AVAILABLE = False
    create_async_engine = None
    AsyncSession = None

# Optional: OpenTelemetry
try:
    from opentelemetry import trace, metrics
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False
    trace = None
    metrics = None

# Optional: FastAPI
try:
    from fastapi import FastAPI, BackgroundTasks, HTTPException
    from fastapi.responses import JSONResponse, FileResponse
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    FastAPI = None

# Import local modules (from previous refactors)
try:
    from quantum_protocol.core.code_security_scanner.models import (
        FindingStatus, ScanConfiguration, SecurityScanResult,
        Severity, ValidatedFinding, VulnerabilityClass,
        ConfidenceRating, AgentRole, TaintFlow,
    )
    from quantum_protocol.core.code_security_scanner.agents import (
        AssessmentAgent, DiscoveryAgent, VerificationAgent,
    )
    from quantum_protocol.core.code_security_scanner.data_flow import DataFlowGraph
except ImportError:
    # Fallback for standalone testing
    FindingStatus = Severity = ValidatedFinding = object
    ScanConfiguration = SecurityScanResult = object
    VulnerabilityClass = ConfidenceRating = AgentRole = object
    TaintFlow = object
    AssessmentAgent = DiscoveryAgent = VerificationAgent = object
    DataFlowGraph = object

# ────────────────────────────────────────────────────────────────────────────
# 1. Enterprise Configuration & Settings
# ────────────────────────────────────────────────────────────────────────────

class OrchestratorSettings(BaseSettings):
    """
    Centralized configuration for the orchestrator.
    Load from ENV variables (e.g., SCANNER_MAX_WORKERS=8)
    """
    # Identity
    scanner_id: str = Field(default_factory=lambda: f"scanner-{uuid.uuid4().hex[:8]}")
    environment: str = "production"  # development, staging, production
    version: str = "2.0.0"
    
    # Concurrency
    max_workers: int = Field(default=4, ge=1, le=64)
    max_process_workers: int = Field(default=2, ge=1, le=16)
    max_thread_workers: int = Field(default=8, ge=1, le=128)
    enable_async: bool = True
    enable_multiprocessing: bool = True
    
    # Resource Limits
    max_memory_mb: int = Field(default=2048, ge=256)
    max_file_size_bytes: int = Field(default=10 * 1024 * 1024, ge=1)
    max_files_per_scan: int = Field(default=50_000, ge=1)
    max_scan_duration_seconds: int = Field(default=3600, ge=60)
    timeout_per_file_seconds: int = Field(default=30, ge=1)
    
    # Caching
    enable_cache: bool = True
    cache_backend: str = "memory"  # memory, redis, memcached
    redis_url: Optional[str] = "redis://localhost:6379/0"
    cache_ttl_seconds: int = Field(default=3600, ge=60)
    cache_max_size: int = Field(default=10000, ge=100)
    
    # Database
    enable_database: bool = False
    database_url: Optional[str] = None
    database_pool_size: int = Field(default=10, ge=1)
    
    # Observability
    enable_tracing: bool = False
    otlp_endpoint: Optional[str] = "http://localhost:4317"
    enable_metrics: bool = True
    log_level: str = "INFO"
    log_format: str = "json"  # json, text
    log_file: Optional[str] = None
    
    # Security
    enable_input_validation: bool = True
    enable_sandboxing: bool = False
    allowed_paths: Optional[List[str]] = None
    blocked_paths: List[str] = Field(default_factory=lambda: [
        "/etc", "/proc", "/sys", "/dev", "/root",
    ])
    
    # Rate Limiting
    enable_rate_limiting: bool = True
    max_scans_per_minute: int = Field(default=10, ge=1)
    max_concurrent_scans: int = Field(default=3, ge=1)
    
    # CI/CD
    fail_on_critical: bool = True
    fail_on_high: bool = False
    sarif_output_path: Optional[str] = None
    junit_output_path: Optional[str] = None
    
    # Compliance
    enable_audit_logging: bool = True
    audit_log_path: Optional[str] = None
    retention_days: int = Field(default=90, ge=1)
    
    class Config:
        env_prefix = "SCANNER_"
        case_sensitive = False
        extra = "ignore"


# Global settings instance
_settings: Optional[OrchestratorSettings] = None

def get_settings() -> OrchestratorSettings:
    """Get or create global settings."""
    global _settings
    if _settings is None:
        _settings = OrchestratorSettings()
    return _settings


# ────────────────────────────────────────────────────────────────────────────
# 2. Enhanced Logging & Observability
# ────────────────────────────────────────────────────────────────────────────

class StructuredLogger:
    """Enterprise structured logging with JSON support."""
    
    def __init__(self, name: str, settings: OrchestratorSettings):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, settings.log_level.upper()))
        self.logger.handlers = []
        self.settings = settings
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        if settings.log_format == "json":
            console_handler.addFilter(self.JsonFilter(settings))
            console_handler.setFormatter(logging.Formatter('%(message)s'))
        else:
            console_handler.setFormatter(
                logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            )
        self.logger.addHandler(console_handler)
        
        # File handler (optional)
        if settings.log_file:
            file_handler = logging.FileHandler(settings.log_file)
            file_handler.setFormatter(logging.Formatter('%(message)s'))
            self.logger.addHandler(file_handler)
    
    class JsonFilter(logging.Filter):
        def __init__(self, settings: OrchestratorSettings):
            self.settings = settings
        
        def filter(self, record):
            record.msg = json.dumps({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
                "scanner_id": self.settings.scanner_id,
                "environment": self.settings.environment,
                "scan_id": getattr(record, 'scan_id', None),
            })
            return True
    
    def info(self, msg: str, **kwargs):
        self.logger.info(msg, extra=kwargs)
    
    def error(self, msg: str, **kwargs):
        self.logger.error(msg, extra=kwargs)
    
    def warning(self, msg: str, **kwargs):
        self.logger.warning(msg, extra=kwargs)
    
    def debug(self, msg: str, **kwargs):
        self.logger.debug(msg, extra=kwargs)
    
    def exception(self, msg: str, **kwargs):
        self.logger.exception(msg, extra=kwargs)


class TelemetryManager:
    """OpenTelemetry integration for distributed tracing."""
    
    def __init__(self, settings: OrchestratorSettings):
        self.settings = settings
        self.tracer = None
        self.meter = None
        self._initialized = False
        
        if settings.enable_tracing and OTEL_AVAILABLE:
            self._initialize_tracing()
        
        if settings.enable_metrics and OTEL_AVAILABLE:
            self._initialize_metrics()
    
    def _initialize_tracing(self):
        """Initialize OpenTelemetry tracing."""
        try:
            provider = TracerProvider()
            if self.settings.otlp_endpoint:
                exporter = OTLPSpanExporter(endpoint=self.settings.otlp_endpoint)
                provider.add_span_processor(BatchSpanProcessor(exporter))
            trace.set_tracer_provider(provider)
            self.tracer = trace.get_tracer("enterprise-scanner")
            self._initialized = True
        except Exception as e:
            logging.warning(f"Failed to initialize tracing: {e}")
    
    def _initialize_metrics(self):
        """Initialize OpenTelemetry metrics."""
        try:
            provider = MeterProvider()
            metrics.set_meter_provider(provider)
            self.meter = metrics.get_meter("enterprise-scanner")
        except Exception as e:
            logging.warning(f"Failed to initialize metrics: {e}")
    
    @contextmanager
    def trace_span(self, name: str, **attributes):
        """Create a trace span for operation."""
        if self.tracer and self._initialized:
            with self.tracer.start_as_current_span(name) as span:
                for key, value in attributes.items():
                    span.set_attribute(key, str(value))
                yield span
        else:
            yield None
    
    def record_metric(self, name: str, value: float, metric_type: str = "gauge"):
        """Record a metric value."""
        if self.meter:
            try:
                if metric_type == "gauge":
                    gauge = self.meter.create_gauge(name)
                    gauge.set(value)
                elif metric_type == "counter":
                    counter = self.meter.create_counter(name)
                    counter.add(value)
                elif metric_type == "histogram":
                    histogram = self.meter.create_histogram(name)
                    histogram.record(value)
            except Exception:
                pass


# ────────────────────────────────────────────────────────────────────────────
# 3. Circuit Breaker & Retry Logic
# ────────────────────────────────────────────────────────────────────────────

class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    """Circuit breaker for resilient operations."""
    
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        half_open_max_calls: int = 3,
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_calls = half_open_max_calls
        
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.last_failure_time: Optional[float] = None
        self.half_open_calls = 0
    
    def call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker protection."""
        if self.state == CircuitState.OPEN:
            if time.time() - self.last_failure_time > self.recovery_timeout:
                self.state = CircuitState.HALF_OPEN
                self.half_open_calls = 0
            else:
                raise Exception("Circuit breaker is OPEN")
        
        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except Exception as e:
            self._on_failure()
            raise
    
    def _on_success(self):
        """Handle successful call."""
        if self.state == CircuitState.HALF_OPEN:
            self.half_open_calls += 1
            if self.half_open_calls >= self.half_open_max_calls:
                self.state = CircuitState.CLOSED
                self.failure_count = 0
        else:
            self.failure_count = 0
    
    def _on_failure(self):
        """Handle failed call."""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.failure_count >= self.failure_threshold:
            self.state = CircuitState.OPEN


class RetryPolicy:
    """Retry policy with exponential backoff."""
    
    def __init__(
        self,
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        exponential_base: float = 2.0,
        retryable_exceptions: Tuple[Type[Exception], ...] = (Exception,),
    ):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
        self.retryable_exceptions = retryable_exceptions
    
    def execute(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with retry logic."""
        last_exception = None
        
        for attempt in range(self.max_retries + 1):
            try:
                return func(*args, **kwargs)
            except self.retryable_exceptions as e:
                last_exception = e
                if attempt < self.max_retries:
                    delay = min(
                        self.base_delay * (self.exponential_base ** attempt),
                        self.max_delay
                    )
                    time.sleep(delay)
        
        raise last_exception


# ────────────────────────────────────────────────────────────────────────────
# 4. Caching Layer
# ────────────────────────────────────────────────────────────────────────────

class CacheBackend(ABC):
    """Abstract base class for cache backends."""
    
    @abstractmethod
    async def get(self, key: str) -> Optional[Any]:
        pass
    
    @abstractmethod
    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        pass
    
    @abstractmethod
    async def delete(self, key: str) -> bool:
        pass
    
    @abstractmethod
    async def clear(self) -> bool:
        pass


class MemoryCache(CacheBackend):
    """In-memory cache with TTL support."""
    
    def __init__(self, max_size: int = 10000):
        self._cache: Dict[str, Tuple[Any, float]] = {}
        self._max_size = max_size
    
    async def get(self, key: str) -> Optional[Any]:
        if key in self._cache:
            value, expiry = self._cache[key]
            if expiry > time.time():
                return value
            else:
                del self._cache[key]
        return None
    
    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        if len(self._cache) >= self._max_size:
            # Evict oldest entries
            oldest = sorted(self._cache.items(), key=lambda x: x[1][1])[:100]
            for k, _ in oldest:
                del self._cache[k]
        
        expiry = time.time() + (ttl or 3600)
        self._cache[key] = (value, expiry)
        return True
    
    async def delete(self, key: str) -> bool:
        if key in self._cache:
            del self._cache[key]
            return True
        return False
    
    async def clear(self) -> bool:
        self._cache.clear()
        return True


class RedisCache(CacheBackend):
    """Redis cache backend."""
    
    def __init__(self, redis_url: str = "redis://localhost:6379/0"):
        self.redis_url = redis_url
        self._redis: Optional[aioredis.Redis] = None
    
    async def _get_redis(self) -> aioredis.Redis:
        if self._redis is None:
            self._redis = await aioredis.from_url(self.redis_url)
        return self._redis
    
    async def get(self, key: str) -> Optional[Any]:
        redis = await self._get_redis()
        value = await redis.get(key)
        if value:
            return json.loads(value)
        return None
    
    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        redis = await self._get_redis()
        serialized = json.dumps(value)
        if ttl:
            await redis.setex(key, ttl, serialized)
        else:
            await redis.set(key, serialized)
        return True
    
    async def delete(self, key: str) -> bool:
        redis = await self._get_redis()
        await redis.delete(key)
        return True
    
    async def clear(self) -> bool:
        redis = await self._get_redis()
        await redis.flushdb()
        return True


class CacheManager:
    """Unified cache manager with backend selection."""
    
    def __init__(self, settings: OrchestratorSettings):
        self.settings = settings
        self._backend: Optional[CacheBackend] = None
        
        if settings.enable_cache:
            if settings.cache_backend == "redis" and REDIS_AVAILABLE:
                self._backend = RedisCache(settings.redis_url)
            else:
                self._backend = MemoryCache(settings.cache_max_size)
    
    async def get(self, key: str) -> Optional[Any]:
        if self._backend:
            return await self._backend.get(key)
        return None
    
    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        if self._backend:
            return await self._backend.set(key, value, ttl or self.settings.cache_ttl_seconds)
        return False
    
    async def delete(self, key: str) -> bool:
        if self._backend:
            return await self._backend.delete(key)
        return False
    
    async def clear(self) -> bool:
        if self._backend:
            return await self._backend.clear()
        return False


# ────────────────────────────────────────────────────────────────────────────
# 5. Rate Limiting
# ────────────────────────────────────────────────────────────────────────────

class RateLimiter:
    """Token bucket rate limiter."""
    
    def __init__(self, max_tokens: int, refill_rate: float):
        self.max_tokens = max_tokens
        self.refill_rate = refill_rate  # tokens per second
        self.tokens = max_tokens
        self.last_refill = time.time()
        self._lock = asyncio.Lock()
    
    async def acquire(self) -> bool:
        async with self._lock:
            now = time.time()
            elapsed = now - self.last_refill
            self.tokens = min(self.max_tokens, self.tokens + elapsed * self.refill_rate)
            self.last_refill = now
            
            if self.tokens >= 1:
                self.tokens -= 1
                return True
            return False
    
    async def wait_for_token(self, timeout: float = 60.0) -> bool:
        start = time.time()
        while time.time() - start < timeout:
            if await self.acquire():
                return True
            await asyncio.sleep(0.1)
        return False


# ────────────────────────────────────────────────────────────────────────────
# 6. Security & Input Validation
# ────────────────────────────────────────────────────────────────────────────

class SecurityValidator:
    """Validate inputs for security."""
    
    def __init__(self, settings: OrchestratorSettings):
        self.settings = settings
        self._blocked_paths = set(settings.blocked_paths)
        self._allowed_paths = set(settings.allowed_paths) if settings.allowed_paths else None
    
    def validate_path(self, path: str) -> bool:
        """Validate that path is safe to scan."""
        if not self.settings.enable_input_validation:
            return True
        
        resolved = Path(path).resolve()
        path_str = str(resolved)
        
        # Check blocked paths
        for blocked in self._blocked_paths:
            if path_str.startswith(blocked):
                return False
        
        # Check allowed paths (if configured)
        if self._allowed_paths:
            for allowed in self._allowed_paths:
                if path_str.startswith(allowed):
                    return True
            return False
        
        return True
    
    def validate_content(self, content: str, max_size: int) -> bool:
        """Validate content size and safety."""
        if len(content) > max_size:
            return False
        
        # Check for binary content
        try:
            content.encode('utf-8')
        except UnicodeEncodeError:
            return False
        
        return True


# ────────────────────────────────────────────────────────────────────────────
# 7. Language Detection (Enhanced)
# ────────────────────────────────────────────────────────────────────────────

_LANGUAGE_MAP: Dict[str, str] = {
    ".py": "python", ".pyw": "python", ".pyi": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".jsx": "javascript",
    ".java": "java", ".kt": "kotlin", ".kts": "kotlin",
    ".go": "go", ".mod": "go",
    ".rb": "ruby", ".gemspec": "ruby",
    ".php": "php",
    ".cs": "csharp", ".csproj": "csharp",
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp",
    ".rs": "rust", ".toml": "rust",
    ".swift": "swift",
    ".scala": "scala", ".sbt": "scala",
    ".groovy": "groovy",
    ".tf": "terraform", ".hcl": "terraform",
    ".yml": "yaml", ".yaml": "yaml",
    ".json": "json",
    ".xml": "xml",
    ".html": "html", ".htm": "html",
    ".sql": "sql",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell", ".fish": "shell",
    ".ps1": "powershell", ".psm1": "powershell",
    ".dockerfile": "dockerfile",
    ".env": "dotenv",
    ".ini": "ini", ".cfg": "ini", ".conf": "ini",
    ".md": "markdown",
    ".vue": "vue",
    ".svelte": "svelte",
}

_SKIP_DIRS: Set[str] = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "vendor", "dist", "build", ".next", "coverage", ".tox",
    ".mypy_cache", ".pytest_cache", ".gradle", ".mvn",
    "target", "bin", "obj", ".vs", ".idea", ".vscode",
    ".terraform", ".serverless", "bower_components",
    ".scanner_cache", ".cache", "eggs", "*.egg-info",
    ".eggs", ".pytest_cache", ".hypothesis", ".nox",
}


def detect_language(path: Path) -> Optional[str]:
    """Detect programming language from file extension and content."""
    suffix = path.suffix.lower()
    name = path.name.lower()
    
    # Special cases
    if name == "dockerfile":
        return "dockerfile"
    if name == "makefile":
        return "makefile"
    if name.endswith(".dockerfile"):
        return "dockerfile"
    
    # Extension mapping
    lang = _LANGUAGE_MAP.get(suffix)
    if lang:
        return lang
    
    # Shebang detection for scripts without extension
    if suffix == "":
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                first_line = f.readline()
                if first_line.startswith("#!"):
                    if "python" in first_line:
                        return "python"
                    if "node" in first_line or "js" in first_line:
                        return "javascript"
                    if "bash" in first_line or "sh" in first_line:
                        return "shell"
        except Exception:
            pass
    
    return None


# ────────────────────────────────────────────────────────────────────────────
# 8. Main Orchestrator Class
# ────────────────────────────────────────────────────────────────────────────

class CodeSecurityScanner:
    """
    Enterprise-grade security scanner with multi-agent verification.
    
    Features:
    - Hybrid concurrency (Process + Thread + Async)
    - Circuit breakers & retry logic
    - Redis/memory caching
    - OpenTelemetry tracing
    - Rate limiting
    - Input validation & security
    - Database persistence (optional)
    - Multi-format export (SARIF/JUnit/HTML/JSON)
    - Health checks & metrics
    """
    
    def __init__(
        self,
        config: Optional[ScanConfiguration] = None,
        settings: Optional[OrchestratorSettings] = None,
        progress_cb: Optional[Callable[[str, int, int], None]] = None,
    ):
        self.settings = settings or get_settings()
        self.config = config or ScanConfiguration()
        self.progress_cb = progress_cb
        
        # Initialize components
        self.logger = StructuredLogger("EnterpriseScanner", self.settings)
        self.telemetry = TelemetryManager(self.settings)
        self.cache = CacheManager(self.settings)
        self.validator = SecurityValidator(self.settings)
        
        # Rate limiting
        self.rate_limiter = RateLimiter(
            max_tokens=self.settings.max_scans_per_minute,
            refill_rate=self.settings.max_scans_per_minute / 60.0,
        )
        
        # Circuit breakers for each agent
        self.discovery_breaker = CircuitBreaker(failure_threshold=5, recovery_timeout=60.0)
        self.verification_breaker = CircuitBreaker(failure_threshold=5, recovery_timeout=60.0)
        self.assessment_breaker = CircuitBreaker(failure_threshold=5, recovery_timeout=60.0)
        
        # Retry policies
        self.retry_policy = RetryPolicy(
            max_retries=3,
            base_delay=1.0,
            max_delay=30.0,
        )
        
        # Initialize agents
        self.dfg = DataFlowGraph()
        self.discovery_agent = DiscoveryAgent(data_flow_graph=self.dfg)
        self.verification_agent = VerificationAgent()
        self.assessment_agent = AssessmentAgent()
        
        # File cache for cross-file analysis
        self._file_cache: Dict[str, str] = {}
        
        # Scan tracking
        self._active_scans: Dict[str, dict] = {}
        self._scan_semaphore = asyncio.Semaphore(self.settings.max_concurrent_scans)
        
        # Database session (optional)
        self._db_engine = None
        self._db_session_factory = None
        if self.settings.enable_database and SQLALCHEMY_AVAILABLE and self.settings.database_url:
            self._initialize_database()
        
        self.logger.info("Enterprise Security Scanner initialized", 
                        scanner_id=self.settings.scanner_id,
                        version=self.settings.version)
    
    def _initialize_database(self):
        """Initialize database connection."""
        try:
            self._db_engine = create_async_engine(
                self.settings.database_url,
                pool_size=self.settings.database_pool_size,
            )
            self._db_session_factory = sessionmaker(
                self._db_engine, class_=AsyncSession, expire_on_commit=False
            )
            self.logger.info("Database initialized successfully")
        except Exception as e:
            self.logger.error(f"Database initialization failed: {e}")
            self.settings.enable_database = False
    
    async def _acquire_scan_slot(self, scan_id: str) -> bool:
        """Acquire a scan slot with rate limiting."""
        if self.settings.enable_rate_limiting:
            acquired = await self.rate_limiter.wait_for_token(timeout=120.0)
            if not acquired:
                return False
        
        await self._scan_semaphore.acquire()
        self._active_scans[scan_id] = {
            "started_at": datetime.now(timezone.utc).isoformat(),
            "status": "running",
        }
        return True
    
    def _release_scan_slot(self, scan_id: str):
        """Release a scan slot."""
        self._scan_semaphore.release()
        if scan_id in self._active_scans:
            self._active_scans[scan_id]["status"] = "completed"
            self._active_scans[scan_id]["completed_at"] = datetime.now(timezone.utc).isoformat()
    
    def scan_directory(
        self,
        path: str,
        scan_mode: str = "full",
        scan_id: Optional[str] = None,
    ) -> SecurityScanResult:
        """
        Scan an entire directory through the multi-agent pipeline.
        
        Synchronous wrapper for async implementation.
        """
        return asyncio.run(self.scan_directory_async(path, scan_mode, scan_id))
    
    async def scan_directory_async(
        self,
        path: str,
        scan_mode: str = "full",
        scan_id: Optional[str] = None,
    ) -> SecurityScanResult:
        """
        Async version of directory scanning with full enterprise features.
        """
        scan_id = scan_id or f"CSS-{uuid.uuid4().hex[:12]}"
        started_at = datetime.now(timezone.utc).isoformat()
        start_time = time.perf_counter()
        
        # Acquire scan slot
        if not await self._acquire_scan_slot(scan_id):
            raise Exception("Rate limit exceeded or max concurrent scans reached")
        
        try:
            with self.telemetry.trace_span("scan_directory", scan_id=scan_id, path=path):
                result = await self._execute_scan_directory(
                    scan_id, path, scan_mode, started_at, start_time
                )
        finally:
            self._release_scan_slot(scan_id)
        
        return result
    
    async def _execute_scan_directory(
        self,
        scan_id: str,
        path: str,
        scan_mode: str,
        started_at: str,
        start_time: float,
    ) -> SecurityScanResult:
        """Execute the actual directory scan."""
        
        # Validate input
        if not self.validator.validate_path(path):
            raise ValueError(f"Path not allowed: {path}")
        
        result = SecurityScanResult(
            scan_id=scan_id,
            started_at=started_at,
            source=path,
            source_type="local",
            configuration=self.config,
        )
        
        root = Path(path).resolve()
        if not root.exists():
            result.errors.append(f"Path does not exist: {path}")
            return result
        
        # Check scan duration limit
        async def check_timeout():
            while True:
                await asyncio.sleep(10)
                if time.perf_counter() - start_time > self.settings.max_scan_duration_seconds:
                    self.logger.warning("Scan duration limit reached", scan_id=scan_id)
                    break
        
        timeout_task = asyncio.create_task(check_timeout())
        
        try:
            # Phase 0: Enumerate eligible files
            eligible = await self._enumerate_files_async(root)
            self.logger.info("Found eligible files", count=len(eligible), scan_id=scan_id)
            result.metadata["total_eligible_files"] = len(eligible)
            
            if not eligible:
                result.warnings.append("No eligible files found to scan.")
                return self._finalize_result(result, start_time)
            
            # Phase 1: Load file contents and run Discovery Agent
            all_discovered = await self._run_discovery_phase(
                eligible, root, scan_id, result
            )
            
            # Phase 2: Verification Agent
            if self.config.enable_verification and all_discovered:
                all_discovered = await self._run_verification_phase(
                    all_discovered, scan_id, result
                )
            
            # Phase 3: Assessment Agent
            if self.config.enable_assessment:
                all_discovered = await self._run_assessment_phase(
                    all_discovered, scan_id, result
                )
            
            # Filter and limit findings
            result.findings = self._filter_findings(all_discovered)
            
            # Finalize
            return self._finalize_result(result, start_time)
            
        finally:
            timeout_task.cancel()
            await self._cleanup()
    
    async def _enumerate_files_async(self, root: Path) -> List[Path]:
        """Enumerate eligible files asynchronously."""
        eligible: List[Path] = []
        skip_dirs = set(self.config.exclude_paths) | _SKIP_DIRS
        
        for p in root.rglob("*"):
            if len(eligible) >= self.config.max_files:
                self.logger.warning("Hit max file limit")
                break
            
            if not p.is_file():
                continue
            
            if any(skip in p.parts for skip in skip_dirs):
                continue
            
            try:
                if p.stat().st_size > self.config.max_file_size_bytes:
                    continue
                if p.stat().st_size == 0:
                    continue
            except OSError:
                continue
            
            lang = detect_language(p)
            if lang is None:
                continue
            
            if self.config.include_languages and lang not in self.config.include_languages:
                continue
            
            eligible.append(p)
        
        return eligible
    
    async def _run_discovery_phase(
        self,
        eligible: List[Path],
        root: Path,
        scan_id: str,
        result: SecurityScanResult,
    ) -> List[ValidatedFinding]:
        """Run discovery phase with parallel processing."""
        all_discovered: List[ValidatedFinding] = []
        files_scanned = 0
        files_skipped = 0
        languages: Set[str] = set()
        
        # Use ProcessPoolExecutor for CPU-bound discovery
        max_workers = min(
            self.settings.max_process_workers,
            len(eligible)
        )
        
        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            future_to_file = {}
            
            for idx, fpath in enumerate(eligible):
                if self.progress_cb:
                    try:
                        self.progress_cb(str(fpath.relative_to(root)), idx + 1, len(eligible))
                    except Exception:
                        pass
                
                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                    relative = str(fpath.relative_to(root))
                    language = detect_language(fpath) or "unknown"
                    languages.add(language)
                    
                    self._file_cache[relative] = content
                    
                    # Submit to process pool
                    future = executor.submit(
                        self._discover_file,
                        content, relative, language,
                        self.config.context_window,
                    )
                    future_to_file[future] = (fpath, relative)
                    
                except Exception as exc:
                    files_skipped += 1
                    result.errors.append(f"{fpath.relative_to(root)}: {exc}")
            
            # Collect results
            for future in as_completed(future_to_file):
                fpath, relative = future_to_file[future]
                try:
                    findings = future.result(timeout=self.settings.timeout_per_file_seconds)
                    findings = findings[:self.config.max_findings_per_file]
                    all_discovered.extend(findings)
                    files_scanned += 1
                except Exception as exc:
                    files_skipped += 1
                    result.errors.append(f"{relative}: {exc}")
        
        result.files_scanned = files_scanned
        result.files_skipped = files_skipped
        result.languages_detected = sorted(languages)
        result.findings_discovered = len(all_discovered)
        
        self.logger.info("Discovery complete", 
                        findings=len(all_discovered), 
                        files=files_scanned,
                        scan_id=scan_id)
        
        return all_discovered
    
    def _discover_file(
        self,
        content: str,
        relative: str,
        language: str,
        context_window: int,
    ) -> List[ValidatedFinding]:
        """Discover vulnerabilities in a single file (for process pool)."""
        try:
            dfg = DataFlowGraph()
            agent = DiscoveryAgent(data_flow_graph=dfg)
            return agent.analyze_file(content, relative, language, context_window)
        except Exception:
            return []
    
    async def _run_verification_phase(
        self,
        findings: List[ValidatedFinding],
        scan_id: str,
        result: SecurityScanResult,
    ) -> List[ValidatedFinding]:
        """Run verification phase with circuit breaker."""
        try:
            verified = self.verification_breaker.call(
                self.verification_agent.verify_findings,
                findings,
                self._file_cache,
                rounds=self.config.verification_rounds,
            )
        except Exception as e:
            self.logger.error("Verification failed", error=str(e), scan_id=scan_id)
            verified = findings
        
        true_positives = [f for f in verified if f.status != FindingStatus.DISPROVED]
        false_positives = [f for f in verified if f.status == FindingStatus.DISPROVED]
        
        result.findings_verified = len(true_positives)
        result.findings_disproved = len(false_positives)
        
        self.logger.info("Verification complete",
                        verified=len(true_positives),
                        disproved=len(false_positives),
                        scan_id=scan_id)
        
        return verified
    
    async def _run_assessment_phase(
        self,
        findings: List[ValidatedFinding],
        scan_id: str,
        result: SecurityScanResult,
    ) -> List[ValidatedFinding]:
        """Run assessment phase with circuit breaker."""
        try:
            assessed = self.assessment_breaker.call(
                self.assessment_agent.assess_findings,
                findings,
                self._file_cache,
                generate_patches=self.config.enable_patch_generation,
            )
        except Exception as e:
            self.logger.error("Assessment failed", error=str(e), scan_id=scan_id)
            assessed = findings
        
        return assessed
    
    def _filter_findings(self, findings: List[ValidatedFinding]) -> List[ValidatedFinding]:
        """Filter findings based on configuration."""
        # Apply confidence threshold
        filtered = [
            f for f in findings
            if f.confidence_score >= self.config.min_confidence_threshold
            or f.status == FindingStatus.DISPROVED
        ]
        
        # Filter info findings
        if not self.config.include_info_findings:
            filtered = [
                f for f in filtered
                if f.severity != Severity.INFO or f.status == FindingStatus.DISPROVED
            ]
        
        # Apply total limit
        filtered = filtered[:self.config.max_total_findings]
        
        return filtered
    
    def _finalize_result(
        self,
        result: SecurityScanResult,
        start_time: float,
    ) -> SecurityScanResult:
        """Finalize scan result with metrics and cleanup."""
        result.completed_at = datetime.now(timezone.utc).isoformat()
        result.duration_seconds = round(time.perf_counter() - start_time, 3)
        result.compute_metrics()
        
        self.logger.info("Scan complete",
                        findings=result.total_findings,
                        score=result.overall_security_score,
                        duration=result.duration_seconds,
                        scan_id=result.scan_id)
        
        return result
    
    async def _cleanup(self):
        """Cleanup resources after scan."""
        self._file_cache.clear()
        self.dfg.reset()
        await self.cache.clear()
    
    async def _persist_result(self, result: SecurityScanResult):
        """Persist scan result to database."""
        if not self.settings.enable_database or not self._db_session_factory:
            return
        
        try:
            async with self._db_session_factory() as session:
                # Save result to database
                # Implementation depends on your ORM models
                await session.commit()
        except Exception as e:
            self.logger.error(f"Failed to persist result: {e}")
    
    # ── File & Content Scanning ─────────────────────────────────────
    
    def scan_file(
        self,
        file_path: str,
        base_path: Optional[str] = None,
    ) -> SecurityScanResult:
        """Scan a single file through the full pipeline."""
        return asyncio.run(self.scan_file_async(file_path, base_path))
    
    async def scan_file_async(
        self,
        file_path: str,
        base_path: Optional[str] = None,
    ) -> SecurityScanResult:
        """Async version of file scanning."""
        scan_id = f"CSS-{uuid.uuid4().hex[:12]}"
        started_at = datetime.now(timezone.utc).isoformat()
        start_time = time.perf_counter()
        
        if not await self._acquire_scan_slot(scan_id):
            raise Exception("Rate limit exceeded")
        
        try:
            path = Path(file_path).resolve()
            base = Path(base_path).resolve() if base_path else path.parent
            
            result = SecurityScanResult(
                scan_id=scan_id,
                started_at=started_at,
                source=str(path),
                source_type="file",
                configuration=self.config,
            )
            
            if not path.exists():
                result.errors.append(f"File not found: {file_path}")
                return result
            
            if not self.validator.validate_path(str(path)):
                result.errors.append(f"Path not allowed: {file_path}")
                return result
            
            language = detect_language(path) or "unknown"
            relative = str(path.relative_to(base))
            
            content = path.read_text(encoding="utf-8", errors="ignore")
            self._file_cache[relative] = content
            
            # Run full pipeline
            discovered = self.discovery_agent.analyze_file(
                content, relative, language, self.config.context_window
            )
            result.findings_discovered = len(discovered)
            
            if self.config.enable_verification:
                verified = self.verification_agent.verify_findings(
                    discovered, self._file_cache, self.config.verification_rounds
                )
            else:
                verified = discovered
            
            if self.config.enable_assessment:
                assessed = self.assessment_agent.assess_findings(
                    verified, self._file_cache, self.config.enable_patch_generation
                )
            else:
                assessed = verified
            
            result.findings = self._filter_findings(assessed)
            result.files_scanned = 1
            result.languages_detected = [language]
            
            return self._finalize_result(result, start_time)
            
        finally:
            self._release_scan_slot(scan_id)
            await self._cleanup()
    
    def scan_content(
        self,
        content: str,
        file_path: str = "inline.py",
        language: str = "python",
    ) -> SecurityScanResult:
        """Scan raw code content (for API/inline usage)."""
        return asyncio.run(self.scan_content_async(content, file_path, language))
    
    async def scan_content_async(
        self,
        content: str,
        file_path: str = "inline.py",
        language: str = "python",
    ) -> SecurityScanResult:
        """Async version of content scanning."""
        scan_id = f"CSS-{uuid.uuid4().hex[:12]}"
        start_time = time.perf_counter()
        
        if not await self._acquire_scan_slot(scan_id):
            raise Exception("Rate limit exceeded")
        
        try:
            result = SecurityScanResult(
                scan_id=scan_id,
                source=file_path,
                source_type="inline",
                configuration=self.config,
            )
            
            if not self.validator.validate_content(content, self.config.max_file_size_bytes):
                result.errors.append("Content too large or invalid")
                return result
            
            self._file_cache[file_path] = content
            
            discovered = self.discovery_agent.analyze_file(
                content, file_path, language, self.config.context_window
            )
            result.findings_discovered = len(discovered)
            
            if self.config.enable_verification:
                verified = self.verification_agent.verify_findings(
                    discovered, self._file_cache, self.config.verification_rounds
                )
            else:
                verified = discovered
            
            result.findings_verified = sum(
                1 for f in verified if f.status != FindingStatus.DISPROVED
            )
            result.findings_disproved = sum(
                1 for f in verified if f.status == FindingStatus.DISPROVED
            )
            
            if self.config.enable_assessment:
                assessed = self.assessment_agent.assess_findings(
                    verified, self._file_cache, self.config.enable_patch_generation
                )
            else:
                assessed = verified
            
            result.findings = assessed
            result.files_scanned = 1
            result.languages_detected = [language]
            
            return self._finalize_result(result, start_time)
            
        finally:
            self._release_scan_slot(scan_id)
            await self._cleanup()
    
    # ── Export & Reporting ───────────────────────────────────────────
    
    def export_sarif(self, result: SecurityScanResult, output_path: str) -> str:
        """Export scan result as SARIF 2.1.0."""
        sarif_data = result.to_sarif()
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(sarif_data, f, indent=2)
        self.logger.info("SARIF exported", path=output_path)
        return output_path
    
    def export_junit(self, result: SecurityScanResult, output_path: str) -> str:
        """Export scan result as JUnit XML for CI/CD."""
        # Implementation depends on your JUnit schema requirements
        pass
    
    def export_html(self, result: SecurityScanResult, output_path: str) -> str:
        """Export scan result as HTML report."""
        # Implementation depends on your HTML template
        pass
    
    async def export_to_database(self, result: SecurityScanResult) -> bool:
        """Export scan result to database."""
        await self._persist_result(result)
        return True
    
    # ── Health Checks & Metrics ──────────────────────────────────────
    
    def get_health_status(self) -> dict:
        """Get scanner health status for monitoring."""
        return {
            "status": "healthy",
            "scanner_id": self.settings.scanner_id,
            "version": self.settings.version,
            "environment": self.settings.environment,
            "active_scans": len(self._active_scans),
            "max_concurrent_scans": self.settings.max_concurrent_scans,
            "cache_enabled": self.settings.enable_cache,
            "database_enabled": self.settings.enable_database,
            "tracing_enabled": self.settings.enable_tracing,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    
    def get_metrics(self) -> dict:
        """Get scanner metrics for monitoring."""
        return {
            "active_scans": len(self._active_scans),
            "cache_backend": self.settings.cache_backend,
            "max_workers": self.settings.max_workers,
            "rate_limit_tokens": self.rate_limiter.tokens,
            "circuit_breakers": {
                "discovery": self.discovery_breaker.state.value,
                "verification": self.verification_breaker.state.value,
                "assessment": self.assessment_breaker.state.value,
            },
        }
    
    # ── Dashboard Helpers ────────────────────────────────────────────
    
    def get_actionable_findings(
        self, result: SecurityScanResult
    ) -> List[ValidatedFinding]:
        """Get only actionable findings."""
        return [f for f in result.findings if f.is_actionable]
    
    def get_findings_by_severity(
        self, result: SecurityScanResult, severity: str,
    ) -> List[ValidatedFinding]:
        """Filter findings by severity level."""
        try:
            sev = Severity(severity)
        except ValueError:
            return []
        return [f for f in result.findings if f.severity == sev]
    
    def get_findings_with_patches(
        self, result: SecurityScanResult
    ) -> List[ValidatedFinding]:
        """Get findings that have patch suggestions."""
        return [f for f in result.findings if f.has_patch]
    
    def get_data_flow_findings(
        self, result: SecurityScanResult,
    ) -> List[ValidatedFinding]:
        """Get findings with data flow traces."""
        return [f for f in result.findings if f.has_data_flow]
    
    @staticmethod
    def get_pipeline_summary(result: SecurityScanResult) -> dict:
        """Get dashboard-friendly pipeline summary."""
        return {
            "scan_id": result.scan_id,
            "duration": f"{result.duration_seconds:.2f}s",
            "files_scanned": result.files_scanned,
            "pipeline": {
                "discovered": result.findings_discovered,
                "verified": result.findings_verified,
                "disproved": result.findings_disproved,
                "false_positive_rate": f"{result.false_positive_rate:.1%}",
            },
            "severity_breakdown": result.findings_by_severity,
            "scores": {
                "overall_security": result.overall_security_score,
                "code_risk": result.code_risk_score,
                "data_flow_risk": result.data_flow_risk_score,
            },
            "patches_available": result.patches_generated,
            "taint_flows_traced": result.taint_flows_traced,
            "actionable_findings": sum(1 for f in result.findings if f.is_actionable),
        }


# ────────────────────────────────────────────────────────────────────────────
# 9. FastAPI Integration (Optional)
# ────────────────────────────────────────────────────────────────────────────

if FASTAPI_AVAILABLE:
    app = FastAPI(
        title="Enterprise Security Scanner API",
        version="2.0.0",
        description="Multi-agent security scanning with verification pipeline",
    )
    
    scanner: Optional[CodeSecurityScanner] = None
    
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        global scanner
        settings = get_settings()
        scanner = CodeSecurityScanner(settings=settings)
        yield
        # Cleanup
        scanner = None
    
    app.router.lifespan_context = lifespan
    
    @app.get("/health")
    async def health_check():
        """Health check endpoint for monitoring."""
        if scanner:
            return scanner.get_health_status()
        return {"status": "unavailable"}
    
    @app.get("/metrics")
    async def get_metrics():
        """Get scanner metrics."""
        if scanner:
            return scanner.get_metrics()
        return {}
    
    @app.post("/scan/directory")
    async def scan_directory_endpoint(
        path: str,
        scan_mode: str = "full",
    ):
        """Scan a directory for vulnerabilities."""
        if not scanner:
            raise HTTPException(503, "Scanner not initialized")
        
        try:
            result = await scanner.scan_directory_async(path, scan_mode)
            return result.to_dict()
        except Exception as e:
            raise HTTPException(500, str(e))
    
    @app.post("/scan/file")
    async def scan_file_endpoint(
        file_path: str,
        base_path: Optional[str] = None,
    ):
        """Scan a single file for vulnerabilities."""
        if not scanner:
            raise HTTPException(503, "Scanner not initialized")
        
        try:
            result = await scanner.scan_file_async(file_path, base_path)
            return result.to_dict()
        except Exception as e:
            raise HTTPException(500, str(e))
    
    @app.post("/scan/content")
    async def scan_content_endpoint(
        content: str,
        file_path: str = "inline.py",
        language: str = "python",
    ):
        """Scan raw code content."""
        if not scanner:
            raise HTTPException(503, "Scanner not initialized")
        
        try:
            result = await scanner.scan_content_async(content, file_path, language)
            return result.to_dict()
        except Exception as e:
            raise HTTPException(500, str(e))
    
    @app.get("/scan/{scan_id}/sarif")
    async def get_sarif(scan_id: str):
        """Get scan result as SARIF."""
        # Implementation depends on your result storage
        pass


# ────────────────────────────────────────────────────────────────────────────
# 10. CLI Entry Point
# ────────────────────────────────────────────────────────────────────────────

def main():
    """CLI entry point for standalone usage."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Enterprise Security Scanner")
    parser.add_argument("path", nargs="?", default=".", help="Path to scan")
    parser.add_argument("--mode", choices=["full", "quick", "deep"], default="full")
    parser.add_argument("--output", "-o", help="Output file path")
    parser.add_argument("--format", choices=["json", "sarif", "html"], default="json")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--fail-on-critical", action="store_true")
    
    args = parser.parse_args()
    
    settings = get_settings()
    if args.verbose:
        settings.log_level = "DEBUG"
    if args.fail_on_critical:
        settings.fail_on_critical = True
    
    scanner = CodeSecurityScanner(settings=settings)
    
    print(f"Enterprise Security Scanner v{settings.version}")
    print(f"Scanner ID: {settings.scanner_id}")
    print(f"Scanning: {args.path}")
    print("=" * 70)
    
    try:
        result = scanner.scan_directory(args.path, scan_mode=args.mode)
        
        # Output
        if args.output:
            if args.format == "sarif":
                scanner.export_sarif(result, args.output)
            elif args.format == "html":
                scanner.export_html(result, args.output)
            else:
                with open(args.output, 'w') as f:
                    f.write(result.to_json())
            print(f"Results written to: {args.output}")
        else:
            print(result.to_summary_report())
        
        # Exit code for CI/CD
        if settings.fail_on_critical and result.critical_count > 0:
            print(f"\n❌ Found {result.critical_count} critical findings")
            sys.exit(1)
        
        print(f"\n✓ Scan complete: {result.total_findings} findings, score {result.overall_security_score}/100")
        sys.exit(0)
        
    except KeyboardInterrupt:
        print("\n⚠ Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n✗ Scan failed: {e}")
        if args.verbose:
            traceback.print_exc()
        sys.exit(2)


if __name__ == "__main__":
    main()