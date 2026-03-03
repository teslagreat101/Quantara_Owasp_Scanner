"""
behavior_analyzer.py — Behavioral Probing Engine
=================================================
Elite-grade detection: observe BEHAVIOR, not just error messages.

Detects:
- Time-based blind SQLi / Command injection / SSRF
- Length-delta based injection confirmation
- Header mutation fingerprinting
- DOM change detection
- Redirect chain variance
- Cache poisoning signals
- Error oracle exploitation

Used by HTTP scanner modules to confirm vulnerabilities without
relying on verbose error messages.
"""

from __future__ import annotations

import asyncio
import re
import statistics
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    # Package import (when used as scanner_engine.behavior_analyzer)
    from .analyzer import (
        AnomalyType, AnalysisVerdict, BlindInjectionAnalyzer,
        DifferentialAnalyzer, HttpSnapshot, shannon_entropy, detect_reflection,
    )
except ImportError:
    # Direct / sys.path import (when run from scanner_engine directory)
    from analyzer import (  # type: ignore[no-redef]
        AnomalyType, AnalysisVerdict, BlindInjectionAnalyzer,
        DifferentialAnalyzer, HttpSnapshot, shannon_entropy, detect_reflection,
    )


# ─────────────────────────────────────────────
# Behavioral signal types
# ─────────────────────────────────────────────
class BehaviorSignal(str, Enum):
    TIMING_BLIND_SQLI = "timing_blind_sqli"
    TIMING_BLIND_CMDI = "timing_blind_cmdi"
    TIMING_BLIND_SSRF = "timing_blind_ssrf"
    LENGTH_ORACLE = "length_oracle"
    BOOLEAN_ORACLE = "boolean_oracle"
    ERROR_ORACLE = "error_oracle"
    REFLECTION_XSS = "reflection_xss"
    HEADER_INJECTION = "header_injection"
    REDIRECT_HIJACK = "redirect_hijack"
    CACHE_POISONING = "cache_poisoning"
    DOM_MANIPULATION = "dom_manipulation"
    CONTENT_TYPE_CONFUSION = "content_type_confusion"


@dataclass
class BehavioralObservation:
    """Raw behavioral data from a probe execution."""
    signal: BehaviorSignal
    confidence: float
    description: str
    timing_ms: float = 0.0
    baseline_timing_ms: float = 0.0
    body_length: int = 0
    baseline_length: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    payload: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    @property
    def timing_delta_ms(self) -> float:
        return self.timing_ms - self.baseline_timing_ms

    @property
    def length_delta(self) -> int:
        return self.body_length - self.baseline_length


@dataclass
class BehaviorProbeResult:
    """Aggregated behavioral probe result for a target parameter."""
    target_url: str = ""
    parameter: str = ""
    observations: List[BehavioralObservation] = field(default_factory=list)
    verdict: AnalysisVerdict = AnalysisVerdict.INCONCLUSIVE
    confidence: float = 0.0
    signals: List[BehaviorSignal] = field(default_factory=list)
    best_payload: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    analysis_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target_url,
            "parameter": self.parameter,
            "verdict": self.verdict.value,
            "confidence": self.confidence,
            "signals": [s.value for s in self.signals],
            "best_payload": self.best_payload,
            "observation_count": len(self.observations),
            "evidence": self.evidence,
            "analysis_ms": self.analysis_ms,
        }


# ─────────────────────────────────────────────
# Timing probe utilities
# ─────────────────────────────────────────────
async def _timed_request(
    fetch_fn: Callable,
    url: str,
    **kwargs,
) -> Tuple[Optional[Any], float]:
    """Execute fetch_fn and return (response, elapsed_ms)."""
    start = time.monotonic()
    try:
        resp = await fetch_fn(url, **kwargs)
        elapsed = (time.monotonic() - start) * 1000
        return resp, elapsed
    except Exception:
        elapsed = (time.monotonic() - start) * 1000
        return None, elapsed


def _stable_baseline(times: List[float], outlier_sigma: float = 2.0) -> float:
    """
    Compute a stable baseline response time excluding outliers.
    Uses mean ± sigma filtering to remove network jitter spikes.
    """
    if not times:
        return 0.0
    if len(times) == 1:
        return times[0]
    mean = statistics.mean(times)
    try:
        stdev = statistics.stdev(times)
    except statistics.StatisticsError:
        return mean
    filtered = [t for t in times if abs(t - mean) <= outlier_sigma * stdev]
    return statistics.mean(filtered) if filtered else mean


# ─────────────────────────────────────────────
# Behavioral Analyzer
# ─────────────────────────────────────────────
class BehaviorAnalyzer:
    """
    Detects vulnerabilities by observing target behavior changes
    rather than parsing error messages.

    Supports:
    - Time-based blind detection (SQLi, CMDI, SSRF)
    - Boolean-based blind detection (length/content oracle)
    - Reflection-based XSS confirmation
    - Header injection fingerprinting
    - Redirect chain analysis
    - Cache behavior analysis
    """

    # ── Time-based detection thresholds
    SLEEP_DELTA_S: float = 3.5           # Minimum time delta to confirm blind injection
    BASELINE_SAMPLES: int = 3            # Requests used to establish baseline
    SLEEP_DELAY_S: float = 5.0           # Sleep payload delay

    # ── Length oracle thresholds
    LENGTH_ORACLE_MIN_DELTA: int = 50    # Minimum byte delta for boolean oracle
    LENGTH_ORACLE_PCT: float = 0.08      # Minimum 8% length change

    # ── Error oracle patterns
    _SQL_ERROR_PATTERNS = [
        re.compile(r"(sql\s+syntax|mysql_fetch|ORA-\d{5}|pg_query|sqlite3\.OperationalError)", re.I),
        re.compile(r"(you have an error in your sql|warning.*\Wmysql_|unclosed quotation mark)", re.I),
        re.compile(r"(SqlException|System\.Data\.SqlClient|microsoft ole db provider)", re.I),
    ]
    _CMDI_ERROR_PATTERNS = [
        re.compile(r"(sh:\s*/[a-z]+:|command not found|permission denied)", re.I),
        re.compile(r"(\broot:x:0:0\b|/etc/passwd|/bin/sh)", re.I),
        re.compile(r"(cannot execute binary file|exec format error)", re.I),
    ]
    _GENERIC_ERROR_PATTERNS = [
        re.compile(r"(exception|traceback|stack trace|at line \d+)", re.I),
        re.compile(r"(fatal error|parse error|syntax error)", re.I),
    ]

    def __init__(self):
        self._blind_analyzer = BlindInjectionAnalyzer()
        self._observations: List[BehavioralObservation] = []

    # ── Public API ───────────────────────────────────────────────
    async def probe_time_blind(
        self,
        fetch_fn: Callable,
        url: str,
        fast_payload: str,
        slow_payload: str,
        parameter: str = "",
        expected_delay_s: float = 5.0,
        baseline_times: Optional[List[float]] = None,
        **request_kwargs,
    ) -> BehavioralObservation:
        """
        Time-based blind injection probe.

        Sends:
        1. fast_payload (e.g., SLEEP(0)) → measure baseline
        2. slow_payload (e.g., SLEEP(5)) → measure probe

        Confirms vulnerability via timing delta.
        """
        # Establish baseline
        if baseline_times is None:
            base_samples = []
            for _ in range(self.BASELINE_SAMPLES):
                _, t = await _timed_request(fetch_fn, url, payload=fast_payload, **request_kwargs)
                base_samples.append(t)
                await asyncio.sleep(0.2)
            baseline_ms = _stable_baseline(base_samples)
        else:
            baseline_ms = _stable_baseline(baseline_times)

        self._blind_analyzer.baseline_time_ms = baseline_ms

        # Execute slow payload
        _, slow_ms = await _timed_request(fetch_fn, url, payload=slow_payload, **request_kwargs)

        vulnerable, confidence, explanation = self._blind_analyzer.analyze_timing_pair(
            fast_time_ms=baseline_ms,
            slow_time_ms=slow_ms,
            expected_delay_s=expected_delay_s,
        )

        # Determine signal type
        if "sleep" in slow_payload.lower() or "waitfor" in slow_payload.lower() or "pg_sleep" in slow_payload.lower():
            signal = BehaviorSignal.TIMING_BLIND_SQLI
        elif "ping" in slow_payload.lower() or "curl" in slow_payload.lower() or "wget" in slow_payload.lower():
            signal = BehaviorSignal.TIMING_BLIND_CMDI
        else:
            signal = BehaviorSignal.TIMING_BLIND_SSRF

        obs = BehavioralObservation(
            signal=signal,
            confidence=confidence if vulnerable else 0.0,
            description=explanation,
            timing_ms=slow_ms,
            baseline_timing_ms=baseline_ms,
            payload=slow_payload,
            evidence={
                "fast_payload": fast_payload,
                "slow_payload": slow_payload,
                "baseline_ms": baseline_ms,
                "probe_ms": slow_ms,
                "delta_ms": slow_ms - baseline_ms,
                "expected_delay_s": expected_delay_s,
                "vulnerable": vulnerable,
                "parameter": parameter,
            },
        )
        self._observations.append(obs)
        return obs

    async def probe_boolean_oracle(
        self,
        fetch_fn: Callable,
        url: str,
        true_payload: str,
        false_payload: str,
        parameter: str = "",
        **request_kwargs,
    ) -> BehavioralObservation:
        """
        Boolean-based blind injection.
        TRUE condition → different response than FALSE condition.
        """
        true_resp, _ = await _timed_request(fetch_fn, url, payload=true_payload, **request_kwargs)
        await asyncio.sleep(0.1)
        false_resp, _ = await _timed_request(fetch_fn, url, payload=false_payload, **request_kwargs)

        true_body = getattr(true_resp, "body", "") or ""
        false_body = getattr(false_resp, "body", "") or ""
        true_len = len(true_body)
        false_len = len(false_body)
        length_delta = abs(true_len - false_len)
        pct_delta = length_delta / max(true_len, false_len, 1)

        # Score boolean oracle
        if pct_delta >= self.LENGTH_ORACLE_PCT and length_delta >= self.LENGTH_ORACLE_MIN_DELTA:
            confidence = min(0.85, pct_delta * 3)
            signal = BehaviorSignal.BOOLEAN_ORACLE
            description = (
                f"Boolean oracle: TRUE response {true_len}b vs FALSE {false_len}b "
                f"(Δ{length_delta}b / {pct_delta:.0%})"
            )
        else:
            confidence = 0.0
            signal = BehaviorSignal.LENGTH_ORACLE
            description = f"No significant boolean difference (Δ{length_delta}b)"

        obs = BehavioralObservation(
            signal=signal,
            confidence=confidence,
            description=description,
            body_length=true_len,
            baseline_length=false_len,
            payload=true_payload,
            evidence={
                "true_payload": true_payload,
                "false_payload": false_payload,
                "true_length": true_len,
                "false_length": false_len,
                "length_delta": length_delta,
                "pct_delta": pct_delta,
                "parameter": parameter,
            },
        )
        self._observations.append(obs)
        return obs

    def analyze_error_oracle(
        self,
        response_body: str,
        payload: str,
        parameter: str = "",
    ) -> BehavioralObservation:
        """
        Error oracle: detect verbose error messages leaked by injection.
        Checks SQL errors, command execution errors, generic exceptions.
        """
        all_patterns = [
            (self._SQL_ERROR_PATTERNS, BehaviorSignal.TIMING_BLIND_SQLI, 0.8),
            (self._CMDI_ERROR_PATTERNS, BehaviorSignal.TIMING_BLIND_CMDI, 0.85),
            (self._GENERIC_ERROR_PATTERNS, BehaviorSignal.ERROR_ORACLE, 0.5),
        ]
        for patterns, signal, conf in all_patterns:
            for pat in patterns:
                m = pat.search(response_body)
                if m:
                    snippet = response_body[max(0, m.start() - 30): m.end() + 60]
                    obs = BehavioralObservation(
                        signal=BehaviorSignal.ERROR_ORACLE,
                        confidence=conf,
                        description=f"Error oracle triggered: {m.group(0)[:80]}",
                        payload=payload,
                        evidence={
                            "error_snippet": snippet,
                            "pattern": pat.pattern[:60],
                            "signal_type": signal.value,
                            "parameter": parameter,
                        },
                    )
                    self._observations.append(obs)
                    return obs

        obs = BehavioralObservation(
            signal=BehaviorSignal.ERROR_ORACLE,
            confidence=0.0,
            description="No error oracle signals detected",
            payload=payload,
        )
        return obs

    def analyze_reflection(
        self,
        payload: str,
        response_body: str,
        response_headers: Dict[str, str],
        parameter: str = "",
    ) -> BehavioralObservation:
        """Confirm XSS via reflection detection + context analysis."""
        reflected, ctx = detect_reflection(payload, response_body)

        if reflected:
            # Check if the payload appears to be executable (not HTML-encoded)
            is_executable = (
                "<script" in (ctx or "").lower()
                or "javascript:" in (ctx or "").lower()
                or "onerror=" in (ctx or "").lower()
                or "onload=" in (ctx or "").lower()
            )
            confidence = 0.9 if is_executable else 0.65

            obs = BehavioralObservation(
                signal=BehaviorSignal.REFLECTION_XSS,
                confidence=confidence,
                description=f"Payload reflected {'(executable context)' if is_executable else '(HTML-encoded or inert)'}",
                payload=payload,
                evidence={
                    "reflected": True,
                    "context": ctx,
                    "executable": is_executable,
                    "parameter": parameter,
                },
            )
        else:
            obs = BehavioralObservation(
                signal=BehaviorSignal.REFLECTION_XSS,
                confidence=0.0,
                description="No reflection found",
                payload=payload,
            )

        self._observations.append(obs)
        return obs

    def analyze_header_injection(
        self,
        baseline_headers: Dict[str, str],
        probe_headers: Dict[str, str],
        payload: str,
        parameter: str = "",
    ) -> BehavioralObservation:
        """
        Detect header injection:
        - CRLF injection → extra headers appear
        - Host header injection → Location/redirect changes
        """
        injected_headers = []
        changed_values = []

        baseline_lower = {k.lower(): v for k, v in baseline_headers.items()}
        probe_lower = {k.lower(): v for k, v in probe_headers.items()}

        # New headers that appeared in probe
        for key, val in probe_lower.items():
            if key not in baseline_lower:
                injected_headers.append(f"{key}: {val}")

        # Headers with changed values
        for key in baseline_lower:
            if key in probe_lower and probe_lower[key] != baseline_lower[key]:
                changed_values.append(f"{key}: {probe_lower[key]!r} (was {baseline_lower[key]!r})")

        if injected_headers or changed_values:
            confidence = 0.8 if injected_headers else 0.5
            obs = BehavioralObservation(
                signal=BehaviorSignal.HEADER_INJECTION,
                confidence=confidence,
                description=f"Header injection: {len(injected_headers)} injected, {len(changed_values)} mutated",
                payload=payload,
                evidence={
                    "injected": injected_headers,
                    "mutated": changed_values,
                    "parameter": parameter,
                },
            )
        else:
            obs = BehavioralObservation(
                signal=BehaviorSignal.HEADER_INJECTION,
                confidence=0.0,
                description="No header injection signals",
                payload=payload,
            )

        self._observations.append(obs)
        return obs

    def analyze_redirect(
        self,
        baseline_redirect: Optional[str],
        probe_redirect: Optional[str],
        payload: str,
        parameter: str = "",
    ) -> BehavioralObservation:
        """Detect open redirect or redirect hijacking."""
        if probe_redirect and probe_redirect != baseline_redirect:
            # Check if probe redirect goes to a different host
            from urllib.parse import urlparse
            baseline_host = urlparse(baseline_redirect or "").netloc
            probe_host = urlparse(probe_redirect).netloc

            if probe_host and probe_host != baseline_host:
                confidence = 0.85
                desc = f"Redirect hijack: → {probe_redirect}"
            else:
                confidence = 0.4
                desc = f"Redirect changed: {baseline_redirect} → {probe_redirect}"

            obs = BehavioralObservation(
                signal=BehaviorSignal.REDIRECT_HIJACK,
                confidence=confidence,
                description=desc,
                payload=payload,
                evidence={
                    "baseline_redirect": baseline_redirect,
                    "probe_redirect": probe_redirect,
                    "different_host": probe_host != baseline_host,
                    "parameter": parameter,
                },
            )
        else:
            obs = BehavioralObservation(
                signal=BehaviorSignal.REDIRECT_HIJACK,
                confidence=0.0,
                description="No redirect change",
                payload=payload,
            )

        self._observations.append(obs)
        return obs

    def analyze_cache_poisoning(
        self,
        first_body: str,
        second_body: str,
        payload: str,
        second_from_cache: bool = False,
        parameter: str = "",
    ) -> BehavioralObservation:
        """
        Detect cache poisoning:
        - Payload reflected in cached response served to subsequent requests
        """
        if second_from_cache:
            reflected, ctx = detect_reflection(payload, second_body)
            if reflected:
                obs = BehavioralObservation(
                    signal=BehaviorSignal.CACHE_POISONING,
                    confidence=0.9,
                    description="Cache poisoning confirmed: payload reflected from cached response",
                    payload=payload,
                    evidence={
                        "cached_reflection": ctx,
                        "parameter": parameter,
                    },
                )
            else:
                obs = BehavioralObservation(
                    signal=BehaviorSignal.CACHE_POISONING,
                    confidence=0.0,
                    description="No cache poisoning — payload not in cached response",
                    payload=payload,
                )
        else:
            obs = BehavioralObservation(
                signal=BehaviorSignal.CACHE_POISONING,
                confidence=0.0,
                description="Second response not from cache",
                payload=payload,
            )

        self._observations.append(obs)
        return obs

    # ── Aggregation ──────────────────────────────────────────────
    def aggregate(self, target_url: str = "", parameter: str = "") -> BehaviorProbeResult:
        """Summarize all observations into a final behavioral result."""
        start = time.time()
        if not self._observations:
            return BehaviorProbeResult(
                target_url=target_url,
                parameter=parameter,
                verdict=AnalysisVerdict.INCONCLUSIVE,
            )

        # Filter significant observations
        significant = [o for o in self._observations if o.confidence >= 0.3]
        if not significant:
            return BehaviorProbeResult(
                target_url=target_url,
                parameter=parameter,
                verdict=AnalysisVerdict.CLEAN,
                observations=self._observations,
            )

        best = max(significant, key=lambda o: o.confidence)
        all_signals = list({o.signal for o in significant})
        avg_confidence = sum(o.confidence for o in significant) / len(significant)

        # Multi-signal bonus
        multi_bonus = min(0.15, len(significant) * 0.05)
        final_confidence = min(1.0, avg_confidence + multi_bonus)

        if final_confidence >= 0.8:
            verdict = AnalysisVerdict.VULNERABLE
        elif final_confidence >= 0.55:
            verdict = AnalysisVerdict.LIKELY_VULNERABLE
        elif final_confidence >= 0.3:
            verdict = AnalysisVerdict.SUSPICIOUS
        else:
            verdict = AnalysisVerdict.INCONCLUSIVE

        return BehaviorProbeResult(
            target_url=target_url,
            parameter=parameter,
            observations=self._observations,
            verdict=verdict,
            confidence=final_confidence,
            signals=all_signals,
            best_payload=best.payload,
            evidence=best.evidence,
            analysis_ms=round((time.time() - start) * 1000, 2),
        )

    def reset(self) -> None:
        """Clear observations for reuse on a new parameter."""
        self._observations.clear()


# ─────────────────────────────────────────────
# Convenience factory
# ─────────────────────────────────────────────
def create_behavior_analyzer() -> BehaviorAnalyzer:
    """Factory for creating a fresh BehaviorAnalyzer per scan session."""
    return BehaviorAnalyzer()
