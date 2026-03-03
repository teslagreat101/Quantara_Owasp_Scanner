"""
analyzer.py — Differential Response Intelligence Engine
========================================================
Compares HTTP responses to detect:
- Silent filtering (WAF interference)
- Partial execution (blind injection)
- Response anomalies (timing, length, entropy)
- DOM changes
- Status variance
- Cache differences

Used by all scanner modules for accurate, low-noise detection.
"""

from __future__ import annotations

import hashlib
import math
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

# ─────────────────────────────────────────────
# Enums
# ─────────────────────────────────────────────
class AnomalyType(str, Enum):
    TIMING_DEVIATION = "timing_deviation"
    LENGTH_DEVIATION = "length_deviation"
    STATUS_CHANGE = "status_change"
    HEADER_MUTATION = "header_mutation"
    ENTROPY_SHIFT = "entropy_shift"
    CONTENT_SIMILARITY = "content_similarity"
    REDIRECT_VARIANCE = "redirect_variance"
    WAF_INTERFERENCE = "waf_interference"
    PARTIAL_EXECUTION = "partial_execution"
    DOM_CHANGE = "dom_change"
    CACHE_DIFFERENCE = "cache_difference"
    REFLECTION_DETECTED = "reflection_detected"


class AnalysisVerdict(str, Enum):
    VULNERABLE = "vulnerable"
    LIKELY_VULNERABLE = "likely_vulnerable"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    WAF_FILTERED = "waf_filtered"
    INCONCLUSIVE = "inconclusive"


# ─────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────
@dataclass
class HttpSnapshot:
    """Captured state of one HTTP response."""
    status_code: int = 200
    body: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    response_time_ms: float = 0.0
    redirect_url: Optional[str] = None
    content_type: str = ""
    content_length: int = 0
    timestamp: float = field(default_factory=time.time)
    payload_used: Optional[str] = None
    request_url: str = ""
    request_method: str = "GET"

    def __post_init__(self):
        if not self.content_length and self.body:
            self.content_length = len(self.body)
        ct = self.headers.get("Content-Type", self.headers.get("content-type", ""))
        if ct and not self.content_type:
            self.content_type = ct


@dataclass
class DiffResult:
    """Structured difference between baseline and probe responses."""
    verdict: AnalysisVerdict = AnalysisVerdict.INCONCLUSIVE
    anomalies: List[AnomalyType] = field(default_factory=list)
    confidence: float = 0.0
    similarity_score: float = 1.0          # 0=completely different, 1=identical
    timing_delta_ms: float = 0.0
    length_delta: int = 0
    length_delta_pct: float = 0.0
    entropy_delta: float = 0.0
    status_changed: bool = False
    headers_changed: List[str] = field(default_factory=list)
    reflection_found: bool = False
    reflection_context: Optional[str] = None
    waf_signals: List[str] = field(default_factory=list)
    summary: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalysisReport:
    """Final analysis report for a scan probe series."""
    target_url: str = ""
    scan_id: str = ""
    verdict: AnalysisVerdict = AnalysisVerdict.INCONCLUSIVE
    overall_confidence: float = 0.0
    diff_results: List[DiffResult] = field(default_factory=list)
    anomaly_count: int = 0
    waf_detected: bool = False
    vulnerable_payloads: List[str] = field(default_factory=list)
    evidence_bundles: List[Dict] = field(default_factory=list)
    analysis_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target_url,
            "scan_id": self.scan_id,
            "verdict": self.verdict.value,
            "confidence": self.overall_confidence,
            "anomalies": self.anomaly_count,
            "waf_detected": self.waf_detected,
            "vulnerable_payloads": self.vulnerable_payloads,
            "analysis_ms": self.analysis_time_ms,
            "evidence": self.evidence_bundles,
        }


# ─────────────────────────────────────────────
# Levenshtein / string similarity
# ─────────────────────────────────────────────
def levenshtein_similarity(a: str, b: str, max_chars: int = 5000) -> float:
    """
    Compute normalized Levenshtein similarity [0.0, 1.0].
    Truncated to max_chars for performance on large responses.
    """
    a = a[:max_chars]
    b = b[:max_chars]
    if a == b:
        return 1.0
    la, lb = len(a), len(b)
    if la == 0 or lb == 0:
        return 0.0

    # Use row-optimized DP
    prev = list(range(lb + 1))
    for i, ca in enumerate(a, 1):
        curr = [i] + [0] * lb
        for j, cb in enumerate(b, 1):
            curr[j] = min(
                prev[j] + 1,
                curr[j - 1] + 1,
                prev[j - 1] + (0 if ca == cb else 1),
            )
        prev = curr

    dist = prev[lb]
    return 1.0 - dist / max(la, lb)


def token_similarity(a: str, b: str) -> float:
    """Word-level Jaccard similarity — faster than Levenshtein for long responses."""
    set_a = set(re.split(r"\W+", a.lower()))
    set_b = set(re.split(r"\W+", b.lower()))
    if not set_a and not set_b:
        return 1.0
    intersection = len(set_a & set_b)
    union = len(set_a | set_b)
    return intersection / union if union else 0.0


def structural_similarity(a: str, b: str) -> float:
    """
    HTML structure similarity: compare tag sequences only.
    Useful for detecting DOM changes when body content changes.
    """
    tag_pattern = re.compile(r"</?[a-zA-Z][^>]*>")
    tags_a = tag_pattern.findall(a)
    tags_b = tag_pattern.findall(b)
    if not tags_a and not tags_b:
        return 1.0
    set_a = set(tags_a)
    set_b = set(tags_b)
    intersection = len(set_a & set_b)
    union = len(set_a | set_b)
    return intersection / union if union else 0.0


# ─────────────────────────────────────────────
# Entropy analysis
# ─────────────────────────────────────────────
def shannon_entropy(data: str) -> float:
    """
    Compute Shannon entropy of a string [0, log2(256)].
    High entropy → compressed/encrypted content or random data.
    """
    if not data:
        return 0.0
    freq: Dict[int, int] = {}
    for ch in data.encode("utf-8", errors="replace"):
        freq[ch] = freq.get(ch, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


# ─────────────────────────────────────────────
# WAF detection
# ─────────────────────────────────────────────
_WAF_HEADERS = {
    "x-sucuri-id", "x-sucuri-cache",
    "x-akamai-transformed", "x-akamai-session-id",
    "x-cdn", "x-waf-event-info",
    "server-timing", "cf-ray", "x-cache-hits",
    "x-imperva-id", "x-ns-proxy-id",
    "x-firewall", "x-f5-client",
    "x-datadome-request",
}

_WAF_BODY_PATTERNS = [
    re.compile(r"access\s+denied", re.I),
    re.compile(r"blocked\s+by\s+(cloudflare|sucuri|akamai|imperva|barracuda)", re.I),
    re.compile(r"you\s+have\s+been\s+blocked", re.I),
    re.compile(r"security\s+(check|challenge|captcha)", re.I),
    re.compile(r"your\s+request\s+was\s+blocked", re.I),
    re.compile(r"incapsula\s+incident", re.I),
    re.compile(r"error\s+code\s*:\s*1020", re.I),
    re.compile(r"ray\s+id\s*:", re.I),
    re.compile(r"mod_security|modsecurity", re.I),
    re.compile(r"please\s+(enable|allow)\s+javascript", re.I),
]

_WAF_STATUS_CODES = {400, 403, 406, 429, 503}


def detect_waf(snapshot: HttpSnapshot) -> List[str]:
    """Return list of WAF signals detected in a response."""
    signals: List[str] = []

    # Header-based detection
    lower_headers = {k.lower(): v for k, v in snapshot.headers.items()}
    for waf_hdr in _WAF_HEADERS:
        if waf_hdr in lower_headers:
            signals.append(f"WAF header: {waf_hdr}")

    # Body-based detection
    body_lower = snapshot.body[:5000]
    for pat in _WAF_BODY_PATTERNS:
        m = pat.search(body_lower)
        if m:
            signals.append(f"WAF body pattern: {m.group(0)[:60]}")

    # Status-based detection
    if snapshot.status_code in _WAF_STATUS_CODES:
        signals.append(f"WAF status code: {snapshot.status_code}")

    # Short response after injection (common WAF behavior)
    if snapshot.content_length < 100 and snapshot.payload_used:
        signals.append("Suspiciously short response after injection")

    return signals


# ─────────────────────────────────────────────
# Reflection detection
# ─────────────────────────────────────────────
def detect_reflection(payload: str, response_body: str) -> Tuple[bool, Optional[str]]:
    """
    Check if the payload is reflected in the response body.
    Returns (reflected, context_snippet).
    """
    if not payload or not response_body:
        return False, None

    # Direct reflection
    if payload in response_body:
        idx = response_body.index(payload)
        snippet = response_body[max(0, idx - 50): idx + len(payload) + 50]
        return True, snippet

    # URL-decoded reflection
    try:
        from urllib.parse import unquote
        decoded = unquote(payload)
        if decoded != payload and decoded in response_body:
            idx = response_body.index(decoded)
            snippet = response_body[max(0, idx - 50): idx + len(decoded) + 50]
            return True, snippet
    except Exception:
        pass

    # HTML entity reflection
    html_payload = payload.replace("<", "&lt;").replace(">", "&gt;")
    if html_payload in response_body:
        return True, f"HTML-encoded reflection: {html_payload}"

    return False, None


# ─────────────────────────────────────────────
# Header diff
# ─────────────────────────────────────────────
def diff_headers(
    baseline_headers: Dict[str, str],
    probe_headers: Dict[str, str],
) -> List[str]:
    """Return list of header keys that changed between baseline and probe."""
    changed = []
    all_keys = set(baseline_headers.keys()) | set(probe_headers.keys())
    for key in all_keys:
        bv = baseline_headers.get(key, "")
        pv = probe_headers.get(key, "")
        if bv != pv:
            changed.append(key)
    return changed


# ─────────────────────────────────────────────
# Core DifferentialAnalyzer
# ─────────────────────────────────────────────
class DifferentialAnalyzer:
    """
    Compares baseline HTTP response against probed responses
    to detect vulnerabilities through behavioral differences.

    Usage:
        analyzer = DifferentialAnalyzer(baseline_snapshot)
        result = analyzer.compare(probe_snapshot, payload="<script>")
        if result.verdict == AnalysisVerdict.VULNERABLE:
            # confirmed finding
    """

    # Thresholds (tunable)
    TIMING_THRESHOLD_MS: float = 2000.0    # 2 s timing diff → possible blind injection
    TIMING_RATIO_THRESHOLD: float = 3.0    # 3× slower → suspicious
    LENGTH_DELTA_THRESHOLD: int = 200      # bytes changed
    LENGTH_DELTA_PCT_THRESHOLD: float = 0.15  # 15% body length change
    ENTROPY_DELTA_THRESHOLD: float = 0.5   # entropy change
    SIMILARITY_VULNERABLE_THRESHOLD: float = 0.5  # below this → large change

    def __init__(self, baseline: HttpSnapshot):
        self._baseline = baseline
        self._baseline_entropy = shannon_entropy(baseline.body)

    def compare(
        self,
        probe: HttpSnapshot,
        payload: Optional[str] = None,
    ) -> DiffResult:
        """
        Compare a probe response against the baseline.
        Returns a structured DiffResult with verdict and evidence.
        """
        result = DiffResult()
        anomalies: List[AnomalyType] = []
        confidence_votes: List[float] = []

        # 1. Status code change
        if probe.status_code != self._baseline.status_code:
            result.status_changed = True
            anomalies.append(AnomalyType.STATUS_CHANGE)
            confidence_votes.append(0.4)

        # 2. Timing analysis
        timing_delta = probe.response_time_ms - self._baseline.response_time_ms
        result.timing_delta_ms = timing_delta
        if timing_delta > self.TIMING_THRESHOLD_MS:
            anomalies.append(AnomalyType.TIMING_DEVIATION)
            confidence_votes.append(
                min(1.0, timing_delta / (self.TIMING_THRESHOLD_MS * 2))
            )
        if self._baseline.response_time_ms > 0:
            ratio = probe.response_time_ms / self._baseline.response_time_ms
            if ratio > self.TIMING_RATIO_THRESHOLD:
                anomalies.append(AnomalyType.TIMING_DEVIATION)
                confidence_votes.append(min(0.9, ratio / 10))

        # 3. Length analysis
        length_delta = probe.content_length - self._baseline.content_length
        result.length_delta = length_delta
        if self._baseline.content_length > 0:
            length_delta_pct = abs(length_delta) / self._baseline.content_length
            result.length_delta_pct = length_delta_pct
            if abs(length_delta) > self.LENGTH_DELTA_THRESHOLD or length_delta_pct > self.LENGTH_DELTA_PCT_THRESHOLD:
                anomalies.append(AnomalyType.LENGTH_DEVIATION)
                confidence_votes.append(min(0.7, length_delta_pct * 2))

        # 4. Content similarity
        sim = levenshtein_similarity(self._baseline.body, probe.body)
        result.similarity_score = sim
        if sim < self.SIMILARITY_VULNERABLE_THRESHOLD:
            anomalies.append(AnomalyType.CONTENT_SIMILARITY)
            confidence_votes.append(1.0 - sim)

        # 5. Entropy shift
        probe_entropy = shannon_entropy(probe.body)
        entropy_delta = abs(probe_entropy - self._baseline_entropy)
        result.entropy_delta = entropy_delta
        if entropy_delta > self.ENTROPY_DELTA_THRESHOLD:
            anomalies.append(AnomalyType.ENTROPY_SHIFT)
            confidence_votes.append(min(0.6, entropy_delta / 2))

        # 6. Header mutation
        changed_headers = diff_headers(self._baseline.headers, probe.headers)
        result.headers_changed = changed_headers
        if changed_headers:
            anomalies.append(AnomalyType.HEADER_MUTATION)
            confidence_votes.append(0.3)

        # 7. Redirect variance
        if probe.redirect_url != self._baseline.redirect_url:
            anomalies.append(AnomalyType.REDIRECT_VARIANCE)
            confidence_votes.append(0.5)

        # 8. WAF detection
        waf_signals = detect_waf(probe)
        result.waf_signals = waf_signals
        if waf_signals:
            anomalies.append(AnomalyType.WAF_INTERFERENCE)
            # WAF blocked = not vulnerable (or needs bypass)
            confidence_votes = [v * 0.3 for v in confidence_votes]

        # 9. Reflection detection
        if payload:
            reflected, ctx = detect_reflection(payload, probe.body)
            result.reflection_found = reflected
            result.reflection_context = ctx
            if reflected:
                anomalies.append(AnomalyType.REFLECTION_DETECTED)
                confidence_votes.append(0.9)

        # 10. Partial execution (body changed but not dramatically)
        if (
            0.5 <= sim < 0.85
            and abs(length_delta) > 50
            and AnomalyType.WAF_INTERFERENCE not in anomalies
        ):
            anomalies.append(AnomalyType.PARTIAL_EXECUTION)
            confidence_votes.append(0.4)

        # ── Compute final confidence
        result.anomalies = list(set(anomalies))
        if confidence_votes:
            # Weighted average (more anomalies → higher confidence cap)
            base_conf = sum(confidence_votes) / len(confidence_votes)
            multi_bonus = min(0.2, len(confidence_votes) * 0.04)
            result.confidence = min(1.0, base_conf + multi_bonus)
        else:
            result.confidence = 0.0

        # ── Determine verdict
        if AnomalyType.WAF_INTERFERENCE in anomalies and result.confidence < 0.4:
            result.verdict = AnalysisVerdict.WAF_FILTERED
        elif result.confidence >= 0.8:
            result.verdict = AnalysisVerdict.VULNERABLE
        elif result.confidence >= 0.55:
            result.verdict = AnalysisVerdict.LIKELY_VULNERABLE
        elif result.confidence >= 0.3:
            result.verdict = AnalysisVerdict.SUSPICIOUS
        elif not anomalies:
            result.verdict = AnalysisVerdict.CLEAN
        else:
            result.verdict = AnalysisVerdict.INCONCLUSIVE

        # ── Build summary
        result.summary = self._build_summary(result, payload)
        result.evidence = {
            "baseline_status": self._baseline.status_code,
            "probe_status": probe.status_code,
            "baseline_length": self._baseline.content_length,
            "probe_length": probe.content_length,
            "timing_delta_ms": timing_delta,
            "similarity": sim,
            "entropy_delta": entropy_delta,
            "payload": payload,
            "waf_signals": waf_signals,
            "reflection": result.reflection_context,
        }

        return result

    def _build_summary(self, result: DiffResult, payload: Optional[str]) -> str:
        parts = [f"Verdict: {result.verdict.value.upper()}"]
        parts.append(f"Confidence: {result.confidence:.0%}")
        if result.anomalies:
            parts.append(f"Anomalies: {', '.join(a.value for a in result.anomalies)}")
        if payload:
            parts.append(f"Payload: {payload[:80]}")
        if result.reflection_found:
            parts.append("Reflection confirmed in response")
        if result.waf_signals:
            parts.append(f"WAF: {result.waf_signals[0]}")
        return " | ".join(parts)

    def update_baseline(self, new_baseline: HttpSnapshot) -> None:
        """Dynamically update baseline (e.g., after authentication)."""
        self._baseline = new_baseline
        self._baseline_entropy = shannon_entropy(new_baseline.body)


# ─────────────────────────────────────────────
# Multi-probe analysis session
# ─────────────────────────────────────────────
class ProbeSession:
    """
    Manages a series of probe comparisons against a fixed baseline.
    Aggregates results across multiple payloads for a target parameter.
    """

    def __init__(self, baseline: HttpSnapshot, target_url: str = "", scan_id: str = ""):
        self._analyzer = DifferentialAnalyzer(baseline)
        self.target_url = target_url
        self.scan_id = scan_id
        self._results: List[DiffResult] = []
        self._start_time = time.time()

    def analyze(self, probe: HttpSnapshot, payload: Optional[str] = None) -> DiffResult:
        result = self._analyzer.compare(probe, payload=payload)
        self._results.append(result)
        return result

    def build_report(self) -> AnalysisReport:
        """Aggregate all probe results into a final report."""
        if not self._results:
            return AnalysisReport(
                target_url=self.target_url,
                scan_id=self.scan_id,
                verdict=AnalysisVerdict.INCONCLUSIVE,
            )

        # Highest confidence wins
        best = max(self._results, key=lambda r: r.confidence)
        waf_detected = any(
            AnomalyType.WAF_INTERFERENCE in r.anomalies for r in self._results
        )
        vulnerable_payloads = [
            r.evidence.get("payload", "")
            for r in self._results
            if r.verdict in (AnalysisVerdict.VULNERABLE, AnalysisVerdict.LIKELY_VULNERABLE)
            and r.evidence.get("payload")
        ]
        all_anomalies = sum(len(r.anomalies) for r in self._results)

        # Confidence aggregation: weighted by verdict strength
        verdict_weights = {
            AnalysisVerdict.VULNERABLE: 1.0,
            AnalysisVerdict.LIKELY_VULNERABLE: 0.7,
            AnalysisVerdict.SUSPICIOUS: 0.4,
            AnalysisVerdict.WAF_FILTERED: 0.2,
            AnalysisVerdict.CLEAN: 0.0,
            AnalysisVerdict.INCONCLUSIVE: 0.1,
        }
        total_weight = sum(verdict_weights.get(r.verdict, 0) * r.confidence for r in self._results)
        avg_conf = total_weight / len(self._results) if self._results else 0.0

        return AnalysisReport(
            target_url=self.target_url,
            scan_id=self.scan_id,
            verdict=best.verdict,
            overall_confidence=round(min(1.0, avg_conf * 1.2), 3),  # slight boost for multiple probes
            diff_results=self._results,
            anomaly_count=all_anomalies,
            waf_detected=waf_detected,
            vulnerable_payloads=vulnerable_payloads,
            evidence_bundles=[r.evidence for r in self._results if r.confidence > 0.3],
            analysis_time_ms=round((time.time() - self._start_time) * 1000, 2),
        )

    @property
    def results(self) -> List[DiffResult]:
        return self._results


# ─────────────────────────────────────────────
# Blind injection timing analyzer
# ─────────────────────────────────────────────
class BlindInjectionAnalyzer:
    """
    Specialized analyzer for time-based blind injection detection.

    Compares:
    - SLEEP(5) payload → should take 5+ seconds
    - SLEEP(0) payload → should be fast
    Decision based on timing differential.
    """

    MIN_SLEEP_DELTA_S: float = 3.5   # At least 3.5s difference expected for SLEEP(5)
    CONFIDENCE_HIGH: float = 0.85
    CONFIDENCE_MED: float = 0.6

    def __init__(self, baseline_time_ms: float = 0.0):
        self.baseline_time_ms = baseline_time_ms

    def analyze_timing_pair(
        self,
        fast_time_ms: float,  # Response with SLEEP(0) / innocuous payload
        slow_time_ms: float,  # Response with SLEEP(5) / delay payload
        expected_delay_s: float = 5.0,
    ) -> Tuple[bool, float, str]:
        """
        Returns (vulnerable, confidence, explanation).
        """
        delta_ms = slow_time_ms - fast_time_ms
        delta_s = delta_ms / 1000.0
        expected_ms = expected_delay_s * 1000.0

        if delta_s >= self.MIN_SLEEP_DELTA_S:
            # Strong timing signal
            conf = min(self.CONFIDENCE_HIGH, delta_s / expected_delay_s)
            return True, conf, (
                f"Timing delta {delta_ms:.0f}ms ≥ expected {expected_ms:.0f}ms "
                f"→ blind time-based injection confirmed"
            )
        elif delta_s >= 1.5:
            # Possible — network jitter or partial execution
            return True, self.CONFIDENCE_MED, (
                f"Timing delta {delta_ms:.0f}ms — possible blind injection (possible jitter)"
            )
        else:
            return False, 0.0, f"No significant timing difference ({delta_ms:.0f}ms)"

    def analyze_with_baseline(
        self,
        sleep_time_ms: float,
        expected_delay_s: float = 5.0,
    ) -> Tuple[bool, float, str]:
        """Compare single sleep probe against stored baseline."""
        return self.analyze_timing_pair(
            fast_time_ms=self.baseline_time_ms,
            slow_time_ms=sleep_time_ms,
            expected_delay_s=expected_delay_s,
        )
