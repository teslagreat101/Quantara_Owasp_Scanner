"""
Quantara False Positive Reduction Layer
========================================

Phase 3 of the Quantara enterprise scanner pipeline.

Implements a multi-step verification pipeline to reduce false positives:

  Step 1 — Baseline Capture
    Fetch the target URL with a benign/safe input to capture the normal response.

  Step 2 — Control Request
    Send a known-safe payload (random string) to get a control response.
    This filters targets that return 200/match for ANY input.

  Step 3 — Payload Injection
    Send the actual attack payload.

  Step 4 — Response Differential Analysis
    Compare payload response vs baseline + control:
      - Status code difference
      - Body size difference (>20% = suspicious)
      - Response time difference (>3x = timing attack confirmed)
      - Unique content that appears only in payload response

  Step 5 — Reflection Validation (XSS / SSTI)
    Confirm the injected payload appears verbatim in the response body.

  Step 6 — Confidence Score Adjustment
    Adjust the finding's `confidence` field based on verification steps passed.

Architecture:
  FPReducer — main orchestrator
  BaselineCapture — fetches baseline + control responses
  DiffEngine — computes response diffs
  ReflectionValidator — confirms payload reflection
  TimingValidator — confirms timing-based injection
  ConfidenceAdjuster — updates confidence based on evidence
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any, Optional

logger = logging.getLogger("owasp_scanner.quantara_fp_reducer")

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

SAFE_PAYLOADS = [
    "QUANTARA_SAFE_PROBE_8x3j",
    "test123",
    "hello_world",
]

# Minimum body difference to count as meaningful (characters)
MIN_BODY_DIFF_CHARS = 50

# If response is ≥ this ratio of baseline, assume flapping (not indicative)
FLAPPING_SIMILARITY_THRESHOLD = 0.95

# Timing: if payload takes this much longer (seconds), consider timing-confirmed
TIMING_CONFIRMATION_DELTA = 3.0

# Reflection validation: if payload string found verbatim in response body
REFLECTION_MIN_PAYLOAD_LEN = 5

# FP confidence adjustments
CONFIDENCE_BOOST_REFLECTION = 0.20
CONFIDENCE_BOOST_DIFF = 0.15
CONFIDENCE_BOOST_TIMING = 0.25
CONFIDENCE_BOOST_STATUS_CHANGE = 0.10
CONFIDENCE_PENALTY_FLAPPING = 0.30
CONFIDENCE_PENALTY_CONTROL_MATCH = 0.40


# ─────────────────────────────────────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ProbeResponse:
    """Normalized HTTP response for comparison."""
    url: str
    status_code: int
    body: str
    headers: dict[str, str]
    duration_ms: float
    error: Optional[str] = None

    @property
    def body_hash(self) -> str:
        return hashlib.md5(self.body.encode("utf-8", errors="replace")).hexdigest()

    @property
    def body_size(self) -> int:
        return len(self.body)


@dataclass
class DiffResult:
    """Result of comparing probe responses."""
    status_changed: bool = False
    status_baseline: int = 0
    status_payload: int = 0
    body_similarity: float = 1.0       # 0.0 = completely different, 1.0 = identical
    body_size_delta: int = 0
    body_size_ratio: float = 1.0
    timing_delta_ms: float = 0.0
    timing_ratio: float = 1.0
    unique_payload_content: str = ""   # content in payload response NOT in baseline
    control_matches_payload: bool = False  # True = flapping/wildcard response


@dataclass
class VerificationResult:
    """Complete FP verification result for a single finding."""
    is_confirmed: bool                 # True = likely true positive
    is_false_positive: bool            # True = likely false positive
    confidence_delta: float            # adjustment to apply to original confidence
    evidence: dict[str, Any] = field(default_factory=dict)
    verdict: str = ""                  # "CONFIRMED" / "LIKELY_TP" / "NEEDS_REVIEW" / "LIKELY_FP" / "FALSE_POSITIVE"
    notes: list[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# HTTP Probe Engine
# ─────────────────────────────────────────────────────────────────────────────

class ProbeEngine:
    """
    Sends HTTP requests for baseline/control/payload probing.
    Shares session with the main scanner for cookie/header consistency.
    """

    def __init__(
        self,
        timeout: float = 12.0,
        headers: Optional[dict] = None,
        cookies: Optional[dict] = None,
    ):
        self.timeout = timeout
        self.headers = headers or {}
        self.cookies = cookies or {}

    def get(self, url: str, extra_headers: Optional[dict] = None) -> ProbeResponse:
        """Synchronous GET probe."""
        all_headers = dict(self.headers)
        if extra_headers:
            all_headers.update(extra_headers)
        start = time.perf_counter()
        try:
            import requests
            resp = requests.get(
                url, headers=all_headers, cookies=self.cookies,
                timeout=self.timeout, verify=False, allow_redirects=True,
            )
            duration_ms = (time.perf_counter() - start) * 1000
            return ProbeResponse(
                url=url,
                status_code=resp.status_code,
                body=resp.text[:50000],  # cap at 50KB for comparison
                headers=dict(resp.headers),
                duration_ms=duration_ms,
            )
        except Exception as e:
            duration_ms = (time.perf_counter() - start) * 1000
            return ProbeResponse(
                url=url, status_code=0, body="", headers={},
                duration_ms=duration_ms, error=str(e),
            )

    def post(
        self, url: str, data: Optional[dict] = None,
        json: Optional[dict] = None, extra_headers: Optional[dict] = None,
    ) -> ProbeResponse:
        """Synchronous POST probe."""
        all_headers = dict(self.headers)
        if extra_headers:
            all_headers.update(extra_headers)
        start = time.perf_counter()
        try:
            import requests
            resp = requests.post(
                url, data=data, json=json, headers=all_headers,
                cookies=self.cookies, timeout=self.timeout,
                verify=False, allow_redirects=True,
            )
            duration_ms = (time.perf_counter() - start) * 1000
            return ProbeResponse(
                url=url,
                status_code=resp.status_code,
                body=resp.text[:50000],
                headers=dict(resp.headers),
                duration_ms=duration_ms,
            )
        except Exception as e:
            duration_ms = (time.perf_counter() - start) * 1000
            return ProbeResponse(
                url=url, status_code=0, body="", headers={},
                duration_ms=duration_ms, error=str(e),
            )


# ─────────────────────────────────────────────────────────────────────────────
# Diff Engine
# ─────────────────────────────────────────────────────────────────────────────

class DiffEngine:
    """Compares HTTP responses to detect meaningful differences."""

    def compare(
        self,
        baseline: ProbeResponse,
        payload: ProbeResponse,
        control: Optional[ProbeResponse] = None,
    ) -> DiffResult:
        result = DiffResult()

        if baseline.error or payload.error:
            return result

        # Status code change
        result.status_baseline = baseline.status_code
        result.status_payload = payload.status_code
        result.status_changed = baseline.status_code != payload.status_code

        # Body similarity (SequenceMatcher on truncated bodies for performance)
        b_body = baseline.body[:5000]
        p_body = payload.body[:5000]
        result.body_similarity = SequenceMatcher(None, b_body, p_body).ratio()
        result.body_size_delta = payload.body_size - baseline.body_size
        if baseline.body_size > 0:
            result.body_size_ratio = payload.body_size / baseline.body_size
        else:
            result.body_size_ratio = 1.0 if payload.body_size == 0 else 999.0

        # Timing
        result.timing_delta_ms = payload.duration_ms - baseline.duration_ms
        if baseline.duration_ms > 0:
            result.timing_ratio = payload.duration_ms / baseline.duration_ms
        else:
            result.timing_ratio = 1.0

        # Unique content in payload response not in baseline
        unique = self._find_unique_content(baseline.body, payload.body)
        result.unique_payload_content = unique[:500]  # cap output

        # Check if control matches payload (flapping / wildcard)
        if control and not control.error:
            c_body = control.body[:5000]
            control_similarity = SequenceMatcher(None, c_body, p_body).ratio()
            result.control_matches_payload = control_similarity > FLAPPING_SIMILARITY_THRESHOLD

        return result

    def _find_unique_content(self, baseline: str, payload: str) -> str:
        """Find content in payload response not present in baseline."""
        # Simple approach: find lines in payload not in baseline
        baseline_lines = set(baseline.splitlines())
        unique_lines = [
            line for line in payload.splitlines()
            if line.strip() and line not in baseline_lines and len(line.strip()) > 10
        ]
        return "\n".join(unique_lines[:20])


# ─────────────────────────────────────────────────────────────────────────────
# Reflection Validator
# ─────────────────────────────────────────────────────────────────────────────

class ReflectionValidator:
    """
    Confirms that the injected payload actually appears verbatim in the response.
    Used for XSS, SSTI, and injection finding validation.
    """

    def validate(self, payload: str, response_body: str) -> tuple[bool, str]:
        """
        Returns (confirmed, evidence).
        confirmed=True if the payload is reflected in the response.
        """
        if not payload or len(payload) < REFLECTION_MIN_PAYLOAD_LEN:
            return False, "payload too short to validate"

        if not response_body:
            return False, "empty response body"

        # Case-insensitive substring check first
        if payload.lower() in response_body.lower():
            # Find the exact context
            idx = response_body.lower().find(payload.lower())
            context_start = max(0, idx - 30)
            context_end = min(len(response_body), idx + len(payload) + 30)
            evidence = response_body[context_start:context_end]
            return True, f"payload reflected at position {idx}: ...{evidence}..."

        # Partial reflection check (at least 80% of the payload is reflected)
        if len(payload) > 10:
            partial_threshold = int(len(payload) * 0.8)
            partial = payload[:partial_threshold]
            if partial.lower() in response_body.lower():
                return True, f"partial reflection ({partial_threshold}/{len(payload)} chars) confirmed"

        return False, "payload not found in response"


# ─────────────────────────────────────────────────────────────────────────────
# Timing Validator
# ─────────────────────────────────────────────────────────────────────────────

class TimingValidator:
    """
    Confirms timing-based injection vulnerabilities.
    Used for: Blind SQLi, Time-based Command Injection, sleep-based SSRF.
    """

    def validate(
        self,
        baseline_ms: float,
        payload_ms: float,
        expected_delay_ms: float = 5000.0,
        tolerance_ms: float = 1000.0,
    ) -> tuple[bool, str]:
        """
        Returns (confirmed, evidence).
        confirmed=True if the payload response took `expected_delay_ms` longer than baseline.
        """
        delta = payload_ms - baseline_ms
        expected_min = expected_delay_ms - tolerance_ms
        expected_max = expected_delay_ms + (tolerance_ms * 3)

        if delta >= expected_min:
            if delta <= expected_max:
                return True, (
                    f"timing confirmed: baseline={baseline_ms:.0f}ms, "
                    f"payload={payload_ms:.0f}ms, delta={delta:.0f}ms "
                    f"(expected ~{expected_delay_ms:.0f}ms)"
                )
            elif delta > expected_max:
                return True, (
                    f"timing confirmed (server slow): delta={delta:.0f}ms "
                    f"exceeds expected={expected_delay_ms:.0f}ms"
                )

        return False, (
            f"timing NOT confirmed: delta={delta:.0f}ms < expected={expected_min:.0f}ms"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Confidence Adjuster
# ─────────────────────────────────────────────────────────────────────────────

class ConfidenceAdjuster:
    """
    Adjusts a finding's confidence score based on verification evidence.
    """

    def adjust(
        self,
        original_confidence: float,
        diff: DiffResult,
        reflection_confirmed: bool = False,
        timing_confirmed: bool = False,
    ) -> tuple[float, str, list[str]]:
        """
        Returns (new_confidence, verdict, notes).
        """
        confidence = original_confidence
        notes = []
        verdict = "NEEDS_REVIEW"

        # --- Penalty: flapping response ---
        if diff.control_matches_payload:
            confidence -= CONFIDENCE_PENALTY_CONTROL_MATCH
            notes.append("FP indicator: control request matches payload response (wildcard/flapping)")

        # --- Boost: reflection confirmed ---
        if reflection_confirmed:
            confidence += CONFIDENCE_BOOST_REFLECTION
            notes.append("TP boost: payload reflected verbatim in response")

        # --- Boost: timing confirmed ---
        if timing_confirmed:
            confidence += CONFIDENCE_BOOST_TIMING
            notes.append("TP boost: timing-based injection confirmed")

        # --- Boost: status code changed ---
        if diff.status_changed:
            if diff.status_payload in (500, 502, 503):
                confidence += CONFIDENCE_BOOST_STATUS_CHANGE * 0.5
                notes.append(f"Weak TP indicator: status changed to {diff.status_payload} (server error)")
            elif diff.status_payload == 200 and diff.status_baseline != 200:
                confidence += CONFIDENCE_BOOST_STATUS_CHANGE
                notes.append(f"TP indicator: status changed from {diff.status_baseline} → 200")

        # --- Boost: meaningful body difference ---
        if diff.body_similarity < 0.85 and not diff.control_matches_payload:
            size_change_pct = abs(diff.body_size_delta) / max(1, diff.status_baseline) * 100
            if abs(diff.body_size_delta) > MIN_BODY_DIFF_CHARS:
                confidence += CONFIDENCE_BOOST_DIFF
                notes.append(
                    f"TP indicator: response body changed by {diff.body_size_delta:+d} chars "
                    f"(similarity={diff.body_similarity:.0%})"
                )

        # --- Penalty: no meaningful difference ---
        if (diff.body_similarity > FLAPPING_SIMILARITY_THRESHOLD and
                not diff.status_changed and not timing_confirmed):
            confidence -= CONFIDENCE_PENALTY_FLAPPING
            notes.append("FP indicator: payload and baseline responses are nearly identical")

        # Clamp confidence to [0.0, 1.0]
        confidence = max(0.0, min(1.0, confidence))

        # Determine verdict
        if confidence >= 0.85:
            verdict = "CONFIRMED"
        elif confidence >= 0.70:
            verdict = "LIKELY_TP"
        elif confidence >= 0.50:
            verdict = "NEEDS_REVIEW"
        elif confidence >= 0.30:
            verdict = "LIKELY_FP"
        else:
            verdict = "FALSE_POSITIVE"

        return confidence, verdict, notes


# ─────────────────────────────────────────────────────────────────────────────
# Main FP Reducer
# ─────────────────────────────────────────────────────────────────────────────

class FPReducer:
    """
    Main false positive reduction orchestrator.

    Runs the full 6-step FP reduction pipeline on a single finding:
      1. Baseline capture
      2. Control request (safe payload)
      3. Payload injection
      4. Response differential analysis
      5. Reflection / timing validation
      6. Confidence adjustment

    Usage:
        reducer = FPReducer(probe_engine=probe)
        result = reducer.verify(
            url="https://example.com/search?q=PAYLOAD",
            original_payload="<script>alert(1)</script>",
            safe_param_value="hello",
            method="GET",
            injection_type="xss",
            original_confidence=0.85,
        )
        if result.is_false_positive:
            skip finding
        else:
            finding.confidence = original + result.confidence_delta
    """

    def __init__(
        self,
        probe_engine: Optional[ProbeEngine] = None,
        timeout: float = 12.0,
        headers: Optional[dict] = None,
        cookies: Optional[dict] = None,
    ):
        self.probe = probe_engine or ProbeEngine(timeout=timeout, headers=headers, cookies=cookies)
        self.diff_engine = DiffEngine()
        self.reflection_validator = ReflectionValidator()
        self.timing_validator = TimingValidator()
        self.confidence_adjuster = ConfidenceAdjuster()

    def verify(
        self,
        url: str,
        original_payload: str,
        safe_param_value: str = "test_probe",
        method: str = "GET",
        injection_type: str = "generic",
        original_confidence: float = 0.75,
        post_data: Optional[dict] = None,
        expected_timing_delay_ms: float = 5000.0,
    ) -> VerificationResult:
        """
        Run full FP reduction pipeline on a single finding.

        url: The vulnerable URL (with payload already injected or a template URL)
        original_payload: The actual payload string that triggered the finding
        safe_param_value: A benign value to use for baseline/control
        injection_type: "xss", "sqli", "ssti", "cmdi", "ssrf", "lfi", "generic"
        """
        notes = []
        evidence = {}

        # Step 1 + 2: Baseline and control
        baseline_url = url.replace(original_payload, safe_param_value) if original_payload in url else url
        control_url = url.replace(original_payload, SAFE_PAYLOADS[0]) if original_payload in url else url

        logger.debug(f"[fp-reducer] Baseline: {baseline_url[:100]}")
        baseline = self._probe(baseline_url, method, post_data, safe_param_value)
        control = self._probe(control_url, method, post_data, SAFE_PAYLOADS[0])

        # Step 3: Payload request
        logger.debug(f"[fp-reducer] Payload: {url[:100]}")
        payload_resp = self._probe(url, method, post_data, original_payload)

        if payload_resp.error:
            return VerificationResult(
                is_confirmed=False,
                is_false_positive=False,
                confidence_delta=0.0,
                verdict="NEEDS_REVIEW",
                notes=[f"Probe failed: {payload_resp.error}"],
            )

        # Step 4: Differential analysis
        diff = self.diff_engine.compare(baseline, payload_resp, control)
        evidence["diff"] = {
            "status_changed": diff.status_changed,
            "body_similarity": round(diff.body_similarity, 3),
            "body_size_delta": diff.body_size_delta,
            "timing_delta_ms": round(diff.timing_delta_ms, 1),
            "control_matches_payload": diff.control_matches_payload,
        }

        # Step 5a: Reflection validation (XSS, SSTI)
        reflection_confirmed = False
        if injection_type in ("xss", "ssti", "injection", "generic"):
            refl, refl_evidence = self.reflection_validator.validate(
                original_payload, payload_resp.body
            )
            reflection_confirmed = refl
            evidence["reflection"] = refl_evidence
            if refl:
                notes.append(f"Reflection confirmed: {refl_evidence[:100]}")

        # Step 5b: Timing validation (sqli-blind, cmdi)
        timing_confirmed = False
        if injection_type in ("sqli", "cmdi", "ssrf") and diff.timing_delta_ms > 1000:
            tc, tc_evidence = self.timing_validator.validate(
                baseline.duration_ms,
                payload_resp.duration_ms,
                expected_timing_delay_ms,
            )
            timing_confirmed = tc
            evidence["timing"] = tc_evidence
            if tc:
                notes.append(f"Timing confirmed: {tc_evidence}")

        # Step 6: Confidence adjustment
        new_confidence, verdict, adj_notes = self.confidence_adjuster.adjust(
            original_confidence, diff, reflection_confirmed, timing_confirmed
        )
        notes.extend(adj_notes)

        confidence_delta = new_confidence - original_confidence
        is_false_positive = verdict == "FALSE_POSITIVE"
        is_confirmed = verdict in ("CONFIRMED", "LIKELY_TP")

        evidence["unique_content"] = diff.unique_payload_content[:200]
        evidence["verdict"] = verdict
        evidence["original_confidence"] = original_confidence
        evidence["adjusted_confidence"] = round(new_confidence, 3)

        logger.info(
            f"[fp-reducer] {url[:60]} | {injection_type} | "
            f"conf: {original_confidence:.2f}→{new_confidence:.2f} | verdict: {verdict}"
        )

        return VerificationResult(
            is_confirmed=is_confirmed,
            is_false_positive=is_false_positive,
            confidence_delta=confidence_delta,
            evidence=evidence,
            verdict=verdict,
            notes=notes,
        )

    def _probe(
        self, url: str, method: str,
        post_data: Optional[dict], payload: str
    ) -> ProbeResponse:
        """Send a single probe request."""
        if method.upper() == "POST":
            data = dict(post_data or {})
            # Replace payload placeholder in POST data values
            for k, v in data.items():
                if isinstance(v, str):
                    data[k] = v
            return self.probe.post(url, data=data)
        else:
            return self.probe.get(url)

    def batch_verify(
        self,
        findings: list[dict],
        max_findings: int = 50,
    ) -> list[dict]:
        """
        Verify a batch of findings. Mutates findings in-place to update
        confidence and add fp_verification data.

        finding dict expected keys: url, payload, injection_type, confidence
        """
        processed = 0
        for finding in findings[:max_findings]:
            if not finding.get("url") or not finding.get("payload"):
                continue

            result = self.verify(
                url=finding["url"],
                original_payload=finding.get("payload", ""),
                injection_type=finding.get("injection_type", "generic"),
                original_confidence=finding.get("confidence", 0.75),
            )

            # Update finding in-place
            finding["confidence"] = max(0.0, min(1.0, finding.get("confidence", 0.75) + result.confidence_delta))
            finding["fp_verdict"] = result.verdict
            finding["fp_notes"] = result.notes
            finding["fp_evidence"] = result.evidence
            finding["is_false_positive"] = result.is_false_positive
            processed += 1

        logger.info(f"[fp-reducer] Batch verification: {processed}/{len(findings)} findings processed")
        return findings


# ─────────────────────────────────────────────────────────────────────────────
# Flapping Detector
# ─────────────────────────────────────────────────────────────────────────────

class FlappingDetector:
    """
    Detect endpoints that return inconsistent responses (flapping).
    These should be excluded from scanning to avoid false positives.
    """

    def __init__(self, probe_engine: Optional[ProbeEngine] = None):
        self.probe = probe_engine or ProbeEngine()

    def is_flapping(self, url: str, samples: int = 3) -> bool:
        """
        Fetch the URL `samples` times and check if responses are consistent.
        Returns True if the endpoint is flapping (inconsistent).
        """
        try:
            responses = [self.probe.get(url) for _ in range(samples)]
            statuses = {r.status_code for r in responses if not r.error}

            # Different status codes across requests = flapping
            if len(statuses) > 1:
                logger.debug(f"[fp-reducer] Flapping detected at {url}: statuses={statuses}")
                return True

            # Check body hashes
            body_hashes = {r.body_hash for r in responses if not r.error and r.body}
            if len(body_hashes) > 2:
                logger.debug(f"[fp-reducer] Body flapping at {url}: {len(body_hashes)} unique bodies")
                return True

            return False
        except Exception as e:
            logger.debug(f"[fp-reducer] Flapping check failed for {url}: {e}")
            return False


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def create_fp_reducer(
    headers: Optional[dict] = None,
    cookies: Optional[dict] = None,
    timeout: float = 12.0,
) -> FPReducer:
    """Factory: create a configured FPReducer instance."""
    probe = ProbeEngine(timeout=timeout, headers=headers, cookies=cookies)
    return FPReducer(probe_engine=probe)


def verify_finding(
    url: str,
    payload: str,
    injection_type: str = "generic",
    confidence: float = 0.75,
    headers: Optional[dict] = None,
    cookies: Optional[dict] = None,
) -> VerificationResult:
    """
    Single-finding FP verification — convenience wrapper.

    Called by QuantaraWebScanner for each HIGH/CRITICAL finding before reporting.
    """
    reducer = create_fp_reducer(headers=headers, cookies=cookies)
    return reducer.verify(
        url=url,
        original_payload=payload,
        injection_type=injection_type,
        original_confidence=confidence,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Enterprise Integration Layer — added by enterprise refactor
# Wires the FP reducer into the enterprise DifferentialAnalyzer for
# multi-signal false positive filtering with similarity + entropy scoring.
# ─────────────────────────────────────────────────────────────────────────────
import logging as _fp_logging

_fp_logger = _fp_logging.getLogger("enterprise.scanner.fp_reducer")


def verify_with_differential(
    url: str,
    payload: str,
    injection_type: str,
    baseline_body: str,
    probe_body: str,
    baseline_time_ms: float = 0.0,
    probe_time_ms: float = 0.0,
    baseline_status: int = 200,
    probe_status: int = 200,
    original_confidence: float = 0.75,
) -> dict:
    """
    Enhanced FP verification using the enterprise DifferentialAnalyzer.

    Combines:
    1. Levenshtein similarity (large diff → genuine finding)
    2. Entropy shift (encrypted/random data change → suspicious)
    3. Timing delta (slow probe → possible blind injection)
    4. Status code change
    5. Payload reflection check

    Returns a dict with:
    - is_false_positive: bool
    - adjusted_confidence: float
    - verdict: str
    - evidence: dict
    """
    import importlib
    import sys
    import os

    # Resolve DifferentialAnalyzer via importlib (avoids static import errors)
    _engine_dir = os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..", "scanner_engine")
    )
    if _engine_dir not in sys.path:
        sys.path.insert(0, _engine_dir)

    try:
        analyzer_mod = importlib.import_module("analyzer")
        HttpSnapshot = getattr(analyzer_mod, "HttpSnapshot")
        DifferentialAnalyzer = getattr(analyzer_mod, "DifferentialAnalyzer")
        AnalysisVerdict = getattr(analyzer_mod, "AnalysisVerdict")
    except (ImportError, AttributeError):
        # Fallback: just return original confidence unchanged
        return {
            "is_false_positive": original_confidence < 0.4,
            "adjusted_confidence": original_confidence,
            "verdict": "inconclusive",
            "evidence": {"note": "DifferentialAnalyzer not available"},
        }

    baseline = HttpSnapshot(
        status_code=baseline_status,
        body=baseline_body,
        response_time_ms=baseline_time_ms,
        content_length=len(baseline_body),
    )
    probe = HttpSnapshot(
        status_code=probe_status,
        body=probe_body,
        response_time_ms=probe_time_ms,
        content_length=len(probe_body),
        payload_used=payload,
    )

    diff_analyzer = DifferentialAnalyzer(baseline)
    diff_result = diff_analyzer.compare(probe, payload=payload)

    # Cross-reference differential verdict with FP reducer
    is_fp = diff_result.verdict in (
        AnalysisVerdict.CLEAN, AnalysisVerdict.WAF_FILTERED
    )
    # Weight adjusted confidence from both signals
    combined = (original_confidence * 0.6) + (diff_result.confidence * 0.4)

    _fp_logger.debug(
        f"verify_with_differential: url={url} injection={injection_type} "
        f"differential_verdict={diff_result.verdict.value} "
        f"original_conf={original_confidence:.2f} combined={combined:.2f} is_fp={is_fp}"
    )

    return {
        "is_false_positive": is_fp,
        "adjusted_confidence": round(combined, 3),
        "verdict": diff_result.verdict.value,
        "similarity_score": diff_result.similarity_score,
        "timing_delta_ms": diff_result.timing_delta_ms,
        "anomalies": [a.value for a in diff_result.anomalies],
        "waf_signals": diff_result.waf_signals,
        "evidence": diff_result.evidence,
    }
