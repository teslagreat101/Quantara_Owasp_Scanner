"""
Quantara AI Security Copilot Layer
=====================================

Phase 10 of the Quantara enterprise scanner pipeline.

Multi-LLM provider with automatic fallback chain:
  1. Gemini (google-generativeai) — primary, cheapest
  2. Anthropic Claude              — secondary fallback
  3. OpenAI GPT                    — tertiary fallback

API keys read from environment:
  GEMINI_API_KEY      — Google Gemini
  ANTROPHIC_API_KEY   — Anthropic Claude (note: typo in .env — missing H)
  ANTHROPIC_API_KEY   — also checked as canonical spelling
  OPENAI_API_KEY      — OpenAI

Fallback triggers:
  - Quota exhausted (429 / ResourceExhausted)
  - Rate limit hit
  - Service unavailable
  - Import error (package not installed)

Capabilities:
  1. Finding Validation — TRUE_POSITIVE / FALSE_POSITIVE / NEEDS_REVIEW
  2. False Positive Reduction — AI-verified confidence scores
  3. Impact Explanation — Business-language impact description
  4. Remediation Code Generation — Language-specific fix suggestions
  5. POC Fix Intelligence — Step-by-step fix code for POC verification panel
  6. Risk Prioritization — AI-sorted priority ranking
  7. Attack Narrative Generation — "An attacker could..." story
  8. Template Suggestion — Suggest new scan templates based on tech stack

Architecture:
  MultiLLMProvider  — manages all three LLM backends + fallback logic
  CopilotConfig     — model, API keys, cost controls
  FindingPromptBuilder — builds structured prompts for each analysis type
  QuantaraAICopilot — main AI copilot class
      ├─ validate_finding()      — TP/FP verdict for one finding
      ├─ explain_impact()        — business impact explanation
      ├─ generate_remediation()  — code-level fix suggestion
      ├─ generate_poc_fix()      — real-time POC verification fix intelligence
      ├─ prioritize_findings()   — AI-sorted risk priority list
      ├─ narrate_attack_chain()  — attack narrative from chain
      ├─ suggest_templates()     — new template suggestions from tech stack
      └─ batch_analyze()         — efficient batch processing
  ResultCache — in-memory cache keyed by finding hash
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger("owasp_scanner.quantara_ai")

# ─────────────────────────────────────────────────────────────────────────────
# Multi-LLM Provider
# ─────────────────────────────────────────────────────────────────────────────

# Quota / rate-limit error signatures for each provider
_QUOTA_ERRORS = {
    "gemini": (
        "ResourceExhausted",
        "quota",
        "429",
        "RESOURCE_EXHAUSTED",
        "exceeded",
    ),
    "anthropic": (
        "rate_limit",
        "RateLimitError",
        "429",
        "overloaded",
        "529",
    ),
    "openai": (
        "RateLimitError",
        "rate_limit",
        "429",
        "quota",
        "insufficient_quota",
    ),
}


def _is_quota_error(provider: str, exc: Exception) -> bool:
    """Return True if the exception looks like a quota / rate-limit error."""
    msg = str(exc).lower()
    exc_type = type(exc).__name__
    signatures = _QUOTA_ERRORS.get(provider, ())
    return any(sig.lower() in msg or sig.lower() in exc_type.lower() for sig in signatures)


class MultiLLMProvider:
    """
    Manages three LLM backends with automatic failover.

    Priority order: Gemini → Anthropic → OpenAI
    Falls back to next provider on quota/rate-limit errors.
    Permanent failures (wrong key, import error) also skip to next provider.
    """

    PROVIDER_ORDER = ["gemini", "anthropic", "openai"]

    def __init__(
        self,
        gemini_key: str = "",
        anthropic_key: str = "",
        openai_key: str = "",
        gemini_model: str = "gemini-1.5-flash",
        anthropic_model: str = "claude-haiku-4-5",
        openai_model: str = "gpt-4o-mini",
        max_tokens: int = 1024,
        temperature: float = 0.1,
        timeout: float = 30.0,
    ):
        self.keys = {
            "gemini": gemini_key or os.environ.get("GEMINI_API_KEY", ""),
            "anthropic": (
                anthropic_key
                or os.environ.get("ANTHROPIC_API_KEY", "")
                or os.environ.get("ANTROPHIC_API_KEY", "")   # typo in .env
            ),
            "openai": openai_key or os.environ.get("OPENAI_API_KEY", ""),
        }
        self.models = {
            "gemini": gemini_model,
            "anthropic": anthropic_model,
            "openai": openai_model,
        }
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.timeout = timeout

        # State
        self._clients: dict[str, Any] = {}
        self._disabled: set[str] = set()   # providers permanently disabled
        self._current_provider: Optional[str] = None
        self._tokens_used: dict[str, int] = {"gemini": 0, "anthropic": 0, "openai": 0}
        self._calls_made: dict[str, int] = {"gemini": 0, "anthropic": 0, "openai": 0}

        self._init_all()

    # ── Init ──────────────────────────────────────────────────────────────────

    def _init_all(self) -> None:
        """Try to initialize each provider client."""
        for provider in self.PROVIDER_ORDER:
            if not self.keys[provider]:
                logger.info(f"[multi-llm] {provider}: no API key — skipping")
                self._disabled.add(provider)
                continue
            try:
                self._init_provider(provider)
            except Exception as e:
                logger.warning(f"[multi-llm] {provider}: init failed — {e}")
                self._disabled.add(provider)

        active = [p for p in self.PROVIDER_ORDER if p not in self._disabled]
        if active:
            self._current_provider = active[0]
            logger.info(f"[multi-llm] Active providers: {active} (primary: {active[0]})")
        else:
            logger.warning("[multi-llm] No LLM providers available — AI analysis disabled")

    def _init_provider(self, provider: str) -> None:
        if provider == "gemini":
            import google.generativeai as genai  # type: ignore
            genai.configure(api_key=self.keys["gemini"])
            self._clients["gemini"] = genai
            logger.info(f"[multi-llm] Gemini initialized (model: {self.models['gemini']})")

        elif provider == "anthropic":
            import anthropic  # type: ignore
            self._clients["anthropic"] = anthropic.Anthropic(
                api_key=self.keys["anthropic"]
            )
            logger.info(f"[multi-llm] Anthropic initialized (model: {self.models['anthropic']})")

        elif provider == "openai":
            from openai import OpenAI  # type: ignore
            self._clients["openai"] = OpenAI(api_key=self.keys["openai"])
            logger.info(f"[multi-llm] OpenAI initialized (model: {self.models['openai']})")

    # ── Per-provider API calls ────────────────────────────────────────────────

    def _call_gemini(self, prompt: str, system: str) -> tuple[str, int]:
        genai = self._clients["gemini"]
        full_prompt = f"{system}\n\n{prompt}" if system else prompt
        model = genai.GenerativeModel(self.models["gemini"])
        response = model.generate_content(
            full_prompt,
            generation_config=genai.GenerationConfig(
                max_output_tokens=self.max_tokens,
                temperature=self.temperature,
            ),
        )
        text = response.text if hasattr(response, "text") else ""
        # Gemini doesn't always expose token counts; estimate
        tokens = len(text.split()) * 2
        return text, tokens

    def _call_anthropic(self, prompt: str, system: str) -> tuple[str, int]:
        client = self._clients["anthropic"]
        response = client.messages.create(
            model=self.models["anthropic"],
            max_tokens=self.max_tokens,
            temperature=self.temperature,
            system=system,
            messages=[{"role": "user", "content": prompt}],
        )
        text = response.content[0].text if response.content else ""
        tokens = response.usage.input_tokens + response.usage.output_tokens
        return text, tokens

    def _call_openai(self, prompt: str, system: str) -> tuple[str, int]:
        client = self._clients["openai"]
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        response = client.chat.completions.create(
            model=self.models["openai"],
            messages=messages,
            max_tokens=self.max_tokens,
            temperature=self.temperature,
        )
        text = response.choices[0].message.content or ""
        tokens = response.usage.total_tokens if response.usage else 0
        return text, tokens

    _DISPATCH = {
        "gemini": "_call_gemini",
        "anthropic": "_call_anthropic",
        "openai": "_call_openai",
    }

    # ── Main call with fallback ───────────────────────────────────────────────

    def call(self, prompt: str, system: str = "") -> tuple[str, int, str]:
        """
        Call the best available LLM provider with automatic fallback.

        Returns: (response_text, tokens_used, provider_used)
        """
        for provider in self.PROVIDER_ORDER:
            if provider in self._disabled:
                continue
            if provider not in self._clients:
                continue

            try:
                method = getattr(self, self._DISPATCH[provider])
                text, tokens = method(prompt, system)
                self._tokens_used[provider] += tokens
                self._calls_made[provider] += 1
                self._current_provider = provider
                logger.debug(
                    f"[multi-llm] {provider} call OK — {tokens} tokens"
                )
                return text, tokens, provider

            except Exception as exc:
                if _is_quota_error(provider, exc):
                    logger.warning(
                        f"[multi-llm] {provider} quota/rate-limit hit — "
                        f"falling back to next provider. Error: {exc}"
                    )
                    # Don't permanently disable on quota — may recover later
                    # But skip for this call sequence
                else:
                    logger.warning(
                        f"[multi-llm] {provider} error ({type(exc).__name__}) — "
                        f"disabling provider. Error: {exc}"
                    )
                    self._disabled.add(provider)

        logger.error("[multi-llm] All LLM providers failed or exhausted")
        return "", 0, "none"

    @property
    def is_available(self) -> bool:
        return any(
            p not in self._disabled and p in self._clients
            for p in self.PROVIDER_ORDER
        )

    def get_stats(self) -> dict:
        return {
            "tokens_by_provider": dict(self._tokens_used),
            "calls_by_provider": dict(self._calls_made),
            "active_providers": [
                p for p in self.PROVIDER_ORDER if p not in self._disabled
            ],
            "current_provider": self._current_provider,
            "disabled_providers": list(self._disabled),
        }


# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CopilotConfig:
    """Configuration for the AI Copilot (multi-LLM)."""

    # Provider API keys (read from env if not set)
    gemini_api_key: str = ""
    anthropic_api_key: str = ""
    openai_api_key: str = ""

    # Model selection per provider
    gemini_model: str = "gemini-1.5-flash"         # Fast + cheap Gemini model
    anthropic_model: str = "claude-haiku-4-5"      # Haiku for cost, Sonnet for quality
    openai_model: str = "gpt-4o-mini"              # Cost-efficient OpenAI model

    max_tokens: int = 1024
    temperature: float = 0.1
    timeout: float = 30.0

    # Cost controls
    enabled: bool = True
    analyze_severities: list[str] = field(
        default_factory=lambda: ["CRITICAL", "HIGH"]
    )
    max_findings_per_run: int = 20
    batch_size: int = 5
    cache_ttl: int = 3600

    # Feature flags
    enable_validation: bool = True
    enable_impact: bool = True
    enable_remediation: bool = True
    enable_poc_fix: bool = True          # POC Fix Intelligence
    enable_prioritization: bool = True
    enable_narrative: bool = True
    enable_template_suggestion: bool = False


# ─────────────────────────────────────────────────────────────────────────────
# AI Analysis Results
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AIVerdict:
    finding_id: str
    verdict: str                    # "TRUE_POSITIVE" / "FALSE_POSITIVE" / "NEEDS_REVIEW"
    confidence: float               # 0.0–1.0
    reasoning: str
    suggested_severity: str = ""
    false_positive_reason: str = ""
    provider_used: str = ""


@dataclass
class AIImpact:
    finding_id: str
    business_impact: str
    technical_impact: str
    attack_scenario: str
    affected_assets: list[str] = field(default_factory=list)
    data_at_risk: list[str] = field(default_factory=list)
    compliance_implications: list[str] = field(default_factory=list)
    provider_used: str = ""


@dataclass
class AIRemediation:
    finding_id: str
    language: str
    vulnerable_code: str
    fixed_code: str
    explanation: str
    additional_controls: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    provider_used: str = ""


@dataclass
class AIPocFix:
    """Real-time POC fix intelligence for the scanner POC verification panel."""
    finding_id: str
    vulnerability_type: str         # e.g. "SQL Injection", "XSS"
    poc_description: str            # What the POC demonstrates
    immediate_fix: str              # Quick 1-line or config fix
    full_fix_code: str              # Complete corrected code block
    fix_language: str               # Language of the fix
    fix_explanation: str            # Why this fix works
    test_steps: list[str]           # How to verify the fix works
    prevention_checklist: list[str] # Broader prevention measures
    cvss_score: str                 # Estimated CVSS if determinable
    owasp_category: str             # e.g. "A03:2021 – Injection"
    references: list[str]           # Links to official docs / OWASP
    provider_used: str = ""


@dataclass
class AIPriority:
    finding_id: str
    priority_rank: int
    priority_label: str             # "P1-CRITICAL" / "P2-HIGH" / "P3-MEDIUM" / "P4-LOW"
    urgency: str                    # "immediate" / "this-sprint" / "this-quarter" / "backlog"
    reasoning: str
    provider_used: str = ""


@dataclass
class AIAnalysis:
    finding_id: str
    verdict: Optional[AIVerdict] = None
    impact: Optional[AIImpact] = None
    remediation: Optional[AIRemediation] = None
    poc_fix: Optional[AIPocFix] = None
    priority: Optional[AIPriority] = None
    tokens_used: int = 0
    provider_used: str = ""
    cached: bool = False
    error: str = ""


# ─────────────────────────────────────────────────────────────────────────────
# Result Cache
# ─────────────────────────────────────────────────────────────────────────────

class ResultCache:
    def __init__(self, ttl: int = 3600):
        self.ttl = ttl
        self._store: dict[str, tuple[Any, float]] = {}

    def get(self, key: str) -> Optional[Any]:
        if key in self._store:
            value, expiry = self._store[key]
            if time.time() < expiry:
                return value
            del self._store[key]
        return None

    def set(self, key: str, value: Any) -> None:
        self._store[key] = (value, time.time() + self.ttl)

    def make_key(self, finding: dict) -> str:
        h = hashlib.md5(
            json.dumps({
                "id": finding.get("id", ""),
                "title": finding.get("title", ""),
                "url": finding.get("file", ""),
                "severity": finding.get("severity", ""),
            }, sort_keys=True).encode()
        ).hexdigest()
        return h

    def clear(self) -> None:
        self._store.clear()


# ─────────────────────────────────────────────────────────────────────────────
# Prompt Builder
# ─────────────────────────────────────────────────────────────────────────────

class FindingPromptBuilder:
    """Builds structured prompts for each analysis type."""

    SYSTEM_PROMPT = """You are Quantara's AI Security Copilot — a senior application security expert.
Your role is to analyze vulnerability scan findings and provide:
- Accurate true/false positive verdicts
- Clear business-impact explanations
- Precise code-level remediation guidance
- Real-time POC fix intelligence
- Risk prioritization

Always be concise, accurate, and actionable. Output JSON only (no markdown wrapper).
Base your analysis on the actual evidence provided, not assumptions."""

    def validation_prompt(self, finding: dict) -> str:
        return f"""Analyze this security finding and determine if it is a true or false positive.

FINDING:
- Title: {finding.get('title', 'Unknown')}
- Severity: {finding.get('severity', 'unknown').upper()}
- Location: {finding.get('file', '')}
- Description: {finding.get('description', '')[:500]}
- Evidence: {finding.get('matched_content', '')[:300]}
- Category: {finding.get('category', '')}
- CWE: {finding.get('cwe', '')}
- OWASP: {finding.get('owasp', '')}

Respond with JSON only:
{{
  "verdict": "TRUE_POSITIVE" | "FALSE_POSITIVE" | "NEEDS_REVIEW",
  "confidence": 0.0-1.0,
  "reasoning": "2-3 sentence explanation",
  "suggested_severity": "critical|high|medium|low|info or empty if no change",
  "false_positive_reason": "why it could be FP, or empty string"
}}"""

    def impact_prompt(self, finding: dict) -> str:
        return f"""Explain the business and technical impact of this security finding.

FINDING:
- Title: {finding.get('title', 'Unknown')}
- Severity: {finding.get('severity', 'unknown').upper()}
- Location: {finding.get('file', '')}
- Description: {finding.get('description', '')[:500]}
- CWE: {finding.get('cwe', '')}

Respond with JSON only:
{{
  "business_impact": "What happens to the business if exploited (1-2 sentences)",
  "technical_impact": "Technical system impact (1-2 sentences)",
  "attack_scenario": "An attacker could... (2-3 step scenario)",
  "affected_assets": ["list of affected systems/data types"],
  "data_at_risk": ["types of data that could be stolen/modified"],
  "compliance_implications": ["relevant compliance frameworks affected, e.g. PCI-DSS, GDPR"]
}}"""

    def remediation_prompt(self, finding: dict) -> str:
        lang = finding.get("language", "")
        return f"""Provide code-level remediation for this security finding.

FINDING:
- Title: {finding.get('title', 'Unknown')}
- Language/Framework: {lang or 'detect from context'}
- Description: {finding.get('description', '')[:500]}
- Evidence (vulnerable code): {finding.get('matched_content', '')[:300]}
- CWE: {finding.get('cwe', '')}

Respond with JSON only:
{{
  "language": "detected/specified language",
  "vulnerable_code": "Example of the vulnerable pattern (pseudocode if needed)",
  "fixed_code": "The corrected code snippet",
  "explanation": "Why this fix resolves the vulnerability",
  "additional_controls": ["other security controls to add"],
  "references": ["OWASP cheat sheet or official docs URL"]
}}"""

    def poc_fix_prompt(self, finding: dict) -> str:
        """Generate comprehensive POC fix intelligence for the verification panel."""
        return f"""You are reviewing a confirmed security vulnerability from a POC (Proof of Concept) test.
Generate complete, production-ready fix intelligence for the development team.

VULNERABILITY DETAILS:
- Title: {finding.get('title', 'Unknown')}
- Type: {finding.get('category', finding.get('cwe', 'Unknown'))}
- Severity: {finding.get('severity', 'unknown').upper()}
- Target: {finding.get('file', finding.get('url', ''))}
- POC Evidence: {finding.get('matched_content', finding.get('description', ''))[:400]}
- Request Method: {finding.get('method', 'GET')}
- Parameter: {finding.get('parameter', 'Unknown')}
- CWE: {finding.get('cwe', '')}
- OWASP: {finding.get('owasp', '')}

Provide a COMPLETE, ACCURATE fix guide. Include real code examples, not pseudocode.

Respond with JSON only:
{{
  "vulnerability_type": "Human-readable vulnerability type",
  "poc_description": "What this POC demonstrates in 1-2 sentences",
  "immediate_fix": "Single most critical 1-line change or config to patch immediately",
  "full_fix_code": "Complete corrected code block with comments explaining each security control",
  "fix_language": "Language/framework of the fix code",
  "fix_explanation": "Why this fix eliminates the vulnerability (technical reasoning)",
  "test_steps": [
    "Step 1: How to verify the fix works",
    "Step 2: Re-run the original POC and confirm failure",
    "Step 3: Run security tests"
  ],
  "prevention_checklist": [
    "Broader prevention measure 1",
    "Broader prevention measure 2"
  ],
  "cvss_score": "Estimated CVSS 3.1 base score and vector string",
  "owasp_category": "OWASPcat e.g. A03:2021 – Injection",
  "references": [
    "https://owasp.org/... or official docs URL"
  ]
}}"""

    def batch_validation_prompt(self, findings: list[dict]) -> str:
        findings_text = []
        for i, f in enumerate(findings):
            findings_text.append(
                f"[{i+1}] Title: {f.get('title','')} | Severity: {f.get('severity','').upper()} "
                f"| Location: {f.get('file','')[:80]} | Evidence: {f.get('matched_content','')[:150]}"
            )

        return f"""Analyze these {len(findings)} security findings for true/false positive verdict.

FINDINGS:
{chr(10).join(findings_text)}

Respond with JSON array only (one object per finding, in order):
[
  {{
    "index": 1,
    "verdict": "TRUE_POSITIVE" | "FALSE_POSITIVE" | "NEEDS_REVIEW",
    "confidence": 0.0-1.0,
    "reasoning": "brief explanation"
  }},
  ...
]"""

    def prioritization_prompt(self, findings: list[dict]) -> str:
        findings_text = []
        for i, f in enumerate(findings):
            findings_text.append(
                f"[{i+1}] ID:{f.get('id','')} | {f.get('title','')} | {f.get('severity','').upper()} "
                f"| CWE:{f.get('cwe','')} | OWASP:{f.get('owasp','')}"
            )

        return f"""Prioritize these {len(findings)} security findings by risk and remediation urgency.

FINDINGS:
{chr(10).join(findings_text)}

Consider: exploitability, business impact, ease of remediation, regulatory requirements.

Respond with JSON array ordered by priority (highest first):
[
  {{
    "index": original_index_number,
    "priority_rank": 1-{len(findings)},
    "priority_label": "P1-CRITICAL" | "P2-HIGH" | "P3-MEDIUM" | "P4-LOW",
    "urgency": "immediate" | "this-sprint" | "this-quarter" | "backlog",
    "reasoning": "brief justification"
  }},
  ...
]"""

    def narrative_prompt(self, chain_dict: dict) -> str:
        nodes = chain_dict.get("nodes", [])
        steps_text = "\n".join(
            f"  Step {n.get('step',i+1)}: [{n.get('severity','')}] {n.get('title','')} at {n.get('url','')}"
            for i, n in enumerate(nodes)
        )

        return f"""Write a concise penetration tester's attack narrative for this multi-step attack chain.

ATTACK CHAIN: {chain_dict.get('title','')}
BUSINESS IMPACT: {chain_dict.get('business_impact', '')}

STEPS:
{steps_text}

Write a 3-5 paragraph narrative in the style of a penetration test report:
- Start with "An attacker could..."
- Explain each step clearly for a technical audience
- End with business impact and urgency

Respond with JSON only:
{{
  "narrative": "Full attack narrative text",
  "summary": "One sentence executive summary",
  "estimated_time_to_exploit": "e.g. 2-4 hours for a skilled attacker"
}}"""

    def template_suggestion_prompt(self, tech_stack: list[str], existing_templates: list[str]) -> str:
        return f"""Based on the detected technology stack, suggest 3-5 new vulnerability scan templates.

DETECTED TECHNOLOGIES: {', '.join(tech_stack)}
EXISTING TEMPLATES (do not duplicate): {', '.join(existing_templates[:20])}

Suggest templates that target technology-specific vulnerabilities not already covered.

Respond with JSON array:
[
  {{
    "template_id": "unique-kebab-case-id",
    "name": "Template Name",
    "description": "What vulnerability it detects",
    "severity": "critical|high|medium|low",
    "owasp": "A03:2021",
    "detection_method": "Brief description of how to detect it"
  }}
]"""


# ─────────────────────────────────────────────────────────────────────────────
# Main AI Copilot
# ─────────────────────────────────────────────────────────────────────────────

class QuantaraAICopilot:
    """
    AI Security Copilot with multi-LLM provider fallback.

    Provider priority: Gemini → Anthropic → OpenAI
    Automatically falls back on quota/rate-limit errors.

    Usage:
        copilot = QuantaraAICopilot(CopilotConfig())
        analyses = copilot.batch_analyze(findings)

        # POC Fix Intelligence (real-time):
        poc_fix = copilot.generate_poc_fix(finding)
        print(poc_fix.full_fix_code)
    """

    def __init__(self, config: Optional[CopilotConfig] = None):
        self.config = config or CopilotConfig()
        self._cache = ResultCache(ttl=self.config.cache_ttl)
        self._prompt_builder = FindingPromptBuilder()
        self._provider: Optional[MultiLLMProvider] = None
        self._total_tokens = 0
        self._total_calls = 0

        if self.config.enabled:
            self._init_provider()

    def _init_provider(self) -> None:
        """Initialize the multi-LLM provider."""
        try:
            self._provider = MultiLLMProvider(
                gemini_key=self.config.gemini_api_key,
                anthropic_key=self.config.anthropic_api_key,
                openai_key=self.config.openai_api_key,
                gemini_model=self.config.gemini_model,
                anthropic_model=self.config.anthropic_model,
                openai_model=self.config.openai_model,
                max_tokens=self.config.max_tokens,
                temperature=self.config.temperature,
                timeout=self.config.timeout,
            )
            if not self._provider.is_available:
                logger.warning(
                    "[ai-copilot] No LLM providers available. "
                    "Set GEMINI_API_KEY, ANTROPHIC_API_KEY, or OPENAI_API_KEY."
                )
                self.config.enabled = False
        except Exception as e:
            logger.error(f"[ai-copilot] Provider init error: {e}")
            self.config.enabled = False

    # ── Core LLM Call ─────────────────────────────────────────────────────────

    def _call_llm(self, prompt: str, system: Optional[str] = None) -> tuple[str, int, str]:
        """
        Call the best available LLM with automatic fallback.
        Returns (text, tokens, provider_used).
        """
        if not self._provider or not self.config.enabled:
            return "", 0, "none"

        text, tokens, provider = self._provider.call(
            prompt,
            system=system or self._prompt_builder.SYSTEM_PROMPT,
        )
        self._total_tokens += tokens
        self._total_calls += 1
        return text, tokens, provider

    def _parse_json(self, text: str) -> Optional[Any]:
        """Parse JSON from LLM response, handling markdown code blocks."""
        if not text:
            return None
        text = text.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            import re
            m = re.search(r"[\[{].*[\]}]", text, re.DOTALL)
            if m:
                try:
                    return json.loads(m.group(0))
                except Exception:
                    pass
        logger.debug(f"[ai-copilot] Failed to parse JSON from: {text[:200]}")
        return None

    # ── Analysis Methods ──────────────────────────────────────────────────────

    def validate_finding(self, finding: dict) -> Optional[AIVerdict]:
        """Run AI validation on a single finding (TP/FP verdict)."""
        if not self.config.enable_validation or not self.config.enabled:
            return None

        cache_key = f"verdict:{self._cache.make_key(finding)}"
        cached = self._cache.get(cache_key)
        if cached:
            return cached

        prompt = self._prompt_builder.validation_prompt(finding)
        text, tokens, provider = self._call_llm(prompt)
        data = self._parse_json(text)

        if data and isinstance(data, dict):
            verdict = AIVerdict(
                finding_id=finding.get("id", ""),
                verdict=data.get("verdict", "NEEDS_REVIEW"),
                confidence=float(data.get("confidence", 0.5)),
                reasoning=data.get("reasoning", ""),
                suggested_severity=data.get("suggested_severity", ""),
                false_positive_reason=data.get("false_positive_reason", ""),
                provider_used=provider,
            )
            self._cache.set(cache_key, verdict)
            return verdict
        return None

    def explain_impact(self, finding: dict) -> Optional[AIImpact]:
        """Generate business impact explanation for a finding."""
        if not self.config.enable_impact or not self.config.enabled:
            return None

        cache_key = f"impact:{self._cache.make_key(finding)}"
        cached = self._cache.get(cache_key)
        if cached:
            return cached

        prompt = self._prompt_builder.impact_prompt(finding)
        text, tokens, provider = self._call_llm(prompt)
        data = self._parse_json(text)

        if data and isinstance(data, dict):
            impact = AIImpact(
                finding_id=finding.get("id", ""),
                business_impact=data.get("business_impact", ""),
                technical_impact=data.get("technical_impact", ""),
                attack_scenario=data.get("attack_scenario", ""),
                affected_assets=data.get("affected_assets", []),
                data_at_risk=data.get("data_at_risk", []),
                compliance_implications=data.get("compliance_implications", []),
                provider_used=provider,
            )
            self._cache.set(cache_key, impact)
            return impact
        return None

    def generate_remediation(self, finding: dict) -> Optional[AIRemediation]:
        """Generate code-level remediation for a finding."""
        if not self.config.enable_remediation or not self.config.enabled:
            return None

        cache_key = f"remediation:{self._cache.make_key(finding)}"
        cached = self._cache.get(cache_key)
        if cached:
            return cached

        prompt = self._prompt_builder.remediation_prompt(finding)
        text, tokens, provider = self._call_llm(prompt)
        data = self._parse_json(text)

        if data and isinstance(data, dict):
            remediation = AIRemediation(
                finding_id=finding.get("id", ""),
                language=data.get("language", ""),
                vulnerable_code=data.get("vulnerable_code", ""),
                fixed_code=data.get("fixed_code", ""),
                explanation=data.get("explanation", ""),
                additional_controls=data.get("additional_controls", []),
                references=data.get("references", []),
                provider_used=provider,
            )
            self._cache.set(cache_key, remediation)
            return remediation
        return None

    def generate_poc_fix(self, finding: dict) -> Optional[AIPocFix]:
        """
        Generate comprehensive POC fix intelligence for the verification panel.

        This is called when a finding has been confirmed via POC and the user
        clicks "Generate Fix" in the Quantara scanner UI. Returns a complete,
        production-ready fix guide with test verification steps.
        """
        if not self.config.enable_poc_fix or not self.config.enabled:
            return None

        cache_key = f"poc_fix:{self._cache.make_key(finding)}"
        cached = self._cache.get(cache_key)
        if cached:
            return cached

        prompt = self._prompt_builder.poc_fix_prompt(finding)
        text, tokens, provider = self._call_llm(prompt)
        data = self._parse_json(text)

        if data and isinstance(data, dict):
            poc_fix = AIPocFix(
                finding_id=finding.get("id", ""),
                vulnerability_type=data.get("vulnerability_type", ""),
                poc_description=data.get("poc_description", ""),
                immediate_fix=data.get("immediate_fix", ""),
                full_fix_code=data.get("full_fix_code", ""),
                fix_language=data.get("fix_language", ""),
                fix_explanation=data.get("fix_explanation", ""),
                test_steps=data.get("test_steps", []),
                prevention_checklist=data.get("prevention_checklist", []),
                cvss_score=data.get("cvss_score", ""),
                owasp_category=data.get("owasp_category", ""),
                references=data.get("references", []),
                provider_used=provider,
            )
            self._cache.set(cache_key, poc_fix)
            logger.info(
                f"[ai-copilot] POC fix generated for {finding.get('id','')} "
                f"via {provider}"
            )
            return poc_fix
        return None

    def prioritize_findings(self, findings: list[dict]) -> list[AIPriority]:
        """AI-rank a list of findings by risk priority."""
        if not self.config.enable_prioritization or not self.config.enabled or not findings:
            return []

        prompt = self._prompt_builder.prioritization_prompt(findings)
        text, tokens, provider = self._call_llm(prompt)
        data = self._parse_json(text)

        priorities = []
        if data and isinstance(data, list):
            for item in data:
                idx = item.get("index", 0) - 1
                finding_id = findings[idx].get("id", "") if 0 <= idx < len(findings) else ""
                priorities.append(AIPriority(
                    finding_id=finding_id,
                    priority_rank=item.get("priority_rank", 0),
                    priority_label=item.get("priority_label", "P4-LOW"),
                    urgency=item.get("urgency", "backlog"),
                    reasoning=item.get("reasoning", ""),
                    provider_used=provider,
                ))
        return priorities

    def narrate_attack_chain(self, chain_dict: dict) -> Optional[dict]:
        """Generate attack narrative for an attack chain."""
        if not self.config.enable_narrative or not self.config.enabled:
            return None

        prompt = self._prompt_builder.narrative_prompt(chain_dict)
        text, tokens, provider = self._call_llm(prompt)
        result = self._parse_json(text)
        if result and isinstance(result, dict):
            result["provider_used"] = provider
        return result

    def suggest_templates(
        self, tech_stack: list[str], existing_templates: list[str]
    ) -> list[dict]:
        """Suggest new scan templates based on tech stack."""
        if not self.config.enable_template_suggestion or not self.config.enabled:
            return []

        prompt = self._prompt_builder.template_suggestion_prompt(tech_stack, existing_templates)
        text, tokens, provider = self._call_llm(prompt)
        data = self._parse_json(text)
        return data if isinstance(data, list) else []

    # ── Batch Processing ──────────────────────────────────────────────────────

    def batch_analyze(
        self, findings: list[dict], skip_low_severity: bool = True
    ) -> list[AIAnalysis]:
        """
        Batch analyze findings efficiently.

        Filters to HIGH/CRITICAL by default, uses caching, processes in order.
        Each finding gets: verdict, impact, remediation, poc_fix.
        """
        if not self.config.enabled:
            logger.info("[ai-copilot] AI analysis disabled — skipping")
            return []

        eligible = [
            f for f in findings
            if not skip_low_severity
            or f.get("severity", "").upper() in self.config.analyze_severities
        ]
        eligible = eligible[:self.config.max_findings_per_run]

        if not eligible:
            logger.info("[ai-copilot] No eligible findings for AI analysis")
            return []

        logger.info(
            f"[ai-copilot] Batch analyzing {len(eligible)} findings "
            f"(provider chain: {' → '.join(MultiLLMProvider.PROVIDER_ORDER)})"
        )
        analyses = []

        for finding in eligible:
            cache_key = self._cache.make_key(finding)
            cached = self._cache.get(f"full:{cache_key}")
            if cached:
                cached.cached = True
                analyses.append(cached)
                continue

            analysis = AIAnalysis(finding_id=finding.get("id", ""))
            tokens_before = self._total_tokens

            if self.config.enable_validation:
                analysis.verdict = self.validate_finding(finding)
                if analysis.verdict:
                    analysis.provider_used = analysis.verdict.provider_used

            if self.config.enable_impact:
                analysis.impact = self.explain_impact(finding)

            if self.config.enable_remediation:
                analysis.remediation = self.generate_remediation(finding)

            if self.config.enable_poc_fix:
                analysis.poc_fix = self.generate_poc_fix(finding)

            analysis.tokens_used = self._total_tokens - tokens_before
            self._cache.set(f"full:{cache_key}", analysis)
            analyses.append(analysis)

            logger.debug(
                f"[ai-copilot] Finding {finding.get('id','')} analyzed: "
                f"verdict={analysis.verdict.verdict if analysis.verdict else 'N/A'}, "
                f"provider={analysis.provider_used}, tokens={analysis.tokens_used}"
            )

        # Batch prioritization
        if self.config.enable_prioritization and eligible:
            priorities = self.prioritize_findings(eligible)
            priority_map = {p.finding_id: p for p in priorities}
            for analysis in analyses:
                analysis.priority = priority_map.get(analysis.finding_id)

        provider_stats = self._provider.get_stats() if self._provider else {}
        logger.info(
            f"[ai-copilot] Batch complete: {len(analyses)} findings, "
            f"{self._total_tokens} total tokens, {self._total_calls} API calls. "
            f"Provider stats: {provider_stats.get('calls_by_provider', {})}"
        )

        return analyses

    # ── Stats ────────────────────────────────────────────────────────────────

    def get_usage_stats(self) -> dict:
        provider_stats = self._provider.get_stats() if self._provider else {}
        return {
            "total_tokens_used": self._total_tokens,
            "total_api_calls": self._total_calls,
            "cache_entries": len(self._cache._store),
            "enabled": self.config.enabled,
            **provider_stats,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Integration: Enrich Findings with AI Analysis
# ─────────────────────────────────────────────────────────────────────────────

def enrich_findings_with_ai(
    findings: list[dict],
    config: Optional[CopilotConfig] = None,
) -> tuple[list[dict], dict]:
    """
    Enrich a list of finding dicts with AI analysis data.

    Mutates findings in-place to add:
      finding["ai_verdict"]                — "TRUE_POSITIVE" / "FALSE_POSITIVE" / "NEEDS_REVIEW"
      finding["ai_confidence"]             — AI confidence score
      finding["ai_reasoning"]              — Brief reasoning
      finding["ai_impact"]                 — Business impact text
      finding["ai_remediation"]            — Code fix suggestion
      finding["ai_poc_fix"]                — Full POC fix intelligence dict
      finding["ai_priority"]               — "P1-CRITICAL" / "P2-HIGH" / etc.
      finding["ai_urgency"]                — "immediate" / "this-sprint" / etc.
      finding["ai_provider"]               — Which LLM provider answered

    Returns (enriched_findings, usage_stats).
    """
    copilot = QuantaraAICopilot(config)
    analyses = copilot.batch_analyze(findings)

    analysis_map = {a.finding_id: a for a in analyses}

    for finding in findings:
        fid = finding.get("id", "")
        analysis = analysis_map.get(fid)
        if not analysis:
            continue

        finding["ai_provider"] = analysis.provider_used

        if analysis.verdict:
            finding["ai_verdict"] = analysis.verdict.verdict
            finding["ai_confidence"] = round(analysis.verdict.confidence, 2)
            finding["ai_reasoning"] = analysis.verdict.reasoning
            if analysis.verdict.suggested_severity:
                finding["ai_suggested_severity"] = analysis.verdict.suggested_severity
            if analysis.verdict.verdict == "FALSE_POSITIVE" and analysis.verdict.confidence > 0.8:
                finding["is_false_positive"] = True
                finding["fp_reason"] = analysis.verdict.false_positive_reason

        if analysis.impact:
            finding["ai_impact"] = analysis.impact.business_impact
            finding["ai_attack_scenario"] = analysis.impact.attack_scenario

        if analysis.remediation:
            finding["ai_remediation"] = analysis.remediation.fixed_code
            finding["ai_remediation_explanation"] = analysis.remediation.explanation

        if analysis.poc_fix:
            finding["ai_poc_fix"] = {
                "vulnerability_type": analysis.poc_fix.vulnerability_type,
                "poc_description": analysis.poc_fix.poc_description,
                "immediate_fix": analysis.poc_fix.immediate_fix,
                "full_fix_code": analysis.poc_fix.full_fix_code,
                "fix_language": analysis.poc_fix.fix_language,
                "fix_explanation": analysis.poc_fix.fix_explanation,
                "test_steps": analysis.poc_fix.test_steps,
                "prevention_checklist": analysis.poc_fix.prevention_checklist,
                "cvss_score": analysis.poc_fix.cvss_score,
                "owasp_category": analysis.poc_fix.owasp_category,
                "references": analysis.poc_fix.references,
                "provider_used": analysis.poc_fix.provider_used,
            }

        if analysis.priority:
            finding["ai_priority"] = analysis.priority.priority_label
            finding["ai_urgency"] = analysis.priority.urgency
            finding["ai_priority_rank"] = analysis.priority.priority_rank

    return findings, copilot.get_usage_stats()


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def create_copilot(
    gemini_key: str = "",
    anthropic_key: str = "",
    openai_key: str = "",
    enabled: bool = True,
    analyze_severities: Optional[list[str]] = None,
) -> QuantaraAICopilot:
    """Factory: create a configured multi-LLM QuantaraAICopilot instance."""
    config = CopilotConfig(
        gemini_api_key=gemini_key,
        anthropic_api_key=anthropic_key,
        openai_api_key=openai_key,
        enabled=enabled,
        analyze_severities=analyze_severities or ["CRITICAL", "HIGH"],
    )
    return QuantaraAICopilot(config)
