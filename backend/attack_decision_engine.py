"""
Quantara AI-Driven Next Attack Decision Engine
===============================================
Autonomous penetration-tester decision pipeline:

    All Findings → Exploitability Analysis → Risk Prediction
        → Priority Queue → Next Attack Selection

The engine evaluates discovered vulnerabilities and intelligently
recommends the next exploitation path, mimicking how a skilled
human attacker would chain findings into attack paths.
"""

from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass, asdict, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ── Sensitivity weights for endpoint types ─────────────────────────────────────
ENDPOINT_SENSITIVITY: Dict[str, float] = {
    "admin":     1.0,
    "api":       0.85,
    "auth":      0.95,
    "login":     0.95,
    "user":      0.75,
    "account":   0.75,
    "config":    0.90,
    "setup":     0.85,
    "install":   0.85,
    "backup":    0.90,
    "debug":     0.90,
    "test":      0.70,
    "internal":  0.80,
    "secret":    1.0,
    "key":       1.0,
    "token":     0.95,
    "password":  1.0,
    "credential":1.0,
}

# ── Severity base scores ───────────────────────────────────────────────────────
SEVERITY_SCORES: Dict[str, float] = {
    "critical": 1.0,
    "high":     0.80,
    "medium":   0.55,
    "low":      0.25,
    "info":     0.05,
}

# ── Attack chain rules ─────────────────────────────────────────────────────────
# (trigger_tag, prerequisite_tag) → recommended_next_action
CHAIN_RULES: List[Tuple[str, str, str, str]] = [
    # (primary_vuln, second_vuln_OR_tag, next_attack_type, rationale)
    ("sql_injection", "database",   "credential_extraction", "SQLi + DB access → attempt credential dump path"),
    ("sql_injection", "auth",       "auth_bypass",           "SQLi on auth endpoint → attempt login bypass"),
    ("ssrf",          "internal",   "lateral_movement",      "SSRF + internal endpoint → map internal network"),
    ("ssrf",          "cloud",      "cloud_metadata",        "SSRF detected → probe cloud metadata endpoints"),
    ("open_redirect", "auth",       "token_theft",           "Open redirect + auth → token/session theft chain"),
    ("open_redirect", "token",      "token_theft",           "Open redirect near token → hijack OAuth flow"),
    ("xss",           "auth",       "session_hijack",        "XSS near auth → attempt session token theft"),
    ("credentials",   "admin",      "privilege_escalation",  "Exposed creds + admin endpoint → privilege escalation"),
    ("credentials",   "api",        "api_takeover",          "Exposed credentials → API key takeover attempt"),
    ("misconfig",     "admin",      "admin_takeover",        "Misconfiguration + admin path → admin panel access"),
    ("takeover",      "dns",        "subdomain_hijack",      "Takeover candidate → confirm DNS CNAME hijack"),
    ("lfi",           "backup",     "source_disclosure",     "LFI + backup files → source code disclosure chain"),
    ("rce",           "any",        "full_compromise",       "RCE detected → full system compromise path"),
]


# ═══════════════════════════════════════════════════════════════════════════════
# Data classes
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ExploitabilityScore:
    finding_id: str
    score: float          # 0.0 – 1.0
    endpoint_sensitivity: float
    severity_base: float
    chain_bonus: float
    rationale: str


@dataclass
class NextAttackRecommendation:
    target_endpoint: str
    attack_type: str
    rationale: str
    estimated_impact: str
    suggested_payload_category: str
    trigger_finding_id: str
    confidence: float     # 0.0 – 1.0
    priority: int         # 1 = highest

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ═══════════════════════════════════════════════════════════════════════════════
# Engine
# ═══════════════════════════════════════════════════════════════════════════════

class AttackDecisionEngine:
    """
    AI-driven autonomous attack sequencing engine.

    Evaluates the full set of findings after each scan module and
    recommends the next highest-value attack path.
    """

    def compute_exploitability_score(
        self,
        finding: Dict[str, Any],
        all_findings: List[Dict[str, Any]],
    ) -> ExploitabilityScore:
        """Score a finding by exploitability (0.0–1.0)."""
        finding_id = finding.get("id", "")
        endpoint = (finding.get("file") or finding.get("endpoint") or "").lower()
        severity = finding.get("severity", "info").lower()
        tags = [t.lower() for t in finding.get("tags", [])]
        title = (finding.get("title") or "").lower()

        # Severity base
        sev_base = SEVERITY_SCORES.get(severity, 0.05)

        # Endpoint sensitivity
        ep_sens = 0.3  # default
        for keyword, weight in ENDPOINT_SENSITIVITY.items():
            if keyword in endpoint or keyword in title:
                ep_sens = max(ep_sens, weight)

        # Chain bonus: does this finding enable another?
        chain_bonus = 0.0
        all_tags = set()
        for f in all_findings:
            all_tags.update(t.lower() for t in f.get("tags", []))
            all_tags.add((f.get("category") or "").lower())

        for primary, secondary, _, _ in CHAIN_RULES:
            if primary in tags or primary in title:
                if secondary == "any" or secondary in all_tags or secondary in endpoint:
                    chain_bonus = max(chain_bonus, 0.20)

        score = min(1.0, sev_base + (ep_sens * 0.3) + chain_bonus)
        rationale = (
            f"sev={severity}({sev_base:.2f}) "
            f"endpoint_sensitivity={ep_sens:.2f} "
            f"chain_bonus={chain_bonus:.2f} "
            f"→ score={score:.2f}"
        )
        return ExploitabilityScore(
            finding_id=finding_id,
            score=score,
            endpoint_sensitivity=ep_sens,
            severity_base=sev_base,
            chain_bonus=chain_bonus,
            rationale=rationale,
        )

    def build_priority_queue(
        self,
        findings: List[Dict[str, Any]],
    ) -> deque:
        """Build a priority queue of (score, finding) sorted highest-first."""
        scored = []
        for f in findings:
            es = self.compute_exploitability_score(f, findings)
            scored.append((es.score, f, es))
        scored.sort(key=lambda x: x[0], reverse=True)
        return deque(scored)

    def recommend_next_action(
        self,
        findings: List[Dict[str, Any]],
        scan_context: Dict[str, Any],
    ) -> Optional[NextAttackRecommendation]:
        """
        Analyse all findings and recommend the highest-value next attack.

        Returns None if there are no actionable findings.
        """
        if not findings:
            return None

        pq = self.build_priority_queue(findings)
        all_tags: set = set()
        for f in findings:
            all_tags.update(t.lower() for t in f.get("tags", []))
            all_tags.add((f.get("category") or "").lower())
            all_tags.add((f.get("title") or "").lower())

        # Check chain rules against the full finding set
        best_score = 0.0
        best_rec: Optional[NextAttackRecommendation] = None

        for chain_score, top_finding, es in pq:
            tags = [t.lower() for t in top_finding.get("tags", [])]
            title = (top_finding.get("title") or "").lower()
            endpoint = top_finding.get("file") or top_finding.get("endpoint") or ""

            for primary, secondary, attack_type, rationale in CHAIN_RULES:
                if primary not in tags and primary not in title:
                    continue
                if secondary == "any" or secondary in all_tags or secondary in endpoint.lower():
                    rec_score = chain_score + 0.15
                    if rec_score > best_score:
                        best_score = rec_score
                        best_rec = NextAttackRecommendation(
                            target_endpoint=endpoint,
                            attack_type=attack_type,
                            rationale=rationale,
                            estimated_impact=_estimate_impact(attack_type),
                            suggested_payload_category=_payload_category(attack_type),
                            trigger_finding_id=top_finding.get("id", ""),
                            confidence=min(0.95, rec_score),
                            priority=1,
                        )
                        break

        # If no chain rules match, return the top-scored finding as a standalone recommendation
        if best_rec is None and pq:
            chain_score, top_finding, es = pq[0]
            endpoint = top_finding.get("file") or top_finding.get("endpoint") or ""
            sev = top_finding.get("severity", "medium")
            best_rec = NextAttackRecommendation(
                target_endpoint=endpoint,
                attack_type="deep_investigation",
                rationale=f"Highest exploitability score {es.score:.2f} — investigate {top_finding.get('title', 'finding')} first",
                estimated_impact=f"{sev.capitalize()} severity — manual investigation recommended",
                suggested_payload_category="manual",
                trigger_finding_id=top_finding.get("id", ""),
                confidence=chain_score,
                priority=1,
            )

        return best_rec

    def generate_attack_summary(
        self,
        findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Generate a human-readable attack summary for the AI Copilot panel.
        """
        if not findings:
            return {
                "total_findings": 0,
                "attack_chains": [],
                "priority_targets": [],
                "risk_narrative": "No findings to analyze. Scan coverage may be insufficient.",
            }

        pq = self.build_priority_queue(findings)
        top5 = list(pq)[:5]

        chains = []
        seen = set()
        all_tags: set = set()
        for f in findings:
            all_tags.update(t.lower() for t in f.get("tags", []))
            all_tags.add((f.get("category") or "").lower())

        for _, f, es in top5:
            tags = [t.lower() for t in f.get("tags", [])]
            title = (f.get("title") or "").lower()
            endpoint = f.get("file") or f.get("endpoint") or ""

            for primary, secondary, attack_type, rationale in CHAIN_RULES:
                chain_key = f"{primary}->{attack_type}"
                if chain_key in seen:
                    continue
                if (primary in tags or primary in title) and (secondary == "any" or secondary in all_tags):
                    chains.append({
                        "chain": chain_key,
                        "rationale": rationale,
                        "endpoint": endpoint,
                        "attack_type": attack_type,
                        "impact": _estimate_impact(attack_type),
                    })
                    seen.add(chain_key)

        # Priority targets (top 3 by exploitability)
        priority_targets = []
        for _, f, es in top5[:3]:
            priority_targets.append({
                "endpoint": f.get("file") or f.get("endpoint") or "unknown",
                "title": f.get("title", "Unknown"),
                "severity": f.get("severity", "info"),
                "exploitability": round(es.score, 2),
                "rationale": es.rationale,
            })

        sev_counts = {"critical": 0, "high": 0, "medium": 0}
        for f in findings:
            sev = f.get("severity", "").lower()
            if sev in sev_counts:
                sev_counts[sev] += 1

        narrative = _generate_narrative(sev_counts, chains)

        return {
            "total_findings": len(findings),
            "attack_chains": chains[:6],
            "priority_targets": priority_targets,
            "risk_narrative": narrative,
            "severity_distribution": sev_counts,
        }


# ── Helpers ────────────────────────────────────────────────────────────────────

def _estimate_impact(attack_type: str) -> str:
    IMPACTS = {
        "credential_extraction": "Database credential dump → account takeover across all services",
        "auth_bypass":           "Authentication bypass → unauthorized access to protected resources",
        "lateral_movement":      "Internal network access → pivot to additional systems",
        "cloud_metadata":        "Cloud metadata exposure → IAM credentials / instance takeover",
        "token_theft":           "Session/OAuth token theft → account takeover",
        "session_hijack":        "Session hijacking → authenticated account takeover",
        "privilege_escalation":  "Privilege escalation → admin / root access",
        "api_takeover":          "API key takeover → data exfiltration / service abuse",
        "admin_takeover":        "Admin panel access → full application control",
        "subdomain_hijack":      "Subdomain takeover → phishing / cookie theft",
        "source_disclosure":     "Source code exposure → secret key / logic disclosure",
        "full_compromise":       "Remote code execution → complete system compromise",
        "deep_investigation":    "Manual investigation required to assess full impact",
    }
    return IMPACTS.get(attack_type, "Unknown impact — manual assessment required")


def _payload_category(attack_type: str) -> str:
    CATEGORIES = {
        "credential_extraction": "sqli_union",
        "auth_bypass":           "sqli_boolean",
        "lateral_movement":      "ssrf_internal",
        "cloud_metadata":        "ssrf_cloud",
        "token_theft":           "open_redirect",
        "session_hijack":        "xss_stored",
        "privilege_escalation":  "broken_access",
        "api_takeover":          "credentials",
        "admin_takeover":        "misconfig",
        "subdomain_hijack":      "takeover",
        "source_disclosure":     "lfi",
        "full_compromise":       "rce",
        "deep_investigation":    "manual",
    }
    return CATEGORIES.get(attack_type, "manual")


def _generate_narrative(sev_counts: Dict[str, int], chains: List[Dict]) -> str:
    crit = sev_counts.get("critical", 0)
    high = sev_counts.get("high", 0)
    med  = sev_counts.get("medium", 0)

    if crit > 0:
        base = f"CRITICAL RISK: {crit} critical vulnerabilities detected. "
    elif high > 0:
        base = f"HIGH RISK: {high} high-severity vulnerabilities require immediate attention. "
    elif med > 0:
        base = f"MEDIUM RISK: {med} medium-severity findings should be remediated. "
    else:
        base = "LOW RISK: No significant vulnerabilities detected in this scan. "

    if chains:
        chain_str = chains[0]["rationale"]
        base += f"Highest priority attack chain identified: {chain_str}."
    else:
        base += "No multi-step attack chains identified at this time."

    return base


# ── Singleton ──────────────────────────────────────────────────────────────────

_engine: Optional[AttackDecisionEngine] = None


def get_attack_decision_engine() -> AttackDecisionEngine:
    global _engine
    if _engine is None:
        _engine = AttackDecisionEngine()
    return _engine
