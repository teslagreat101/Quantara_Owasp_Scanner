"""
Quantum Protocol v4.0 — A06: Insecure Design (Extended)
Rate limiting, CSRF, mass assignment, business logic flaws,
race conditions, account enumeration, transaction safety.
"""
from __future__ import annotations
import re, logging
from typing import Optional
from quantum_protocol.models.enums import AlgoFamily, RiskLevel, ScanMode
from quantum_protocol.models.findings import CryptoFinding
from quantum_protocol.rules.owasp_rules import VulnRule, _compile
from quantum_protocol.utils.analysis import confidence_to_level, sanitize_line

logger = logging.getLogger("quantum_protocol.insecure_design")

_EXTENDED_RULES: list[VulnRule] = [
    VulnRule("DES-001", "Model\\.(?:update|updateMany|findOneAndUpdate)\\s*\\(\\s*(?:\\{.*?\\})?\\s*,\\s*(?:req\\.body|request\\.data|params)", AlgoFamily.VULN_MASS_ASSIGNMENT, RiskLevel.HIGH, 0.82, "Model update with raw user data \u2014 mass assignment", "CWE-915", ('javascript', 'typescript'), ('design', 'mass-assignment')),
    VulnRule("DES-002", "\\.update_attributes\\s*\\(\\s*params", AlgoFamily.VULN_MASS_ASSIGNMENT, RiskLevel.HIGH, 0.85, "Rails update_attributes with raw params", "CWE-915", ('ruby',), ('design', 'mass-assignment')),
    VulnRule("DES-003", "serializer\\.save\\s*\\(\\s*\\*\\*(?:request\\.data|validated_data)", AlgoFamily.VULN_MASS_ASSIGNMENT, RiskLevel.MEDIUM, 0.72, "DRF serializer.save with spread data", "CWE-915", ('python',), ('design', 'mass-assignment')),
    VulnRule("DES-004", "@app\\.route\\s*\\(\\s*['\\\"][^'\\\"]+['\\\"]\\s*,\\s*methods\\s*=\\s*\\[.*?['\\\"]POST['\\\"].*?\\]\\s*\\)(?!.*csrf)", AlgoFamily.VULN_CSRF, RiskLevel.MEDIUM, 0.65, "POST route without CSRF reference", "CWE-352", ('python',), ('design', 'csrf')),
    VulnRule("DES-005", "(?:async|await)\\s+.*?(?:transfer|withdraw|debit|credit|purchase|order)\\s*\\(", AlgoFamily.VULN_BUSINESS_LOGIC, RiskLevel.MEDIUM, 0.6, "Financial operation \u2014 verify idempotency and isolation", "CWE-362", (), ('design', 'race-condition')),
    VulnRule("DES-006", "if\\s+.*?(?:user|email).*?(?:not found|invalid|doesn't exist)", AlgoFamily.VULN_BUSINESS_LOGIC, RiskLevel.MEDIUM, 0.68, "User enumeration via specific error messages", "CWE-204", (), ('design', 'enumeration')),
    VulnRule("DES-007", "res\\.status\\s*\\(\\s*(?:200|201)\\s*\\).*?(?:Invalid|Wrong|Incorrect)", AlgoFamily.VULN_BUSINESS_LOGIC, RiskLevel.MEDIUM, 0.72, "Success status with error message \u2014 inconsistent API", "CWE-204", ('javascript', 'typescript'), ('design', 'api')),
    VulnRule("DES-008", "sleep\\s*\\(\\s*\\d|Thread\\.sleep\\s*\\(\\s*\\d|time\\.sleep\\s*\\(\\s*\\d", AlgoFamily.VULN_BUSINESS_LOGIC, RiskLevel.LOW, 0.55, "Fixed delay \u2014 verify not used for security timing", "CWE-208", (), ('design', 'timing')),
    VulnRule("DES-009", "(?:express-rate-limit|ratelimit|@throttle|RateLimit)\\b", AlgoFamily.VULN_MISSING_RATE_LIMIT, RiskLevel.INFO, 0.5, "Rate limiting present \u2014 verify covers auth endpoints", "CWE-770", (), ('design', 'rate-limit')),
    VulnRule("DES-010", "(?:protect_from_forgery|CsrfViewMiddleware|csrf_protect)\\b", AlgoFamily.VULN_CSRF, RiskLevel.INFO, 0.5, "CSRF middleware present \u2014 verify not bypassed", "CWE-352", (), ('design', 'csrf')),
]

COMPILED_EXTENDED = _compile(_EXTENDED_RULES)

def scan_insecure_design(content, relative_path, language, scan_mode, context_window=3):
    """Run extended insecure_design analysis."""
    findings, seen, lines_list = [], set(), content.split("\n")
    for compiled_re, rule in COMPILED_EXTENDED:
        if rule.languages and language and language not in rule.languages:
            continue
        for match in compiled_re.finditer(content):
            ln = content[:match.start()].count("\n") + 1
            dk = f"{relative_path}:{ln}:{rule.id}"
            if dk in seen: continue
            seen.add(dk)
            raw = lines_list[ln-1] if ln <= len(lines_list) else ""
            cs = max(0, ln - context_window - 1)
            ce = min(len(lines_list), ln + context_window)
            findings.append(CryptoFinding(
                id=CryptoFinding.generate_id(relative_path, ln, f"EXT-{rule.id}"),
                file=relative_path, language=language or "unknown",
                line_number=ln, line_content=sanitize_line(raw.strip()),
                column_start=None, column_end=None,
                algorithm=rule.family.value, family=rule.family,
                risk=rule.risk, confidence=round(rule.confidence, 3),
                confidence_level=confidence_to_level(rule.confidence),
                key_size=None, hndl_relevant=False, pattern_note=rule.note,
                migration={"action": rule.remediation or "Review and remediate", "cwe": rule.cwe},
                compliance_violations=[], context_lines=[sanitize_line(l) for l in lines_list[cs:ce]],
                cwe_id=rule.cwe, cvss_estimate=rule.risk.numeric,
                remediation_effort="medium", tags=list(rule.tags),
            ))
    return findings
