"""
Quantum Protocol v4.0 — OWASP Vulnerability Scanner
Enterprise-grade multi-layer analysis engine for OWASP Top 10:2025 coverage.

Performs:
  1. Regex-based pattern matching (100+ compiled rules)
  2. Language-aware filtering (only runs relevant patterns per file type)
  3. Context-aware confidence calibration
  4. OWASP/CWE/compliance mapping
  5. Deduplication and false-positive reduction
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Optional

from quantum_protocol.models.enums import (
    AlgoFamily, ComplianceFramework, ConfidenceLevel, RiskLevel, ScanMode,
    COMPLIANCE_VIOLATIONS, VulnCategory, OwaspCategory,
)
from quantum_protocol.models.findings import CryptoFinding, CWE_MAP
from quantum_protocol.rules.owasp_rules import (
    VulnRule, COMPILED_VULN_RULES,
    INJECTION_RULES, ACCESS_CONTROL_RULES, MISCONFIG_RULES,
    AUTH_RULES, DESIGN_RULES, INTEGRITY_RULES, CLOUD_RULES,
    FRONTEND_RULES, LOG_EXC_RULES, DATA_RECON_RULES, API_RULES,
    SUPPLY_CHAIN_RULES, _compile,
)
from quantum_protocol.utils.analysis import confidence_to_level, sanitize_line

logger = logging.getLogger("quantum_protocol.owasp")

# Pre-compiled rule sets by scan mode for performance
_MODE_RULES: dict[ScanMode, list[tuple[re.Pattern, VulnRule]]] = {}


def _get_rules_for_mode(mode: ScanMode) -> list[tuple[re.Pattern, VulnRule]]:
    """Get pre-compiled rules filtered by scan mode."""
    if mode not in _MODE_RULES:
        if mode == ScanMode.FULL or mode == ScanMode.OWASP:
            _MODE_RULES[mode] = COMPILED_VULN_RULES
        elif mode == ScanMode.INJECTION:
            _MODE_RULES[mode] = _compile(INJECTION_RULES)
        elif mode == ScanMode.FRONTEND:
            _MODE_RULES[mode] = _compile(FRONTEND_RULES + DATA_RECON_RULES)
        elif mode == ScanMode.CLOUD:
            _MODE_RULES[mode] = _compile(CLOUD_RULES + MISCONFIG_RULES)
        elif mode == ScanMode.API:
            _MODE_RULES[mode] = _compile(API_RULES + AUTH_RULES + DESIGN_RULES)
        elif mode == ScanMode.RECON:
            _MODE_RULES[mode] = _compile(DATA_RECON_RULES + FRONTEND_RULES + MISCONFIG_RULES)
        elif mode == ScanMode.COMPLIANCE:
            _MODE_RULES[mode] = COMPILED_VULN_RULES
        else:
            _MODE_RULES[mode] = COMPILED_VULN_RULES
    return _MODE_RULES[mode]


# False-positive path patterns
_FP_PATH_PATTERNS = re.compile(
    r'(?:test[s_]?/|spec[s_]?/|__test__|\.test\.|\.spec\.|'
    r'mock[s_]?/|fixture[s_]?/|example[s_]?/|sample[s_]?/|'
    r'doc[s_]?/|demo/|vendor/|node_modules/)',
    re.IGNORECASE,
)

# Context patterns that reduce confidence
_TEST_CONTEXT_PATTERNS = re.compile(
    r'(?:test_|_test|TestCase|describe\s*\(|it\s*\(|expect\s*\(|'
    r'assert|mock|stub|fake|fixture|example|sample|placeholder|TODO)',
    re.IGNORECASE,
)


def scan_owasp(
    content: str,
    relative_path: str,
    language: Optional[str],
    scan_mode: ScanMode,
    context_window: int = 3,
) -> list[CryptoFinding]:
    """
    Scan file content for OWASP vulnerabilities.

    Args:
        content: File contents as string
        relative_path: Relative file path for reporting
        language: Detected language (e.g. "python", "javascript")
        scan_mode: Current scan mode
        context_window: Lines of context to capture

    Returns:
        List of CryptoFinding objects for detected vulnerabilities
    """
    if not content or not content.strip():
        return []

    findings: list[CryptoFinding] = []
    seen: set[str] = set()
    lines = content.split("\n")
    is_fp_path = bool(_FP_PATH_PATTERNS.search(relative_path))
    rules = _get_rules_for_mode(scan_mode)

    for compiled_re, rule in rules:
        # Language filtering: skip rules not relevant to this file type
        if rule.languages and language and language not in rule.languages:
            continue

        for match in compiled_re.finditer(content):
            line_no = content[:match.start()].count("\n") + 1
            col_start = match.start() - content.rfind("\n", 0, match.start()) - 1
            col_end = col_start + len(match.group())

            # Deduplication
            dedup_key = f"{relative_path}:{line_no}:{rule.family.value}:{rule.id}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            # Context extraction
            ctx_start = max(0, line_no - context_window - 1)
            ctx_end = min(len(lines), line_no + context_window)
            ctx_lines = lines[ctx_start:ctx_end]
            raw_line = lines[line_no - 1] if line_no <= len(lines) else ""

            # Confidence calibration
            confidence = rule.confidence

            # Reduce confidence for test/example files
            if is_fp_path:
                confidence *= 0.50

            # Reduce confidence if context suggests test/mock code
            ctx_text = "\n".join(ctx_lines)
            if _TEST_CONTEXT_PATTERNS.search(ctx_text):
                confidence *= 0.70

            # Boost for high-risk patterns with clear indicators
            if rule.risk == RiskLevel.CRITICAL and "user" in raw_line.lower():
                confidence = min(1.0, confidence * 1.10)

            # Cut-off
            if confidence < 0.30:
                continue

            # CWE mapping
            cwe_id = rule.cwe
            if not cwe_id:
                from quantum_protocol.models.enums import COMPLIANCE_VIOLATIONS as _cv
                # Fallback CWE from extended map
                pass

            # Compliance violations
            compliance = [fw.value for fw in COMPLIANCE_VIOLATIONS.get(rule.family, [])]

            # Remediation
            remediation_map = _build_remediation(rule)

            findings.append(CryptoFinding(
                id=CryptoFinding.generate_id(relative_path, line_no, f"OWASP-{rule.family.value}"),
                file=relative_path,
                language=language or "unknown",
                line_number=line_no,
                line_content=sanitize_line(raw_line.strip()),
                column_start=col_start,
                column_end=col_end,
                algorithm=rule.family.value,
                family=rule.family,
                risk=rule.risk,
                confidence=round(confidence, 3),
                confidence_level=confidence_to_level(confidence),
                key_size=None,
                hndl_relevant=False,
                pattern_note=rule.note,
                migration=remediation_map,
                compliance_violations=compliance,
                context_lines=[sanitize_line(l) for l in ctx_lines],
                cwe_id=cwe_id,
                cvss_estimate=_estimate_vuln_cvss(rule),
                remediation_effort=_estimate_effort(rule),
                tags=list(rule.tags),
                is_secret=False,
            ))

    return findings


def _build_remediation(rule: VulnRule) -> dict:
    """Build remediation guidance for a vulnerability."""
    base = {
        "notes": rule.note,
        "cwe": rule.cwe,
        "owasp_category": rule.family.vuln_category.value,
    }
    if rule.remediation:
        base["action"] = rule.remediation
    else:
        base["action"] = _DEFAULT_REMEDIATION.get(rule.family.vuln_category, "Review and fix the identified vulnerability.")
    return base


_DEFAULT_REMEDIATION: dict[VulnCategory, str] = {
    VulnCategory.INJECTION: "Use parameterized queries, prepared statements, or ORM methods. Validate and sanitize all user input.",
    VulnCategory.ACCESS_CONTROL: "Implement server-side authorization checks. Use allowlists for file paths and URLs.",
    VulnCategory.MISCONFIG: "Remove debug settings, change default credentials, apply security headers.",
    VulnCategory.AUTH: "Use strong password hashing (bcrypt/argon2), validate JWT properly, set secure cookie flags.",
    VulnCategory.SUPPLY_CHAIN: "Pin dependency versions, use lockfiles, verify package integrity.",
    VulnCategory.INTEGRITY: "Use safe deserialization, add SRI to external resources, pin CI/CD action versions.",
    VulnCategory.CLOUD: "Apply least-privilege IAM, enable encryption, restrict network access, avoid running as root.",
    VulnCategory.FRONTEND: "Remove secrets from client bundles, disable source maps in production, avoid eval().",
    VulnCategory.LOGGING: "Redact sensitive data before logging, implement audit trails.",
    VulnCategory.EXCEPTION: "Implement fail-closed error handling, avoid empty catch blocks.",
    VulnCategory.INSECURE_DESIGN: "Apply rate limiting, CSRF protection, restrict mass assignment.",
    VulnCategory.API_SECURITY: "Limit data exposure, implement pagination, restrict GraphQL introspection.",
    VulnCategory.DATA_EXPOSURE: "Remove PII from source, encrypt at rest, avoid internal URLs in code.",
    VulnCategory.RECON: "Review exposed endpoints and TODO comments for security implications.",
}


def _estimate_vuln_cvss(rule: VulnRule) -> float:
    """Estimate CVSS for vulnerability findings."""
    base = rule.risk.numeric
    # Injection and RCE vulnerabilities get highest scores
    if rule.family in (AlgoFamily.VULN_SQL_INJECTION, AlgoFamily.VULN_COMMAND_INJECTION,
                       AlgoFamily.VULN_TEMPLATE_INJECTION, AlgoFamily.VULN_UNSAFE_DESER):
        return min(10.0, max(base, 9.0))
    if rule.family in (AlgoFamily.VULN_SSRF, AlgoFamily.VULN_PATH_TRAVERSAL):
        return min(10.0, max(base, 8.5))
    if rule.family in (AlgoFamily.VULN_XSS, AlgoFamily.VULN_DOM_XSS):
        return min(10.0, max(base, 7.0))
    if rule.family in (AlgoFamily.VULN_JWT_MISCONFIG, AlgoFamily.VULN_DEFAULT_CREDS):
        return min(10.0, max(base, 9.0))
    if rule.family in (AlgoFamily.VULN_PUBLIC_S3, AlgoFamily.VULN_OVERPRIVILEGED_IAM):
        return min(10.0, max(base, 9.0))
    return min(10.0, round(base, 1))


def _estimate_effort(rule: VulnRule) -> str:
    """Estimate remediation effort."""
    cat = rule.family.vuln_category
    if cat in (VulnCategory.MISCONFIG, VulnCategory.LOGGING):
        return "low"
    if cat in (VulnCategory.AUTH, VulnCategory.FRONTEND):
        return "medium"
    if cat in (VulnCategory.INJECTION, VulnCategory.INTEGRITY):
        return "medium"
    if cat in (VulnCategory.CLOUD, VulnCategory.ACCESS_CONTROL):
        return "medium"
    if cat == VulnCategory.INSECURE_DESIGN:
        return "high"
    return "medium"
