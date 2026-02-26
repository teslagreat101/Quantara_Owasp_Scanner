"""
Quantum Protocol v4.0 — A09: Security Logging & Alerting (Extended)
Audit logging gaps, sensitive data in logs, PII exposure,
log injection, missing security events.
"""
from __future__ import annotations
import re, logging
from typing import Optional
from quantum_protocol.models.enums import AlgoFamily, RiskLevel, ScanMode
from quantum_protocol.models.findings import CryptoFinding
from quantum_protocol.rules.owasp_rules import VulnRule, _compile
from quantum_protocol.utils.analysis import confidence_to_level, sanitize_line

logger = logging.getLogger("quantum_protocol.logging_scanner")

_EXTENDED_RULES: list[VulnRule] = [
    VulnRule("LOG-E01", "(?:log|logger|logging)\\.\\w+\\s*\\(.*?(?:request\\.body|req\\.body|request\\.data|request\\.POST)", AlgoFamily.VULN_SENSITIVE_LOG, RiskLevel.HIGH, 0.78, "Logging raw request body \u2014 may contain PII/secrets", "CWE-532", (), ('logging', 'request')),
    VulnRule("LOG-E02", "(?:log|logger|logging)\\.\\w+\\s*\\(.*?(?:Authorization|Cookie|Set-Cookie|X-Api-Key|Bearer)", AlgoFamily.VULN_SENSITIVE_LOG, RiskLevel.HIGH, 0.82, "Logging auth headers \u2014 credential exposure", "CWE-532", (), ('logging', 'headers')),
    VulnRule("LOG-E03", "(?:log|logger|logging)\\.\\w+\\s*\\(.*?(?:credit.?card|card.?number|cvv|ssn|social.?security)", AlgoFamily.VULN_PII_IN_LOGS, RiskLevel.CRITICAL, 0.88, "PCI/PII data in log statement", "CWE-532", (), ('logging', 'pii')),
    VulnRule("LOG-E04", "except.*?\\n\\s*(?:print|logger\\.\\w+)\\s*\\(.*?(?:traceback|stacktrace|stack_trace|\\.stack|\\.backtrace)", AlgoFamily.VULN_VERBOSE_ERRORS, RiskLevel.MEDIUM, 0.68, "Full stack trace logged \u2014 may leak internals", "CWE-209", (), ('logging', 'exception')),
    VulnRule("LOG-E05", "(?:winston|bunyan|pino|log4j|logback|serilog).*?(?:level|Level)\\s*[=:]\\s*['\\\"]?(?:silly|verbose|trace|all|debug)", AlgoFamily.VULN_VERBOSE_ERRORS, RiskLevel.MEDIUM, 0.72, "Verbose logging level in production", "CWE-209", (), ('logging', 'level')),
    VulnRule("LOG-E06", "(?:login|authenticate|sign_in).*?(?:success|fail)(?!.*(?:log|audit|event|track|record))", AlgoFamily.VULN_MISSING_AUDIT_LOG, RiskLevel.MEDIUM, 0.6, "Auth event without audit logging", "CWE-778", (), ('logging', 'audit')),
    VulnRule("LOG-E07", "(?:admin|superuser|root).*?(?:create|delete|modify|update|grant)(?!.*(?:log|audit))", AlgoFamily.VULN_MISSING_AUDIT_LOG, RiskLevel.MEDIUM, 0.58, "Admin action without audit trail", "CWE-778", (), ('logging', 'audit')),
    VulnRule("LOG-E08", "(?:\\\\n|\\\\r|%0a|%0d).*?(?:log|logger)\\.\\w+\\s*\\(", AlgoFamily.VULN_HEADER_INJECTION, RiskLevel.MEDIUM, 0.72, "Log injection \u2014 newline before log call", "CWE-117", (), ('logging', 'injection')),
    VulnRule("LOG-E09", "request\\.(?:ip|remote_addr|x_forwarded_for).*?(?:log|print|console)", AlgoFamily.VULN_SENSITIVE_LOG, RiskLevel.LOW, 0.55, "Client IP logged \u2014 verify GDPR compliance", "CWE-532", (), ('logging', 'privacy')),
    VulnRule("LOG-E10", "(?:AUDIT|audit_log|AuditLog|SecurityEvent)\\b", AlgoFamily.VULN_MISSING_AUDIT_LOG, RiskLevel.INFO, 0.5, "Audit logging reference \u2014 verify coverage", "CWE-778", (), ('logging', 'audit')),
]

COMPILED_EXTENDED = _compile(_EXTENDED_RULES)

def scan_logging_scanner(content, relative_path, language, scan_mode, context_window=3):
    """Run extended logging_scanner analysis."""
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
