"""
Quantum Protocol v4.0 — Sensitive Data Exposure Scanner
PII detection, internal IP/URL exposure, cleartext storage patterns.
"""
from __future__ import annotations
import re, logging
from quantum_protocol.models.enums import AlgoFamily, RiskLevel, ScanMode
from quantum_protocol.models.findings import CryptoFinding
from quantum_protocol.rules.owasp_rules import VulnRule, _compile
from quantum_protocol.utils.analysis import confidence_to_level, sanitize_line

logger = logging.getLogger("quantum_protocol.data_exposure")

_DATA_RULES: list[VulnRule] = [
    VulnRule("PII-001", r'\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b', AlgoFamily.VULN_PII_IN_CODE, RiskLevel.HIGH, 0.65, "Potential SSN pattern in source code", "CWE-359", (), ("data","pii")),
    VulnRule("PII-002", r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b', AlgoFamily.VULN_PII_IN_CODE, RiskLevel.CRITICAL, 0.72, "Credit card number pattern in source", "CWE-359", (), ("data","pii","pci")),
    VulnRule("PII-003", r'(?:cleartext|plaintext|plain_text|unencrypted)\s*[=:]\s*(?:true|True|1)', AlgoFamily.VULN_CLEARTEXT_STORAGE, RiskLevel.HIGH, 0.82, "Cleartext storage explicitly enabled", "CWE-312", (), ("data","cleartext")),
    VulnRule("PII-004", r'(?:store|save|write|persist|cache).*?(?:password|secret|token|key|credential).*?(?:plain|clear|text|raw|unencrypted)', AlgoFamily.VULN_CLEARTEXT_STORAGE, RiskLevel.HIGH, 0.78, "Storing sensitive data without encryption", "CWE-312", (), ("data","cleartext")),
    VulnRule("PII-005", r'(?:email|phone|address|name|ssn|dob|birth)\s*[=:]\s*["\'][^"\']{5,}["\'].*?(?:test|sample|example|fake|dummy)', AlgoFamily.VULN_SENSITIVE_COMMENT, RiskLevel.LOW, 0.55, "Test PII data in source — ensure not real data", "CWE-359", (), ("data","pii","test")),
    VulnRule("PII-006", r'Base64\.(?:encode|decode|getEncoder|getDecoder).*?(?:password|secret|token)', AlgoFamily.VULN_CLEARTEXT_STORAGE, RiskLevel.HIGH, 0.78, "Sensitive data with Base64 encoding — not encryption", "CWE-312", ("java","python","javascript"), ("data","encoding")),
    VulnRule("PII-007", r'(?:btoa|atob)\s*\(.*?(?:password|secret|token|key)', AlgoFamily.VULN_CLEARTEXT_STORAGE, RiskLevel.HIGH, 0.78, "Sensitive data with btoa/atob — not encryption", "CWE-312", ("javascript","typescript"), ("data","encoding")),
]

COMPILED_DATA_RULES = _compile(_DATA_RULES)

def scan_sensitive_data(content, relative_path, language, scan_mode, context_window=3):
    """Detect PII, cleartext storage, and sensitive data exposure."""
    findings, seen, lines = [], set(), content.split("\n")
    for compiled_re, rule in COMPILED_DATA_RULES:
        if rule.languages and language and language not in rule.languages:
            continue
        for match in compiled_re.finditer(content):
            ln = content[:match.start()].count("\n") + 1
            dk = f"{relative_path}:{ln}:{rule.id}"
            if dk in seen: continue
            seen.add(dk)
            raw = lines[ln-1] if ln <= len(lines) else ""
            # Extra FP reduction for PII patterns
            if rule.id in ("PII-001", "PII-002"):
                # Skip if in test/fixture/constant/ID context
                if any(fp in raw.lower() for fp in ("test", "example", "port", "timeout", "size", "count", "version", "0000", "1234")):
                    continue
            cs, ce = max(0,ln-context_window-1), min(len(lines),ln+context_window)
            findings.append(CryptoFinding(
                id=CryptoFinding.generate_id(relative_path, ln, f"DATA-{rule.id}"),
                file=relative_path, language=language or "unknown",
                line_number=ln, line_content=sanitize_line(raw.strip()),
                column_start=None, column_end=None,
                algorithm=rule.family.value, family=rule.family,
                risk=rule.risk, confidence=round(rule.confidence, 3),
                confidence_level=confidence_to_level(rule.confidence),
                key_size=None, hndl_relevant=False, pattern_note=rule.note,
                migration={"action": "Remove PII from source or encrypt sensitive data", "cwe": rule.cwe},
                compliance_violations=[], context_lines=[sanitize_line(l) for l in lines[cs:ce]],
                cwe_id=rule.cwe, cvss_estimate=rule.risk.numeric,
                remediation_effort="medium", tags=list(rule.tags),
            ))
    return findings
