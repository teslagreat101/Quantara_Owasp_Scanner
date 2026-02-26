"""
Quantum Protocol v4.0 — A10: Exception Handling (Extended)
Fail-open logic, resource leaks, null safety, unhandled promises,
panic recovery, broad exception handling.
"""
from __future__ import annotations
import re, logging
from typing import Optional
from quantum_protocol.models.enums import AlgoFamily, RiskLevel, ScanMode
from quantum_protocol.models.findings import CryptoFinding
from quantum_protocol.rules.owasp_rules import VulnRule, _compile
from quantum_protocol.utils.analysis import confidence_to_level, sanitize_line

logger = logging.getLogger("quantum_protocol.exception_scanner")

_EXTENDED_RULES: list[VulnRule] = [
    VulnRule("EXC-E01", "except\\s+Exception\\s*(?:as\\s+\\w+)?\\s*:\\s*\\n\\s*(?:pass|return\\s+(?:True|None|\\{)|continue)", AlgoFamily.VULN_SWALLOWED_ERROR, RiskLevel.HIGH, 0.82, "Broad exception caught and silently swallowed", "CWE-390", ('python',), ('exception', 'swallowed')),
    VulnRule("EXC-E02", "except\\s*:\\s*$", AlgoFamily.VULN_SWALLOWED_ERROR, RiskLevel.HIGH, 0.85, "Bare except \u2014 catches SystemExit and KeyboardInterrupt", "CWE-396", ('python',), ('exception', 'bare-except')),
    VulnRule("EXC-E03", "\\.catch\\s*\\(\\s*\\(\\s*\\)\\s*=>\\s*\\{\\s*\\}\\s*\\)", AlgoFamily.VULN_SWALLOWED_ERROR, RiskLevel.HIGH, 0.82, "Promise .catch with empty handler", "CWE-390", ('javascript', 'typescript'), ('exception', 'swallowed')),
    VulnRule("EXC-E04", "\\.catch\\s*\\(\\s*(?:_|e|err)\\s*=>\\s*(?:null|undefined|void\\s+0|console\\.log)\\s*\\)", AlgoFamily.VULN_SWALLOWED_ERROR, RiskLevel.MEDIUM, 0.72, "Promise .catch with minimal handling", "CWE-390", ('javascript', 'typescript'), ('exception', 'swallowed')),
    VulnRule("EXC-E05", "try\\s*\\{[^}]*(?:verify|validate|authenticate|authorize)[^}]*\\}\\s*catch\\s*\\([^)]*\\)\\s*\\{[^}]*(?:next\\(\\)|return\\s+true|res\\.status\\s*\\(\\s*200)", AlgoFamily.VULN_FAIL_OPEN, RiskLevel.CRITICAL, 0.88, "Security check succeeds on error \u2014 fail-open", "CWE-636", ('javascript', 'typescript'), ('exception', 'fail-open')),
    VulnRule("EXC-E06", "defer\\s+(?:recover|func)", AlgoFamily.VULN_FAIL_OPEN, RiskLevel.MEDIUM, 0.6, "Go defer/recover \u2014 verify no auth bypass on panic", "CWE-636", ('go',), ('exception', 'go')),
    VulnRule("EXC-E07", "(?:open|File\\.open|fopen)\\s*\\((?!.*(?:with\\s|using\\s|try|finally|defer|Close))", AlgoFamily.VULN_RESOURCE_LEAK, RiskLevel.MEDIUM, 0.62, "File opened without cleanup \u2014 resource leak", "CWE-404", (), ('exception', 'resource-leak')),
    VulnRule("EXC-E08", "(?:connect|createConnection|getConnection)\\s*\\((?!.*(?:finally|close|release|dispose))", AlgoFamily.VULN_RESOURCE_LEAK, RiskLevel.MEDIUM, 0.6, "Connection without cleanup", "CWE-404", (), ('exception', 'resource-leak')),
    VulnRule("EXC-E09", "process\\.on\\s*\\(\\s*['\\\"](?:uncaughtException|unhandledRejection)['\\\"]", AlgoFamily.VULN_UNHANDLED_PROMISE, RiskLevel.MEDIUM, 0.68, "Global exception handler \u2014 verify recovery", "CWE-755", ('javascript', 'typescript'), ('exception', 'global')),
    VulnRule("EXC-E10", "@SneakyThrows|throws\\s+Exception\\s*\\{", AlgoFamily.VULN_SWALLOWED_ERROR, RiskLevel.MEDIUM, 0.68, "Broad exception propagation", "CWE-755", ('java',), ('exception', 'java')),
    VulnRule("EXC-E11", "rescue\\s*=>\\s*(?:nil|false|true|next|0)", AlgoFamily.VULN_SWALLOWED_ERROR, RiskLevel.HIGH, 0.78, "Ruby rescue with trivial return", "CWE-390", ('ruby',), ('exception', 'swallowed')),
    VulnRule("EXC-E12", "catch\\s*\\(\\s*Throwable\\s", AlgoFamily.VULN_SWALLOWED_ERROR, RiskLevel.MEDIUM, 0.72, "Java catching Throwable \u2014 too broad", "CWE-396", ('java',), ('exception', 'java')),
]

COMPILED_EXTENDED = _compile(_EXTENDED_RULES)

def scan_exception_scanner(content, relative_path, language, scan_mode, context_window=3):
    """Run extended exception_scanner analysis."""
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
