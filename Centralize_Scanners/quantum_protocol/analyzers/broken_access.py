"""
Quantum Protocol v4.0 — A01: Broken Access Control (Extended)
IDOR, privilege escalation, CORS bypass, path traversal, SSRF,
missing auth middleware, forced browsing, file upload bypass.
"""
from __future__ import annotations
import re, logging
from typing import Optional
from quantum_protocol.models.enums import AlgoFamily, RiskLevel, ScanMode
from quantum_protocol.models.findings import CryptoFinding
from quantum_protocol.rules.owasp_rules import VulnRule, _compile
from quantum_protocol.utils.analysis import confidence_to_level, sanitize_line

logger = logging.getLogger("quantum_protocol.broken_access")

_EXTENDED_RULES: list[VulnRule] = [
    VulnRule("BAC-001", "(?:findById|findByPk|findOne|get_object_or_404|find_by)\\s*\\(\\s*(?:req|request|params|args)\\.\\w+\\s*\\)", AlgoFamily.VULN_IDOR, RiskLevel.HIGH, 0.78, "Direct object reference from user input without ownership verification", "CWE-639", (), ('access', 'idor')),
    VulnRule("BAC-002", "@PermitAll|@AllowAnonymous|AllowAny\\b|authentication_classes\\s*=\\s*\\[\\s*\\]", AlgoFamily.VULN_MISSING_AUTH_MIDDLEWARE, RiskLevel.HIGH, 0.82, "Endpoint explicitly permits unauthenticated access", "CWE-862", (), ('access', 'auth')),
    VulnRule("BAC-003", "app\\.(?:get|post|put|patch|delete)\\s*\\([^)]*(?:admin|user|account|profile|settings|dashboard|manage)", AlgoFamily.VULN_MISSING_AUTH_MIDDLEWARE, RiskLevel.MEDIUM, 0.68, "Sensitive route \u2014 verify authentication middleware applied", "CWE-862", ('javascript', 'typescript'), ('access', 'auth', 'route')),
    VulnRule("BAC-004", "\\.(?:unlink|rmdir|unlinkSync|rmdirSync|remove|delete_file)\\s*\\(\\s*(?:req|request|params|input)", AlgoFamily.VULN_PATH_TRAVERSAL, RiskLevel.CRITICAL, 0.88, "File deletion with user-controlled path", "CWE-22", (), ('access', 'path-traversal')),
    VulnRule("BAC-005", "(?:multer|formidable|busboy|multipart).*?(?:dest|uploadDir|saveTo)\\s*[=:]\\s*(?:req|request|params)", AlgoFamily.VULN_FILE_UPLOAD, RiskLevel.HIGH, 0.8, "File upload destination from user input", "CWE-434", ('javascript', 'typescript'), ('access', 'upload')),
    VulnRule("BAC-006", "\\.(?:mimetype|content_type|type)\\s*[=!]=\\s*['\\\"](?:image|application)", AlgoFamily.VULN_FILE_UPLOAD, RiskLevel.MEDIUM, 0.65, "Client-side MIME type check \u2014 validate server-side", "CWE-434", (), ('access', 'upload')),
    VulnRule("BAC-007", "if\\s+.*?(?:user|req|session)\\.\\w*(?:role|admin|isAdmin|is_staff|is_superuser|permission)", AlgoFamily.VULN_PRIVILEGE_ESCALATION, RiskLevel.MEDIUM, 0.62, "Role check \u2014 ensure server-side and not bypassable", "CWE-269", (), ('access', 'authz')),
    VulnRule("BAC-008", "\\.cors\\s*\\(\\s*\\{[^}]*origin\\s*:\\s*(?:true|\\[)", AlgoFamily.VULN_CORS_MISCONFIG, RiskLevel.HIGH, 0.8, "Dynamic CORS origin \u2014 verify allowlist validation", "CWE-942", ('javascript', 'typescript'), ('access', 'cors')),
    VulnRule("BAC-009", "Access-Control-Allow-Methods[:\\s]*(?:PUT|DELETE|PATCH)", AlgoFamily.VULN_CORS_MISCONFIG, RiskLevel.MEDIUM, 0.7, "CORS allows state-changing methods", "CWE-942", (), ('access', 'cors')),
    VulnRule("BAC-010", "urllib\\.request\\.urlopen\\s*\\(\\s*(?:url|req|request|params|input)", AlgoFamily.VULN_SSRF, RiskLevel.CRITICAL, 0.88, "Python urllib with user-controlled URL \u2014 SSRF", "CWE-918", ('python',), ('access', 'ssrf')),
    VulnRule("BAC-011", "HttpClient\\.(?:GetAsync|PostAsync|SendAsync)\\s*\\(\\s*(?:url|request|input)", AlgoFamily.VULN_SSRF, RiskLevel.HIGH, 0.82, ".NET HttpClient with user-controlled URL", "CWE-918", ('csharp',), ('access', 'ssrf')),
    VulnRule("BAC-012", "RestTemplate\\.(?:getForObject|postForObject|exchange)\\s*\\(\\s*(?:url|request)", AlgoFamily.VULN_SSRF, RiskLevel.HIGH, 0.82, "Java RestTemplate with variable URL", "CWE-918", ('java',), ('access', 'ssrf')),
    VulnRule("BAC-013", "\\.sendFile\\s*\\(\\s*(?:path\\.)?(?:resolve|join)\\s*\\(.*?(?:req|params|query)", AlgoFamily.VULN_PATH_TRAVERSAL, RiskLevel.CRITICAL, 0.85, "Express sendFile with user-influenced path", "CWE-22", ('javascript', 'typescript'), ('access', 'path-traversal')),
    VulnRule("BAC-014", "(?:proxy_pass|upstream|reverse_proxy|ProxyPass)\\s+https?://", AlgoFamily.VULN_SSRF, RiskLevel.MEDIUM, 0.65, "Reverse proxy \u2014 verify no user-controlled destination", "CWE-918", ('config',), ('access', 'ssrf')),
    VulnRule("BAC-015", "filepath\\.Clean\\s*\\(.*?(?:req|r\\.URL|query|param)", AlgoFamily.VULN_PATH_TRAVERSAL, RiskLevel.HIGH, 0.78, "Go filepath.Clean with user input \u2014 may not prevent all traversals", "CWE-22", ('go',), ('access', 'path-traversal')),
]

COMPILED_EXTENDED = _compile(_EXTENDED_RULES)

def scan_broken_access(content, relative_path, language, scan_mode, context_window=3):
    """Run extended broken_access analysis."""
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
