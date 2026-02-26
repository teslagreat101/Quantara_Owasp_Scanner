"""
Quantum Protocol v4.0 — A02: Security Misconfiguration (Extended)
Debug modes, default creds, missing headers, exposed endpoints,
verbose errors, directory listing, TLS config, server banners.
"""
from __future__ import annotations
import re, logging
from typing import Optional
from quantum_protocol.models.enums import AlgoFamily, RiskLevel, ScanMode
from quantum_protocol.models.findings import CryptoFinding
from quantum_protocol.rules.owasp_rules import VulnRule, _compile
from quantum_protocol.utils.analysis import confidence_to_level, sanitize_line

logger = logging.getLogger("quantum_protocol.misconfig_engine")

_EXTENDED_RULES: list[VulnRule] = [
    VulnRule("CFG-001", "(?:ALLOWED_HOSTS|AllowedHosts)\\s*=\\s*\\[\\s*['\\\"]?\\*['\\\"]?\\s*\\]", AlgoFamily.VULN_PERMISSIVE_POLICY, RiskLevel.HIGH, 0.85, "Django ALLOWED_HOSTS = ['*'] \u2014 accepts any host header", "CWE-16", ('python',), ('misconfig', 'django')),
    VulnRule("CFG-002", "(?:SECRET_KEY|SECURITY_KEY)\\s*=\\s*['\\\"](?:change.?me|default|insecure|development|xxx|your.?secret|temporary|test)['\\\"]", AlgoFamily.VULN_DEFAULT_CREDS, RiskLevel.CRITICAL, 0.9, "Framework secret key set to default/insecure value", "CWE-1393", (), ('misconfig', 'secret-key')),
    VulnRule("CFG-003", "server_tokens\\s+on|ServerSignature\\s+On|X-Powered-By", AlgoFamily.VULN_MISSING_HEADERS, RiskLevel.LOW, 0.72, "Server version disclosure via headers", "CWE-200", ('config',), ('misconfig', 'headers')),
    VulnRule("CFG-004", "ssl_protocols?\\s+.*?(?:SSLv2|SSLv3|TLSv1(?:\\.0)?(?:\\s|;|$))", AlgoFamily.VULN_PERMISSIVE_POLICY, RiskLevel.HIGH, 0.88, "Deprecated SSL/TLS protocol enabled", "CWE-327", ('config',), ('misconfig', 'tls')),
    VulnRule("CFG-005", "ssl_ciphers?\\s+.*?(?:NULL|EXPORT|DES|RC4|MD5|aNULL|eNULL)", AlgoFamily.VULN_PERMISSIVE_POLICY, RiskLevel.HIGH, 0.88, "Weak cipher suite in TLS configuration", "CWE-327", ('config',), ('misconfig', 'tls')),
    VulnRule("CFG-006", "MIDDLEWARE\\s*=\\s*\\[(?!.*SecurityMiddleware)", AlgoFamily.VULN_MISSING_HEADERS, RiskLevel.MEDIUM, 0.68, "Django MIDDLEWARE without SecurityMiddleware", "CWE-693", ('python',), ('misconfig', 'django')),
    VulnRule("CFG-007", "app\\.use\\s*\\(\\s*(?:express\\.static|serve-static)\\s*\\(\\s*['\\\"]\\.?/?['\\\"]", AlgoFamily.VULN_DIRECTORY_LISTING, RiskLevel.MEDIUM, 0.72, "Static file serving from root \u2014 verify no sensitive files", "CWE-548", ('javascript', 'typescript'), ('misconfig', 'static')),
    VulnRule("CFG-008", "options\\s+Indexes|autoindex\\s+on|DirectoryIndex\\s+disabled", AlgoFamily.VULN_DIRECTORY_LISTING, RiskLevel.MEDIUM, 0.82, "Directory listing enabled", "CWE-548", ('config',), ('misconfig', 'listing')),
    VulnRule("CFG-009", "(?:verbose|log_level|loglevel|LOG_LEVEL)\\s*[=:]\\s*['\\\"]?(?:DEBUG|TRACE|ALL)['\\\"]?", AlgoFamily.VULN_VERBOSE_ERRORS, RiskLevel.MEDIUM, 0.72, "Verbose logging in production config", "CWE-209", ('config',), ('misconfig', 'logging')),
    VulnRule("CFG-010", "X-Frame-Options\\s*[=:]\\s*['\\\"]?ALLOW", AlgoFamily.VULN_MISSING_HEADERS, RiskLevel.HIGH, 0.82, "X-Frame-Options allows framing \u2014 clickjacking", "CWE-693", ('config',), ('misconfig', 'headers')),
    VulnRule("CFG-011", "SECURE_SSL_REDIRECT\\s*=\\s*False", AlgoFamily.VULN_MISSING_HEADERS, RiskLevel.HIGH, 0.85, "Django SSL redirect disabled", "CWE-319", ('python',), ('misconfig', 'django')),
    VulnRule("CFG-012", "SESSION_COOKIE_SECURE\\s*=\\s*False", AlgoFamily.VULN_INSECURE_COOKIE, RiskLevel.HIGH, 0.85, "Django session cookie not secure", "CWE-614", ('python',), ('misconfig', 'cookie')),
    VulnRule("CFG-013", "CSRF_COOKIE_SECURE\\s*=\\s*False", AlgoFamily.VULN_INSECURE_COOKIE, RiskLevel.HIGH, 0.82, "Django CSRF cookie not secure", "CWE-614", ('python',), ('misconfig', 'cookie')),
    VulnRule("CFG-014", "helmet\\s*\\(\\s*\\)(?!.*contentSecurityPolicy)", AlgoFamily.VULN_MISSING_HEADERS, RiskLevel.MEDIUM, 0.65, "Express Helmet without CSP", "CWE-693", ('javascript', 'typescript'), ('misconfig', 'express')),
    VulnRule("CFG-015", "Strict-Transport-Security.*?max-age\\s*=\\s*(?:[0-9]{1,5})\\b", AlgoFamily.VULN_MISSING_HEADERS, RiskLevel.MEDIUM, 0.75, "HSTS max-age too short (< 1 year)", "CWE-319", ('config',), ('misconfig', 'hsts')),
    VulnRule("CFG-016", "(?:expose_php|phpinfo|php_flag)\\s*=?\\s*(?:On|1|true)", AlgoFamily.VULN_VERBOSE_ERRORS, RiskLevel.HIGH, 0.82, "PHP info/configuration exposed", "CWE-200", ('php', 'config'), ('misconfig', 'php')),
    VulnRule("CFG-017", "(?:listen|bind)\\s+(?:0\\.0\\.0\\.0|::)\\s*:\\s*(?:22|3306|5432|6379|27017|9200|8080)\\b", AlgoFamily.VULN_EXPOSED_ADMIN, RiskLevel.HIGH, 0.82, "Sensitive service bound to all interfaces", "CWE-200", ('config',), ('misconfig', 'network')),
]

COMPILED_EXTENDED = _compile(_EXTENDED_RULES)

def scan_misconfig_engine(content, relative_path, language, scan_mode, context_window=3):
    """Run extended misconfig_engine analysis."""
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
