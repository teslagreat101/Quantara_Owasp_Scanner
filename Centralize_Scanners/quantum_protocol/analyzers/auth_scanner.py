"""
Quantum Protocol v4.0 — A07: Authentication Failures (Extended)
Password policy, session management, JWT deep analysis,
MFA gaps, credential stuffing defense, OAuth misconfiguration.
"""
from __future__ import annotations
import re, logging
from typing import Optional
from quantum_protocol.models.enums import AlgoFamily, RiskLevel, ScanMode
from quantum_protocol.models.findings import CryptoFinding
from quantum_protocol.rules.owasp_rules import VulnRule, _compile
from quantum_protocol.utils.analysis import confidence_to_level, sanitize_line

logger = logging.getLogger("quantum_protocol.auth_scanner")

_EXTENDED_RULES: list[VulnRule] = [
    VulnRule("ATH-001", "(?:password|passwd).*?(?:min_length|minlength|minimum)\\s*[=:]\\s*(?:[0-7])\\b", AlgoFamily.VULN_WEAK_PASSWORD_POLICY, RiskLevel.HIGH, 0.82, "Password minimum length < 8", "CWE-521", (), ('auth', 'password')),
    VulnRule("ATH-002", "jwt\\.(?:encode|sign)\\s*\\([^)]*(?!.*exp)", AlgoFamily.VULN_JWT_MISCONFIG, RiskLevel.HIGH, 0.75, "JWT without expiration \u2014 tokens never expire", "CWE-613", (), ('auth', 'jwt')),
    VulnRule("ATH-003", "(?:session|express-session).*?(?:maxAge|max_age)\\s*[=:]\\s*(?:null|undefined|0|false|None)", AlgoFamily.VULN_SESSION_FIXATION, RiskLevel.HIGH, 0.8, "Session without expiration", "CWE-613", (), ('auth', 'session')),
    VulnRule("ATH-004", "(?:oauth|OAuth).*?(?:state|nonce)\\s*[=:]\\s*(?:null|undefined|false|None|['\\\"]['\\\"])", AlgoFamily.VULN_CSRF, RiskLevel.HIGH, 0.82, "OAuth without state/nonce \u2014 CSRF risk", "CWE-352", (), ('auth', 'oauth')),
    VulnRule("ATH-005", "(?:redirect_uri|callback_url|return_url)\\s*[=:]\\s*(?:req|request|params)\\.", AlgoFamily.VULN_OPEN_REDIRECT, RiskLevel.HIGH, 0.82, "OAuth redirect_uri from user input", "CWE-601", (), ('auth', 'oauth')),
    VulnRule("ATH-006", "password\\s*[=!]=\\s*['\\\"]['\\\"]|len\\s*\\(\\s*password\\s*\\)\\s*==\\s*0", AlgoFamily.VULN_WEAK_PASSWORD_POLICY, RiskLevel.HIGH, 0.78, "Empty password acceptance", "CWE-521", (), ('auth', 'password')),
    VulnRule("ATH-007", "(?:otp|totp|mfa|two_factor).*?secret\\s*[=:]\\s*['\\\"][A-Z2-7]{16,}['\\\"]", AlgoFamily.VULN_HARDCODED_CREDS, RiskLevel.CRITICAL, 0.9, "TOTP/MFA secret hardcoded", "CWE-798", (), ('auth', 'mfa')),
    VulnRule("ATH-008", "(?:compare|equals)\\s*\\(\\s*(?:password|token|secret)", AlgoFamily.VULN_WEAK_PASSWORD_POLICY, RiskLevel.MEDIUM, 0.72, "String comparison for secrets \u2014 use constant-time", "CWE-208", (), ('auth', 'timing')),
    VulnRule("ATH-009", "(?:remember_me|stay_signed_in|keep_logged_in)\\s*[=:]\\s*(?:true|True|1)", AlgoFamily.VULN_INSECURE_COOKIE, RiskLevel.MEDIUM, 0.68, "Remember-me \u2014 verify secure implementation", "CWE-613", (), ('auth', 'session')),
    VulnRule("ATH-010", "jwt\\.(?:decode|verify)\\s*\\([^)]*algorithms\\s*[=:]\\s*\\[\\s*['\\\"](?:HS|RS)", AlgoFamily.VULN_JWT_MISCONFIG, RiskLevel.MEDIUM, 0.65, "JWT decode with explicit algorithm \u2014 verify no confusion attack", "CWE-345", (), ('auth', 'jwt')),
    VulnRule("ATH-011", "(?:login|authenticate|sign_in).*?(?:attempts|tries|count|failed)\\s*[><=]+\\s*\\d+", AlgoFamily.VULN_MISSING_RATE_LIMIT, RiskLevel.MEDIUM, 0.65, "Login attempt counting \u2014 verify account lockout is effective", "CWE-307", (), ('auth', 'brute-force')),
    VulnRule("ATH-012", "(?:API_KEY|api_key|apiKey)\\s*[=:]\\s*(?:req|request)\\.(?:headers?|query|params)\\.\\w+(?!\\s*\\|\\|)", AlgoFamily.VULN_MISSING_AUTH_MIDDLEWARE, RiskLevel.MEDIUM, 0.65, "API key from request without fallback/validation", "CWE-306", (), ('auth', 'api-key')),
]

COMPILED_EXTENDED = _compile(_EXTENDED_RULES)

def scan_auth_scanner(content, relative_path, language, scan_mode, context_window=3):
    """Run extended auth_scanner analysis."""
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
