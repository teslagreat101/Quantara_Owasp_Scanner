"""
Quantum Protocol v4.0 — Frontend JavaScript Analyzer
Deep analysis of client-side code for secrets, endpoints, DOM XSS vectors,
source maps, env leaks, and build artifact analysis.

Covers: API key extraction, endpoint discovery, DOM XSS sinks/sources,
        postMessage abuse, localStorage sensitive data, webpack/vite leaks
"""
from __future__ import annotations
import re, logging
from typing import Optional
from quantum_protocol.models.enums import AlgoFamily, RiskLevel, ScanMode
from quantum_protocol.models.findings import CryptoFinding
from quantum_protocol.rules.owasp_rules import VulnRule, _compile
from quantum_protocol.utils.analysis import confidence_to_level, sanitize_line
from quantum_protocol.analyzers.secrets_engine import shannon_entropy

logger = logging.getLogger("quantum_protocol.frontend")

_FRONTEND_EXT_RULES: list[VulnRule] = [
    # ── Firebase Detection ─────────────────────────────────────
    VulnRule("FE-FB1", r'apiKey\s*[=:]\s*["\']AIza[0-9A-Za-z_-]{30,}["\']', AlgoFamily.VULN_JS_SECRET, RiskLevel.HIGH, 0.90, "Firebase API key detected (AIza prefix)", "CWE-798", ("javascript","typescript","html"), ("frontend","secret","firebase")),
    VulnRule("FE-FB2", r'(?:firebaseConfig|firebase\.initializeApp)\s*(?:\(|=)', AlgoFamily.VULN_JS_SECRET, RiskLevel.MEDIUM, 0.78, "Firebase configuration object in frontend", "CWE-798", ("javascript","typescript"), ("frontend","secret","firebase")),
    VulnRule("FE-FB3", r'(?:databaseURL|storageBucket|messagingSenderId)\s*[=:]\s*["\'][^"\']+["\']', AlgoFamily.VULN_JS_SECRET, RiskLevel.MEDIUM, 0.72, "Firebase service config in client code", "CWE-798", ("javascript","typescript"), ("frontend","secret","firebase")),

    # ── SaaS API Keys in Frontend ──────────────────────────────
    VulnRule("FE-E01", r'(?:google|gcp|GOOGLE).*?(?:key|apiKey|api_key)\s*[=:]\s*["\']AIza[0-9A-Za-z_-]{35}["\']', AlgoFamily.VULN_JS_SECRET, RiskLevel.HIGH, 0.90, "Google API key in frontend code", "CWE-798", ("javascript","typescript"), ("frontend","secret","google")),
    VulnRule("FE-E02", r'(?:mapbox|MAPBOX).*?(?:token|key)\s*[=:]\s*["\'](?:pk|sk)\.[a-zA-Z0-9]{60,}["\']', AlgoFamily.VULN_JS_SECRET, RiskLevel.HIGH, 0.88, "Mapbox token in frontend", "CWE-798", ("javascript","typescript"), ("frontend","secret","mapbox")),
    VulnRule("FE-E03", r'(?:algolia|ALGOLIA).*?(?:key|apiKey)\s*[=:]\s*["\'][a-f0-9]{32}["\']', AlgoFamily.VULN_JS_SECRET, RiskLevel.HIGH, 0.85, "Algolia API key in frontend", "CWE-798", ("javascript","typescript"), ("frontend","secret","algolia")),
    VulnRule("FE-E04", r'(?:stripe|STRIPE).*?(?:key|publishable)\s*[=:]\s*["\']pk_(?:live|test)_[a-zA-Z0-9]{24,}["\']', AlgoFamily.VULN_JS_SECRET, RiskLevel.MEDIUM, 0.82, "Stripe publishable key in frontend (expected, verify no secret key)", "CWE-798", ("javascript","typescript"), ("frontend","secret","stripe")),
    VulnRule("FE-E05", r'(?:stripe|STRIPE).*?(?:secret|sk)\s*[=:]\s*["\']sk_(?:live|test)_[a-zA-Z0-9]{24,}["\']', AlgoFamily.VULN_JS_SECRET, RiskLevel.CRITICAL, 0.95, "Stripe SECRET key in frontend — immediate rotation required", "CWE-798", ("javascript","typescript"), ("frontend","secret","stripe")),
    VulnRule("FE-E06", r'(?:twilio|TWILIO).*?(?:sid|token|key)\s*[=:]\s*["\'](?:AC|SK)[a-f0-9]{32}["\']', AlgoFamily.VULN_JS_SECRET, RiskLevel.CRITICAL, 0.90, "Twilio credential in frontend code", "CWE-798", ("javascript","typescript"), ("frontend","secret","twilio")),
    VulnRule("FE-E07", r'(?:sendgrid|SENDGRID).*?(?:key|apiKey)\s*[=:]\s*["\']SG\.[a-zA-Z0-9_-]{22,}["\']', AlgoFamily.VULN_JS_SECRET, RiskLevel.CRITICAL, 0.90, "SendGrid API key in frontend", "CWE-798", ("javascript","typescript"), ("frontend","secret","sendgrid")),
    VulnRule("FE-E08", r'(?:aws|AWS|cognito).*?(?:IdentityPoolId|poolId)\s*[=:]\s*["\'][\w-]+:[\w-]{36}["\']', AlgoFamily.VULN_JS_SECRET, RiskLevel.HIGH, 0.82, "AWS Cognito Pool ID in frontend", "CWE-798", ("javascript","typescript"), ("frontend","secret","aws")),
    VulnRule("FE-E09", r'(?:supabase|SUPABASE).*?(?:key|anon|service)\s*[=:]\s*["\']eyJ[a-zA-Z0-9_-]{50,}["\']', AlgoFamily.VULN_JS_SECRET, RiskLevel.HIGH, 0.85, "Supabase key in frontend", "CWE-798", ("javascript","typescript"), ("frontend","secret","supabase")),
    VulnRule("FE-E10", r'(?:openai|OPENAI).*?(?:key|apiKey)\s*[=:]\s*["\']sk-[a-zA-Z0-9]{32,}["\']', AlgoFamily.VULN_JS_SECRET, RiskLevel.CRITICAL, 0.95, "OpenAI API key in frontend — severe billing risk", "CWE-798", ("javascript","typescript"), ("frontend","secret","openai")),

    # ── Webpack/Vite/Build Artifact Leaks ──────────────────────
    VulnRule("FE-E20", r'webpackChunkName\s*:\s*["\'][^"\']+["\']', AlgoFamily.RECON_TECH_FINGERPRINT, RiskLevel.INFO, 0.65, "Webpack chunk name reveals internal module structure", "CWE-200", ("javascript","typescript"), ("frontend","webpack","recon")),
    VulnRule("FE-E21", r'__webpack_require__\s*\(\s*["\']\./', AlgoFamily.RECON_TECH_FINGERPRINT, RiskLevel.INFO, 0.60, "Webpack internal require reveals module paths", "CWE-200", ("javascript","typescript"), ("frontend","webpack","recon")),
    VulnRule("FE-E22", r'import\.meta\.env\.\w+', AlgoFamily.VULN_ENV_INLINE, RiskLevel.MEDIUM, 0.72, "Vite import.meta.env variable — verify no secrets", "CWE-798", ("javascript","typescript"), ("frontend","env","vite")),

    # ── WebSocket/SSE Endpoints ────────────────────────────────
    VulnRule("FE-E30", r'(?:new\s+WebSocket|io\.connect|io\s*\()\s*\(\s*["\']wss?://[^"\']+["\']', AlgoFamily.RECON_ENDPOINT, RiskLevel.MEDIUM, 0.75, "WebSocket endpoint discovered in frontend", "CWE-200", ("javascript","typescript"), ("frontend","websocket","recon")),
    VulnRule("FE-E31", r'new\s+EventSource\s*\(\s*["\'][^"\']+["\']', AlgoFamily.RECON_ENDPOINT, RiskLevel.LOW, 0.65, "Server-Sent Events endpoint in frontend", "CWE-200", ("javascript","typescript"), ("frontend","sse","recon")),

    # ── Angular-specific ───────────────────────────────────────
    VulnRule("FE-E40", r'\[innerHTML\]\s*=\s*["\']', AlgoFamily.VULN_DOM_XSS, RiskLevel.HIGH, 0.82, "Angular innerHTML binding — XSS if unsanitized", "CWE-79", ("typescript",), ("frontend","angular","xss")),
    VulnRule("FE-E41", r'bypassSecurityTrust(?:Html|Script|Url|ResourceUrl|Style)', AlgoFamily.VULN_DOM_XSS, RiskLevel.HIGH, 0.85, "Angular DomSanitizer bypass — verify input is trusted", "CWE-79", ("typescript",), ("frontend","angular","xss")),

    # ── Next.js / SSR leaks ────────────────────────────────────
    VulnRule("FE-E50", r'getServerSideProps.*?(?:secret|key|token|password|credential)', AlgoFamily.VULN_JS_SECRET, RiskLevel.HIGH, 0.78, "Sensitive data in getServerSideProps may leak to client __NEXT_DATA__", "CWE-200", ("javascript","typescript"), ("frontend","nextjs")),
    VulnRule("FE-E51", r'__NEXT_DATA__', AlgoFamily.RECON_TECH_FINGERPRINT, RiskLevel.INFO, 0.65, "Next.js data hydration — review for sensitive data leaks", "CWE-200", ("javascript","typescript","html"), ("frontend","nextjs","recon")),
]

COMPILED_FRONTEND_EXT = _compile(_FRONTEND_EXT_RULES)

# ── High-Entropy String Extraction for JS ──────────────────────

_JS_STRING_RE = re.compile(
    r'''(?:["'])((?:[A-Za-z0-9+/=_\-]){20,})(["'])''',
    re.MULTILINE,
)
_JS_TEMPLATE_RE = re.compile(
    r'`([^`]*?(?:https?://|wss?://|/api/|/v[0-9]+/|/internal/|/admin/)[^`]*?)`',
    re.MULTILINE,
)
_URL_EXTRACT_RE = re.compile(
    r'''(?:["'`])((?:https?://|wss?://|/api/|/v[0-9]+/|/internal/|/admin/|/graphql|/auth/|/webhook)[^\s"'`]{4,})(?:["'`])''',
    re.MULTILINE,
)

def scan_frontend(
    content: str,
    relative_path: str,
    language: Optional[str],
    scan_mode: ScanMode,
    context_window: int = 3,
) -> list[CryptoFinding]:
    """Deep frontend JavaScript analysis."""
    if language not in ("javascript", "typescript", "vue", "svelte", "html"):
        return []

    findings: list[CryptoFinding] = []
    seen: set[str] = set()
    lines = content.split("\n")

    # Layer 1: Extended frontend-specific patterns
    for compiled_re, rule in COMPILED_FRONTEND_EXT:
        if rule.languages and language and language not in rule.languages:
            continue
        for match in compiled_re.finditer(content):
            line_no = content[:match.start()].count("\n") + 1
            dedup = f"{relative_path}:{line_no}:{rule.id}"
            if dedup in seen:
                continue
            seen.add(dedup)
            raw_line = lines[line_no - 1] if line_no <= len(lines) else ""
            ctx_s = max(0, line_no - context_window - 1)
            ctx_e = min(len(lines), line_no + context_window)

            findings.append(CryptoFinding(
                id=CryptoFinding.generate_id(relative_path, line_no, f"FE-{rule.id}"),
                file=relative_path, language=language or "javascript",
                line_number=line_no, line_content=sanitize_line(raw_line.strip()),
                column_start=None, column_end=None,
                algorithm=rule.family.value, family=rule.family,
                risk=rule.risk, confidence=round(rule.confidence, 3),
                confidence_level=confidence_to_level(rule.confidence),
                key_size=None, hndl_relevant=False, pattern_note=rule.note,
                migration={"action": "Move secrets to server-side, use backend proxy for API calls", "cwe": rule.cwe},
                compliance_violations=[], context_lines=[sanitize_line(l) for l in lines[ctx_s:ctx_e]],
                cwe_id=rule.cwe, cvss_estimate=rule.risk.numeric,
                remediation_effort="medium", tags=list(rule.tags),
            ))

    # Layer 2: High-entropy string extraction
    for match in _JS_STRING_RE.finditer(content):
        val = match.group(1)
        if len(val) < 24 or len(val) > 256:
            continue
        ent = shannon_entropy(val)
        if ent < 4.2:
            continue
        line_no = content[:match.start()].count("\n") + 1
        dedup = f"{relative_path}:{line_no}:entropy-fe"
        if dedup in seen:
            continue
        seen.add(dedup)
        raw_line = lines[line_no - 1] if line_no <= len(lines) else ""
        # Skip common false positives
        if any(fp in raw_line.lower() for fp in ("hash", "sha256", "sha512", "digest", "css", "font", "base64", "uuid")):
            continue

        findings.append(CryptoFinding(
            id=CryptoFinding.generate_id(relative_path, line_no, "FE-ENTROPY"),
            file=relative_path, language=language or "javascript",
            line_number=line_no, line_content=sanitize_line(raw_line.strip()),
            column_start=None, column_end=None,
            algorithm="Frontend-High-Entropy", family=AlgoFamily.VULN_JS_SECRET,
            risk=RiskLevel.MEDIUM, confidence=round(min(0.85, (ent - 4.0) * 0.3 + 0.5), 3),
            confidence_level=confidence_to_level(0.65),
            key_size=None, hndl_relevant=False,
            pattern_note=f"High-entropy string in frontend (entropy={ent:.1f} bits/char) — potential leaked secret",
            migration={"action": "Verify this is not a secret. Move to server-side if it is."},
            compliance_violations=[], context_lines=[],
            cwe_id="CWE-798", tags=["frontend", "entropy", "secret"],
        ))

    # Layer 3: URL/endpoint extraction for recon
    for match in _URL_EXTRACT_RE.finditer(content):
        url = match.group(1)
        line_no = content[:match.start()].count("\n") + 1
        dedup = f"{relative_path}:{line_no}:url-{url[:30]}"
        if dedup in seen:
            continue
        seen.add(dedup)
        raw_line = lines[line_no - 1] if line_no <= len(lines) else ""

        # Classify endpoint risk
        is_admin = bool(re.search(r'/admin|/debug|/internal|/private|/secret', url, re.I))
        is_api = bool(re.search(r'/api/|/v[0-9]+/|/graphql|/webhook|/oauth', url, re.I))
        is_internal = bool(re.search(r'localhost|127\.0\.0\.1|\.internal\.|\.local\.|\.corp\.', url, re.I))

        if is_admin or is_internal:
            risk = RiskLevel.MEDIUM
            family = AlgoFamily.RECON_ADMIN_ROUTE if is_admin else AlgoFamily.RECON_INTERNAL_SERVICE
        elif is_api:
            risk = RiskLevel.INFO
            family = AlgoFamily.RECON_ENDPOINT
        else:
            continue  # Skip generic URLs

        findings.append(CryptoFinding(
            id=CryptoFinding.generate_id(relative_path, line_no, f"FE-URL-{url[:20]}"),
            file=relative_path, language=language or "javascript",
            line_number=line_no, line_content=sanitize_line(raw_line.strip()),
            column_start=None, column_end=None,
            algorithm=family.value, family=family,
            risk=risk, confidence=0.72,
            confidence_level=confidence_to_level(0.72),
            key_size=None, hndl_relevant=False,
            pattern_note=f"Endpoint discovered in frontend: {url[:80]}",
            migration={"action": "Review endpoint exposure and access controls"},
            compliance_violations=[], context_lines=[],
            cwe_id="CWE-200", tags=["frontend", "recon", "endpoint"],
        ))

    return findings
