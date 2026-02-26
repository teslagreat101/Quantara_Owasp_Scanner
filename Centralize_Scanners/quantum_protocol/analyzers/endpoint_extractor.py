"""
Quantum Protocol v4.0 — Bug Bounty Recon Engine
Endpoint discovery, technology fingerprinting, attack surface mapping.
"""
from __future__ import annotations
import re, logging
from typing import Optional
from quantum_protocol.models.enums import AlgoFamily, RiskLevel, ScanMode
from quantum_protocol.models.findings import CryptoFinding
from quantum_protocol.utils.analysis import confidence_to_level, sanitize_line

logger = logging.getLogger("quantum_protocol.recon")

# ── URL/Path Extraction Patterns ───────────────────────────────
_URL_RE = re.compile(r'''(?:["'`])(/(?:api|v[0-9]+|internal|admin|auth|oauth|graphql|webhook|ws|debug|health|metrics|status|swagger|\.well-known)/[^\s"'`]{2,80})(?:["'`])''', re.I)
_HTTP_URL_RE = re.compile(r'''(?:["'`])(https?://[^\s"'`]{8,200})(?:["'`])''', re.I)
_INTERNAL_DNS_RE = re.compile(r'''(?:["'`])([\w.-]+\.(?:internal|local|corp|private|svc\.cluster\.local|intranet|staging|dev|test)\.[.\w]+)(?:["'`])''', re.I)

# ── Technology Fingerprinting ──────────────────────────────────
_TECH_PATTERNS = [
    (r'from\s+(?:flask|django|fastapi|starlette|tornado|bottle)\b', "Python Web Framework", ("python",)),
    (r'(?:require|import).*?(?:express|koa|hapi|fastify|nest)\b', "Node.js Framework", ("javascript","typescript")),
    (r'import\s+(?:org\.springframework|javax\.servlet)', "Java Spring", ("java",)),
    (r'(?:require|import).*?(?:react|vue|angular|svelte|next|nuxt)\b', "Frontend SPA Framework", ("javascript","typescript")),
    (r'(?:require|import).*?(?:sequelize|typeorm|prisma|mongoose|knex)\b', "ORM/Database", ("javascript","typescript")),
    (r'from\s+(?:sqlalchemy|peewee|tortoise|mongoengine|pymongo)\b', "Python ORM/DB", ("python",)),
    (r'(?:require|import).*?(?:passport|jsonwebtoken|jose|auth0)\b', "Auth Library", ("javascript","typescript")),
    (r'(?:require|import).*?(?:stripe|paypal|braintree|square)\b', "Payment Integration", ("javascript","typescript","python")),
    (r'(?:redis|memcached|elasticache)\s*[.(]', "Cache Layer", ()),
    (r'(?:kafka|rabbitmq|celery|bull|amqp)\b', "Message Queue", ()),
    (r'(?:grpc|protobuf|thrift)\b', "RPC Framework", ()),
    (r'(?:graphql|apollo|hasura|prisma)\b', "GraphQL", ("javascript","typescript","python")),
    (r'(?:docker|kubernetes|k8s|helm|istio|envoy)\b', "Container/Orchestration", ("config","dockerfile")),
]

_ADMIN_ROUTES = re.compile(r'''(?:["'`])/(?:admin|administrator|dashboard|manage|control-panel|panel|cms|backend|backoffice|staff|moderator|superadmin|sysadmin)(?:/|["'`])''', re.I)

def scan_recon(content, relative_path, language, scan_mode, context_window=3):
    """Extract endpoints, fingerprint tech stack, map attack surface."""
    findings, seen, lines = [], set(), content.split("\n")

    # API/Internal endpoints
    for regex, family, risk in [
        (_URL_RE, AlgoFamily.RECON_ENDPOINT, RiskLevel.INFO),
        (_ADMIN_ROUTES, AlgoFamily.RECON_ADMIN_ROUTE, RiskLevel.MEDIUM),
    ]:
        for match in regex.finditer(content):
            val = match.group(1)
            ln = content[:match.start()].count("\n") + 1
            dk = f"{relative_path}:{ln}:recon-{val[:20]}"
            if dk in seen: continue
            seen.add(dk)
            raw = lines[ln-1] if ln <= len(lines) else ""
            findings.append(CryptoFinding(
                id=CryptoFinding.generate_id(relative_path, ln, f"RECON-{val[:15]}"),
                file=relative_path, language=language or "unknown",
                line_number=ln, line_content=sanitize_line(raw.strip()),
                column_start=None, column_end=None,
                algorithm=family.value, family=family,
                risk=risk, confidence=0.72,
                confidence_level=confidence_to_level(0.72),
                key_size=None, hndl_relevant=False,
                pattern_note=f"Endpoint: {val[:80]}",
                migration={"action": "Review endpoint access controls"},
                compliance_violations=[], context_lines=[],
                cwe_id="CWE-200", tags=["recon", "endpoint"],
            ))

    # Full URLs (HTTP/HTTPS)
    for match in _HTTP_URL_RE.finditer(content):
        url = match.group(1)
        ln = content[:match.start()].count("\n") + 1
        is_internal = bool(re.search(r'localhost|127\.0\.0\.1|\.internal|\.local|\.corp|\.staging|\.dev', url, re.I))
        if not is_internal:
            continue
        dk = f"{relative_path}:{ln}:url-{url[:25]}"
        if dk in seen: continue
        seen.add(dk)
        raw = lines[ln-1] if ln <= len(lines) else ""
        findings.append(CryptoFinding(
            id=CryptoFinding.generate_id(relative_path, ln, f"RECON-URL"),
            file=relative_path, language=language or "unknown",
            line_number=ln, line_content=sanitize_line(raw.strip()),
            column_start=None, column_end=None,
            algorithm=AlgoFamily.VULN_INTERNAL_URL.value, family=AlgoFamily.VULN_INTERNAL_URL,
            risk=RiskLevel.MEDIUM, confidence=0.78,
            confidence_level=confidence_to_level(0.78),
            key_size=None, hndl_relevant=False,
            pattern_note=f"Internal URL: {url[:80]}",
            migration={"action": "Remove internal URLs from source code"},
            compliance_violations=[], context_lines=[],
            cwe_id="CWE-200", tags=["recon", "internal-url"],
        ))

    # Internal DNS
    for match in _INTERNAL_DNS_RE.finditer(content):
        host = match.group(1)
        ln = content[:match.start()].count("\n") + 1
        dk = f"{relative_path}:{ln}:dns-{host[:20]}"
        if dk in seen: continue
        seen.add(dk)
        raw = lines[ln-1] if ln <= len(lines) else ""
        findings.append(CryptoFinding(
            id=CryptoFinding.generate_id(relative_path, ln, f"RECON-DNS"),
            file=relative_path, language=language or "unknown",
            line_number=ln, line_content=sanitize_line(raw.strip()),
            column_start=None, column_end=None,
            algorithm=AlgoFamily.RECON_INTERNAL_SERVICE.value, family=AlgoFamily.RECON_INTERNAL_SERVICE,
            risk=RiskLevel.MEDIUM, confidence=0.78,
            confidence_level=confidence_to_level(0.78),
            key_size=None, hndl_relevant=False,
            pattern_note=f"Internal service: {host}",
            migration={"action": "Remove internal service references from code"},
            compliance_violations=[], context_lines=[],
            cwe_id="CWE-200", tags=["recon", "internal-service"],
        ))

    # Tech fingerprinting
    for pat, tech, langs in _TECH_PATTERNS:
        if langs and language and language not in langs:
            continue
        m = re.search(pat, content, re.I)
        if m:
            ln = content[:m.start()].count("\n") + 1
            dk = f"{relative_path}:tech-{tech}"
            if dk in seen: continue
            seen.add(dk)
            raw = lines[ln-1] if ln <= len(lines) else ""
            findings.append(CryptoFinding(
                id=CryptoFinding.generate_id(relative_path, ln, f"RECON-TECH-{tech[:10]}"),
                file=relative_path, language=language or "unknown",
                line_number=ln, line_content=sanitize_line(raw.strip()),
                column_start=None, column_end=None,
                algorithm=AlgoFamily.RECON_TECH_FINGERPRINT.value, family=AlgoFamily.RECON_TECH_FINGERPRINT,
                risk=RiskLevel.INFO, confidence=0.80,
                confidence_level=confidence_to_level(0.80),
                key_size=None, hndl_relevant=False,
                pattern_note=f"Technology: {tech}",
                migration={}, compliance_violations=[], context_lines=[],
                cwe_id="CWE-200", tags=["recon", "tech-fingerprint"],
            ))
    return findings
