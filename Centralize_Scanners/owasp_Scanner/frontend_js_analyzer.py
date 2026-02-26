"""
Quantum Protocol v4.0 — Frontend JavaScript Secret Mining Engine

Scans .js, .jsx, .ts, .tsx, .mjs, .vue, .svelte files and bundled frontend
code (webpack, vite, rollup output) to extract secrets, API endpoints,
internal URLs, debug configs, and sensitive data shipped to the client.

Detections:
  - API keys embedded in frontend bundles (Firebase, Stripe, Google, Algolia, etc.)
  - Backend API URLs and internal service endpoints
  - OAuth client IDs + secrets shipped to the browser
  - Firebase config objects
  - GraphQL introspection endpoints
  - WebSocket endpoints with auth tokens
  - DOM XSS vectors: eval(), innerHTML, document.write(), postMessage
  - localStorage/sessionStorage with sensitive data
  - Source maps in production
  - Console.log with sensitive data
  - dangerouslySetInnerHTML, v-html, [innerHTML] binding
  - Hardcoded base URLs for environments
  - .env variables inlined by webpack/vite
  - Webpack comments revealing internal paths
"""

from __future__ import annotations

import re
import math
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path

# ────────────────────────────────────────────────────────────────────────────
# Constants
# ────────────────────────────────────────────────────────────────────────────

FRONTEND_EXTENSIONS = {
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".vue", ".svelte", ".html", ".htm",
}

BUNDLE_INDICATORS = {
    "webpackChunkName", "webpackJsonp", "__webpack_require__",
    "import.meta.env", "process.env.REACT_APP_", "process.env.NEXT_PUBLIC_",
    "process.env.VITE_", "import.meta.hot",
}


# ────────────────────────────────────────────────────────────────────────────
# Finding Classification
# ────────────────────────────────────────────────────────────────────────────

@dataclass
class FrontendFinding:
    """A single frontend security finding."""
    id: str
    file: str
    line_number: int
    column: int
    finding_type: str  # api-key | endpoint | secret | debug-leak | xss-vector | misconfig
    severity: str      # Critical | High | Medium | Low | Info
    title: str
    description: str
    matched_value: str
    redacted_value: str
    entropy: float
    category: str      # OWASP category
    cwe: str
    remediation: str
    confidence: float
    framework: Optional[str] = None
    tags: list[str] = field(default_factory=list)


# ────────────────────────────────────────────────────────────────────────────
# Entropy Analysis
# ────────────────────────────────────────────────────────────────────────────

def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy in bits per character."""
    if not data:
        return 0.0
    freq = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _redact(value: str, visible: int = 4) -> str:
    """Redact a secret value, showing only first/last few chars."""
    if len(value) <= visible * 2 + 3:
        return "***REDACTED***"
    return f"{value[:visible]}...{value[-visible:]}"


# ────────────────────────────────────────────────────────────────────────────
# Pattern Definitions
# ────────────────────────────────────────────────────────────────────────────

@dataclass
class JSPattern:
    id: str
    pattern: str
    finding_type: str
    severity: str
    title: str
    description: str
    cwe: str
    remediation: str
    confidence: float
    category: str = "A04:2025-Cryptographic Failures"
    framework: Optional[str] = None
    tags: tuple[str, ...] = ()


def _build_frontend_rules() -> list[JSPattern]:
    """Build all frontend JS/TS detection rules."""
    rules: list[JSPattern] = []

    def _add(id_: str, pattern: str, ftype: str, severity: str, title: str,
             desc: str, cwe: str, remediation: str, conf: float,
             category: str = "A04:2025-Cryptographic Failures",
             framework: Optional[str] = None, tags: tuple = ()):
        rules.append(JSPattern(
            id=id_, pattern=pattern, finding_type=ftype, severity=severity,
            title=title, description=desc, cwe=cwe, remediation=remediation,
            confidence=conf, category=category, framework=framework, tags=tags,
        ))

    # ── Exposed API Keys ──────────────────────────────────────────
    _add("FE-001", r"""(?:firebase|FIREBASE).*?apiKey\s*[:=]\s*["']([A-Za-z0-9_\-]{20,})["']""",
         "api-key", "High", "Firebase API Key Exposed",
         "Firebase API key found in client-side code. While Firebase API keys are designed to be public, they should be restricted with security rules.",
         "CWE-312", "Restrict key via Firebase Console > Project Settings > API restrictions. Implement proper Firestore/RTDB security rules.",
         0.85, tags=("firebase", "api-key"))

    _add("FE-002", r"""(?:stripe|STRIPE).*?(?:pk_live|pk_test)_[A-Za-z0-9]{20,}""",
         "api-key", "Medium", "Stripe Publishable Key Exposed",
         "Stripe publishable key found in frontend code. Publishable keys are meant to be public but should be monitored.",
         "CWE-312", "Ensure this is a publishable key (pk_*), never a secret key (sk_*). Rotate if sk_* is found.",
         0.90, tags=("stripe", "payment"))

    _add("FE-003", r"""(?:sk_live|sk_test)_[A-Za-z0-9]{20,}""",
         "secret", "Critical", "Stripe Secret Key in Frontend!",
         "Stripe SECRET key found in client-side code. This provides full API access to your Stripe account.",
         "CWE-798", "IMMEDIATELY rotate this key in Stripe Dashboard. Move to server-side environment variable. Never expose sk_* keys.",
         0.99, tags=("stripe", "payment", "critical"))

    _add("FE-004", r"""(?:google|GOOGLE).*?(?:AIza|GOOG)[A-Za-z0-9_\-]{30,}""",
         "api-key", "High", "Google API Key Exposed",
         "Google API key found in frontend bundle. May allow quota theft and unauthorized API usage.",
         "CWE-312", "Restrict key to specific APIs and HTTP referrers in Google Cloud Console.",
         0.85, tags=("google", "api-key"))

    _add("FE-005", r"""(?:algolia|ALGOLIA).*?(?:apiKey|api_key)\s*[:=]\s*["']([a-f0-9]{32})["']""",
         "api-key", "Medium", "Algolia API Key Exposed",
         "Algolia API key found in frontend code. Ensure this is a Search-Only API key, not an Admin key.",
         "CWE-312", "Use Search-Only API keys for frontend. Never expose Admin API keys in client code.",
         0.80, tags=("algolia", "search"))

    _add("FE-006", r"""(?:mapbox|MAPBOX).*?(?:pk|sk)\.[A-Za-z0-9_\-]{50,}""",
         "api-key", "Medium", "Mapbox Token Exposed",
         "Mapbox access token found in frontend code.",
         "CWE-312", "Restrict token scope and URLs in Mapbox account settings.",
         0.80, tags=("mapbox", "api-key"))

    _add("FE-007", r"""(?:aws_cognito|cognito|COGNITO).*?(?:us|eu|ap)-\w+-\d+[_:][A-Za-z0-9\-]+""",
         "secret", "High", "AWS Cognito Pool ID Exposed",
         "AWS Cognito Identity/User Pool ID found in frontend. Could enable unauthorized pool access.",
         "CWE-312", "Implement proper Cognito IAM roles and unauthenticated access policies.",
         0.75, tags=("aws", "cognito"))

    _add("FE-008", r"""(?:REACT_APP|NEXT_PUBLIC|VITE)_[A-Z_]+\s*[:=]\s*["']([^"']{10,})["']""",
         "debug-leak", "Medium", "Build-time Environment Variable Inlined",
         "Environment variable from build tool (React/Next.js/Vite) found inlined in bundle.",
         "CWE-200", "Review all REACT_APP_*/NEXT_PUBLIC_*/VITE_* variables. Only expose non-sensitive values to client.",
         0.70, tags=("build", "env-var"))

    _add("FE-009", r"""(?:client_?id|CLIENT_?ID)\s*[:=]\s*["']([A-Za-z0-9\-_.]{15,})["']""",
         "secret", "High", "OAuth Client ID in Frontend",
         "OAuth Client ID found in frontend code. While Client IDs can be public, ensure the Client Secret is not exposed.",
         "CWE-312", "Verify Client Secret is NOT in the bundle. Use PKCE flow for SPAs instead of Client Secret.",
         0.65, tags=("oauth", "auth"))

    _add("FE-010", r"""(?:client_?secret|CLIENT_?SECRET)\s*[:=]\s*["']([A-Za-z0-9\-_.]{15,})["']""",
         "secret", "Critical", "OAuth Client SECRET in Frontend!",
         "OAuth Client Secret found in client-side code. This completely compromises the OAuth flow.",
         "CWE-798", "IMMEDIATELY rotate the client secret. Move to backend server. Use PKCE flow for SPAs.",
         0.95, tags=("oauth", "auth", "critical"))

    # ── XSS Vectors & Dangerous Patterns ──────────────────────────
    _add("FE-020", r"""\beval\s*\(\s*(?!["']\s*\))""",
         "xss-vector", "High", "eval() Usage Detected",
         "eval() executes arbitrary code from strings. If user input reaches eval(), it's a critical XSS/RCE vector.",
         "CWE-95", "Replace eval() with JSON.parse() for data, or Function() constructor with strict input validation.",
         0.80, category="A03:2025-Injection", tags=("xss", "code-execution"))

    _add("FE-021", r"""\bnew\s+Function\s*\(""",
         "xss-vector", "High", "new Function() Usage Detected",
         "new Function() dynamically creates functions from strings, similar to eval().",
         "CWE-95", "Avoid dynamic function creation. Use predefined functions or safe template systems.",
         0.75, category="A03:2025-Injection", tags=("xss", "code-execution"))

    _add("FE-022", r"""document\.write\s*\(""",
         "xss-vector", "High", "document.write() Usage",
         "document.write() can introduce XSS if it includes unsanitized user input.",
         "CWE-79", "Use safe DOM manipulation methods: createElement(), textContent, or framework-specific rendering.",
         0.70, category="A03:2025-Injection", tags=("xss", "dom"))

    _add("FE-023", r"""\.innerHTML\s*=\s*(?!["'`]\s*$)""",
         "xss-vector", "High", "Direct innerHTML Assignment",
         "Setting innerHTML directly with dynamic content can lead to DOM-based XSS.",
         "CWE-79", "Use textContent for text, or DOMPurify.sanitize() before innerHTML assignment.",
         0.75, category="A03:2025-Injection", tags=("xss", "dom"))

    _add("FE-024", r"""dangerouslySetInnerHTML\s*=\s*\{""",
         "xss-vector", "High", "React dangerouslySetInnerHTML",
         "dangerouslySetInnerHTML bypasses React's XSS protection. Requires careful sanitization.",
         "CWE-79", "Use DOMPurify.sanitize() before passing to dangerouslySetInnerHTML. Prefer safe alternatives.",
         0.80, category="A03:2025-Injection", framework="React", tags=("xss", "react"))

    _add("FE-025", r"""v-html\s*=""",
         "xss-vector", "High", "Vue v-html Directive",
         "v-html renders raw HTML in Vue, bypassing XSS protection.",
         "CWE-79", "Use {{ }} interpolation for text content. Sanitize with DOMPurify if v-html is required.",
         0.80, category="A03:2025-Injection", framework="Vue", tags=("xss", "vue"))

    _add("FE-026", r"""\[innerHTML\]\s*=""",
         "xss-vector", "High", "Angular innerHTML Binding",
         "Angular [innerHTML] binding can introduce XSS if not properly sanitized by Angular's DomSanitizer.",
         "CWE-79", "Use Angular's DomSanitizer.bypassSecurityTrustHtml() only with pre-sanitized content.",
         0.75, category="A03:2025-Injection", framework="Angular", tags=("xss", "angular"))

    _add("FE-027", r"""(?:postMessage|addEventListener\s*\(\s*["']message["'])\s*(?!.*origin)""",
         "xss-vector", "Medium", "postMessage Without Origin Check",
         "postMessage or message event listener found without apparent origin validation.",
         "CWE-346", "Always validate event.origin in message event handlers. Restrict postMessage target origin.",
         0.60, category="A01:2025-Broken Access Control", tags=("xss", "postMessage"))

    # ── Sensitive Data Storage ─────────────────────────────────────
    _add("FE-030", r"""localStorage\.setItem\s*\(\s*["'](?:token|auth|session|jwt|password|secret|key|credential)""",
         "misconfig", "High", "Sensitive Data in localStorage",
         "Storing authentication tokens/secrets in localStorage makes them accessible to any XSS attack.",
         "CWE-922", "Use httpOnly cookies for auth tokens instead of localStorage. Use sessionStorage as a minimum.",
         0.80, category="A02:2025-Security Misconfiguration", tags=("storage", "xss"))

    _add("FE-031", r"""sessionStorage\.setItem\s*\(\s*["'](?:password|secret|key|credential)""",
         "misconfig", "Medium", "Secrets in sessionStorage",
         "Sensitive data stored in sessionStorage is vulnerable to XSS attacks within the tab lifetime.",
         "CWE-922", "Use httpOnly cookies for secrets. Never store passwords or keys in web storage.",
         0.75, category="A02:2025-Security Misconfiguration", tags=("storage", "xss"))

    # ── Source Map & Debug Leaks ───────────────────────────────────
    _add("FE-040", r"""//[#@]\s*sourceMappingURL\s*=""",
         "debug-leak", "Medium", "Source Map Reference in Production",
         "Source map reference found. If served in production, attackers can read original source code.",
         "CWE-200", "Remove source maps from production builds. Configure bundler to exclude source map comments.",
         0.85, tags=("sourcemap", "debug"))

    _add("FE-041", r"""console\.\s*(?:log|debug|warn|info|trace)\s*\(\s*.*?(?:password|secret|token|key|auth|credential|api[_-]?key)""",
         "debug-leak", "High", "Sensitive Data in Console Output",
         "Console statement may log sensitive data (passwords, tokens, keys) visible in browser DevTools.",
         "CWE-532", "Remove all console statements logging sensitive data in production builds. Use a logging library with redaction.",
         0.70, tags=("console", "debug"))

    _add("FE-042", r"""webpackChunkName|__webpack_require__|webpackJsonp""",
         "debug-leak", "Low", "Webpack Internal Reference Detected",
         "Webpack bundle internals exposed. May reveal internal module structure and paths.",
         "CWE-200", "Enable webpack code splitting and minification. Configure devtool appropriately for production.",
         0.50, tags=("webpack", "build"))

    # ── Endpoint & URL Discovery ───────────────────────────────────
    _add("FE-050", r"""(?:https?://)?(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?(?:/[^\s"'`,;)}\]]*)?""",
         "endpoint", "Medium", "Localhost/Development URL Reference",
         "Reference to localhost/development URL found in code. May indicate debug endpoints in production.",
         "CWE-200", "Remove or conditionally exclude development URLs from production builds.",
         0.60, tags=("endpoint", "development"))

    _add("FE-051", r"""(?:https?://)[a-zA-Z0-9\-_.]+\.(?:internal|local|corp|dev|staging|test)(?::\d+)?[^\s"']*""",
         "endpoint", "High", "Internal/Staging URL Exposed",
         "Internal or staging environment URL found in client-side code.",
         "CWE-200", "Use environment-specific configuration. Never hardcode internal URLs in frontend bundles.",
         0.75, tags=("endpoint", "internal"))

    _add("FE-052", r"""(?:fetch|axios|http|ajax)\s*(?:\(|\.(?:get|post|put|delete|patch))\s*\(\s*["'`](?:/api/|/internal/|/admin/|/debug/)""",
         "endpoint", "High", "Sensitive API Endpoint Called from Frontend",
         "Frontend code directly calls admin/internal/debug API endpoints.",
         "CWE-200", "Route admin/debug requests through authenticated backend proxy. Do not expose internal endpoints.",
         0.70, tags=("endpoint", "admin"))

    _add("FE-053", r"""["'`](?:wss?://)[^"'`]+(?:token|auth|key|secret)=[^"'`]+""",
         "secret", "High", "WebSocket URL with Auth Token",
         "WebSocket connection URL contains authentication credentials in the query string.",
         "CWE-319", "Use separate WebSocket authentication messages instead of URL parameters.",
         0.80, tags=("websocket", "auth"))

    _add("FE-054", r"""(?:/graphql|/gql)\s*(?:["'`]|$)""",
         "endpoint", "Medium", "GraphQL Endpoint Reference",
         "GraphQL endpoint found in frontend. Verify introspection is disabled in production.",
         "CWE-200", "Disable GraphQL introspection in production. Implement query depth/complexity limiting.",
         0.55, tags=("graphql", "endpoint"))

    # ── Framework-Specific Patterns ────────────────────────────────
    _add("FE-060", r"""\{\{.*?\|safe\s*\}\}""",
         "xss-vector", "High", "Unescaped Template Output (Jinja2/Django)",
         "Template uses |safe filter which bypasses HTML escaping, enabling XSS.",
         "CWE-79", "Remove |safe filter. Sanitize data server-side before passing to template.",
         0.80, category="A03:2025-Injection", framework="Django/Jinja2", tags=("xss", "template"))

    _add("FE-061", r"""\{!!.*?!!\}""",
         "xss-vector", "High", "Unescaped Blade Output (Laravel)",
         "Laravel Blade {!! !!} syntax outputs raw HTML without escaping.",
         "CWE-79", "Use {{ }} for auto-escaped output. Sanitize if raw output is required.",
         0.80, category="A03:2025-Injection", framework="Laravel", tags=("xss", "template"))

    _add("FE-062", r"""<%[-=]\s*(?!.*?encodeURI|.*?escape)""",
         "xss-vector", "Medium", "EJS Unescaped Output",
         "EJS template uses <%- or <%= which may output unescaped HTML.",
         "CWE-79", "Use <%- only for pre-sanitized content. Prefer <%= with HTML escaping for user data.",
         0.55, category="A03:2025-Injection", framework="EJS", tags=("xss", "template"))

    return rules


# ────────────────────────────────────────────────────────────────────────────
# Scanner Engine
# ────────────────────────────────────────────────────────────────────────────

ALL_FRONTEND_RULES = _build_frontend_rules()
COMPILED_FRONTEND_RULES = [
    (re.compile(r.pattern, re.IGNORECASE | re.MULTILINE), r)
    for r in ALL_FRONTEND_RULES
]


def is_frontend_file(filepath: str) -> bool:
    """Check if a file is a frontend JavaScript/TypeScript file."""
    return Path(filepath).suffix.lower() in FRONTEND_EXTENSIONS


def is_bundle_file(content: str) -> bool:
    """Check if the file content appears to be a bundled output."""
    return any(indicator in content for indicator in BUNDLE_INDICATORS)


def scan_frontend_file(
    content: str,
    filepath: str,
    base_path: str = "",
) -> list[FrontendFinding]:
    """
    Scan a single frontend file for security issues.

    Returns a list of FrontendFinding objects.
    """
    findings: list[FrontendFinding] = []
    lines = content.split("\n")
    relative = filepath.replace(base_path, "").lstrip("/\\") if base_path else filepath
    seen_ids: set[str] = set()

    is_bundle = is_bundle_file(content)

    for compiled_re, rule in COMPILED_FRONTEND_RULES:
        for match in compiled_re.finditer(content):
            # Determine line number
            line_start = content.count("\n", 0, match.start()) + 1
            col = match.start() - content.rfind("\n", 0, match.start())

            matched_text = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
            matched_text = matched_text.strip()[:200]  # Limit length

            # Entropy analysis for API keys and secrets
            entropy = _shannon_entropy(matched_text)

            # Skip low-entropy matches for secret/api-key types
            if rule.finding_type in ("api-key", "secret") and entropy < 2.5 and len(matched_text) < 20:
                continue

            # Deduplicate
            finding_key = f"{rule.id}:{line_start}:{matched_text[:30]}"
            if finding_key in seen_ids:
                continue
            seen_ids.add(finding_key)

            # Confidence adjustment
            conf = rule.confidence
            if is_bundle:
                conf = min(conf + 0.05, 1.0)  # Slightly higher confidence in bundles
            if entropy > 4.0 and rule.finding_type in ("api-key", "secret"):
                conf = min(conf + 0.10, 1.0)  # High entropy boosts confidence

            finding_id = f"FE-{relative}:{line_start}:{rule.id}"

            findings.append(FrontendFinding(
                id=finding_id,
                file=relative,
                line_number=line_start,
                column=col,
                finding_type=rule.finding_type,
                severity=rule.severity,
                title=rule.title,
                description=rule.description,
                matched_value=matched_text,
                redacted_value=_redact(matched_text) if rule.finding_type in ("api-key", "secret") else matched_text[:80],
                entropy=round(entropy, 2),
                category=rule.category,
                cwe=rule.cwe,
                remediation=rule.remediation,
                confidence=round(conf, 2),
                framework=rule.framework,
                tags=list(rule.tags),
            ))

    return findings


def scan_frontend_directory(
    root: str,
    max_files: int = 10_000,
) -> list[FrontendFinding]:
    """
    Walk a directory tree and scan all frontend files.

    Returns aggregated list of FrontendFinding objects.
    """
    all_findings: list[FrontendFinding] = []
    root_path = Path(root)
    scanned = 0
    skip_dirs = {
        "node_modules", ".git", ".next", "dist", "build", "__pycache__",
        ".venv", "venv", "vendor", ".cache", "coverage",
    }

    for fpath in root_path.rglob("*"):
        if scanned >= max_files:
            break
        if fpath.is_dir():
            continue
        if any(skip in fpath.parts for skip in skip_dirs):
            continue
        if not is_frontend_file(str(fpath)):
            continue

        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
            if len(content) > 5_000_000:  # Skip files >5MB
                continue
            findings = scan_frontend_file(content, str(fpath), str(root_path))
            all_findings.extend(findings)
            scanned += 1
        except (OSError, PermissionError):
            continue

    return all_findings
