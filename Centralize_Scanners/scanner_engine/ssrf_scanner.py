"""
Quantum Protocol v5.0 — SSRF Scanner Module
A10: Server-Side Request Forgery (SSRF) Detection

Detects:
  - Direct URL fetching from user input (requests.get, urllib, http.client)
  - URL construction with user-controlled data
  - DNS rebinding vectors
  - Cloud metadata endpoint access (169.254.169.254, metadata.google.internal)
  - Internal service enumeration patterns
  - SSRF via PDF/image generators
  - Redirect-based SSRF (open redirect chains)

Supports: Python, Java, Go, JavaScript/TypeScript, PHP, Ruby, C#
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path


# ────────────────────────────────────────────────────────────────────────────
# Data Models
# ────────────────────────────────────────────────────────────────────────────

@dataclass
class SSRFFinding:
    """A single SSRF vulnerability finding."""
    id: str
    file: str
    line_number: int
    severity: str       # Critical | High | Medium | Low | Info
    title: str
    description: str
    matched_content: str
    category: str       # OWASP category
    cwe: str
    remediation: str
    confidence: float
    ssrf_type: str      # direct | metadata | redirect | dns-rebind | pdf-gen
    language: Optional[str] = None
    tags: list[str] = field(default_factory=list)


# ────────────────────────────────────────────────────────────────────────────
# Pattern Definitions
# ────────────────────────────────────────────────────────────────────────────

@dataclass
class SSRFPattern:
    id: str
    pattern: str
    ssrf_type: str
    severity: str
    title: str
    description: str
    cwe: str
    remediation: str
    confidence: float
    language_hint: Optional[str] = None
    tags: tuple[str, ...] = ()


def _build_ssrf_rules() -> list[SSRFPattern]:
    """Build all SSRF detection rules."""
    rules: list[SSRFPattern] = []

    def _add(id_: str, pattern: str, stype: str, severity: str, title: str,
             desc: str, cwe: str, remed: str, conf: float,
             lang: Optional[str] = None, tags: tuple = ()):
        rules.append(SSRFPattern(
            id=id_, pattern=pattern, ssrf_type=stype, severity=severity,
            title=title, description=desc, cwe=cwe, remediation=remed,
            confidence=conf, language_hint=lang, tags=tags,
        ))

    # ══════════════════════════════════════════════════════════════
    # Direct SSRF — URL from user input (CWE-918)
    # ══════════════════════════════════════════════════════════════

    _add("SSRF-001",
         r"""(?:requests\.(?:get|post|put|delete|patch|head|options)|urllib\.request\.urlopen|urllib\.request\.Request|httpx\.(?:get|post|put|delete|AsyncClient))\s*\(\s*(?:f["']|.*?\+\s*(?:request|req|params|args|user|input|data|url))""",
         "direct", "Critical", "Python SSRF — HTTP Request with User Input",
         "HTTP request made with a URL derived from user-controllable input. Attacker can fetch internal resources.",
         "CWE-918", "Validate URLs against an allowlist of domains/IPs. Block private IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x).",
         0.85, "python", ("ssrf", "python"))

    _add("SSRF-002",
         r"""(?:fetch|axios\.(?:get|post|put|delete)|http\.(?:get|request)|got|superagent|node-fetch)\s*\(\s*(?:`.*?\$\{(?:req|request|params|query|body|user)|.*?\+\s*(?:req|request|params|query|body|user))""",
         "direct", "Critical", "Node.js SSRF — HTTP Request with User Input",
         "Server-side HTTP request constructed from request parameters. Classic SSRF vector.",
         "CWE-918", "Use URL parsing to validate scheme and host. Maintain domain allowlist. Block internal IPs.",
         0.85, "javascript", ("ssrf", "node"))

    _add("SSRF-003",
         r"""(?:HttpClient|WebClient|RestTemplate|OkHttpClient).*?(?:\.(?:get|post|execute|send|newCall))\s*\(\s*(?:.*?\+\s*(?:request|getParameter|input))""",
         "direct", "Critical", "Java SSRF — HTTP Client with User Input",
         "Java HTTP client URL built from user-provided data.",
         "CWE-918", "Use URL class to parse and validate. Block non-HTTPS schemes. Allowlist target hosts.",
         0.80, "java", ("ssrf", "java"))

    _add("SSRF-004",
         r"""(?:http\.(?:Get|Post|NewRequest)|net/http).*?(?:fmt\.Sprintf|.*?\+\s*(?:r\.URL|r\.Form|r\.Body|mux\.Vars))""",
         "direct", "Critical", "Go SSRF — HTTP Request with User Data",
         "Go HTTP request URL built from request parameters.",
         "CWE-918", "Parse URLs with url.Parse(), validate scheme and host. Block private CIDRs with net.ParseIP().",
         0.80, "go", ("ssrf", "go"))

    _add("SSRF-005",
         r"""(?:curl_init|file_get_contents|fopen)\s*\(\s*\$_(?:GET|POST|REQUEST)""",
         "direct", "Critical", "PHP SSRF — File/URL Functions with User Input",
         "PHP URL-fetching function called directly with superglobal user input.",
         "CWE-918", "Validate URLs against an allowlist. Disable allow_url_fopen if possible. Use cURL with CURLOPT_PROTOCOLS.",
         0.90, "php", ("ssrf", "php"))

    # ══════════════════════════════════════════════════════════════
    # Cloud Metadata SSRF (CWE-918)
    # ══════════════════════════════════════════════════════════════

    _add("SSRF-010",
         r"""169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com|100\.100\.100\.200""",
         "metadata", "Critical", "Cloud Metadata Endpoint Reference",
         "Reference to cloud metadata endpoint detected. If reachable via SSRF, attacker can access instance credentials.",
         "CWE-918", "Block access to 169.254.169.254 via WAF/firewall. Use IMDSv2 (token-required) on AWS. Validate all outbound URLs.",
         0.75, tags=("ssrf", "cloud", "metadata"))

    _add("SSRF-011",
         r"""(?:http|https)://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)(?::\d+)?/""",
         "direct", "High", "Internal Network URL Hardcoded",
         "URL pointing to internal/private IP address detected. May indicate SSRF target or misconfiguration.",
         "CWE-918", "Remove hardcoded internal URLs. Use environment variables for service discovery.",
         0.60, tags=("ssrf", "internal"))

    # ══════════════════════════════════════════════════════════════
    # SSRF via PDF/Image Generators (CWE-918)
    # ══════════════════════════════════════════════════════════════

    _add("SSRF-020",
         r"""(?:wkhtmltopdf|puppeteer|playwright|selenium).*?(?:goto|navigate|setContent|page\.url|page\.setContent)\s*\(\s*(?:req|request|params|user|input|data)""",
         "pdf-gen", "High", "SSRF via Headless Browser/PDF Generator",
         "Headless browser or PDF generator navigating to user-controlled URL. Can fetch internal resources and exfiltrate data.",
         "CWE-918", "Validate URLs before passing to headless browser. Block internal IPs. Use sandboxed rendering environment.",
         0.75, tags=("ssrf", "pdf", "headless"))

    _add("SSRF-021",
         r"""(?:weasyprint|pdfkit|reportlab|html-pdf|jsPDF).*?(?:render|generate|create)\s*\(\s*(?:req|request|user|input|url|data)""",
         "pdf-gen", "High", "SSRF via PDF Library with User Input",
         "PDF generation library using user-controlled content/URL. External resources in HTML can trigger SSRF.",
         "CWE-918", "Sanitize HTML before PDF generation. Block external resource loading. Use CSS-only styling.",
         0.70, tags=("ssrf", "pdf"))

    # ══════════════════════════════════════════════════════════════
    # DNS Rebinding (CWE-350)
    # ══════════════════════════════════════════════════════════════

    _add("SSRF-030",
         r"""(?:dns|resolve|lookup|getaddrinfo).*?(?:request|req|params|user|input)""",
         "dns-rebind", "Medium", "DNS Resolution with User Input",
         "DNS lookup performed on user-controlled hostname. May be vulnerable to DNS rebinding attacks.",
         "CWE-350", "Resolve DNS and validate IP before making request. Re-validate IP after resolution (anti-rebinding).",
         0.55, tags=("ssrf", "dns", "rebinding"))

    # ══════════════════════════════════════════════════════════════
    # Redirect-based SSRF (CWE-601 + CWE-918)
    # ══════════════════════════════════════════════════════════════

    _add("SSRF-040",
         r"""(?:follow_redirects|allow_redirects|maxRedirects|followRedirect)\s*[:=]\s*(?:True|true|yes|\d+)""",
         "redirect", "Medium", "HTTP Client Follows Redirects",
         "HTTP client configured to follow redirects. Combined with user-controlled URL, enables redirect-based SSRF.",
         "CWE-918", "Disable redirect following for user-controlled URLs, or validate each redirect destination.",
         0.50, tags=("ssrf", "redirect"))

    _add("SSRF-041",
         r"""(?:webhook|callback|notify|hook)_?(?:url|endpoint|uri)\s*[:=]\s*(?:request|req|params|body|user)""",
         "direct", "High", "Webhook URL from User Input",
         "Webhook/callback URL set from user input. Server will make requests to attacker-controlled endpoints.",
         "CWE-918", "Validate webhook URLs against domain allowlist. Block private IPs. Use HMAC verification.",
         0.80, tags=("ssrf", "webhook"))

    return rules


# ────────────────────────────────────────────────────────────────────────────
# Scanner Engine
# ────────────────────────────────────────────────────────────────────────────

ALL_SSRF_RULES = _build_ssrf_rules()
COMPILED_SSRF_RULES = [
    (re.compile(r.pattern, re.IGNORECASE | re.MULTILINE), r)
    for r in ALL_SSRF_RULES
]

SKIP_DIRS = {
    "node_modules", ".git", ".next", "dist", "build", "__pycache__",
    ".venv", "venv", "vendor", ".cache", "coverage", ".svn",
}

SCAN_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php",
    ".vue", ".svelte", ".cs", ".rs", ".swift", ".kt", ".groovy", ".scala",
    ".mjs", ".cjs", ".yaml", ".yml", ".json", ".xml", ".conf",
}


def _detect_language(filepath: str) -> str:
    """Detect language from file extension."""
    ext = Path(filepath).suffix.lower()
    lang_map = {
        ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript",
        ".ts": "TypeScript", ".tsx": "TypeScript", ".mjs": "JavaScript",
        ".java": "Java", ".go": "Go", ".rb": "Ruby", ".php": "PHP",
        ".cs": "C#", ".rs": "Rust", ".swift": "Swift", ".kt": "Kotlin",
    }
    return lang_map.get(ext, "Unknown")


def scan_ssrf_file(
    content: str,
    filepath: str,
    base_path: str = "",
) -> list[SSRFFinding]:
    """Scan a single file for SSRF vulnerabilities."""
    findings: list[SSRFFinding] = []
    relative = filepath.replace(base_path, "").lstrip("/\\") if base_path else filepath
    language = _detect_language(filepath)
    seen: set[str] = set()

    for compiled_re, rule in COMPILED_SSRF_RULES:
        # Language filtering
        lang_match = (
            rule.language_hint is None
            or rule.language_hint.lower() == language.lower()
            or rule.language_hint.lower() in language.lower()
        )

        for match in compiled_re.finditer(content):
            line_num = content.count("\n", 0, match.start()) + 1
            matched_text = match.group(0).strip()[:250]

            finding_key = f"{rule.id}:{line_num}"
            if finding_key in seen:
                continue
            seen.add(finding_key)

            conf = rule.confidence
            if not lang_match:
                conf *= 0.6

            findings.append(SSRFFinding(
                id=f"SSRF-{relative}:{line_num}:{rule.id}",
                file=relative,
                line_number=line_num,
                severity=rule.severity,
                title=rule.title,
                description=rule.description,
                matched_content=matched_text,
                category="A10:2025-SSRF",
                cwe=rule.cwe,
                remediation=rule.remediation,
                confidence=round(conf, 2),
                ssrf_type=rule.ssrf_type,
                language=language,
                tags=list(rule.tags),
            ))

    return findings


def scan_ssrf_directory(
    root: str,
    max_files: int = 50_000,
) -> list[SSRFFinding]:
    """Walk a directory tree and scan for SSRF vulnerabilities."""
    all_findings: list[SSRFFinding] = []
    root_path = Path(root)
    scanned = 0

    for fpath in root_path.rglob("*"):
        if scanned >= max_files:
            break
        if fpath.is_dir():
            continue
        if any(skip in fpath.parts for skip in SKIP_DIRS):
            continue
        if fpath.suffix.lower() not in SCAN_EXTENSIONS:
            continue

        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
            if len(content) > 5_000_000:
                continue
            findings = scan_ssrf_file(content, str(fpath), str(root_path))
            all_findings.extend(findings)
            scanned += 1
        except (OSError, PermissionError):
            continue

    return all_findings


# ─────────────────────────────────────────────────────────────────────────────
# Enterprise Integration Layer — added by enterprise refactor
# Adds: telemetry, NormalizedFinding export, behavioral probe stubs
# ─────────────────────────────────────────────────────────────────────────────
import time as _ssrf_time
import logging as _ssrf_logging

_ssrf_logger = _ssrf_logging.getLogger("enterprise.scanner.ssrf")


def normalize_ssrf_finding(f: SSRFFinding, scan_id: str = "") -> dict:
    """Convert SSRFFinding to NormalizedFinding-compatible dict."""
    return {
        "id": f.id,
        "scanner_source": "ssrf",
        "module": "ssrf",
        "category": f.category,
        "severity": f.severity.lower(),
        "title": f.title,
        "description": f.description,
        "matched_content": f.matched_content,
        "cwe": f.cwe,
        "owasp": "A10:2025",
        "file": f.file,
        "line_number": f.line_number,
        "confidence": f.confidence,
        "remediation": f.remediation,
        "tags": list(f.tags) + ["ssrf", "server-side-request-forgery"],
        "scan_id": scan_id,
    }


def scan_ssrf_file_telemetry(
    content: str,
    filepath: str,
    base_path: str = "",
    scan_id: str = "",
) -> tuple[list[SSRFFinding], dict]:
    """Wraps scan_ssrf_file() with structured telemetry."""
    start = _ssrf_time.monotonic()
    findings = scan_ssrf_file(content, filepath, base_path)
    elapsed_ms = (_ssrf_time.monotonic() - start) * 1000
    return findings, {
        "scanner": "ssrf",
        "scan_id": scan_id,
        "file": filepath,
        "findings_count": len(findings),
        "duration_ms": round(elapsed_ms, 2),
        "timestamp": _ssrf_time.time(),
    }


def scan_ssrf_directory_enterprise(
    root: str,
    max_files: int = 50_000,
    scan_id: str = "",
    on_finding=None,
) -> tuple[list[SSRFFinding], dict]:
    """
    Enterprise wrapper for scan_ssrf_directory().
    Adds structured telemetry + optional real-time finding callback.
    """
    from pathlib import Path as _Path
    start = _ssrf_time.time()
    findings, files_scanned = [], 0

    for fpath in _Path(root).rglob("*"):
        if files_scanned >= max_files:
            break
        if fpath.is_dir() or any(skip in fpath.parts for skip in SKIP_DIRS):
            continue
        if fpath.suffix.lower() not in SCAN_EXTENSIONS:
            continue
        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
            if len(content) > 5_000_000:
                continue
            file_findings, _ = scan_ssrf_file_telemetry(
                content, str(fpath), root, scan_id=scan_id
            )
            for f in file_findings:
                findings.append(f)
                if on_finding:
                    try:
                        on_finding(normalize_ssrf_finding(f, scan_id))
                    except Exception:
                        pass
            files_scanned += 1
        except (OSError, PermissionError):
            continue

    telemetry = {
        "scanner": "ssrf",
        "scan_id": scan_id,
        "root": root,
        "files_scanned": files_scanned,
        "findings_count": len(findings),
        "duration_ms": round((_ssrf_time.time() - start) * 1000, 2),
        "severity_breakdown": {
            sev: sum(1 for f in findings if f.severity.lower() == sev)
            for sev in ["critical", "high", "medium", "low", "info"]
        },
    }
    _ssrf_logger.info(
        f"ssrf_scanner: {len(findings)} findings across {files_scanned} files "
        f"in {telemetry['duration_ms']:.0f}ms"
    )
    return findings, telemetry


async def probe_ssrf_behavioral(
    fetch_fn,
    url: str,
    parameter: str,
    test_url: str = "http://169.254.169.254/latest/meta-data/",
    baseline_ms: float = 0.0,
) -> dict:
    """
    Behavioral SSRF probe for live HTTP scanning.
    Compares response content against known cloud metadata indicators.
    Integrates with BehaviorAnalyzer for timing + content evidence.
    """
    import asyncio as _asyncio
    try:
        import time as _t
        start = _t.monotonic()
        resp = await _asyncio.wait_for(
            fetch_fn(url, params={parameter: test_url}),
            timeout=10.0,
        )
        elapsed = (_t.monotonic() - start) * 1000
        body = getattr(resp, "text", "") or ""
        cloud_indicators = [
            "ami-id", "instance-id", "security-credentials",
            "computeMetadata", "instanceMetadata", "subscriptionId",
        ]
        metadata_leaked = any(ind in body for ind in cloud_indicators)
        return {
            "vulnerable": metadata_leaked,
            "confidence": 0.95 if metadata_leaked else 0.0,
            "timing_ms": elapsed,
            "baseline_ms": baseline_ms,
            "test_url": test_url,
            "parameter": parameter,
            "evidence": body[:500] if metadata_leaked else "",
        }
    except Exception as exc:
        return {
            "vulnerable": False,
            "confidence": 0.0,
            "error": str(exc),
            "parameter": parameter,
        }
