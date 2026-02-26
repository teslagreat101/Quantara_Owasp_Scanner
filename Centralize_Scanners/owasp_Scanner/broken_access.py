"""
Quantum Protocol v4.0 — A01: Broken Access Control Scanner

Detects:
  - IDOR patterns (direct user-supplied ID in DB queries without ownership check)
  - Path traversal (../ in file operations, unsanitized path joins)
  - CORS misconfigurations (origin reflection, regex bypasses, wildcard + credentials)
  - Privilege escalation (client-side role checks, missing middleware)
  - SSRF patterns (requests.get(user_url), fetch(userInput), cloud metadata)
  - Unrestricted file upload
  - Open redirects
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path

@dataclass
class AccessControlFinding:
    id: str
    file: str
    line_number: int
    severity: str
    title: str
    description: str
    matched_content: str
    category: str
    subcategory: str   # idor | path-traversal | cors | priv-escalation | ssrf | file-upload | open-redirect
    cwe: str
    remediation: str
    confidence: float
    tags: list[str] = field(default_factory=list)

@dataclass
class AccessControlPattern:
    id: str
    pattern: str
    severity: str
    title: str
    description: str
    cwe: str
    remediation: str
    confidence: float
    subcategory: str
    tags: tuple[str, ...] = ()

def _build_rules() -> list[AccessControlPattern]:
    rules: list[AccessControlPattern] = []

    def _add(id_: str, pat: str, sev: str, title: str, desc: str,
             cwe: str, rem: str, conf: float, sub: str, tags: tuple = ()):
        rules.append(AccessControlPattern(id_, pat, sev, title, desc, cwe, rem, conf, sub, tags))

    # ── IDOR Patterns ─────────────────────────────────────────────
    _add("AC-001",
         r"""(?:find(?:One|ById|ByPk)?|get|load|fetch|read)\s*\(\s*(?:req\.(?:params|query|body)|request\.(?:args|form|data|GET|POST))\s*(?:\[|\.(?:get|id))""",
         "High", "Potential IDOR — Direct Object Reference",
         "User-supplied ID passed directly to database lookup without ownership verification.",
         "CWE-639", "Validate that the authenticated user owns the requested resource. Add ownership checks.",
         0.70, "idor", ("idor", "authorization"))

    _add("AC-002",
         r"""\.(?:objects\.get|objects\.filter|query|where)\s*\(\s*(?:id|pk|user_id)\s*=\s*(?:request|req)""",
         "High", "Django/ORM IDOR — Direct ID from Request",
         "ORM query using request-supplied ID for direct object lookup without authorization check.",
         "CWE-639", "Filter by authenticated user: Model.objects.filter(id=request_id, owner=request.user)",
         0.75, "idor", ("idor", "django", "orm"))

    _add("AC-003",
         r"""@(?:PermitAll|Public|AllowAnonymous|NoAuth)""",
         "High", "Public Endpoint Annotation — No Auth Required",
         "Endpoint annotated to skip authentication. Verify this is intentional and not on sensitive routes.",
         "CWE-306", "Review all @PermitAll/@Public endpoints. Add authentication for sensitive operations.",
         0.65, "idor", ("idor", "annotation"))

    # ── Path Traversal ────────────────────────────────────────────
    _add("AC-010",
         r"""(?:open|read_file|readFile|readFileSync|send_file|sendFile|serve_file)\s*\(\s*(?:req|request|user|input|params|args)""",
         "Critical", "Path Traversal — File Access with User Input",
         "File operation using user-controllable input. Attacker can read arbitrary files with ../ sequences.",
         "CWE-22", "Validate file path. Use os.path.realpath() and verify it's within allowed directory.",
         0.80, "path-traversal", ("path-traversal", "file"))

    _add("AC-011",
         r"""os\.path\.join\s*\(\s*\w+\s*,\s*(?:req|request|user|input|params)""",
         "High", "Path Traversal — os.path.join with User Input",
         "os.path.join does NOT prevent path traversal. '/base' + '../../etc/passwd' = '/etc/passwd'.",
         "CWE-22", "Use pathlib and call .resolve(), then verify result starts with base directory.",
         0.80, "path-traversal", ("path-traversal", "python"))

    _add("AC-012",
         r"""\.\.(?:/|\\)""",
         "Medium", "Path Traversal Sequence Detected",
         "Literal ../ or ..\\ sequence found — may indicate path traversal test or vulnerability.",
         "CWE-22", "Validate and sanitize all file paths. Reject paths containing .. sequences.",
         0.50, "path-traversal", ("path-traversal",))

    # ── CORS Misconfigurations ────────────────────────────────────
    _add("AC-020",
         r"""Access-Control-Allow-Credentials\s*[:=]\s*["']?true["']?.*?Access-Control-Allow-Origin\s*[:=]\s*["']?\*|Allow-Origin\s*[:=]\s*["']?\*["']?.*?Allow-Credentials\s*[:=]\s*true""",
         "Critical", "CORS Wildcard with Credentials",
         "Wildcard origin (*) combined with credentials: true. Browser blocks this, but misconfig indicates broken CORS understanding.",
         "CWE-942", "Set specific allowed origins. Never combine wildcard with credentials.",
         0.85, "cors", ("cors", "credentials"))

    _add("AC-021",
         r"""(?:origin|Origin)\s*(?:=|:)\s*.*?(?:req(?:uest)?\.(?:headers?|origin)|getHeader\s*\(\s*["']Origin["']\))""",
         "Critical", "CORS Origin Reflection (Dynamic)",
         "Response origin dynamically set from request header. Any website can make credentialed requests.",
         "CWE-942", "Validate origin against a strict allowlist. Never reflect the request origin.",
         0.85, "cors", ("cors", "reflection"))

    _add("AC-022",
         r"""(?:re\.match|RegExp|test|match)\s*\(.*?(?:origin|Origin).*?(?:\.(?:com|org|net|io))\b""",
         "High", "CORS Regex Bypass Risk",
         "Regex-based CORS origin validation. Common bypasses: evil.com.attacker.com, evilcom (missing dot escaping).",
         "CWE-942", "Use exact string matching against an allowlist. Escape dots in regex patterns.",
         0.65, "cors", ("cors", "regex"))

    # ── Privilege Escalation ──────────────────────────────────────
    _add("AC-030",
         r"""(?:if|&&)\s*\(?(?:user|currentUser|req\.user)\.(?:role|isAdmin|is_admin|is_superuser|admin|permissions?)\s*(?:===?|==|!==?)\s*["']?(?:admin|superadmin|root|moderator)""",
         "High", "Client-Side Role Check",
         "Authorization check appears to be client-side only. Server must independently verify roles.",
         "CWE-284", "Move all authorization checks to server-side middleware. Never trust client-provided roles.",
         0.60, "priv-escalation", ("authorization", "role-check"))

    _add("AC-031",
         r"""(?:isAdmin|is_admin|is_superuser|role)\s*[:=]\s*(?:true|["']admin["']).*?(?:localStorage|sessionStorage|cookie)""",
         "Critical", "Admin Flag in Client Storage",
         "Admin/role flag stored in client-side storage (localStorage/sessionStorage/cookies). Trivially tamperable.",
         "CWE-284", "Store roles on server only. Verify authorization server-side on every request.",
         0.80, "priv-escalation", ("authorization", "client-storage"))

    # ── SSRF Patterns ─────────────────────────────────────────────
    _add("AC-040",
         r"""(?:requests\.(?:get|post|put|delete|head|patch)|fetch|http\.(?:get|request)|urllib\.request\.urlopen|axios\.(?:get|post))\s*\(\s*(?:req|request|user|input|params|url|target)""",
         "Critical", "SSRF — HTTP Request with User-Supplied URL",
         "Server-side HTTP request using user-controllable URL. Attacker can reach internal services.",
         "CWE-918", "Validate URL against allowlist. Block private IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x). Use URL parsers.",
         0.80, "ssrf", ("ssrf", "http"))

    _add("AC-041",
         r"""(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)""",
         "Critical", "Cloud Metadata Endpoint",
         "Cloud instance metadata endpoint URL. Primary SSRF target — yields IAM credentials, instance data.",
         "CWE-918", "Block metadata IP ranges. Use IMDSv2 (AWS) with hop-limit=1. Use SDK for metadata access.",
         0.95, "ssrf", ("ssrf", "cloud-metadata"))

    _add("AC-042",
         r"""(?:0\.0\.0\.0|127\.0\.0\.1|localhost|::1|0:0:0:0)\s*(?::\d+)?""",
         "Medium", "Loopback/Internal Address Reference",
         "Internal address found — may indicate SSRF target or development configuration left in production.",
         "CWE-918", "Remove internal addresses from code. Use configuration files with environment-specific values.",
         0.45, "ssrf", ("ssrf", "internal"))

    # ── Unrestricted File Upload ──────────────────────────────────
    _add("AC-050",
         r"""(?:multer|upload|formidable|busboy|file_upload|FileUpload).*?(?:any\(\)|single\(\)|array\(\)|fields\(\))""",
         "High", "File Upload Without Type Validation",
         "File upload middleware configured without explicit file type restrictions.",
         "CWE-434", "Validate file type by checking magic bytes (not just extension). Set max file size. Store outside webroot.",
         0.60, "file-upload", ("upload", "validation"))

    _add("AC-051",
         r"""\.(?:filename|originalname|name)\s*(?:\.(?:endsWith|includes|match).*?(?:php|exe|jsp|asp|sh|bat|cmd|ps1|cgi|pl)|\.\s*split\s*\(\s*["']\.)""",
         "High", "Blacklist-Based File Extension Validation",
         "Using blacklist to filter file extensions. Blacklists are easily bypassed (double extensions, null bytes).",
         "CWE-434", "Use an allowlist of permitted extensions. Validate MIME type from file content, not extension.",
         0.70, "file-upload", ("upload", "blacklist"))

    # ── Open Redirects ────────────────────────────────────────────
    _add("AC-060",
         r"""(?:redirect|302|sendRedirect|redirect_to|header\s*\(\s*["']Location)\s*(?:\(|[:=])\s*(?:req|request|params|args|user_?input)""",
         "High", "Open Redirect",
         "Redirect URL set from user input. Attacker can craft links that redirect users to malicious sites.",
         "CWE-601", "Validate redirect URLs against an allowlist of domains. Use relative paths only.",
         0.75, "open-redirect", ("redirect",))

    return rules

ALL_ACCESS_RULES = _build_rules()
COMPILED_ACCESS_RULES = [(re.compile(r.pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL), r) for r in ALL_ACCESS_RULES]

SKIP_DIRS = {"node_modules", ".git", ".next", "dist", "build", "__pycache__", ".venv", "venv", "vendor", ".cache"}
SCAN_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php", ".cs", ".rs", ".vue", ".svelte", ".html", ".yaml", ".yml", ".json", ".conf"}

def scan_access_file(content: str, filepath: str, base_path: str = "") -> list[AccessControlFinding]:
    findings: list[AccessControlFinding] = []
    relative = filepath.replace(base_path, "").lstrip("/\\") if base_path else filepath
    seen: set[str] = set()
    for compiled_re, rule in COMPILED_ACCESS_RULES:
        for match in compiled_re.finditer(content):
            line_num = content.count("\n", 0, match.start()) + 1
            key = f"{rule.id}:{line_num}"
            if key in seen: continue
            seen.add(key)
            findings.append(AccessControlFinding(
                id=f"AC-{relative}:{line_num}:{rule.id}", file=relative, line_number=line_num,
                severity=rule.severity, title=rule.title, description=rule.description,
                matched_content=match.group(0).strip()[:200], category="A01:2025-Broken Access Control",
                subcategory=rule.subcategory, cwe=rule.cwe, remediation=rule.remediation,
                confidence=rule.confidence, tags=list(rule.tags),
            ))
    return findings

def scan_access_directory(root: str, max_files: int = 50_000) -> list[AccessControlFinding]:
    all_findings: list[AccessControlFinding] = []
    root_path = Path(root)
    scanned = 0
    for fpath in root_path.rglob("*"):
        if scanned >= max_files: break
        if fpath.is_dir(): continue
        if any(s in fpath.parts for s in SKIP_DIRS): continue
        if fpath.suffix.lower() not in SCAN_EXTENSIONS: continue
        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
            if len(content) > 5_000_000: continue
            all_findings.extend(scan_access_file(content, str(fpath), str(root_path)))
            scanned += 1
        except (OSError, PermissionError): continue
    return all_findings
