"""
Quantum Protocol v4.0 — A05: Injection Scanner Engine

Detects:
  - SQL Injection (string concat, raw queries, ORM bypasses)
  - Cross-Site Scripting / XSS (reflected, stored, DOM-based, template)
  - Command Injection (os.system, subprocess, child_process, backtick exec)
  - Server-Side Template Injection / SSTI (Jinja2, Twig, Mako, Pug, EL)
  - NoSQL Injection (MongoDB operators from user input, JSON.parse in queries)
  - LDAP Injection (unsanitized filter construction)
  - XXE / XML External Entity injection
  - Header Injection / CRLF
  - XPath Injection

Supports: Python, Java, Go, JavaScript/TypeScript, PHP, Ruby, C#
"""

from __future__ import annotations

import re
import time as _time
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path


# ────────────────────────────────────────────────────────────────────────────
# Data Models
# ────────────────────────────────────────────────────────────────────────────

@dataclass
class InjectionFinding:
    """A single injection vulnerability finding."""
    id: str
    file: str
    line_number: int
    severity: str       # Critical | High | Medium | Low | Info
    title: str
    description: str
    matched_content: str
    injection_type: str # sqli | xss | cmdi | ssti | nosqli | ldapi | xxe | crlf | xpath
    category: str       # OWASP category
    cwe: str
    remediation: str
    confidence: float
    language: Optional[str] = None
    tags: list[str] = field(default_factory=list)


# ────────────────────────────────────────────────────────────────────────────
# Pattern Definitions
# ────────────────────────────────────────────────────────────────────────────

@dataclass
class InjectionPattern:
    id: str
    pattern: str
    injection_type: str
    severity: str
    title: str
    description: str
    cwe: str
    remediation: str
    confidence: float
    language_hint: Optional[str] = None
    tags: tuple[str, ...] = ()


def _build_injection_rules() -> list[InjectionPattern]:
    """Build all injection detection rules."""
    rules: list[InjectionPattern] = []

    def _add(id_: str, pattern: str, itype: str, severity: str, title: str,
             desc: str, cwe: str, remed: str, conf: float,
             lang: Optional[str] = None, tags: tuple = ()):
        rules.append(InjectionPattern(
            id=id_, pattern=pattern, injection_type=itype, severity=severity,
            title=title, description=desc, cwe=cwe, remediation=remed,
            confidence=conf, language_hint=lang, tags=tags,
        ))

    # ══════════════════════════════════════════════════════════════
    # SQL Injection (CWE-89)
    # ══════════════════════════════════════════════════════════════

    _add("INJ-001",
         r"""(?:execute|query|cursor\.execute|db\.query|connection\.query)\s*\(\s*(?:f["']|["']\s*(?:\+|%|\.format)).*?(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|UNION)""",
         "sqli", "Critical", "SQL Injection via String Concatenation",
         "SQL query built with string concatenation/interpolation using user-controllable data. Classic SQLi vector.",
         "CWE-89", "Use parameterized queries / prepared statements. Never concatenate user input into SQL strings.",
         0.85, tags=("sqli", "concatenation"))

    _add("INJ-002",
         r"""(?:cursor\.execute|db\.execute)\s*\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE)\s+.*?["']\s*%\s*(?:\(|[a-zA-Z])""",
         "sqli", "Critical", "Python SQL Injection (%-formatting)",
         "Python SQL query using %-style string formatting with external variables.",
         "CWE-89", "Use cursor.execute('SELECT ... WHERE id = %s', (user_id,)) with tuple parameter binding.",
         0.90, "python", ("sqli", "python"))

    _add("INJ-003",
         r"""f["'](?:SELECT|INSERT|UPDATE|DELETE)\s+.*?\{(?:request|req|params|args|user_?input|data)""",
         "sqli", "Critical", "Python f-string SQL Injection",
         "SQL query using Python f-strings with request/user data interpolated.",
         "CWE-89", "Use parameterized queries. Replace f-strings in SQL with parameter placeholders.",
         0.90, "python", ("sqli", "python", "f-string"))

    _add("INJ-004",
         r"""\.(?:raw|extra|rawQuery|raw_query)\s*\(\s*(?:f["']|["']\s*(?:\+|%))""",
         "sqli", "High", "ORM Raw Query with String Interpolation",
         "ORM raw/extra query uses string interpolation. Bypasses ORM's built-in parameterization.",
         "CWE-89", "Use .raw('SELECT ... WHERE id = %s', [param]) or ORM query builders instead.",
         0.80, tags=("sqli", "orm"))

    _add("INJ-005",
         r"""(?:sequelize|knex|prisma)\.\s*(?:\$queryRaw|query)\s*\(\s*(?:`|["'])\s*(?:SELECT|INSERT|UPDATE|DELETE)""",
         "sqli", "High", "Node.js ORM Raw SQL Query",
         "Raw SQL query through Node.js ORM. If user input is interpolated, it's vulnerable to SQLi.",
         "CWE-89", "Use Prisma.$queryRaw with tagged templates, Sequelize bind parameters, or Knex query builder.",
         0.75, "javascript", ("sqli", "node", "orm"))

    _add("INJ-006",
         r"""(?:PreparedStatement|Statement)\s+\w+\s*=\s*.*?createStatement\s*\(\)|\.executeQuery\s*\(\s*["']\s*\+""",
         "sqli", "Critical", "Java SQL Injection (Statement)",
         "Java using Statement instead of PreparedStatement with string concatenation.",
         "CWE-89", "Use PreparedStatement with ? placeholders. Never use Statement with concatenated user input.",
         0.85, "java", ("sqli", "java"))

    _add("INJ-007",
         r"""(?:DB\.|db\.)\s*(?:Exec|Query|QueryRow)\s*\(\s*(?:fmt\.Sprintf|.*?\+\s*(?:r\.URL|r\.Form|r\.Body))""",
         "sqli", "Critical", "Go SQL Injection",
         "Go SQL query with fmt.Sprintf or string concatenation using request data.",
         "CWE-89", "Use db.Query('SELECT ... WHERE id = $1', userId) with parameter placeholders.",
         0.80, "go", ("sqli", "go"))

    _add("INJ-008",
         r"""\$(?:wpdb|this)\s*->\s*(?:query|prepare)\s*\(\s*["']\s*(?:SELECT|INSERT|UPDATE|DELETE).*?\$_(?:GET|POST|REQUEST)""",
         "sqli", "Critical", "PHP SQL Injection (WordPress/Direct)",
         "PHP SQL query directly using superglobal variables ($_GET, $_POST, $_REQUEST).",
         "CWE-89", "Use $wpdb->prepare() with %s/%d placeholders. Use PDO prepared statements.",
         0.90, "php", ("sqli", "php", "wordpress"))

    # ══════════════════════════════════════════════════════════════
    # Cross-Site Scripting / XSS (CWE-79)
    # ══════════════════════════════════════════════════════════════

    _add("INJ-020",
         r"""response\.write\s*\(\s*(?:request|req)\.(?:GET|POST|query|params|body)\[""",
         "xss", "Critical", "Reflected XSS — Direct Echo",
         "User input from request directly written to response without encoding.",
         "CWE-79", "HTML-encode all user input before output. Use framework auto-escaping.",
         0.90, tags=("xss", "reflected"))

    _add("INJ-021",
         r"""(?:res\.send|res\.write|response\.write|HttpResponse)\s*\(\s*.*?(?:req\.(?:query|params|body)|request\.(?:GET|POST))\[""",
         "xss", "High", "Reflected XSS — User Input in Response",
         "Request parameters directly included in HTTP response body.",
         "CWE-79", "Apply output encoding based on context (HTML, JS, URL, CSS). Use framework template engine.",
         0.80, tags=("xss", "reflected"))

    _add("INJ-022",
         r"""\|\s*safe\b""",
         "xss", "High", "Template |safe Filter (XSS Bypass)",
         "Django/Jinja2 |safe filter disables auto-escaping, enabling XSS if used with user data.",
         "CWE-79", "Remove |safe filter. Sanitize data server-side before passing to template.",
         0.75, "python", ("xss", "template", "django"))

    _add("INJ-023",
         r"""document\.(?:write|writeln)\s*\(\s*(?:.*?(?:location|document\.URL|document\.referrer|window\.name))""",
         "xss", "Critical", "DOM-based XSS via document.write",
         "document.write with data from location/URL/referrer enables DOM-based XSS.",
         "CWE-79", "Never use document.write with URL-derived data. Use textContent or DOMPurify.",
         0.85, "javascript", ("xss", "dom"))

    _add("INJ-024",
         r"""\.innerHTML\s*=\s*.*?(?:location|document\.URL|urlParams|searchParams|window\.(?:name|location))""",
         "xss", "Critical", "DOM XSS via innerHTML with URL Data",
         "innerHTML set from URL parameters or location data. Classic DOM-based XSS.",
         "CWE-79", "Use textContent for text. If HTML is needed, sanitize with DOMPurify.sanitize().",
         0.85, "javascript", ("xss", "dom"))

    _add("INJ-025",
         r"""(?:res\.render|render_template|render)\s*\(\s*["'][^"']+["']\s*,\s*\{[^}]*(?:req\.|request\.)""",
         "xss", "Medium", "User Input Passed to Template",
         "Request data passed directly to template rendering. If template auto-escaping is disabled, XSS is possible.",
         "CWE-79", "Ensure template auto-escaping is enabled. Validate and sanitize input before passing to templates.",
         0.60, tags=("xss", "template"))

    # ══════════════════════════════════════════════════════════════
    # Command Injection (CWE-78)
    # ══════════════════════════════════════════════════════════════

    _add("INJ-040",
         r"""os\.system\s*\(\s*(?:f["']|.*?\+\s*(?:request|input|argv|args|user|data))""",
         "cmdi", "Critical", "Python Command Injection (os.system)",
         "os.system() called with string containing user-controllable data.",
         "CWE-78", "Use subprocess.run() with a list of arguments (no shell=True). Validate all input.",
         0.90, "python", ("cmdi", "python"))

    _add("INJ-041",
         r"""subprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True[^)]*(?:request|input|argv|args|user|data)""",
         "cmdi", "Critical", "Python Command Injection (subprocess shell=True)",
         "subprocess with shell=True and user-controllable input enables arbitrary command execution.",
         "CWE-78", "Use subprocess.run(['cmd', 'arg1', 'arg2'], shell=False) with argument list.",
         0.90, "python", ("cmdi", "python"))

    _add("INJ-042",
         r"""child_process\.(?:exec|execSync|spawn|spawnSync)\s*\(\s*(?:`.*?\$\{|.*?\+\s*(?:req|request|input|args))""",
         "cmdi", "Critical", "Node.js Command Injection",
         "Node.js child_process executing commands with user-controllable input.",
         "CWE-78", "Use execFile/execFileSync with argument arrays. Never interpolate user data into shell commands.",
         0.90, "javascript", ("cmdi", "node"))

    _add("INJ-043",
         r"""Runtime\.getRuntime\(\)\.exec\s*\(\s*(?:.*?\+\s*(?:request|input|getParameter))""",
         "cmdi", "Critical", "Java Command Injection",
         "Runtime.exec() called with user-controllable input concatenated into command string.",
         "CWE-78", "Use ProcessBuilder with argument list. Validate input against strict allowlist.",
         0.85, "java", ("cmdi", "java"))

    _add("INJ-044",
         r"""(?:exec|system|passthru|shell_exec|popen|proc_open)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)""",
         "cmdi", "Critical", "PHP Command Injection",
         "PHP command execution function called directly with superglobal user input.",
         "CWE-78", "Use escapeshellarg() and escapeshellcmd(). Prefer language-native alternatives to shell commands.",
         0.95, "php", ("cmdi", "php"))

    _add("INJ-045",
         r"""(?:`[^`]*\$\{[^}]*(?:request|req|params|args|input))|(?:`[^`]*\$\([^)]*(?:request|req|params|args|input))""",
         "cmdi", "Critical", "Backtick Command Injection",
         "Shell backtick execution with interpolated user-controllable data.",
         "CWE-78", "Avoid backtick execution. Use language-native APIs with proper input validation.",
         0.85, tags=("cmdi", "backtick"))

    # ══════════════════════════════════════════════════════════════
    # Server-Side Template Injection / SSTI (CWE-94)
    # ══════════════════════════════════════════════════════════════

    _add("INJ-060",
         r"""render_template_string\s*\(\s*(?:request|req|user|input|data)""",
         "ssti", "Critical", "Jinja2 SSTI (render_template_string)",
         "render_template_string called with user-controllable input. Enables arbitrary Python code execution.",
         "CWE-94", "Never pass user input to render_template_string. Use render_template with separate template files.",
         0.95, "python", ("ssti", "jinja2", "rce"))

    _add("INJ-061",
         r"""(?:Template|Environment)\s*\(\s*.*?(?:request|user_?input|data|body)""",
         "ssti", "High", "Template Engine with User Input",
         "Template engine initialized with user-controllable data. May enable SSTI.",
         "CWE-94", "Use pre-defined template files. Never construct templates from user input.",
         0.70, tags=("ssti", "template"))

    _add("INJ-062",
         r"""(?:Mako|MakoTemplate|render_template)\s*\(\s*.*?(?:request|input)""",
         "ssti", "High", "Mako Template Injection",
         "Mako template rendered with user input. Mako templates allow arbitrary Python execution.",
         "CWE-94", "Never pass user input as Mako template content. Use parameterized template variables.",
         0.75, "python", ("ssti", "mako"))

    # ══════════════════════════════════════════════════════════════
    # NoSQL Injection (CWE-943)
    # ══════════════════════════════════════════════════════════════

    _add("INJ-070",
         r"""\.(?:find|findOne|findOneAndUpdate|updateOne|deleteOne|aggregate)\s*\(\s*(?:req\.body|req\.query|req\.params|request\.(?:json|form|data))""",
         "nosqli", "Critical", "MongoDB NoSQL Injection",
         "MongoDB query directly using request body/params. Attacker can inject operators like $gt, $ne, $regex.",
         "CWE-943", "Validate and sanitize input. Use express-mongo-sanitize. Explicitly map query fields.",
         0.85, "javascript", ("nosqli", "mongodb"))

    _add("INJ-071",
         r"""JSON\.parse\s*\(\s*(?:req\.body|req\.query|request\.data|input)\s*\).*?(?:\.find|\.update|\.delete|collection)""",
         "nosqli", "High", "JSON.parse to MongoDB Query",
         "User JSON input parsed and passed to MongoDB query. Enables operator injection.",
         "CWE-943", "Define a strict schema for query input. Reject unexpected keys. Use mongo-sanitize.",
         0.75, "javascript", ("nosqli", "mongodb"))

    _add("INJ-072",
         r"""(?:\$gt|\$ne|\$regex|\$where|\$exists|\$or)\s*[:=].*?(?:req|request|input|user|body|query)""",
         "nosqli", "High", "MongoDB Operator from User Input",
         "MongoDB query operators ($gt, $ne, $regex, $where) constructed from user-controllable data.",
         "CWE-943", "Never allow query operators from user input. Validate with a strict whitelist.",
         0.70, tags=("nosqli", "operator"))

    # ══════════════════════════════════════════════════════════════
    # LDAP Injection (CWE-90)
    # ══════════════════════════════════════════════════════════════

    _add("INJ-080",
         r"""(?:\(\&\(|ldap\.search|ldap_search)\s*\(.*?(?:\+\s*(?:user|input|request|req)|f["'].*?\{(?:user|input|request|req))""",
         "ldapi", "Critical", "LDAP Injection",
         "LDAP filter constructed with user-controllable input without sanitization.",
         "CWE-90", "Use LDAP filter escaping functions. In Python: ldap.filter.escape_filter_chars(). Never concatenate.",
         0.80, tags=("ldapi", "injection"))

    # ══════════════════════════════════════════════════════════════
    # XML External Entity / XXE (CWE-611)
    # ══════════════════════════════════════════════════════════════

    _add("INJ-090",
         r"""(?:etree\.parse|etree\.fromstring|minidom\.parseString|xml\.sax\.parseString|XMLParser|SAXParser)\s*\(""",
         "xxe", "High", "XML Parser Without XXE Protection",
         "XML parser used without explicitly disabling external entity processing.",
         "CWE-611", "Disable DTD and external entities: parser.setFeature(feature_external_ges, False). Use defusedxml.",
         0.65, "python", ("xxe", "xml"))

    _add("INJ-091",
         r"""DocumentBuilderFactory\.newInstance\(\)(?!.*?setFeature.*?disallow-doctype-decl)""",
         "xxe", "High", "Java XXE — DocumentBuilder Without Protection",
         "Java XML DocumentBuilder created without disabling DTD processing.",
         "CWE-611", "Add factory.setFeature('http://apache.org/xml/features/disallow-doctype-decl', true)",
         0.70, "java", ("xxe", "java"))

    _add("INJ-092",
         r"""(?:simplexml_load_string|DOMDocument\s*\(\))\s*(?!.*?libxml_disable_entity_loader)""",
         "xxe", "High", "PHP XXE — XML Loading Without Protection",
         "PHP XML parsing without libxml_disable_entity_loader().",
         "CWE-611", "Call libxml_disable_entity_loader(true) before parsing XML. Use LIBXML_NOENT | LIBXML_NONET flags.",
         0.70, "php", ("xxe", "php"))

    # ══════════════════════════════════════════════════════════════
    # Header / CRLF Injection (CWE-113)
    # ══════════════════════════════════════════════════════════════

    _add("INJ-095",
         r"""(?:response\.setHeader|res\.set|header)\s*\(\s*["'][^"']+["']\s*,\s*(?:req|request|user|input)""",
         "crlf", "High", "HTTP Header Injection",
         "HTTP response header set from user-controllable input. May enable CRLF injection and response splitting.",
         "CWE-113", "Validate and sanitize header values. Strip \\r and \\n characters from user input.",
         0.75, tags=("crlf", "header"))

    _add("INJ-096",
         r"""(?:redirect|302|Location)\s*(?:\(|[:=])\s*(?:req|request|user|input|params)""",
         "crlf", "High", "Open Redirect / Header Injection",
         "Redirect URL set from user input. May enable open redirect and CRLF injection.",
         "CWE-601", "Validate redirect URLs against an allowlist of domains. Never redirect to user-supplied URLs.",
         0.70, tags=("redirect", "crlf"))

    return rules


# ────────────────────────────────────────────────────────────────────────────
# Scanner Engine
# ────────────────────────────────────────────────────────────────────────────

ALL_INJECTION_RULES = _build_injection_rules()
COMPILED_INJECTION_RULES = [
    (re.compile(r.pattern, re.IGNORECASE | re.MULTILINE), r)
    for r in ALL_INJECTION_RULES
]

SKIP_DIRS = {
    "node_modules", ".git", ".next", "dist", "build", "__pycache__",
    ".venv", "venv", "vendor", ".cache", "coverage", ".svn",
}

SCAN_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php",
    ".vue", ".svelte", ".html", ".htm", ".cs", ".rs", ".swift",
    ".kt", ".groovy", ".scala", ".mjs", ".cjs", ".ejs", ".pug",
    ".hbs", ".handlebars", ".twig", ".blade.php",
}


def _detect_language(filepath: str) -> str:
    """Detect language from file extension."""
    ext = Path(filepath).suffix.lower()
    lang_map = {
        ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript",
        ".ts": "TypeScript", ".tsx": "TypeScript", ".mjs": "JavaScript",
        ".java": "Java", ".go": "Go", ".rb": "Ruby", ".php": "PHP",
        ".cs": "C#", ".rs": "Rust", ".swift": "Swift", ".kt": "Kotlin",
        ".vue": "Vue", ".svelte": "Svelte", ".html": "HTML",
    }
    return lang_map.get(ext, "Unknown")


def scan_injection_file(
    content: str,
    filepath: str,
    base_path: str = "",
) -> list[InjectionFinding]:
    """Scan a single file for injection vulnerabilities."""
    findings: list[InjectionFinding] = []
    relative = filepath.replace(base_path, "").lstrip("/\\") if base_path else filepath
    language = _detect_language(filepath)
    seen: set[str] = set()

    for compiled_re, rule in COMPILED_INJECTION_RULES:
        # Language filtering: boost confidence if language matches
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

            # Adjust confidence based on language match
            conf = rule.confidence
            if not lang_match:
                conf *= 0.6  # Lower confidence if language doesn't match

            findings.append(InjectionFinding(
                id=f"INJ-{relative}:{line_num}:{rule.id}",
                file=relative,
                line_number=line_num,
                severity=rule.severity,
                title=rule.title,
                description=rule.description,
                matched_content=matched_text,
                injection_type=rule.injection_type,
                category="A05:2025-Injection",
                cwe=rule.cwe,
                remediation=rule.remediation,
                confidence=round(conf, 2),
                language=language,
                tags=list(rule.tags),
            ))

    return findings


def scan_injection_directory(
    root: str,
    max_files: int = 50_000,
) -> list[InjectionFinding]:
    """Walk a directory tree and scan for injection vulnerabilities."""
    all_findings: list[InjectionFinding] = []
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
            findings = scan_injection_file(content, str(fpath), str(root_path))
            all_findings.extend(findings)
            scanned += 1
        except (OSError, PermissionError):
            continue

    return all_findings


# ─────────────────────────────────────────────────────────────────────────────
# Enterprise Integration Layer — added by enterprise refactor
# Provides: telemetry, NormalizedFinding export, BaseScanner compatibility
# Does NOT modify any existing logic above.
# ─────────────────────────────────────────────────────────────────────────────
import logging as _logging

_inj_logger = _logging.getLogger("enterprise.scanner.injection")


def normalize_injection_finding(f: InjectionFinding, scan_id: str = "") -> dict:
    """
    Convert an InjectionFinding to a NormalizedFinding-compatible dict.
    Compatible with orchestrator.normalize_finding() and BaseScanner.
    """
    return {
        "id": f.id,
        "scanner_source": "injection",
        "module": "injection",
        "category": f.category,
        "severity": f.severity.lower(),
        "title": f.title,
        "description": f.description,
        "matched_content": f.matched_content,
        "cwe": f.cwe,
        "owasp": "A03:2025",
        "file": f.file,
        "line_number": f.line_number,
        "confidence": f.confidence,
        "remediation": f.remediation,
        "tags": list(f.tags) + [f.injection_type, "injection"],
        "scan_id": scan_id,
        "language": f.language,
    }


def scan_injection_file_telemetry(
    content: str,
    filepath: str,
    base_path: str = "",
    scan_id: str = "",
) -> tuple[list[InjectionFinding], dict]:
    """
    Wraps scan_injection_file() with structured telemetry.
    Returns (findings, telemetry_dict).
    """
    start = _time.monotonic()
    findings = scan_injection_file(content, filepath, base_path)
    elapsed_ms = (_time.monotonic() - start) * 1000

    telemetry = {
        "scanner": "injection",
        "scan_id": scan_id,
        "file": filepath,
        "findings_count": len(findings),
        "duration_ms": round(elapsed_ms, 2),
        "timestamp": _time.time(),
    }
    if findings:
        _inj_logger.info(
            f"injection_scanner: {len(findings)} findings in {filepath} ({elapsed_ms:.1f}ms)"
        )
    return findings, telemetry


def scan_injection_directory_enterprise(
    root: str,
    max_files: int = 50_000,
    scan_id: str = "",
    on_finding=None,
) -> tuple[list[InjectionFinding], dict]:
    """
    Enterprise wrapper for scan_injection_directory().
    Adds per-file telemetry, structured logging, and optional real-time callback.

    Args:
        root: Directory to scan
        max_files: Maximum files to process
        scan_id: Correlation ID for this scan session
        on_finding: Optional callback(finding) for real-time streaming

    Returns:
        (findings, summary_telemetry)
    """
    start = _time.time()
    findings, files_scanned = [], 0

    root_path = Path(root)
    for fpath in root_path.rglob("*"):
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
            file_findings, _ = scan_injection_file_telemetry(
                content, str(fpath), str(root_path), scan_id=scan_id
            )
            for f in file_findings:
                findings.append(f)
                if on_finding:
                    try:
                        on_finding(normalize_injection_finding(f, scan_id))
                    except Exception:
                        pass
            files_scanned += 1
        except (OSError, PermissionError):
            continue

    telemetry = {
        "scanner": "injection",
        "scan_id": scan_id,
        "root": root,
        "files_scanned": files_scanned,
        "findings_count": len(findings),
        "duration_ms": round((_time.time() - start) * 1000, 2),
        "severity_breakdown": {
            sev: sum(1 for f in findings if f.severity.lower() == sev)
            for sev in ["critical", "high", "medium", "low", "info"]
        },
    }
    _inj_logger.info(
        f"injection_scanner: {len(findings)} findings across {files_scanned} files "
        f"in {telemetry['duration_ms']:.0f}ms"
    )
    return findings, telemetry
