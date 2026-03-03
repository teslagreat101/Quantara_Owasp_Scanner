"""
Quantum Protocol v4.0 — A02: Security Misconfiguration Engine

Detects:
  - Debug/Development mode in production (Django, Flask, Express, Rails, Spring, PHP)
  - Default credentials (admin/admin, root/root, etc.)
  - Missing security headers in configuration
  - Exposed admin/debug endpoints in routing configs
  - Overly permissive configurations (wildcard CORS, chmod 777, etc.)
  - Docker security misconfigs (privileged, exposed socket, running as root)
  - Verbose error output in production
  - Exposed configuration files
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
class MisconfigFinding:
    """A single security misconfiguration finding."""
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
    subcategory: str    # debug-mode | default-creds | missing-header | exposed-endpoint | permissive-config | docker
    tags: list[str] = field(default_factory=list)


# ────────────────────────────────────────────────────────────────────────────
# Pattern Definitions
# ────────────────────────────────────────────────────────────────────────────

@dataclass
class MisconfigPattern:
    id: str
    pattern: str
    severity: str
    title: str
    description: str
    cwe: str
    remediation: str
    confidence: float
    subcategory: str
    file_filter: Optional[str] = None  # Regex for filename filtering
    tags: tuple[str, ...] = ()


def _build_misconfig_rules() -> list[MisconfigPattern]:
    """Build all security misconfiguration detection rules."""
    rules: list[MisconfigPattern] = []

    def _add(id_: str, pattern: str, severity: str, title: str, desc: str,
             cwe: str, remed: str, conf: float, subcat: str,
             file_filter: Optional[str] = None, tags: tuple = ()):
        rules.append(MisconfigPattern(
            id=id_, pattern=pattern, severity=severity, title=title,
            description=desc, cwe=cwe, remediation=remed, confidence=conf,
            subcategory=subcat, file_filter=file_filter, tags=tags,
        ))

    # ── Debug/Development Mode in Production ──────────────────────
    _add("MC-001", r"""DEBUG\s*=\s*True""",
         "Critical", "Django DEBUG Mode Enabled",
         "Django DEBUG=True exposes detailed error pages, SQL queries, and server information to end users.",
         "CWE-489", "Set DEBUG=False in production settings. Use environment variables: DEBUG=os.environ.get('DEBUG', 'False') == 'True'",
         0.90, "debug-mode", r"settings\.py$|\.env$", ("django", "debug"))

    _add("MC-002", r"""app\.debug\s*=\s*True|app\.run\s*\([^)]*debug\s*=\s*True""",
         "Critical", "Flask Debug Mode Enabled",
         "Flask debug mode enables the interactive debugger and code reloader. In production, this allows arbitrary code execution.",
         "CWE-489", "Set app.debug=False and use FLASK_ENV=production. Never enable debug in production WSGI config.",
         0.90, "debug-mode", r"\.py$", ("flask", "debug"))

    _add("MC-003", r"""NODE_ENV\s*[:=]\s*["']?development["']?""",
         "High", "Node.js Development Mode",
         "NODE_ENV set to development. May enable verbose error output and disable security features.",
         "CWE-489", "Set NODE_ENV=production in production environments. Add to deployment scripts and Docker configs.",
         0.75, "debug-mode", r"\.env$|\.js$|\.ts$|docker", ("node", "debug"))

    _add("MC-004", r"""RAILS_ENV\s*[:=]\s*["']?(?:development|test)["']?""",
         "High", "Rails Development/Test Mode",
         "Rails environment set to development or test, which enables debug output and disables security features.",
         "CWE-489", "Set RAILS_ENV=production. Verify in config/environments/production.rb.",
         0.80, "debug-mode", r"\.env$|\.rb$", ("rails", "debug"))

    _add("MC-005", r"""(?:display_errors|error_reporting)\s*(?:=|:)\s*(?:On|E_ALL|1|true)""",
         "High", "PHP Error Display Enabled",
         "PHP configured to display errors to users, potentially exposing system information and file paths.",
         "CWE-209", "Set display_errors=Off and log_errors=On in php.ini for production.",
         0.85, "debug-mode", r"(?:php\.ini|\.htaccess|\.php)$", ("php", "debug"))

    _add("MC-006", r"""management\.endpoints\.web\.exposure\.include\s*=\s*\*""",
         "Critical", "Spring Boot Actuator Endpoints Exposed",
         "All Spring Boot Actuator endpoints exposed to web, including /env, /configprops, /heapdump.",
         "CWE-215", "Restrict management.endpoints.web.exposure.include to health,info only. Secure with Spring Security.",
         0.90, "debug-mode", r"(?:application\.\w+|bootstrap\.\w+)$", ("spring", "actuator"))

    _add("MC-007", r"""EnableDebugging|SetDevelopment\s*\(\s*true\s*\)|devMode\s*[:=]\s*true""",
         "High", "Debug/Development Mode Flag Enabled",
         "Generic debug or development mode flag detected. May enable unsafe features in production.",
         "CWE-489", "Disable debug mode flags for production deployment. Use environment-based configuration.",
         0.65, "debug-mode", tags=("debug",))

    # ── Default Credentials ───────────────────────────────────────
    _add("MC-010", r"""(?:username|user|login)\s*[:=]\s*["']admin["']\s*(?:\n|,|;).*?(?:password|pass|pwd)\s*[:=]\s*["'](?:admin|password|123456|changeme|default)["']""",
         "Critical", "Default Admin Credentials",
         "Default administrator credentials detected. These are commonly targeted by automated attacks.",
         "CWE-798", "Change default credentials immediately. Implement account lockout and password complexity requirements.",
         0.85, "default-creds", tags=("credentials", "admin"))

    _add("MC-011", r"""(?:password|passwd|pwd)\s*[:=]\s*["'](?:admin|root|password|123456|changeme|default|test|letmein|qwerty|abc123|monkey|master|dragon)["']""",
         "Critical", "Common Default Password Detected",
         "Extremely common/default password found in configuration. These are in every password dictionary.",
         "CWE-798", "Use strong, unique passwords. Implement password complexity policies. Use secrets management (Vault, AWS Secrets Manager).",
         0.80, "default-creds", tags=("credentials", "weak-password"))

    _add("MC-012", r"""(?:your[-_]?api[-_]?key[-_]?here|changeme|CHANGE[-_]?ME|INSERT[-_]?(?:YOUR|API)[-_]?KEY|TODO[-_:]?\s*(?:replace|add|change|update).*(?:key|secret|password|token))""",
         "Medium", "Placeholder Credential Detected",
         "Placeholder or TODO marker for a credential that may not have been replaced.",
         "CWE-798", "Replace placeholder credentials with actual secure values from a secrets manager.",
         0.70, "default-creds", tags=("placeholder", "credentials"))

    # ── Missing Security Headers ──────────────────────────────────
    _add("MC-020", r"""(?:Content-Security-Policy|content_security_policy)\s*[:=]\s*["']?\s*(?:unsafe-inline|unsafe-eval|\*)""",
         "High", "Weak Content-Security-Policy",
         "CSP policy contains unsafe-inline or unsafe-eval, which weakens XSS protection significantly.",
         "CWE-693", "Remove 'unsafe-inline' and 'unsafe-eval' from CSP. Use nonce-based or hash-based CSP.",
         0.80, "missing-header", tags=("csp", "xss"))

    _add("MC-021", r"""X-Frame-Options\s*[:=]\s*["']?(?:ALLOW|allow)""",
         "High", "X-Frame-Options Allow-All",
         "X-Frame-Options configured to allow framing, enabling clickjacking attacks.",
         "CWE-1021", "Set X-Frame-Options: DENY or SAMEORIGIN. Or use CSP frame-ancestors directive.",
         0.85, "missing-header", tags=("clickjacking", "headers"))

    _add("MC-022", r"""Access-Control-Allow-Origin\s*[:=]\s*["']?\*["']?""",
         "High", "Wildcard CORS Origin (*)",
         "CORS configured with wildcard origin (*). Any website can make requests to this application.",
         "CWE-942", "Restrict Access-Control-Allow-Origin to specific trusted domains. Never use * with credentials.",
         0.80, "missing-header", tags=("cors", "access-control"))

    _add("MC-023", r"""(?:Access-Control-Allow-Origin)\s*[:=]\s*.*(?:request\.(?:origin|headers)|\$_SERVER\['HTTP_ORIGIN'\])""",
         "Critical", "CORS Origin Reflection",
         "CORS origin is dynamically set from the request origin, effectively allowing any domain.",
         "CWE-942", "Validate origin against a strict allowlist. Never reflect the request origin directly.",
         0.85, "missing-header", tags=("cors", "reflection"))

    # ── Exposed Endpoints ─────────────────────────────────────────
    _add("MC-030", r"""(?:route|path|url|endpoint)\s*(?:\(|[:=])\s*["'](?:/admin|/phpmyadmin|/adminer|/wp-admin|/manager|/console)""",
         "High", "Admin Panel Route Exposed",
         "Administrative panel route defined. Ensure it's protected by authentication and IP restrictions.",
         "CWE-284", "Protect admin routes with authentication middleware, IP allow-listing, and rate limiting.",
         0.70, "exposed-endpoint", tags=("admin", "route"))

    _add("MC-031", r"""(?:route|path|url|endpoint)\s*(?:\(|[:=])\s*["'](?:/swagger|/swagger-ui|/api-docs|/openapi\.json|/redoc)""",
         "Medium", "API Documentation Endpoint Exposed",
         "API documentation endpoint (Swagger/OpenAPI) accessible. May expose internal API structure to attackers.",
         "CWE-200", "Add authentication to API documentation endpoints in production. Consider disabling in prod.",
         0.75, "exposed-endpoint", tags=("swagger", "api-docs"))

    _add("MC-032", r"""(?:route|path|url|endpoint)\s*(?:\(|[:=])\s*["'](?:/graphql|/gql)["']""",
         "Medium", "GraphQL Endpoint Exposed",
         "GraphQL endpoint defined. If introspection is enabled, the entire API schema is discoverable.",
         "CWE-200", "Disable GraphQL introspection in production. Implement query depth and complexity limiting.",
         0.70, "exposed-endpoint", tags=("graphql", "api"))

    _add("MC-033", r"""(?:route|path|url|endpoint)\s*(?:\(|[:=])\s*["'](?:/debug|/trace|/metrics|/health|/status)""",
         "High", "Debug/Monitoring Endpoint Exposed",
         "Debug or monitoring endpoint defined without apparent authentication.",
         "CWE-215", "Protect monitoring endpoints with authentication. Return minimal info on /health. Restrict /debug to internal network.",
         0.65, "exposed-endpoint", tags=("debug", "monitoring"))

    # ── Permissive Configurations ─────────────────────────────────
    _add("MC-040", r"""(?:allow_all_origins|CORS_ALLOW_ALL_ORIGINS|cors_origins_allow_all)\s*[:=]\s*(?:True|true|1|yes)""",
         "High", "All CORS Origins Allowed",
         "Application configured to allow requests from any origin, bypassing same-origin policy.",
         "CWE-942", "List specific allowed origins. Never allow all origins in production.",
         0.85, "permissive-config", tags=("cors", "permissive"))

    _add("MC-041", r"""chmod\s+777|permissions?\s*[:=]\s*0?777""",
         "Critical", "World-Writable File Permissions (777)",
         "File permissions set to 777 (world-readable/writable/executable). Severe security risk.",
         "CWE-732", "Use least-privilege permissions. Typical: 755 for directories, 644 for files, 600 for sensitive configs.",
         0.90, "permissive-config", tags=("permissions", "filesystem"))

    _add("MC-042", r"""(?:bind|listen|host)\s*(?:\(|[:=])\s*["']?0\.0\.0\.0["']?""",
         "Medium", "Service Binding to All Interfaces (0.0.0.0)",
         "Service binds to 0.0.0.0, making it accessible on all network interfaces including public ones.",
         "CWE-668", "Bind to 127.0.0.1 for local-only access, or specific internal IPs. Use firewall rules.",
         0.60, "permissive-config", tags=("network", "binding"))

    _add("MC-043", r"""anonymous_access\s*[:=]\s*(?:true|enabled|1)|allow_anonymous\s*[:=]\s*true""",
         "High", "Anonymous Access Enabled",
         "Anonymous/unauthenticated access is explicitly enabled.",
         "CWE-306", "Disable anonymous access. Require authentication for all resources.",
         0.75, "permissive-config", tags=("auth", "anonymous"))

    # ── Docker Security ───────────────────────────────────────────
    _add("MC-050", r"""--privileged""",
         "Critical", "Docker Privileged Mode",
         "Docker container running in privileged mode. Container has full host kernel access.",
         "CWE-250", "Remove --privileged flag. Use specific capabilities with --cap-add if needed.",
         0.90, "docker", r"(?:docker|compose|Makefile|\.sh)$", ("docker", "privileged"))

    _add("MC-051", r"""--net(?:work)?[=\s]+host|network_mode\s*:\s*["']?host""",
         "High", "Docker Host Network Mode",
         "Container shares the host's network namespace. Host's network interfaces are directly accessible.",
         "CWE-668", "Use bridge networking (default) or custom networks. Only use host mode when absolutely necessary.",
         0.85, "docker", r"(?:docker|compose)$", ("docker", "network"))

    _add("MC-052", r"""(?:USER\s+root|user:\s*["']?root)""",
         "High", "Container Running as Root",
         "Container configured to run as root user. If compromised, attacker has root access.",
         "CWE-250", "Add 'USER nonroot' to Dockerfile. Create a non-root user with minimal permissions.",
         0.75, "docker", r"(?:Dockerfile|compose)$", ("docker", "root"))

    _add("MC-053", r"""/var/run/docker\.sock""",
         "Critical", "Docker Socket Exposed to Container",
         "Docker socket mounted inside container. Provides full control over Docker host.",
         "CWE-250", "Never mount Docker socket in production containers. Use Docker API proxy with restricted permissions.",
         0.95, "docker", r"(?:docker|compose)$", ("docker", "socket"))

    _add("MC-054", r"""COPY\s+\.\s+\.""",
         "Medium", "Docker COPY All Files",
         "COPY . . without .dockerignore may include .env files, .git directory, and sensitive configs.",
         "CWE-200", "Create a .dockerignore file excluding .env, .git, node_modules, and other sensitive files.",
         0.70, "docker", r"Dockerfile$", ("docker", "copy"))

    _add("MC-055", r"""ARG\s+(?:\w+(?:SECRET|PASSWORD|KEY|TOKEN|CREDENTIAL)\w*)\s*=""",
         "High", "Secrets in Docker ARG",
         "Secrets passed as Docker ARG are visible in image layers and image history.",
         "CWE-200", "Use Docker secrets or BuildKit --mount=type=secret. Never use ARG for secrets.",
         0.80, "docker", r"Dockerfile$", ("docker", "secrets"))

    # ── Verbose Error Output ──────────────────────────────────────
    _add("MC-060", r"""(?:traceback|stacktrace|stack_trace)\s*[:=]\s*(?:true|1|enabled)""",
         "High", "Stack Trace Output Enabled",
         "Application configured to output full stack traces, potentially revealing internal architecture.",
         "CWE-209", "Disable stack trace output in production. Log errors server-side with a unique error ID.",
         0.75, "debug-mode", tags=("error-handling", "verbose"))

    _add("MC-061", r"""(?:detailed_errors|show_errors|verbose_errors)\s*[:=]\s*(?:true|1|yes|enabled)""",
         "High", "Detailed Error Messages Enabled",
         "Detailed error messages enabled, potentially exposing database queries, file paths, and internal structure.",
         "CWE-209", "Disable detailed errors in production. Use generic error messages with logged error IDs.",
         0.75, "debug-mode", tags=("error-handling", "verbose"))

    return rules


# ────────────────────────────────────────────────────────────────────────────
# Scanner Engine
# ────────────────────────────────────────────────────────────────────────────

ALL_MISCONFIG_RULES = _build_misconfig_rules()
COMPILED_MISCONFIG_RULES = [
    (re.compile(r.pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL), r)
    for r in ALL_MISCONFIG_RULES
]

SKIP_DIRS = {
    "node_modules", ".git", ".next", "dist", "build", "__pycache__",
    ".venv", "venv", "vendor", ".cache", "coverage", ".svn",
}

SCAN_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php",
    ".yaml", ".yml", ".json", ".xml", ".conf", ".cfg", ".ini", ".env",
    ".toml", ".tf", ".hcl", ".sh", ".bash", ".ps1", ".properties",
    ".cs", ".rs", ".gradle", ".groovy", ".htaccess",
}


def scan_misconfig_file(
    content: str,
    filepath: str,
    base_path: str = "",
) -> list[MisconfigFinding]:
    """Scan a single file for security misconfigurations."""
    findings: list[MisconfigFinding] = []
    relative = filepath.replace(base_path, "").lstrip("/\\") if base_path else filepath
    seen: set[str] = set()

    for compiled_re, rule in COMPILED_MISCONFIG_RULES:
        # Apply file filter if specified
        if rule.file_filter:
            if not re.search(rule.file_filter, filepath, re.IGNORECASE):
                continue

        for match in compiled_re.finditer(content):
            line_num = content.count("\n", 0, match.start()) + 1
            matched_text = match.group(0).strip()[:200]

            finding_key = f"{rule.id}:{line_num}"
            if finding_key in seen:
                continue
            seen.add(finding_key)

            findings.append(MisconfigFinding(
                id=f"MC-{relative}:{line_num}:{rule.id}",
                file=relative,
                line_number=line_num,
                severity=rule.severity,
                title=rule.title,
                description=rule.description,
                matched_content=matched_text,
                category="A02:2025-Security Misconfiguration",
                cwe=rule.cwe,
                remediation=rule.remediation,
                confidence=rule.confidence,
                subcategory=rule.subcategory,
                tags=list(rule.tags),
            ))

    return findings


def scan_misconfig_directory(
    root: str,
    max_files: int = 50_000,
) -> list[MisconfigFinding]:
    """Walk a directory tree and scan for security misconfigurations."""
    all_findings: list[MisconfigFinding] = []
    root_path = Path(root)
    scanned = 0

    # Also check for Dockerfiles without extension match
    dockerfile_names = {"dockerfile", "docker-compose.yml", "docker-compose.yaml", "makefile"}

    for fpath in root_path.rglob("*"):
        if scanned >= max_files:
            break
        if fpath.is_dir():
            continue
        if any(skip in fpath.parts for skip in SKIP_DIRS):
            continue

        is_scannable = (
            fpath.suffix.lower() in SCAN_EXTENSIONS
            or fpath.name.lower() in dockerfile_names
        )
        if not is_scannable:
            continue

        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
            if len(content) > 5_000_000:
                continue
            findings = scan_misconfig_file(content, str(fpath), str(root_path))
            all_findings.extend(findings)
            scanned += 1
        except (OSError, PermissionError):
            continue

    return all_findings


# ─────────────────────────────────────────────────────────────────────────────
# Enterprise Integration Layer — added by enterprise refactor
# ─────────────────────────────────────────────────────────────────────────────
import logging as _logging

_misc_logger = _logging.getLogger("enterprise.scanner.misconfig")


def normalize_misconfig_finding(f: MisconfigFinding, scan_id: str = "") -> dict:
    """Convert MisconfigFinding to NormalizedFinding-compatible dict."""
    return {
        "id": f.id,
        "scanner_source": "misconfig",
        "module": "misconfig",
        "category": f.category,
        "severity": f.severity.lower(),
        "title": f.title,
        "description": f.description,
        "matched_content": f.matched_content,
        "cwe": f.cwe,
        "owasp": "A05:2025",
        "file": f.file,
        "line_number": f.line_number,
        "confidence": f.confidence,
        "remediation": f.remediation,
        "tags": list(f.tags) + ["misconfiguration"],
        "scan_id": scan_id,
    }


def scan_misconfig_file_telemetry(
    content: str,
    filepath: str,
    base_path: str = "",
    scan_id: str = "",
) -> tuple[list[MisconfigFinding], dict]:
    """Wraps scan_misconfig_file() with structured telemetry."""
    start = _time.monotonic()
    findings = scan_misconfig_file(content, filepath, base_path)
    elapsed_ms = (_time.monotonic() - start) * 1000
    telemetry = {
        "scanner": "misconfig",
        "scan_id": scan_id,
        "file": filepath,
        "findings_count": len(findings),
        "duration_ms": round(elapsed_ms, 2),
        "timestamp": _time.time(),
    }
    return findings, telemetry


def scan_misconfig_directory_enterprise(
    root: str,
    max_files: int = 50_000,
    scan_id: str = "",
    on_finding=None,
) -> tuple[list[MisconfigFinding], dict]:
    """
    Enterprise wrapper for scan_misconfig_directory().
    Adds structured telemetry + optional real-time finding callback.
    """
    from pathlib import Path as _Path
    start = _time.time()
    findings, files_scanned = [], 0
    dockerfile_names = {"dockerfile", "docker-compose.yml", "makefile"}

    for fpath in _Path(root).rglob("*"):
        if files_scanned >= max_files:
            break
        if fpath.is_dir() or any(skip in fpath.parts for skip in SKIP_DIRS):
            continue
        is_scannable = (
            fpath.suffix.lower() in SCAN_EXTENSIONS
            or fpath.name.lower() in dockerfile_names
        )
        if not is_scannable:
            continue
        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
            if len(content) > 5_000_000:
                continue
            file_findings, _ = scan_misconfig_file_telemetry(
                content, str(fpath), root, scan_id=scan_id
            )
            for f in file_findings:
                findings.append(f)
                if on_finding:
                    try:
                        on_finding(normalize_misconfig_finding(f, scan_id))
                    except Exception:
                        pass
            files_scanned += 1
        except (OSError, PermissionError):
            continue

    telemetry = {
        "scanner": "misconfig",
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
    _misc_logger.info(
        f"misconfig_scanner: {len(findings)} findings across {files_scanned} files "
        f"in {telemetry['duration_ms']:.0f}ms"
    )
    return findings, telemetry
