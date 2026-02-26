"""
Technology Fingerprinting Engine v1.0
======================================

Passive + active technology detection for web applications.
Used by the Quantara scanner to select relevant templates and provide
attack surface context.

Detection categories:
  - Web servers: nginx, Apache, IIS, Caddy, Lighttpd
  - App frameworks: Django, Flask, Rails, Laravel, Express, FastAPI, Spring, .NET
  - Frontend: React, Vue, Angular, Next.js, Nuxt, Gatsby
  - CMS: WordPress, Drupal, Joomla, Magento, Shopify
  - Cloud/CDN: Cloudflare, AWS CloudFront, Fastly, Akamai, Azure, GCP
  - Databases (from error pages): MySQL, PostgreSQL, MongoDB, SQLite
  - Languages: PHP, Python, Ruby, Java, Go, Node.js, .NET
  - Security tech: WAF detection, HSTS, CSP, CORS policies
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("owasp_scanner.tech_fingerprinting")


# ─────────────────────────────────────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class TechProfile:
    """Technology fingerprint of a scanned target."""
    url: str
    server: str = ""                        # nginx, apache, iis, etc.
    language: str = ""                      # php, python, ruby, java, go, node
    framework: str = ""                     # django, flask, laravel, rails, spring
    cms: str = ""                           # wordpress, drupal, joomla
    frontend: str = ""                      # react, vue, angular, nextjs
    cdn: str = ""                           # cloudflare, cloudfront, akamai
    cloud: str = ""                         # aws, gcp, azure
    waf: str = ""                           # cloudflare_waf, aws_waf, etc.
    database: str = ""                      # mysql, postgres, mongodb
    os: str = ""                            # linux, windows
    tech_stack: list[str] = field(default_factory=list)  # all detected techs
    security_headers: dict[str, bool] = field(default_factory=dict)
    has_hsts: bool = False
    has_csp: bool = False
    has_x_frame: bool = False
    has_cors: bool = False
    cors_wildcard: bool = False
    cookies_secure: bool = True             # False if any insecure cookie found
    cookies_httponly: bool = True
    allows_http: bool = False               # True if HTTP (not HTTPS) is accessible
    has_admin_panel: bool = False
    exposed_tech_headers: list[str] = field(default_factory=list)  # leaking version info
    wordpress_version: str = ""
    php_version: str = ""
    server_version: str = ""               # e.g., "Apache/2.4.51"
    api_type: str = ""                     # rest, graphql, soap
    is_spa: bool = False

    @property
    def attack_surface_tags(self) -> list[str]:
        """Return relevant Quantara template tags based on detected tech."""
        tags = []
        if "wordpress" in (self.cms or "").lower():
            tags.extend(["wordpress", "cms"])
        if "php" in (self.language or "").lower():
            tags.extend(["php"])
        if "graphql" in (self.api_type or "").lower():
            tags.extend(["graphql"])
        if "nginx" in (self.server or "").lower():
            tags.extend(["nginx"])
        if "iis" in (self.server or "").lower():
            tags.extend(["iis"])
        if "cloudflare" in (self.cdn or "").lower() or "cloudflare" in (self.waf or "").lower():
            tags.extend(["cloudflare"])
        if "aws" in (self.cloud or "").lower():
            tags.extend(["aws", "amazon"])
        if not self.has_hsts:
            tags.append("misconfig")
        if self.cors_wildcard:
            tags.extend(["cors", "misconfig"])
        if self.has_admin_panel:
            tags.extend(["admin", "panel"])
        # Always include generic/dast tags
        tags.extend(["generic", "dast", "owasp-top10"])
        return list(set(tags))


# ─────────────────────────────────────────────────────────────────────────────
# Fingerprint Signatures
# ─────────────────────────────────────────────────────────────────────────────

# Each entry: (pattern, technology_category, technology_name)
HEADER_SIGNATURES: list[tuple[str, str, str]] = [
    # Server header patterns
    (r"nginx(?:/[\d.]+)?", "server", "nginx"),
    (r"apache(?:/[\d.]+)?", "server", "apache"),
    (r"microsoft-iis(?:/[\d.]+)?", "server", "iis"),
    (r"caddy", "server", "caddy"),
    (r"lighttpd(?:/[\d.]+)?", "server", "lighttpd"),
    (r"openresty(?:/[\d.]+)?", "server", "openresty"),
    (r"gunicorn(?:/[\d.]+)?", "server", "gunicorn"),
    (r"uvicorn", "server", "uvicorn"),
    (r"jetty(?:/[\d.]+)?", "server", "jetty"),
    (r"tomcat(?:/[\d.]+)?", "server", "tomcat"),
    (r"werkzeug(?:/[\d.]+)?", "server", "werkzeug"),

    # Language/framework from response headers
    (r"x-powered-by.*php", "language", "php"),
    (r"x-powered-by.*asp\.net", "language", "aspnet"),
    (r"x-powered-by.*express", "framework", "express"),
    (r"x-powered-by.*next\.js", "framework", "nextjs"),
    (r"x-generator.*drupal", "cms", "drupal"),
    (r"x-generator.*wordpress", "cms", "wordpress"),

    # Cloud/CDN headers
    (r"cf-ray", "cdn", "cloudflare"),
    (r"x-amz-request-id|x-amz-cf-id", "cloud", "aws"),
    (r"x-goog-request-id|x-cloud-trace-context", "cloud", "gcp"),
    (r"x-azure-ref|x-ms-request-id", "cloud", "azure"),
    (r"fastly-io-info|x-served-by.*cache", "cdn", "fastly"),
    (r"x-cache.*akamai|aka-origin-hop", "cdn", "akamai"),

    # WAF detection
    (r"cf-cache-status", "waf", "cloudflare"),
    (r"x-sucuri-id", "waf", "sucuri"),
    (r"x-wr-diag|x-forwarded-server.*squid", "waf", "squid_proxy"),
]

BODY_SIGNATURES: list[tuple[str, str, str]] = [
    # WordPress
    (r"/wp-content/|/wp-includes/|wp-json|<link[^>]+\/wp-", "cms", "wordpress"),
    (r"wordpress[\d. ]+", "cms", "wordpress"),

    # Drupal
    (r"Drupal\.settings|drupal_settings_json|data-drupal-", "cms", "drupal"),
    (r"/sites/default/files/|/modules/system/", "cms", "drupal"),

    # Joomla
    (r"/components/com_|Joomla!|\?option=com_|/media/jui/", "cms", "joomla"),

    # Magento
    (r"Mage\.Cookies|mage/cookies|/skin/frontend/|var BLANK_URL", "cms", "magento"),

    # Shopify
    (r"Shopify\.|cdn\.shopify\.com|shopify-section", "cms", "shopify"),

    # React
    (r"__reactFiber|__REACT_DEVTOOLS|react-root|ReactDOM\.render", "frontend", "react"),
    (r"data-reactroot|data-reactid", "frontend", "react"),

    # Vue.js
    (r"Vue\.__version|__VUE__|__vue_component|data-v-", "frontend", "vue"),

    # Angular
    (r"ng-version|ng-app|angular\.js|AngularJS\s+v", "frontend", "angular"),
    (r"_angular_host", "frontend", "angular"),

    # Next.js
    (r"__NEXT_DATA__|/_next/static|next/dist", "frontend", "nextjs"),
    (r"__nextjs_scroll_focus_boundary", "frontend", "nextjs"),

    # Nuxt.js
    (r"__NUXT__|/_nuxt/|nuxtjs", "frontend", "nuxt"),

    # Django
    (r"csrfmiddlewaretoken|djdt|django\.contrib", "framework", "django"),

    # Laravel
    (r"laravel_session|csrf_token.*laravel|__laravel_session", "framework", "laravel"),
    (r"Laravel\s+v|Illuminate\\", "framework", "laravel"),

    # Ruby on Rails
    (r"csrf-token.*authenticity_token|data-authenticity-token", "framework", "rails"),
    (r"Phusion Passenger|\/assets\/application-[a-f0-9]+\.js", "framework", "rails"),

    # Spring/Java
    (r"Spring Framework|spring\.io|org\.springframework", "framework", "spring"),
    (r"JSESSIONID", "language", "java"),

    # ASP.NET
    (r"__VIEWSTATE|__EVENTTARGET|ASP\.NET_SessionId|\.aspx", "framework", "aspnet"),

    # GraphQL
    (r"\"__typename\"|\{\"data\":|\"errors\":\[|graphql|application/graphql", "api", "graphql"),

    # Swagger / OpenAPI
    (r"swagger-ui|Swagger UI|openapi|redoc\.standalone", "api", "openapi"),

    # PHP indicators
    (r"\.php[?#\">]|PHPSESSID|var_dump\(|print_r\(", "language", "php"),

    # Database error signatures
    (r"SQL syntax.*MySQL|mysql_num_rows|mysqli_", "database", "mysql"),
    (r"PostgreSQL.*ERROR|Npgsql|PSQLException", "database", "postgresql"),
    (r"org\.mongodb\.|MongoException|mongoerr", "database", "mongodb"),
    (r"SQLite.*Exception|\[SQLITE_ERROR\]", "database", "sqlite"),

    # S3 / cloud storage
    (r"<ListBucketResult|\.s3\.amazonaws\.com|s3\.aws", "cloud", "aws_s3"),

    # Admin panels
    (r"/admin/|/wp-admin/|/administrator/|/backend/|/manage/|/panel/", "admin", "admin_panel"),
    (r"phpmyadmin|adminer|phpinfo\(\)", "admin", "admin_panel"),
]

COOKIE_SIGNATURES: list[tuple[str, str, str]] = [
    (r"PHPSESSID", "language", "php"),
    (r"JSESSIONID", "language", "java"),
    (r"ASP\.NET_SessionId|\.AspNet\.", "framework", "aspnet"),
    (r"laravel_session", "framework", "laravel"),
    (r"_rails_session|_session_id", "framework", "rails"),
    (r"csrftoken|django", "framework", "django"),
    (r"wp[-_]|wordpress", "cms", "wordpress"),
    (r"shopify_session", "cms", "shopify"),
]

PATH_SIGNATURES: list[tuple[str, str, str]] = [
    (r"wp-login\.php|xmlrpc\.php|wp-admin", "cms", "wordpress"),
    (r"drupal|modules/system", "cms", "drupal"),
    (r"joomla|components/com_", "cms", "joomla"),
    (r"phpmyadmin|adminer\.php", "admin", "admin_panel"),
    (r"api/v\d+|api/graphql|graphql", "api", "rest_api"),
    (r"\.php$", "language", "php"),
    (r"\.aspx$|\.ashx$", "framework", "aspnet"),
    (r"\.jsp$|\.do$", "language", "java"),
    (r"\.rb$|rack|sinatra", "language", "ruby"),
]

# Version extraction patterns
VERSION_PATTERNS: list[tuple[str, str]] = [
    (r"wordpress[/ ](\d+\.\d+(?:\.\d+)?)", "wordpress_version"),
    (r"PHP/(\d+\.\d+(?:\.\d+)?)", "php_version"),
    (r"(Apache|nginx|IIS)/(\d+\.\d+(?:\.\d+)?)", "server_version"),
    (r"drupal[/ ](\d+\.\d+(?:\.\d+)?)", "drupal_version"),
]


# ─────────────────────────────────────────────────────────────────────────────
# Fingerprinter
# ─────────────────────────────────────────────────────────────────────────────

class TechFingerprinter:
    """
    Passive technology fingerprinter.
    Analyzes HTTP response headers, body, cookies, and URL to detect tech stack.
    """

    def fingerprint(
        self,
        url: str,
        status_code: int,
        headers: dict[str, str],     # lowercase keys
        body: str,
        cookies: dict[str, str] = None,
    ) -> TechProfile:
        profile = TechProfile(url=url)
        tech_set: set[str] = set()
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        body_lower = body[:50000].lower()  # only scan first 50KB
        cookies = cookies or {}

        # ── Header analysis ───────────────────────────────────────────
        self._analyze_headers(headers_lower, profile, tech_set)

        # ── Body analysis ─────────────────────────────────────────────
        self._analyze_body(body, body_lower, profile, tech_set)

        # ── Cookie analysis ───────────────────────────────────────────
        self._analyze_cookies(headers_lower, cookies, profile, tech_set)

        # ── Security header checks ────────────────────────────────────
        self._check_security_headers(headers_lower, profile)

        # ── Version extraction ────────────────────────────────────────
        self._extract_versions(headers_lower, body[:5000], profile)

        # ── URL path hints ─────────────────────────────────────────────
        self._analyze_url_path(url, profile, tech_set)

        # ── OS detection from Server header ───────────────────────────
        server_raw = headers_lower.get("server", "")
        if "win" in server_raw:
            profile.os = "windows"
        elif any(k in server_raw for k in ("ubuntu", "debian", "centos", "linux", "unix")):
            profile.os = "linux"

        # ── Expose known version-leaking headers ─────────────────────
        leaking_headers = ["server", "x-powered-by", "x-aspnet-version",
                           "x-aspnetmvc-version", "x-generator", "x-drupal-cache"]
        for hdr in leaking_headers:
            val = headers.get(hdr, "")
            if val and "/" in val:
                profile.exposed_tech_headers.append(f"{hdr}: {val}")

        # ── HTTP vs HTTPS ──────────────────────────────────────────────
        profile.allows_http = url.startswith("http://")

        # ── Deduplicate tech stack ────────────────────────────────────
        profile.tech_stack = sorted(tech_set)

        return profile

    def _analyze_headers(
        self, headers: dict[str, str], profile: TechProfile, tech_set: set[str]
    ):
        # Combine all header key:value strings for pattern matching
        combined = "\n".join(f"{k}: {v}" for k, v in headers.items())

        for pattern, category, tech_name in HEADER_SIGNATURES:
            if re.search(pattern, combined, re.IGNORECASE):
                tech_set.add(tech_name)
                self._assign_tech(profile, category, tech_name)

        # Specific version extraction from Server header
        server = headers.get("server", "")
        if server and not profile.server:
            # Clean server name
            clean = re.sub(r"[ /].*", "", server)
            if clean:
                profile.server = clean.lower()
                tech_set.add(clean.lower())

    def _analyze_body(
        self, body: str, body_lower: str, profile: TechProfile, tech_set: set[str]
    ):
        for pattern, category, tech_name in BODY_SIGNATURES:
            if re.search(pattern, body, re.IGNORECASE):
                tech_set.add(tech_name)
                self._assign_tech(profile, category, tech_name)
                if category == "admin":
                    profile.has_admin_panel = True

        # SPA detection (large JS, no server-side content)
        if (
            "react" in profile.frontend.lower()
            or "vue" in profile.frontend.lower()
            or "angular" in profile.frontend.lower()
            or "nextjs" in profile.frontend.lower()
        ):
            profile.is_spa = True

    def _analyze_cookies(
        self,
        headers: dict[str, str],
        cookies: dict[str, str],
        profile: TechProfile,
        tech_set: set[str],
    ):
        set_cookie = headers.get("set-cookie", "")
        all_cookies = set_cookie + " " + " ".join(f"{k}={v}" for k, v in cookies.items())

        for pattern, category, tech_name in COOKIE_SIGNATURES:
            if re.search(pattern, all_cookies, re.IGNORECASE):
                tech_set.add(tech_name)
                self._assign_tech(profile, category, tech_name)

        # Check cookie security flags
        if set_cookie:
            cookies_lower = set_cookie.lower()
            if "secure" not in cookies_lower:
                profile.cookies_secure = False
            if "httponly" not in cookies_lower:
                profile.cookies_httponly = False

    def _check_security_headers(self, headers: dict[str, str], profile: TechProfile):
        # HSTS
        profile.has_hsts = "strict-transport-security" in headers
        profile.security_headers["hsts"] = profile.has_hsts

        # CSP
        profile.has_csp = "content-security-policy" in headers
        profile.security_headers["csp"] = profile.has_csp

        # X-Frame-Options
        profile.has_x_frame = "x-frame-options" in headers
        profile.security_headers["x_frame_options"] = profile.has_x_frame

        # X-Content-Type-Options
        profile.security_headers["x_content_type"] = "x-content-type-options" in headers

        # X-XSS-Protection (deprecated but still checked)
        profile.security_headers["x_xss_protection"] = "x-xss-protection" in headers

        # Referrer-Policy
        profile.security_headers["referrer_policy"] = "referrer-policy" in headers

        # Permissions-Policy
        profile.security_headers["permissions_policy"] = "permissions-policy" in headers

        # CORS
        acao = headers.get("access-control-allow-origin", "")
        profile.has_cors = bool(acao)
        profile.security_headers["cors"] = profile.has_cors
        profile.cors_wildcard = acao.strip() == "*"

    def _extract_versions(self, headers: dict[str, str], body_head: str, profile: TechProfile):
        combined = "\n".join(f"{k}: {v}" for k, v in headers.items()) + "\n" + body_head

        # WordPress version
        m = re.search(r"wordpress[/ ]?(\d+\.\d+(?:\.\d+)?)", combined, re.IGNORECASE)
        if m:
            profile.wordpress_version = m.group(1)

        # PHP version
        m = re.search(r"PHP/(\d+\.\d+(?:\.\d+)?)", combined, re.IGNORECASE)
        if m:
            profile.php_version = m.group(1)

        # Server version
        server_raw = headers.get("server", "")
        m = re.search(r"(nginx|apache|iis|caddy|lighttpd)/(\d+\.\d+(?:\.\d+)?)", server_raw, re.IGNORECASE)
        if m:
            profile.server_version = f"{m.group(1)}/{m.group(2)}"

    def _analyze_url_path(self, url: str, profile: TechProfile, tech_set: set[str]):
        for pattern, category, tech_name in PATH_SIGNATURES:
            if re.search(pattern, url, re.IGNORECASE):
                tech_set.add(tech_name)
                self._assign_tech(profile, category, tech_name)
                if category == "admin":
                    profile.has_admin_panel = True

    def _assign_tech(self, profile: TechProfile, category: str, tech_name: str):
        """Assign detected technology to the appropriate profile field."""
        if category == "server" and not profile.server:
            profile.server = tech_name
        elif category == "language" and not profile.language:
            profile.language = tech_name
        elif category == "framework" and not profile.framework:
            profile.framework = tech_name
        elif category == "cms" and not profile.cms:
            profile.cms = tech_name
        elif category == "frontend" and not profile.frontend:
            profile.frontend = tech_name
        elif category == "cdn" and not profile.cdn:
            profile.cdn = tech_name
        elif category == "cloud" and not profile.cloud:
            profile.cloud = tech_name
        elif category == "waf" and not profile.waf:
            profile.waf = tech_name
        elif category == "database" and not profile.database:
            profile.database = tech_name
        elif category == "api":
            if not profile.api_type:
                profile.api_type = tech_name


# ─────────────────────────────────────────────────────────────────────────────
# Security Header Analyzer
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SecurityHeaderIssue:
    """A missing or misconfigured security header."""
    header: str
    severity: str
    description: str
    recommendation: str
    owasp: str
    cwe: str


SECURITY_HEADER_CHECKS: list[tuple[str, str, str, str, str, str]] = [
    # (header_key, severity, description, recommendation, owasp, cwe)
    (
        "strict-transport-security",
        "high",
        "Missing Strict-Transport-Security (HSTS) header. Allows downgrade attacks.",
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "A05:2021",
        "CWE-319",
    ),
    (
        "content-security-policy",
        "high",
        "Missing Content-Security-Policy (CSP) header. Increases XSS risk.",
        "Add a restrictive CSP: Content-Security-Policy: default-src 'self'",
        "A03:2021",
        "CWE-116",
    ),
    (
        "x-frame-options",
        "medium",
        "Missing X-Frame-Options header. Application may be vulnerable to clickjacking.",
        "Add: X-Frame-Options: DENY or SAMEORIGIN",
        "A05:2021",
        "CWE-1021",
    ),
    (
        "x-content-type-options",
        "medium",
        "Missing X-Content-Type-Options: nosniff. Allows MIME-type sniffing attacks.",
        "Add: X-Content-Type-Options: nosniff",
        "A05:2021",
        "CWE-16",
    ),
    (
        "referrer-policy",
        "low",
        "Missing Referrer-Policy header. May leak sensitive URL data in referrer.",
        "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "A05:2021",
        "CWE-200",
    ),
    (
        "permissions-policy",
        "low",
        "Missing Permissions-Policy header. Allows unrestricted browser feature access.",
        "Add: Permissions-Policy: geolocation=(), camera=(), microphone=()",
        "A05:2021",
        "CWE-16",
    ),
]


def analyze_security_headers(headers: dict[str, str]) -> list[SecurityHeaderIssue]:
    """Analyze response headers and return list of security issues found."""
    headers_lower = {k.lower(): v for k, v in headers.items()}
    issues = []

    for hdr_key, severity, description, recommendation, owasp, cwe in SECURITY_HEADER_CHECKS:
        if hdr_key not in headers_lower:
            issues.append(SecurityHeaderIssue(
                header=hdr_key,
                severity=severity,
                description=description,
                recommendation=recommendation,
                owasp=owasp,
                cwe=cwe,
            ))

    # Special checks: check for insecure values
    # CORS wildcard
    acao = headers_lower.get("access-control-allow-origin", "")
    acac = headers_lower.get("access-control-allow-credentials", "")
    if acao == "*" and "true" in acac.lower():
        issues.append(SecurityHeaderIssue(
            header="access-control-allow-origin + access-control-allow-credentials",
            severity="critical",
            description=(
                "CORS misconfiguration: Access-Control-Allow-Origin: * combined with "
                "Access-Control-Allow-Credentials: true. This allows any origin to make "
                "credentialed cross-origin requests."
            ),
            recommendation=(
                "Never combine wildcard ACAO with ACAC: true. "
                "Allowlist specific trusted origins."
            ),
            owasp="A05:2021",
            cwe="CWE-346",
        ))
    elif acao == "*":
        issues.append(SecurityHeaderIssue(
            header="access-control-allow-origin",
            severity="medium",
            description="CORS wildcard: Access-Control-Allow-Origin: * allows any origin access.",
            recommendation="Restrict ACAO to specific trusted origins.",
            owasp="A05:2021",
            cwe="CWE-346",
        ))

    # Check X-Powered-By leaking framework info
    xpb = headers_lower.get("x-powered-by", "")
    if xpb:
        issues.append(SecurityHeaderIssue(
            header="x-powered-by",
            severity="info",
            description=f"X-Powered-By header reveals technology: {xpb}",
            recommendation="Remove X-Powered-By header to prevent technology fingerprinting.",
            owasp="A05:2021",
            cwe="CWE-200",
        ))

    # Check Server header leaking version
    server = headers_lower.get("server", "")
    if server and "/" in server:
        issues.append(SecurityHeaderIssue(
            header="server",
            severity="info",
            description=f"Server header reveals software version: {server}",
            recommendation="Configure server to hide version information.",
            owasp="A05:2021",
            cwe="CWE-200",
        ))

    return issues


# ─────────────────────────────────────────────────────────────────────────────
# WAF Detection
# ─────────────────────────────────────────────────────────────────────────────

WAF_SIGNATURES: list[tuple[str, str]] = [
    # (pattern_in_headers_or_body, waf_name)
    (r"cf-ray", "Cloudflare"),
    (r"x-sucuri-id|sucuri-waf", "Sucuri WAF"),
    (r"x-qcloud-waf|qcloud", "TencentCloud WAF"),
    (r"x-akamai-ssl|x-check-cacheable", "Akamai WAF"),
    (r"x-mod-defender", "ModDefender"),
    (r"x-perimeterx-score", "PerimeterX"),
    (r"x-powered-by.*imperva|x-iinfo", "Imperva Incapsula"),
    (r"x-firewall-protection", "Generic WAF"),
    (r"anquanbao", "AnQuanBao WAF"),
    (r"webscreamer", "WebScreamer WAF"),
    (r"x-360wzws", "360 WAF"),
    (r"barracuda", "Barracuda WAF"),
    (r"dw-waf|dotDefender", "dotDefender"),
    (r"bigip", "F5 BIG-IP"),
    (r"fortigate|fortiweb", "FortiWAF"),
    (r"naxsi_error", "NAXSI WAF"),
    (r"modsecurity|mod_security", "ModSecurity"),
]


def detect_waf(headers: dict[str, str], body: str = "") -> str:
    """Detect WAF from headers and body. Returns WAF name or empty string."""
    combined = "\n".join(f"{k}: {v}" for k, v in headers.items()) + "\n" + body[:2000]
    combined_lower = combined.lower()

    for pattern, waf_name in WAF_SIGNATURES:
        if re.search(pattern, combined_lower, re.IGNORECASE):
            return waf_name

    return ""


# ─────────────────────────────────────────────────────────────────────────────
# Convenience function
# ─────────────────────────────────────────────────────────────────────────────

def fingerprint_response(
    url: str,
    status_code: int,
    headers: dict[str, str],
    body: str,
) -> TechProfile:
    """
    One-shot fingerprinting function.
    Returns a TechProfile with all detected technologies.
    """
    fingerprinter = TechFingerprinter()
    profile = fingerprinter.fingerprint(url, status_code, headers, body)

    # Additional WAF detection
    if not profile.waf:
        profile.waf = detect_waf(headers, body)
    if profile.waf:
        profile.tech_stack = list(set(profile.tech_stack + [profile.waf.lower().replace(" ", "_")]))

    return profile
