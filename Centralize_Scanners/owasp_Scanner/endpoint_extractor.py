"""
Quantum Protocol v4.0 — Bug Bounty Recon / Endpoint Extraction Engine

Capabilities:
  - Extract ALL URLs, paths, and endpoints from source code
  - Classify by type: API, admin, internal, debug, documentation, webhook
  - Extract HTTP methods used with each endpoint
  - Detect environment-specific URLs (staging, dev, local, internal)
  - Extract hostnames, IPs, and internal service names
  - Detect internal DNS names (.internal, .local, .corp, .svc.cluster.local)
  - Cloud metadata URLs
  - S3 bucket names, Azure blob URLs, GCP storage URLs
  - Technology fingerprinting from imports/requires
  - Comment mining for developer intel (TODO, FIXME, HACK, internal refs)
  - Attack surface summary report generation
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path
from collections import Counter


# ────────────────────────────────────────────────────────────────────────────
# Data Models
# ────────────────────────────────────────────────────────────────────────────

@dataclass
class ExtractedEndpoint:
    """An extracted URL or API endpoint from source code."""
    url: str
    file: str
    line_number: int
    endpoint_type: str   # api | admin | internal | debug | documentation | webhook | cdn | cloud
    http_method: Optional[str] = None
    risk_level: str = "Info"
    description: str = ""
    tags: list[str] = field(default_factory=list)


@dataclass
class TechFingerprint:
    """Technology stack fingerprint from a codebase."""
    frameworks: list[str] = field(default_factory=list)
    languages: list[str] = field(default_factory=list)
    databases: list[str] = field(default_factory=list)
    cloud_providers: list[str] = field(default_factory=list)
    api_gateways: list[str] = field(default_factory=list)
    build_tools: list[str] = field(default_factory=list)
    packages: list[str] = field(default_factory=list)


@dataclass
class DeveloperComment:
    """An interesting developer comment found in code."""
    file: str
    line_number: int
    comment_type: str  # todo | fixme | hack | insecure | sensitive | reference
    content: str
    severity: str = "Info"


@dataclass
class AttackSurfaceReport:
    """Complete attack surface analysis report."""
    total_endpoints: int = 0
    endpoints: list[ExtractedEndpoint] = field(default_factory=list)
    endpoints_by_type: dict[str, int] = field(default_factory=dict)
    endpoints_by_risk: dict[str, int] = field(default_factory=dict)
    tech_fingerprint: TechFingerprint = field(default_factory=TechFingerprint)
    developer_comments: list[DeveloperComment] = field(default_factory=list)
    cloud_resources: list[str] = field(default_factory=list)
    internal_hosts: list[str] = field(default_factory=list)
    summary: str = ""


# ────────────────────────────────────────────────────────────────────────────
# URL / Endpoint Extraction Patterns
# ────────────────────────────────────────────────────────────────────────────

URL_PATTERN = re.compile(
    r"""(?:https?://)[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+""",
    re.IGNORECASE,
)

PATH_PATTERN = re.compile(
    r"""["'`](/(?:api|v[0-9]+|admin|internal|debug|health|metrics|swagger|graphql|webhook|callback|auth|login|register|upload|download|export|import|config|settings|manage|dashboard|actuator|trace|phpinfo|server-status|\.env|\.git)/[^"'`\s]*)["'`]""",
    re.IGNORECASE,
)

# Admin / sensitive paths
ADMIN_PATHS = re.compile(
    r"""["'`](/(?:admin|phpmyadmin|adminer|wp-admin|manager|console|actuator|debug|trace|swagger|swagger-ui|api-docs|openapi\.json|graphql|\.env|\.git|phpinfo|server-status|server-info|elmah|solr|jenkins|jmx-console|web-console)[^"'`\s]*)["'`]""",
    re.IGNORECASE,
)

# Cloud Metadata URLs
CLOUD_METADATA = re.compile(
    r"""(?:http://)?(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)/[^\s"']+""",
    re.IGNORECASE,
)

# S3 Bucket patterns
S3_BUCKET = re.compile(
    r"""(?:https?://)?(?:([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3[.\-](?:amazonaws\.com|us-east-\d|us-west-\d|eu-west-\d|ap-\w+-\d)|s3://([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]))""",
    re.IGNORECASE,
)

# Azure Blob Storage
AZURE_BLOB = re.compile(
    r"""https?://([a-z0-9]{3,24})\.blob\.core\.windows\.net/[^\s"']+""",
    re.IGNORECASE,
)

# GCP Storage
GCP_STORAGE = re.compile(
    r"""(?:https?://storage\.googleapis\.com/|gs://)([a-z0-9][a-z0-9._\-]{1,61}[a-z0-9])/[^\s"']*""",
    re.IGNORECASE,
)

# Internal DNS names
INTERNAL_DNS = re.compile(
    r"""[a-zA-Z0-9\-]+\.(?:internal|local|corp|svc\.cluster\.local|lan|home|private|intranet)(?::\d+)?""",
    re.IGNORECASE,
)

# IP Addresses
IP_ADDRESS = re.compile(
    r"""\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?::\d{1,5})?\b""",
)

# HTTP Method patterns
HTTP_METHOD_CALL = re.compile(
    r"""(?:\.(?:get|post|put|delete|patch|head|options))\s*\(\s*["'`]([^"'`]+)""",
    re.IGNORECASE,
)

# WebSocket endpoints
WEBSOCKET_URL = re.compile(
    r"""wss?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+""",
    re.IGNORECASE,
)


# ────────────────────────────────────────────────────────────────────────────
# Technology Fingerprinting Patterns
# ────────────────────────────────────────────────────────────────────────────

FRAMEWORK_PATTERNS: dict[str, re.Pattern] = {
    "React": re.compile(r"""(?:from\s+["']react["']|require\s*\(\s*["']react["']\)|import\s+React)"""),
    "Next.js": re.compile(r"""(?:from\s+["']next[/"']|@next/)"""),
    "Vue": re.compile(r"""(?:from\s+["']vue["']|require\s*\(\s*["']vue["']\)|createApp)"""),
    "Angular": re.compile(r"""(?:@angular/|@Component|@Injectable|@NgModule)"""),
    "Svelte": re.compile(r"""(?:<script.*?lang=["']ts["']|from\s+["']svelte)"""),
    "Express": re.compile(r"""(?:from\s+["']express["']|require\s*\(\s*["']express["']\))"""),
    "Django": re.compile(r"""(?:from\s+django|import\s+django|INSTALLED_APPS|urlpatterns)"""),
    "Flask": re.compile(r"""(?:from\s+flask|import\s+flask|Flask\s*\()"""),
    "FastAPI": re.compile(r"""(?:from\s+fastapi|import\s+fastapi|FastAPI\s*\()"""),
    "Spring": re.compile(r"""(?:@SpringBootApplication|@RestController|@RequestMapping|springframework)"""),
    "Rails": re.compile(r"""(?:Rails\.application|ActiveRecord|ActionController|Gemfile)"""),
    "Laravel": re.compile(r"""(?:Illuminate\\|Route::|Artisan::|Laravel)"""),
    "Go Fiber": re.compile(r"""(?:fiber\.New\(\)|"github\.com/gofiber/fiber")"""),
    "Gin": re.compile(r"""(?:gin\.Default\(\)|"github\.com/gin-gonic/gin")"""),
}

DATABASE_PATTERNS: dict[str, re.Pattern] = {
    "PostgreSQL": re.compile(r"""(?:postgres://|psycopg2|pg_connect|DATABASE_URL.*?postgres)""", re.I),
    "MySQL": re.compile(r"""(?:mysql://|mysql2?|pymysql|mysql_connect)""", re.I),
    "MongoDB": re.compile(r"""(?:mongodb(?:\+srv)?://|mongoose|MongoClient)""", re.I),
    "Redis": re.compile(r"""(?:redis://|ioredis|redis\.createClient|REDIS_URL)""", re.I),
    "SQLite": re.compile(r"""(?:sqlite3|\.sqlite|sqlite:)""", re.I),
    "DynamoDB": re.compile(r"""(?:dynamodb|DynamoDBClient|aws-sdk.*?DynamoDB)""", re.I),
    "Elasticsearch": re.compile(r"""(?:elasticsearch|@elastic/|Elasticsearch\()""", re.I),
}

CLOUD_PATTERNS: dict[str, re.Pattern] = {
    "AWS": re.compile(r"""(?:aws-sdk|boto3|@aws-sdk/|amazonaws\.com|AWS\.|import\s+aws)""", re.I),
    "Google Cloud": re.compile(r"""(?:@google-cloud/|google-cloud|googleapis|GCP_|GOOGLE_CLOUD)""", re.I),
    "Azure": re.compile(r"""(?:@azure/|azure-storage|microsoftonline\.com|AZURE_)""", re.I),
    "Firebase": re.compile(r"""(?:firebase/|firebaseConfig|initializeApp.*firebase)""", re.I),
    "Vercel": re.compile(r"""(?:@vercel/|VERCEL_|vercel\.app)""", re.I),
    "Cloudflare": re.compile(r"""(?:@cloudflare/|wrangler|CLOUDFLARE_)""", re.I),
}


# ────────────────────────────────────────────────────────────────────────────
# Comment Mining Patterns
# ────────────────────────────────────────────────────────────────────────────

COMMENT_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("todo", re.compile(r"""(?://|#|/\*)\s*TODO\s*:?\s*(.+)""", re.I), "Info"),
    ("fixme", re.compile(r"""(?://|#|/\*)\s*FIXME\s*:?\s*(.+)""", re.I), "Low"),
    ("hack", re.compile(r"""(?://|#|/\*)\s*HACK\s*:?\s*(.+)""", re.I), "Medium"),
    ("insecure", re.compile(r"""(?://|#|/\*)\s*(?:NOTE|WARNING)\s*:?\s*.*(?:insecure|unsafe|vulnerable|weak|broken|bypass|hardcoded).*""", re.I), "High"),
    ("sensitive", re.compile(r"""(?://|#|/\*)\s*.*(?:password|secret|key|token|credential)\s*(?:is|=|:).*""", re.I), "High"),
    ("reference", re.compile(r"""(?://|#|/\*)\s*.*(?:JIRA|TICKET|ISSUE|BUG)-?\d+.*""", re.I), "Info"),
]


# ────────────────────────────────────────────────────────────────────────────
# Endpoint Type Classification
# ────────────────────────────────────────────────────────────────────────────

def _classify_endpoint(url: str) -> tuple[str, str]:
    """Classify an endpoint URL and assign risk level."""
    url_lower = url.lower()

    admin_keywords = ["/admin", "/manage", "/console", "/phpmyadmin", "/adminer", "/wp-admin", "/jmx", "/jenkins"]
    debug_keywords = ["/debug", "/trace", "/actuator", "/phpinfo", "/server-status", "/server-info", "/elmah", "/profiler"]
    docs_keywords = ["/swagger", "/api-docs", "/openapi", "/redoc", "/graphql"]
    internal_keywords = ["/internal", "/.env", "/.git", "/config", "/.htaccess"]
    webhook_keywords = ["/webhook", "/callback", "/hook", "/notify"]

    if any(k in url_lower for k in admin_keywords):
        return "admin", "High"
    if any(k in url_lower for k in debug_keywords):
        return "debug", "Critical"
    if any(k in url_lower for k in docs_keywords):
        return "documentation", "Medium"
    if any(k in url_lower for k in internal_keywords):
        return "internal", "High"
    if any(k in url_lower for k in webhook_keywords):
        return "webhook", "Medium"
    if "/api/" in url_lower or "/v1/" in url_lower or "/v2/" in url_lower or "/v3/" in url_lower:
        return "api", "Low"
    if "s3" in url_lower or "blob.core" in url_lower or "storage.googleapis" in url_lower:
        return "cloud", "Medium"
    if "cdn" in url_lower or "static" in url_lower:
        return "cdn", "Info"

    return "general", "Info"


# ────────────────────────────────────────────────────────────────────────────
# Scanner Engine
# ────────────────────────────────────────────────────────────────────────────

SKIP_DIRS = {
    "node_modules", ".git", ".next", "dist", "build", "__pycache__",
    ".venv", "venv", "vendor", ".cache", "coverage", ".svn",
}

SCAN_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php",
    ".vue", ".svelte", ".html", ".htm", ".yaml", ".yml", ".json",
    ".xml", ".conf", ".cfg", ".ini", ".env", ".toml", ".tf", ".hcl",
    ".sh", ".bash", ".zsh", ".ps1", ".dockerfile", ".cs", ".rs",
    ".swift", ".kt", ".groovy", ".gradle", ".scala", ".mjs", ".cjs",
}


def scan_file_endpoints(
    content: str,
    filepath: str,
    base_path: str = "",
) -> tuple[list[ExtractedEndpoint], list[DeveloperComment]]:
    """Scan a single file for endpoints and developer comments."""
    endpoints: list[ExtractedEndpoint] = []
    comments: list[DeveloperComment] = []
    lines = content.split("\n")
    relative = filepath.replace(base_path, "").lstrip("/\\") if base_path else filepath
    seen_urls: set[str] = set()

    # Extract full URLs
    for match in URL_PATTERN.finditer(content):
        url = match.group(0).rstrip(".,;)]}\"'`")
        if url in seen_urls or len(url) < 10:
            continue
        seen_urls.add(url)
        line_num = content.count("\n", 0, match.start()) + 1
        etype, risk = _classify_endpoint(url)
        endpoints.append(ExtractedEndpoint(
            url=url, file=relative, line_number=line_num,
            endpoint_type=etype, risk_level=risk,
            description=f"URL found in {relative}",
        ))

    # Extract API paths
    for match in PATH_PATTERN.finditer(content):
        path = match.group(1)
        if path in seen_urls:
            continue
        seen_urls.add(path)
        line_num = content.count("\n", 0, match.start()) + 1
        etype, risk = _classify_endpoint(path)
        endpoints.append(ExtractedEndpoint(
            url=path, file=relative, line_number=line_num,
            endpoint_type=etype, risk_level=risk,
            description=f"API path reference in {relative}",
        ))

    # Extract admin paths
    for match in ADMIN_PATHS.finditer(content):
        path = match.group(1)
        if path in seen_urls:
            continue
        seen_urls.add(path)
        line_num = content.count("\n", 0, match.start()) + 1
        etype, risk = _classify_endpoint(path)
        endpoints.append(ExtractedEndpoint(
            url=path, file=relative, line_number=line_num,
            endpoint_type=etype, risk_level=risk,
            description=f"Sensitive path in {relative}",
            tags=["admin", "sensitive"],
        ))

    # Cloud metadata
    for match in CLOUD_METADATA.finditer(content):
        url = match.group(0)
        if url in seen_urls:
            continue
        seen_urls.add(url)
        line_num = content.count("\n", 0, match.start()) + 1
        endpoints.append(ExtractedEndpoint(
            url=url, file=relative, line_number=line_num,
            endpoint_type="cloud", risk_level="Critical",
            description="Cloud metadata endpoint — potential SSRF target",
            tags=["ssrf", "cloud-metadata"],
        ))

    # S3 Buckets
    for match in S3_BUCKET.finditer(content):
        bucket = match.group(1) or match.group(2)
        if not bucket or bucket in seen_urls:
            continue
        seen_urls.add(bucket)
        line_num = content.count("\n", 0, match.start()) + 1
        endpoints.append(ExtractedEndpoint(
            url=f"s3://{bucket}", file=relative, line_number=line_num,
            endpoint_type="cloud", risk_level="Medium",
            description=f"S3 bucket reference: {bucket}",
            tags=["aws", "s3"],
        ))

    # WebSocket URLs
    for match in WEBSOCKET_URL.finditer(content):
        url = match.group(0)
        if url in seen_urls:
            continue
        seen_urls.add(url)
        line_num = content.count("\n", 0, match.start()) + 1
        endpoints.append(ExtractedEndpoint(
            url=url, file=relative, line_number=line_num,
            endpoint_type="api", risk_level="Medium",
            description="WebSocket endpoint",
            tags=["websocket"],
        ))

    # HTTP method calls
    for match in HTTP_METHOD_CALL.finditer(content):
        method_match = re.search(r"\.(get|post|put|delete|patch|head|options)", match.group(0), re.I)
        method = method_match.group(1).upper() if method_match else None
        path = match.group(1)
        if path in seen_urls:
            continue
        seen_urls.add(path)
        line_num = content.count("\n", 0, match.start()) + 1
        etype, risk = _classify_endpoint(path)
        endpoints.append(ExtractedEndpoint(
            url=path, file=relative, line_number=line_num,
            endpoint_type=etype, risk_level=risk, http_method=method,
            description=f"{method or 'HTTP'} request to {path}",
        ))

    # Developer comments
    for line_num, line in enumerate(lines, 1):
        for comment_type, pattern, severity in COMMENT_PATTERNS:
            if pattern.search(line):
                comments.append(DeveloperComment(
                    file=relative, line_number=line_num,
                    comment_type=comment_type, content=line.strip()[:200],
                    severity=severity,
                ))
                break  # One match per line

    return endpoints, comments


def fingerprint_technology(content: str) -> TechFingerprint:
    """Identify technology stack from source code content."""
    fp = TechFingerprint()

    for name, pattern in FRAMEWORK_PATTERNS.items():
        if pattern.search(content):
            fp.frameworks.append(name)

    for name, pattern in DATABASE_PATTERNS.items():
        if pattern.search(content):
            fp.databases.append(name)

    for name, pattern in CLOUD_PATTERNS.items():
        if pattern.search(content):
            fp.cloud_providers.append(name)

    return fp


def scan_directory_endpoints(
    root: str,
    max_files: int = 50_000,
) -> AttackSurfaceReport:
    """
    Walk a directory tree and extract all endpoints, fingerprint technology,
    and mine developer comments.

    Returns a comprehensive AttackSurfaceReport.
    """
    report = AttackSurfaceReport()
    root_path = Path(root)
    scanned = 0

    all_content = ""  # Aggregate for tech fingerprinting
    type_counter: Counter[str] = Counter()
    risk_counter: Counter[str] = Counter()

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
            if len(content) > 10_000_000:
                continue

            endpoints, comments = scan_file_endpoints(content, str(fpath), str(root_path))
            report.endpoints.extend(endpoints)
            report.developer_comments.extend(comments)

            # Sample content for tech fingerprinting (first 500KB of each file)
            all_content += content[:500_000] + "\n"

            scanned += 1
        except (OSError, PermissionError):
            continue

    # Fingerprint technology from aggregated content
    report.tech_fingerprint = fingerprint_technology(all_content)

    # Extract internal hosts
    internal_hosts = set()
    for match in INTERNAL_DNS.finditer(all_content):
        internal_hosts.add(match.group(0))
    report.internal_hosts = sorted(internal_hosts)

    # Cloud resources
    cloud_resources = set()
    for match in S3_BUCKET.finditer(all_content):
        bucket = match.group(1) or match.group(2)
        if bucket:
            cloud_resources.add(f"s3://{bucket}")
    for match in AZURE_BLOB.finditer(all_content):
        cloud_resources.add(f"azure://{match.group(1)}")
    for match in GCP_STORAGE.finditer(all_content):
        cloud_resources.add(f"gs://{match.group(1)}")
    report.cloud_resources = sorted(cloud_resources)

    # Statistics
    for ep in report.endpoints:
        type_counter[ep.endpoint_type] += 1
        risk_counter[ep.risk_level] += 1

    report.total_endpoints = len(report.endpoints)
    report.endpoints_by_type = dict(type_counter)
    report.endpoints_by_risk = dict(risk_counter)

    # Summary
    report.summary = (
        f"Discovered {report.total_endpoints} endpoints across {scanned} files. "
        f"Frameworks: {', '.join(report.tech_fingerprint.frameworks) or 'None detected'}. "
        f"Databases: {', '.join(report.tech_fingerprint.databases) or 'None detected'}. "
        f"Cloud: {', '.join(report.tech_fingerprint.cloud_providers) or 'None detected'}. "
        f"Developer comments: {len(report.developer_comments)}. "
        f"Internal hosts: {len(report.internal_hosts)}. "
        f"Cloud resources: {len(report.cloud_resources)}."
    )

    return report
