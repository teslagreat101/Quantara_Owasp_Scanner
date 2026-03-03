"""
Quantara Attack Surface Discovery — Intelligent Web Crawler
============================================================

Phase 1 of the Quantara enterprise scanner pipeline.

Capabilities:
  - Recursive BFS/DFS crawling up to configurable depth
  - JavaScript endpoint extraction (fetch, axios, XMLHttpRequest, route defs)
  - Form/input/parameter discovery (HTML form parsing)
  - Hidden route probing (common admin/debug/config paths)
  - API schema auto-discovery (OpenAPI/Swagger/GraphQL introspection)
  - Sitemap.xml + robots.txt parsing (treats Disallow as high-value targets)
  - Endpoint graph model for scan orchestration
  - Full scope enforcement (only crawl in-scope domains)

Architecture:
  QuantaraCrawler
      ├─ _fetch()           — async HTTP fetch with retries
      ├─ _extract_links()   — anchor/form/script/meta/CSS link extraction
      ├─ _extract_js_endpoints() — regex-based JS route extraction
      ├─ _extract_forms()   — form/input parameter extraction
      ├─ _probe_hidden()    — wordlist-based hidden path probing
      ├─ _fetch_robots()    — robots.txt disallow path collection
      ├─ _fetch_sitemap()   — sitemap.xml URL collection
      └─ _discover_api_schema() — OpenAPI/Swagger/GraphQL discovery

  ScanGraph — lightweight endpoint graph (nodes=endpoints, edges=links)
"""

from __future__ import annotations

import asyncio
import logging
import re
import urllib.parse
from collections import defaultdict, deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any, Optional
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs, urlencode

logger = logging.getLogger("owasp_scanner.quantara_crawler")

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_MAX_DEPTH = 3
DEFAULT_MAX_URLS = 300
DEFAULT_TIMEOUT = 12.0
DEFAULT_MAX_CONCURRENT = 8
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (compatible; Quantara/1.0-Crawler; +https://quantara.security)"
)

# Common admin/config/debug paths to probe
HIDDEN_PATH_WORDLIST = [
    # Admin interfaces
    "/admin", "/admin/", "/administrator", "/admin/login", "/admin/dashboard",
    "/wp-admin", "/wp-admin/", "/cpanel", "/phpmyadmin", "/adminer",
    # Config / secrets
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/config.php", "/config.js", "/config.json", "/config.yaml", "/config.yml",
    "/settings.py", "/settings.php", "/app/config", "/application.properties",
    "/web.config", "/appsettings.json", "/.aws/credentials", "/.git/config",
    # API / docs
    "/api", "/api/v1", "/api/v2", "/api/v3", "/graphql", "/gql",
    "/swagger", "/swagger-ui", "/swagger-ui.html", "/swagger.json",
    "/openapi.json", "/openapi.yaml", "/api-docs", "/v1/api-docs",
    "/redoc", "/docs", "/api/docs",
    # Debug / status
    "/debug", "/debug/", "/server-status", "/server-info",
    "/_profiler", "/_debug_toolbar", "/phpinfo.php", "/info.php",
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/beans",
    "/metrics", "/health", "/healthz", "/ready", "/readyz",
    "/status", "/_health",
    # Backup / source
    "/backup", "/backup.zip", "/backup.tar.gz", "/backup.sql",
    "/db.sql", "/dump.sql", "/database.sql",
    "/.git", "/.git/HEAD", "/.svn", "/.hg",
    "/index.php.bak", "/index.html.bak", "/index.bak",
    # Misc
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/security.txt", "/.well-known/security.txt",
    "/trace", "/TRACE",
]

# JavaScript endpoint extraction patterns
_JS_ENDPOINT_PATTERNS = [
    # fetch("...") / fetch('...')
    re.compile(r"""fetch\s*\(\s*['"]((?:https?://[^'"]+|/[^'"]*)[^'"]*)['"]\s*""", re.I),
    # axios.get/post/put/delete("...")
    re.compile(r"""axios\s*\.\s*(?:get|post|put|patch|delete|request)\s*\(\s*['"]((?:https?://[^'"]+|/[^'"]*)[^'"]*)['"]\s*""", re.I),
    # $.ajax({ url: "..." })
    re.compile(r"""(?:url|URL)\s*:\s*['"]((?:https?://[^'"]+|/[^'"]+)[^'"]*)['"]\s*""", re.I),
    # XMLHttpRequest open("...", "...")
    re.compile(r"""\.open\s*\(\s*['"]\w+['"]\s*,\s*['"]((?:https?://[^'"]+|/[^'"]+)[^'"]*)['"]\s*""", re.I),
    # Express-style routes: app.get("/path", ...) / router.post("/path", ...)
    re.compile(r"""(?:app|router)\s*\.\s*(?:get|post|put|patch|delete|use|all)\s*\(\s*['"]((?:/[^'"]*)[^'"]*)['"]\s*""", re.I),
    # Next.js / React Router paths
    re.compile(r"""(?:path|href|to|from)\s*[:=]\s*['"]((?:/[^'"]{2,})[^'"]*)['"]\s*""", re.I),
    # API base URL pattern: "/api/v1/..."
    re.compile(r"""['"]((?:/api/[^'"]{2,})[^'"]*)['"]\s*""", re.I),
    # href in strings
    re.compile(r"""href\s*[:=]\s*['"]((?:https?://[^'"]+|/[^'"]+)[^'"]*)['"]\s*""", re.I),
]

# GraphQL introspection query
_GRAPHQL_INTROSPECTION = """{"query":"query{__schema{types{name}}}"}"""

_OPENAPI_PATHS = [
    "/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml",
    "/api-docs", "/v1/api-docs", "/v2/api-docs", "/api/swagger.json",
    "/api/openapi.json", "/docs/swagger.json",
]

_GRAPHQL_PATHS = [
    "/graphql", "/gql", "/api/graphql", "/v1/graphql", "/graphiql",
    "/playground",
]


# ─────────────────────────────────────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DiscoveredEndpoint:
    """A single endpoint discovered during crawling."""
    url: str
    method: str = "GET"
    params: list[str] = field(default_factory=list)      # query/form param names
    source: str = "crawl"                                  # crawl / js / form / probe / sitemap / robots / api_schema
    depth: int = 0
    content_type: str = ""
    status_code: int = 0
    response_size: int = 0
    is_interesting: bool = False                           # admin, debug, config, etc.
    tags: list[str] = field(default_factory=list)          # graphql, api, admin, auth, etc.
    forms: list[dict] = field(default_factory=list)        # extracted form objects

    def __hash__(self):
        return hash(self.url + self.method)

    def __eq__(self, other):
        return self.url == other.url and self.method == other.method


@dataclass
class ScanGraph:
    """
    Lightweight endpoint graph.

    nodes: url → DiscoveredEndpoint
    edges: src_url → set of dst_url (links/forms discovered from src)
    param_map: url → set of param names observed
    """
    nodes: dict[str, DiscoveredEndpoint] = field(default_factory=dict)
    edges: dict[str, set] = field(default_factory=lambda: defaultdict(set))
    param_map: dict[str, set] = field(default_factory=lambda: defaultdict(set))
    technologies: list[str] = field(default_factory=list)
    api_schemas: list[dict] = field(default_factory=list)

    def add_endpoint(self, ep: DiscoveredEndpoint) -> None:
        if ep.url not in self.nodes:
            self.nodes[ep.url] = ep
        for p in ep.params:
            self.param_map[ep.url].add(p)

    def add_edge(self, src: str, dst: str) -> None:
        self.edges[src].add(dst)

    def all_urls(self) -> list[str]:
        return list(self.nodes.keys())

    def all_endpoints(self) -> list[DiscoveredEndpoint]:
        return list(self.nodes.values())

    def interesting_endpoints(self) -> list[DiscoveredEndpoint]:
        return [ep for ep in self.nodes.values() if ep.is_interesting]

    def to_dict(self) -> dict:
        return {
            "total_endpoints": len(self.nodes),
            "interesting_count": len(self.interesting_endpoints()),
            "api_schemas_found": len(self.api_schemas),
            "endpoints": [
                {
                    "url": ep.url, "method": ep.method, "source": ep.source,
                    "depth": ep.depth, "params": ep.params, "tags": ep.tags,
                    "is_interesting": ep.is_interesting, "status_code": ep.status_code,
                }
                for ep in self.nodes.values()
            ],
            "edges": {k: list(v) for k, v in self.edges.items()},
        }


# ─────────────────────────────────────────────────────────────────────────────
# HTML Parser — link, form, and script extraction
# ─────────────────────────────────────────────────────────────────────────────

class _HTMLLinkParser(HTMLParser):
    """Extract all links, forms, and script sources from an HTML page."""

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links: list[str] = []
        self.forms: list[dict] = []
        self.script_srcs: list[str] = []
        self._current_form: Optional[dict] = None

    def handle_starttag(self, tag: str, attrs: list[tuple]):
        attrs_dict = dict(attrs)
        tag = tag.lower()

        if tag == "a":
            href = attrs_dict.get("href", "")
            if href:
                resolved = self._resolve(href)
                if resolved:
                    self.links.append(resolved)

        elif tag == "form":
            self._current_form = {
                "action": self._resolve(attrs_dict.get("action", self.base_url)) or self.base_url,
                "method": (attrs_dict.get("method", "GET") or "GET").upper(),
                "inputs": [],
                "source": "form",
            }

        elif tag in ("input", "select", "textarea") and self._current_form is not None:
            name = attrs_dict.get("name") or attrs_dict.get("id") or ""
            input_type = attrs_dict.get("type", "text")
            if name:
                self._current_form["inputs"].append({
                    "name": name, "type": input_type,
                    "value": attrs_dict.get("value", ""),
                })

        elif tag == "script":
            src = attrs_dict.get("src", "")
            if src:
                resolved = self._resolve(src)
                if resolved:
                    self.script_srcs.append(resolved)

        elif tag == "link":
            rel = attrs_dict.get("rel", "")
            href = attrs_dict.get("href", "")
            if href and rel in ("stylesheet", "preload", "prefetch", "canonical"):
                resolved = self._resolve(href)
                if resolved:
                    self.links.append(resolved)

        elif tag in ("iframe", "frame"):
            src = attrs_dict.get("src", "")
            if src:
                resolved = self._resolve(src)
                if resolved:
                    self.links.append(resolved)

        elif tag == "meta":
            http_equiv = (attrs_dict.get("http-equiv") or "").lower()
            if http_equiv == "refresh":
                content = attrs_dict.get("content", "")
                m = re.search(r"url\s*=\s*(.+)", content, re.I)
                if m:
                    resolved = self._resolve(m.group(1).strip().strip("'\""))
                    if resolved:
                        self.links.append(resolved)

    def handle_endtag(self, tag: str):
        if tag.lower() == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

    def _resolve(self, href: str) -> Optional[str]:
        if not href:
            return None
        href = href.strip()
        # Skip non-HTTP schemes
        if href.startswith(("#", "javascript:", "mailto:", "tel:", "data:", "void")):
            return None
        try:
            return urljoin(self.base_url, href)
        except Exception:
            return None


# ─────────────────────────────────────────────────────────────────────────────
# Quantara Crawler
# ─────────────────────────────────────────────────────────────────────────────

class QuantaraCrawler:
    """
    Enterprise-grade recursive web crawler for attack surface discovery.

    Usage:
        crawler = QuantaraCrawler(base_url="https://example.com",
                                   max_depth=3, max_urls=300)
        graph = asyncio.run(crawler.crawl())
        print(graph.to_dict())
    """

    def __init__(
        self,
        base_url: str,
        max_depth: int = DEFAULT_MAX_DEPTH,
        max_urls: int = DEFAULT_MAX_URLS,
        timeout: float = DEFAULT_TIMEOUT,
        max_concurrent: int = DEFAULT_MAX_CONCURRENT,
        user_agent: str = DEFAULT_USER_AGENT,
        follow_redirects: bool = True,
        probe_hidden: bool = True,
        extract_js: bool = True,
        discover_api: bool = True,
        scope_hosts: Optional[list[str]] = None,  # if None, auto-derive from base_url
        auth_headers: Optional[dict] = None,
        cookies: Optional[dict] = None,
        extra_headers: Optional[dict] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.user_agent = user_agent
        self.follow_redirects = follow_redirects
        self.probe_hidden = probe_hidden
        self.extract_js = extract_js
        self.discover_api = discover_api
        self.auth_headers = auth_headers or {}
        self.cookies = cookies or {}
        self.extra_headers = extra_headers or {}

        parsed = urlparse(base_url)
        self._base_scheme = parsed.scheme
        self._base_host = parsed.netloc

        # Derive in-scope hosts
        if scope_hosts:
            self._scope_hosts = set(scope_hosts)
        else:
            hostname = parsed.hostname or ""
            self._scope_hosts = {self._base_host}
            # Also allow www variant
            if hostname.startswith("www."):
                self._scope_hosts.add(hostname[4:])
            else:
                self._scope_hosts.add(f"www.{hostname}")

        self._visited: set[str] = set()
        self._graph = ScanGraph()
        self._semaphore: Optional[asyncio.Semaphore] = None

    # ── Public entry point ───────────────────────────────────────────────────

    def crawl(self) -> ScanGraph:
        """Synchronous entry point. Returns populated ScanGraph."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(lambda: asyncio.run(self._crawl_async()))
                    return future.result(timeout=120)
            else:
                return loop.run_until_complete(self._crawl_async())
        except Exception:
            return asyncio.run(self._crawl_async())

    async def _crawl_async(self) -> ScanGraph:
        """Async crawl pipeline."""
        self._semaphore = asyncio.Semaphore(self.max_concurrent)

        try:
            import httpx
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=self.follow_redirects,
                headers=self._build_headers(),
                cookies=self.cookies,
                verify=False,
            ) as client:
                self._client = client

                # Phase 1: Fetch robots.txt and sitemap.xml
                await self._fetch_robots()
                await self._fetch_sitemap()

                # Phase 2: BFS crawl starting from base URL
                await self._bfs_crawl(self.base_url)

                # Phase 3: Probe hidden paths (concurrent)
                if self.probe_hidden:
                    await self._probe_hidden_paths()

                # Phase 4: Discover API schemas
                if self.discover_api:
                    await self._discover_api_schema()

        except ImportError:
            logger.warning("httpx not available; using requests fallback for crawler")
            await self._crawl_sync_fallback()

        logger.info(
            f"[quantara_crawler] Crawl complete: {len(self._graph.nodes)} endpoints, "
            f"{len(self._graph.interesting_endpoints())} interesting"
        )
        return self._graph

    # ── BFS Crawl ───────────────────────────────────────────────────────────

    async def _bfs_crawl(self, start_url: str) -> None:
        """Breadth-first crawl from start_url."""
        queue: deque[tuple[str, int]] = deque([(start_url, 0)])

        while queue and len(self._visited) < self.max_urls:
            url, depth = queue.popleft()
            url = self._normalize_url(url)

            if not url or url in self._visited or not self._in_scope(url):
                continue
            if depth > self.max_depth:
                continue

            self._visited.add(url)

            # Fetch page
            content, status, content_type = await self._fetch(url)
            if content is None:
                continue

            # Build endpoint record
            ep = DiscoveredEndpoint(
                url=url,
                method="GET",
                source="crawl",
                depth=depth,
                status_code=status,
                content_type=content_type,
                response_size=len(content),
                is_interesting=self._is_interesting(url),
                tags=self._infer_tags(url, content_type),
            )
            self._graph.add_endpoint(ep)

            if status not in (200, 201, 301, 302, 304):
                continue

            is_html = "html" in content_type.lower()
            is_js = "javascript" in content_type.lower() or url.endswith(".js")

            # Extract links from HTML
            if is_html:
                links, forms, script_srcs = self._parse_html(url, content)

                # Add discovered links to queue
                for link in links:
                    norm = self._normalize_url(link)
                    if norm and norm not in self._visited and self._in_scope(norm):
                        queue.append((norm, depth + 1))
                        self._graph.add_edge(url, norm)

                # Process forms
                for form in forms:
                    form_ep = DiscoveredEndpoint(
                        url=form["action"],
                        method=form.get("method", "GET"),
                        params=[inp["name"] for inp in form.get("inputs", [])],
                        source="form",
                        depth=depth,
                        is_interesting=self._is_interesting(form["action"]),
                        tags=["form"] + self._infer_tags(form["action"], ""),
                        forms=[form],
                    )
                    self._graph.add_endpoint(form_ep)
                    ep.forms.extend(forms)

                # Fetch and analyze inline JS + external JS files
                if self.extract_js:
                    js_endpoints = self._extract_js_endpoints(content, url)
                    for js_ep in js_endpoints:
                        norm = self._normalize_url(js_ep)
                        if norm and norm not in self._visited and self._in_scope(norm):
                            queue.append((norm, depth + 1))
                            self._graph.add_edge(url, norm)

                    # Fetch external JS files
                    for js_src in script_srcs:
                        if js_src not in self._visited and self._in_scope(js_src):
                            js_content, _, _ = await self._fetch(js_src)
                            if js_content:
                                self._visited.add(js_src)
                                js_eps = self._extract_js_endpoints(js_content, js_src)
                                for js_ep in js_eps:
                                    norm = self._normalize_url(js_ep)
                                    if norm and norm not in self._visited and self._in_scope(norm):
                                        queue.append((norm, depth + 1))
                                        self._graph.add_edge(js_src, norm)
                                        js_endpoint = DiscoveredEndpoint(
                                            url=norm, method="GET",
                                            source="js",
                                            depth=depth + 1,
                                            is_interesting=self._is_interesting(norm),
                                            tags=["js-extracted"] + self._infer_tags(norm, ""),
                                        )
                                        self._graph.add_endpoint(js_endpoint)

            elif is_js and self.extract_js:
                # Direct JS file — extract endpoints
                js_eps = self._extract_js_endpoints(content, url)
                for js_ep in js_eps:
                    norm = self._normalize_url(js_ep)
                    if norm and norm not in self._visited and self._in_scope(norm):
                        queue.append((norm, depth + 1))
                        self._graph.add_edge(url, norm)
                        js_endpoint = DiscoveredEndpoint(
                            url=norm, method="GET", source="js", depth=depth + 1,
                            is_interesting=self._is_interesting(norm),
                            tags=["js-extracted"] + self._infer_tags(norm, ""),
                        )
                        self._graph.add_endpoint(js_endpoint)

    # ── HTTP Fetch ───────────────────────────────────────────────────────────

    async def _fetch(self, url: str) -> tuple[Optional[str], int, str]:
        """Fetch URL, return (body_text, status_code, content_type)."""
        async with self._semaphore:
            try:
                resp = await self._client.get(url)
                ct = resp.headers.get("content-type", "")
                # Only decode text content
                if any(t in ct.lower() for t in ("text", "html", "json", "javascript", "xml")):
                    try:
                        body = resp.text
                    except Exception:
                        body = resp.content.decode("utf-8", errors="replace")
                else:
                    body = ""
                return body, resp.status_code, ct
            except Exception as e:
                logger.debug(f"[crawler] fetch failed {url}: {e}")
                return None, 0, ""

    async def _fetch_head(self, url: str) -> tuple[int, str]:
        """HEAD request for probing — returns (status, content_type)."""
        async with self._semaphore:
            try:
                resp = await self._client.head(url)
                return resp.status_code, resp.headers.get("content-type", "")
            except Exception:
                # Fallback to GET with limited body
                try:
                    resp = await self._client.get(url)
                    return resp.status_code, resp.headers.get("content-type", "")
                except Exception:
                    return 0, ""

    # ── robots.txt ───────────────────────────────────────────────────────────

    async def _fetch_robots(self) -> None:
        """Parse robots.txt — treat Disallow paths as high-value targets."""
        robots_url = f"{self._base_scheme}://{self._base_host}/robots.txt"
        content, status, _ = await self._fetch(robots_url)
        if not content or status != 200:
            return

        for line in content.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line[9:].strip().split("#")[0].strip()
                if path and path != "/":
                    full_url = f"{self._base_scheme}://{self._base_host}{path}"
                    ep = DiscoveredEndpoint(
                        url=full_url, method="GET", source="robots",
                        is_interesting=True,
                        tags=["robots-disallow", "high-value"],
                    )
                    self._graph.add_endpoint(ep)
                    logger.debug(f"[crawler] robots.txt disallow → {full_url}")
            elif line.lower().startswith("sitemap:"):
                sitemap_url = line[8:].strip()
                await self._parse_sitemap_content(sitemap_url)

    # ── Sitemap ──────────────────────────────────────────────────────────────

    async def _fetch_sitemap(self) -> None:
        """Parse sitemap.xml to extract all indexed URLs."""
        sitemap_url = f"{self._base_scheme}://{self._base_host}/sitemap.xml"
        await self._parse_sitemap_content(sitemap_url)

    async def _parse_sitemap_content(self, sitemap_url: str) -> None:
        content, status, _ = await self._fetch(sitemap_url)
        if not content or status != 200:
            return

        # Extract <loc> URLs
        for m in re.finditer(r"<loc>\s*([^<]+)\s*</loc>", content, re.I):
            url = m.group(1).strip()
            if self._in_scope(url):
                ep = DiscoveredEndpoint(
                    url=url, method="GET", source="sitemap",
                    is_interesting=self._is_interesting(url),
                    tags=self._infer_tags(url, ""),
                )
                self._graph.add_endpoint(ep)

        # Nested sitemap index
        for m in re.finditer(r"<sitemap>\s*<loc>\s*([^<]+)\s*</loc>", content, re.I):
            nested_url = m.group(1).strip()
            if nested_url != sitemap_url:
                await self._parse_sitemap_content(nested_url)

    # ── Hidden Path Probing ──────────────────────────────────────────────────

    async def _probe_hidden_paths(self) -> None:
        """Concurrently probe all hidden paths in the wordlist."""
        tasks = []
        for path in HIDDEN_PATH_WORDLIST:
            url = f"{self._base_scheme}://{self._base_host}{path}"
            if url not in self._visited:
                tasks.append(self._probe_single(url))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        found = sum(1 for r in results if r and not isinstance(r, Exception))
        logger.info(f"[crawler] Hidden path probe: {found}/{len(tasks)} found")

    async def _probe_single(self, url: str) -> Optional[DiscoveredEndpoint]:
        """Probe a single path — add to graph if interesting response."""
        status, content_type = await self._fetch_head(url)
        if status in (200, 201, 403, 401, 301, 302, 307, 308):
            ep = DiscoveredEndpoint(
                url=url,
                method="GET",
                source="probe",
                status_code=status,
                content_type=content_type,
                is_interesting=True,
                tags=self._infer_interesting_tags(url, status),
            )
            self._graph.add_endpoint(ep)
            logger.debug(f"[crawler] Hidden path: {status} {url}")
            return ep
        return None

    # ── API Schema Discovery ─────────────────────────────────────────────────

    async def _discover_api_schema(self) -> None:
        """Try to discover OpenAPI/Swagger/GraphQL schemas."""
        # OpenAPI / Swagger
        for path in _OPENAPI_PATHS:
            url = f"{self._base_scheme}://{self._base_host}{path}"
            content, status, ct = await self._fetch(url)
            if status == 200 and content:
                if "swagger" in content.lower() or "openapi" in content.lower() or '"paths"' in content:
                    schema = self._parse_openapi(content, url)
                    if schema:
                        self._graph.api_schemas.append(schema)
                        logger.info(f"[crawler] OpenAPI schema found: {url} ({len(schema.get('endpoints', []))} endpoints)")
                        # Add all discovered API endpoints to graph
                        for ep_data in schema.get("endpoints", []):
                            full_url = f"{self._base_scheme}://{self._base_host}{ep_data['path']}"
                            ep = DiscoveredEndpoint(
                                url=full_url,
                                method=ep_data.get("method", "GET"),
                                params=ep_data.get("params", []),
                                source="api_schema",
                                is_interesting=True,
                                tags=["openapi", "api"] + self._infer_tags(full_url, ""),
                            )
                            self._graph.add_endpoint(ep)

        # GraphQL
        for path in _GRAPHQL_PATHS:
            url = f"{self._base_scheme}://{self._base_host}{path}"
            content, status, ct = await self._fetch_graphql_introspection(url)
            if content:
                schema = self._parse_graphql_schema(content, url)
                if schema:
                    self._graph.api_schemas.append(schema)
                    ep = DiscoveredEndpoint(
                        url=url,
                        method="POST",
                        source="api_schema",
                        is_interesting=True,
                        tags=["graphql", "api"],
                    )
                    self._graph.add_endpoint(ep)
                    logger.info(f"[crawler] GraphQL found: {url} ({len(schema.get('types', []))} types)")

    async def _fetch_graphql_introspection(self, url: str) -> tuple[Optional[str], int, str]:
        """POST GraphQL introspection query."""
        async with self._semaphore:
            try:
                resp = await self._client.post(
                    url,
                    content=_GRAPHQL_INTROSPECTION,
                    headers={"Content-Type": "application/json"},
                )
                ct = resp.headers.get("content-type", "")
                if "json" in ct or "graphql" in ct:
                    return resp.text, resp.status_code, ct
                return None, resp.status_code, ct
            except Exception:
                return None, 0, ""

    def _parse_openapi(self, content: str, source_url: str) -> Optional[dict]:
        """Parse OpenAPI/Swagger JSON or YAML to extract endpoint paths."""
        try:
            import json
            data = json.loads(content)
        except Exception:
            try:
                import yaml
                data = yaml.safe_load(content)
            except Exception:
                return None

        if not isinstance(data, dict):
            return None

        endpoints = []
        paths = data.get("paths", {}) or {}
        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            for method in ("get", "post", "put", "patch", "delete", "head", "options"):
                if method in path_item:
                    op = path_item[method]
                    params = []
                    for param in (op.get("parameters") or []):
                        if isinstance(param, dict) and param.get("name"):
                            params.append(param["name"])
                    endpoints.append({
                        "path": path, "method": method.upper(),
                        "params": params,
                        "summary": (op.get("summary") or op.get("description") or ""),
                    })

        return {
            "source": source_url,
            "type": "openapi",
            "version": data.get("openapi") or data.get("swagger") or "unknown",
            "endpoints": endpoints,
        }

    def _parse_graphql_schema(self, content: str, source_url: str) -> Optional[dict]:
        """Parse GraphQL introspection response to extract types."""
        try:
            import json
            data = json.loads(content)
        except Exception:
            return None

        types_data = (
            data.get("data", {})
            .get("__schema", {})
            .get("types", [])
        )
        if not types_data:
            return None

        type_names = [t.get("name", "") for t in types_data if not (t.get("name") or "").startswith("__")]
        return {
            "source": source_url,
            "type": "graphql",
            "types": type_names,
        }

    # ── JS Endpoint Extraction ───────────────────────────────────────────────

    def _extract_js_endpoints(self, js_content: str, base_url: str) -> list[str]:
        """Extract API endpoints from JavaScript source."""
        found = []
        for pattern in _JS_ENDPOINT_PATTERNS:
            for m in pattern.finditer(js_content):
                raw = m.group(1).strip()
                # Skip obviously templated strings
                if "${" in raw or "{{" in raw:
                    continue
                # Skip very short or clearly not-paths
                if len(raw) < 3:
                    continue
                # Resolve relative paths
                if raw.startswith("/"):
                    parsed = urlparse(base_url)
                    raw = f"{parsed.scheme}://{parsed.netloc}{raw}"
                elif not raw.startswith("http"):
                    raw = urljoin(base_url, raw)
                found.append(raw)

        return list(set(found))

    # ── HTML Parsing ─────────────────────────────────────────────────────────

    def _parse_html(self, url: str, content: str) -> tuple[list[str], list[dict], list[str]]:
        """Parse HTML to extract links, forms, and script sources."""
        parser = _HTMLLinkParser(url)
        try:
            parser.feed(content)
        except Exception:
            pass
        return parser.links, parser.forms, parser.script_srcs

    # ── Scope & Classification ───────────────────────────────────────────────

    def _in_scope(self, url: str) -> bool:
        """Check if URL is in scope (same domain family)."""
        try:
            parsed = urlparse(url)
            host = parsed.netloc.lower()
            # Allow same host or configured scope hosts
            return host in self._scope_hosts or any(
                host.endswith(f".{s}") or host == s
                for s in self._scope_hosts
            )
        except Exception:
            return False

    def _normalize_url(self, url: str) -> Optional[str]:
        """Normalize URL: strip fragments, sort query params, lowercase scheme/host."""
        if not url:
            return None
        try:
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https"):
                return None
            # Strip fragment
            normalized = parsed._replace(fragment="")
            # Normalize scheme + host to lowercase
            normalized = normalized._replace(
                scheme=parsed.scheme.lower(),
                netloc=parsed.netloc.lower(),
            )
            return urlunparse(normalized)
        except Exception:
            return None

    def _is_interesting(self, url: str) -> bool:
        """True if URL path looks like an admin, config, backup, or API endpoint."""
        path = urlparse(url).path.lower()
        interesting_patterns = [
            "/admin", "/administrator", "/login", "/auth", "/oauth",
            "/api/", "/v1/", "/v2/", "/graphql", "/gql",
            "/.env", "/config", "/backup", "/.git", "/.svn",
            "/debug", "/phpinfo", "/server-status", "/actuator",
            "/swagger", "/openapi", "/wp-admin", "/phpmyadmin",
            "/secret", "/password", "/token", "/key",
        ]
        return any(p in path for p in interesting_patterns)

    def _infer_tags(self, url: str, content_type: str) -> list[str]:
        """Infer semantic tags for an endpoint."""
        tags = []
        path = urlparse(url).path.lower()
        ct = content_type.lower()

        if "/api/" in path or "/graphql" in path or "json" in ct:
            tags.append("api")
        if "/admin" in path or "/dashboard" in path:
            tags.append("admin")
        if "/login" in path or "/auth" in path or "/oauth" in path:
            tags.append("auth")
        if "graphql" in path or "gql" in path:
            tags.append("graphql")
        if path.endswith((".js", ".jsx", ".ts", ".tsx")) or "javascript" in ct:
            tags.append("javascript")
        if path.endswith((".json", ".yaml", ".yml")) or "json" in ct:
            tags.append("config")
        if any(p in path for p in ("/backup", "/.git", "/.env", "/.svn")):
            tags.append("sensitive")
        return tags

    def _infer_interesting_tags(self, url: str, status: int) -> list[str]:
        """Tags for probed paths based on status code."""
        tags = self._infer_tags(url, "")
        if status == 403:
            tags.append("forbidden-indicates-exists")
        elif status == 401:
            tags.append("auth-required")
        elif status == 200:
            tags.append("accessible")
        return tags + ["probe-result"]

    # ── Headers ─────────────────────────────────────────────────────────────

    def _build_headers(self) -> dict:
        headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
        headers.update(self.auth_headers)
        headers.update(self.extra_headers)
        return headers

    # ── Sync fallback ────────────────────────────────────────────────────────

    async def _crawl_sync_fallback(self) -> None:
        """Fallback: limited crawl using requests (no async)."""
        try:
            import requests
            session = requests.Session()
            session.headers.update(self._build_headers())
            session.cookies.update(self.cookies)

            queue = deque([(self.base_url, 0)])
            while queue and len(self._visited) < min(self.max_urls, 50):
                url, depth = queue.popleft()
                url = self._normalize_url(url)
                if not url or url in self._visited or not self._in_scope(url):
                    continue
                self._visited.add(url)

                try:
                    resp = session.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
                    ct = resp.headers.get("content-type", "")
                    ep = DiscoveredEndpoint(
                        url=url, method="GET", source="crawl", depth=depth,
                        status_code=resp.status_code, content_type=ct,
                        response_size=len(resp.content),
                        is_interesting=self._is_interesting(url),
                        tags=self._infer_tags(url, ct),
                    )
                    self._graph.add_endpoint(ep)
                    if "html" in ct.lower() and depth < self.max_depth:
                        links, forms, _ = self._parse_html(url, resp.text)
                        for link in links:
                            norm = self._normalize_url(link)
                            if norm and norm not in self._visited and self._in_scope(norm):
                                queue.append((norm, depth + 1))
                except Exception as e:
                    logger.debug(f"[crawler-sync] {url}: {e}")
        except ImportError:
            logger.warning("[crawler] Neither httpx nor requests available")


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def discover_attack_surface(
    url: str,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_urls: int = DEFAULT_MAX_URLS,
    probe_hidden: bool = True,
    extract_js: bool = True,
    discover_api: bool = True,
    auth_headers: Optional[dict] = None,
    cookies: Optional[dict] = None,
) -> ScanGraph:
    """
    Convenience function: crawl `url` and return a populated ScanGraph.

    Called by the orchestrator's pre-scan phase to build the endpoint map
    before running vulnerability templates.
    """
    crawler = QuantaraCrawler(
        base_url=url,
        max_depth=max_depth,
        max_urls=max_urls,
        probe_hidden=probe_hidden,
        extract_js=extract_js,
        discover_api=discover_api,
        auth_headers=auth_headers,
        cookies=cookies,
    )
    return crawler.crawl()


def graph_to_url_list(graph: ScanGraph) -> list[str]:
    """Extract a flat list of discovered URLs from a ScanGraph."""
    return graph.all_urls()


def graph_to_fuzz_targets(graph: ScanGraph) -> list[dict]:
    """
    Extract fuzzing targets: endpoints with parameters.
    Returns list of {"url": ..., "method": ..., "params": [...]} dicts.
    """
    targets = []
    for ep in graph.all_endpoints():
        if ep.params:
            targets.append({
                "url": ep.url,
                "method": ep.method,
                "params": ep.params,
                "source": ep.source,
                "tags": ep.tags,
            })
    return targets


# ─────────────────────────────────────────────────────────────────────────────
# Enterprise Integration Layer — added by enterprise refactor
# Extends the crawler with enterprise BaseScanner-compatible ScanTarget output
# and deep endpoint prioritization for the adaptive escalation engine.
# ─────────────────────────────────────────────────────────────────────────────
import logging as _cr_logging

_cr_logger = _cr_logging.getLogger("enterprise.scanner.crawler")


def graph_to_scan_targets(graph: ScanGraph) -> list[dict]:
    """
    Convert crawled ScanGraph endpoints to enterprise ScanTarget-compatible dicts.
    These can be passed directly to BaseScanner.scan() or the EnterpriseScheduler.

    Priority scoring:
    - Authenticated endpoints with params → HIGH (1)
    - Endpoints with params → NORMAL (2)
    - Authenticated, no params → NORMAL (2)
    - Static endpoints → BACKGROUND (4)
    """
    targets = []
    for ep in graph.all_endpoints():
        has_auth = any(
            tag in (ep.tags or [])
            for tag in ["authenticated", "admin", "api", "graphql"]
        )
        has_params = bool(ep.params)

        if has_auth and has_params:
            priority = 1   # HIGH
        elif has_params:
            priority = 2   # NORMAL
        elif has_auth:
            priority = 2   # NORMAL
        else:
            priority = 4   # BACKGROUND

        targets.append({
            "url": ep.url,
            "method": ep.method,
            "params": ep.params,
            "headers": ep.headers if hasattr(ep, "headers") else {},
            "source": ep.source,
            "tags": ep.tags,
            "priority": priority,
            "has_params": has_params,
            "has_auth": has_auth,
        })

    targets.sort(key=lambda t: t["priority"])
    _cr_logger.debug(f"graph_to_scan_targets: {len(targets)} targets extracted")
    return targets


def prioritize_attack_surface(graph: ScanGraph) -> dict:
    """
    Produce an enterprise attack surface prioritization report from a ScanGraph.
    Identifies highest-value targets for the adaptive escalation engine.
    """
    all_eps = graph.all_endpoints()
    high_value = [
        ep for ep in all_eps
        if ep.params and any(
            tag in (ep.tags or [])
            for tag in ["admin", "api", "authenticated", "graphql", "upload", "payment"]
        )
    ]
    param_rich = sorted(
        [ep for ep in all_eps if ep.params],
        key=lambda ep: len(ep.params),
        reverse=True,
    )[:20]

    return {
        "total_endpoints": len(all_eps),
        "endpoints_with_params": sum(1 for ep in all_eps if ep.params),
        "high_value_targets": len(high_value),
        "high_value_urls": [ep.url for ep in high_value[:10]],
        "top_param_rich": [
            {"url": ep.url, "params": ep.params}
            for ep in param_rich[:10]
        ],
        "fuzz_targets": graph_to_fuzz_targets(graph),
        "scan_targets": graph_to_scan_targets(graph),
    }
