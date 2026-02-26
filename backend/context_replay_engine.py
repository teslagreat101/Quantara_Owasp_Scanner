"""
Context Replay Engine
=====================
Preserves the full original HTTP request environment so that exploit
verification is executed under the same conditions as the original scan:

    headers · cookies · auth tokens · body structure · content-type
    CSRF tokens · origin/referer · request encoding

Without replay context, verification misses auth-gated vulnerabilities.
"""

from __future__ import annotations

import copy
import json
import logging
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Optional, Tuple
from urllib.parse import quote, urlencode, urlparse, parse_qs, urlunparse

logger = logging.getLogger(__name__)

# ── Headers that must be stripped before cloning (auto-recalculated) ─────────
_STRIP_HEADERS: frozenset[str] = frozenset({
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authorization",
    "te",
    "trailers",
    "upgrade",
    "host",           # will be set by aiohttp from URL
})

# ── Safe default headers to add when missing ─────────────────────────────────
_DEFAULT_HEADERS: Dict[str, str] = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Cache-Control": "no-cache",
}


# ═══════════════════════════════════════════════════════════════════════════════
# Data classes
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class RequestContext:
    """
    Captures the complete HTTP request environment from the original scan.
    Passed into verification so the engine can replay it exactly.
    """
    method: str = "GET"
    url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    body: Dict[str, Any] = field(default_factory=dict)
    raw_body: Optional[str] = None          # pre-serialised body string
    content_type: str = "application/x-www-form-urlencoded"
    auth_type: str = "none"                 # bearer | cookie | basic | none | apikey
    auth_token: Optional[str] = None
    api_key_header: Optional[str] = None   # e.g. "X-API-Key"
    vulnerable_param: str = "input"
    origin: Optional[str] = None
    referer: Optional[str] = None
    csrf_token: Optional[str] = None
    csrf_header: Optional[str] = None       # e.g. "X-CSRF-Token"

    @classmethod
    def from_finding(cls, finding: Dict[str, Any]) -> "RequestContext":
        """Build a RequestContext from a finding dict (scanner output format)."""
        ctx_raw = finding.get("request_context") or {}
        instance = cls(
            method=(ctx_raw.get("method") or finding.get("method") or "GET").upper(),
            url=ctx_raw.get("url") or finding.get("file") or finding.get("endpoint") or "",
            headers=dict(ctx_raw.get("headers") or {}),
            cookies=dict(ctx_raw.get("cookies") or {}),
            body=dict(ctx_raw.get("body") or {}),
            raw_body=ctx_raw.get("raw_body"),
            content_type=ctx_raw.get("content_type") or "application/x-www-form-urlencoded",
            auth_type=(ctx_raw.get("auth_type") or "none").lower(),
            auth_token=ctx_raw.get("auth_token"),
            api_key_header=ctx_raw.get("api_key_header"),
            vulnerable_param=finding.get("parameter") or ctx_raw.get("vulnerable_param") or "input",
            origin=ctx_raw.get("origin"),
            referer=ctx_raw.get("referer"),
            csrf_token=ctx_raw.get("csrf_token"),
            csrf_header=ctx_raw.get("csrf_header"),
        )
        return instance

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "RequestContext":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ReplayRequest:
    """
    The fully assembled request ready for execution.
    Returned by ContextReplayEngine.build_*() methods.
    """
    method: str
    url: str
    headers: Dict[str, str]
    cookies: Dict[str, str]
    body: Optional[Dict[str, Any]]          # form data
    json_body: Optional[Dict[str, Any]]     # JSON body
    raw_body: Optional[str]
    injected_param: Optional[str] = None
    injected_payload: Optional[str] = None


# ═══════════════════════════════════════════════════════════════════════════════
# Context Replay Engine
# ═══════════════════════════════════════════════════════════════════════════════

class ContextReplayEngine:
    """
    Assembles HTTP requests for verification by:
      1. Sanitising original headers
      2. Injecting payload ONLY into the vulnerable parameter
      3. Preserving all auth, cookies, CSRF, and encoding context
      4. Maintaining session continuity across repeated attempts
    """

    # ── Header management ─────────────────────────────────────────────────────

    def sanitize_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """
        Remove dangerous/conflicting headers; inject safe defaults for any missing.
        Auth headers are preserved.
        """
        cleaned: Dict[str, str] = {}
        for k, v in headers.items():
            if k.lower() not in _STRIP_HEADERS:
                cleaned[k] = v
        # Fill in safe defaults only where missing
        for k, v in _DEFAULT_HEADERS.items():
            if k.lower() not in {h.lower() for h in cleaned}:
                cleaned[k] = v
        return cleaned

    def build_auth_headers(self, ctx: RequestContext) -> Dict[str, str]:
        """Construct Authorization / API-key headers from context."""
        headers: Dict[str, str] = {}
        if ctx.auth_type == "bearer" and ctx.auth_token:
            headers["Authorization"] = f"Bearer {ctx.auth_token}"
        elif ctx.auth_type == "basic" and ctx.auth_token:
            headers["Authorization"] = f"Basic {ctx.auth_token}"
        elif ctx.auth_type == "apikey" and ctx.api_key_header and ctx.auth_token:
            headers[ctx.api_key_header] = ctx.auth_token
        if ctx.csrf_token and ctx.csrf_header:
            headers[ctx.csrf_header] = ctx.csrf_token
        if ctx.origin:
            headers["Origin"] = ctx.origin
        if ctx.referer:
            headers["Referer"] = ctx.referer
        return headers

    # ── Payload injection ─────────────────────────────────────────────────────

    def inject_payload(
        self,
        ctx: RequestContext,
        payload: str,
        param: Optional[str] = None,
    ) -> ReplayRequest:
        """
        Inject payload into ONLY the vulnerable parameter.

        GET/HEAD  → query string injection
        POST/PUT  → body injection (form or JSON, inferred from content_type)
        """
        param = param or ctx.vulnerable_param
        headers = self.sanitize_headers(copy.deepcopy(ctx.headers))
        headers.update(self.build_auth_headers(ctx))
        cookies = copy.deepcopy(ctx.cookies)

        url = ctx.url
        body: Optional[Dict[str, Any]] = None
        json_body: Optional[Dict[str, Any]] = None
        raw_body: Optional[str] = None

        method = ctx.method.upper()

        if method in ("GET", "HEAD", "DELETE", "OPTIONS"):
            # Inject into query string
            url = _inject_into_qs(ctx.url, param, payload)
        else:
            # Inject into body
            ct = ctx.content_type.lower()
            if "json" in ct:
                json_body = copy.deepcopy(ctx.body) if isinstance(ctx.body, dict) else {}
                json_body[param] = payload
                headers["Content-Type"] = "application/json"
            elif "xml" in ct:
                # XML body — inject into raw string if provided
                raw_body = ctx.raw_body or ""
                raw_body = raw_body.replace(f"<{param}>", f"<{param}>{payload}", 1) \
                    if f"<{param}>" in raw_body else raw_body
                raw_body += f"\n<!-- {param}={payload} -->"
                headers["Content-Type"] = "text/xml"
            else:
                # Default: form-urlencoded
                body = copy.deepcopy(ctx.body) if isinstance(ctx.body, dict) else {}
                body[param] = payload
                headers["Content-Type"] = "application/x-www-form-urlencoded"

        return ReplayRequest(
            method=method,
            url=url,
            headers=headers,
            cookies=cookies,
            body=body,
            json_body=json_body,
            raw_body=raw_body,
            injected_param=param,
            injected_payload=payload,
        )

    def build_baseline(self, ctx: RequestContext) -> ReplayRequest:
        """
        Build baseline request — no payload injection, original context preserved.
        """
        headers = self.sanitize_headers(copy.deepcopy(ctx.headers))
        headers.update(self.build_auth_headers(ctx))
        cookies = copy.deepcopy(ctx.cookies)

        body: Optional[Dict[str, Any]] = None
        json_body: Optional[Dict[str, Any]] = None
        ct = ctx.content_type.lower()

        if ctx.method.upper() not in ("GET", "HEAD", "DELETE", "OPTIONS"):
            if "json" in ct:
                json_body = copy.deepcopy(ctx.body) if isinstance(ctx.body, dict) else {}
                headers["Content-Type"] = "application/json"
            else:
                body = copy.deepcopy(ctx.body) if isinstance(ctx.body, dict) else {}
                headers["Content-Type"] = "application/x-www-form-urlencoded"

        return ReplayRequest(
            method=ctx.method.upper(),
            url=ctx.url,
            headers=headers,
            cookies=cookies,
            body=body,
            json_body=json_body,
            raw_body=ctx.raw_body,
        )

    def apply_updated_token(self, ctx: RequestContext, new_token: str) -> RequestContext:
        """Create a copy of ctx with a refreshed auth token."""
        updated = copy.deepcopy(ctx)
        updated.auth_token = new_token
        return updated


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _inject_into_qs(url: str, param: str, payload: str) -> str:
    """
    Inject (or replace) a parameter in the URL query string.
    Uses proper URL encoding to handle special characters.
    """
    try:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [payload]   # replace or add
        new_query = urlencode(qs, doseq=True)
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))
    except Exception:
        # Fallback: simple append
        sep = "&" if "?" in url else "?"
        return f"{url}{sep}{param}={quote(payload, safe='')}"


async def execute_replay_request(
    session: Any,
    req: "ReplayRequest",
    timeout: float = 10.0,
) -> Dict[str, Any]:
    """
    Execute a ReplayRequest against an aiohttp ClientSession.
    Returns a normalised response dict compatible with the verifier's _fetch().
    """
    import time
    t0 = time.monotonic()
    try:
        kwargs: Dict[str, Any] = {
            "allow_redirects": True,
            "cookies": req.cookies or {},
            "headers": req.headers or {},
        }
        if req.json_body is not None:
            kwargs["json"] = req.json_body
        elif req.body is not None:
            kwargs["data"] = req.body
        elif req.raw_body is not None:
            kwargs["data"] = req.raw_body

        resp = await session.request(req.method, req.url, **kwargs)
        body = await resp.text(errors="replace")
        elapsed = (time.monotonic() - t0) * 1000
        return {
            "status": resp.status,
            "length": len(body),
            "body": body[:4000],
            "headers": dict(resp.headers),
            "elapsed_ms": elapsed,
            "cookies": {k: v.value for k, v in resp.cookies.items()},
        }
    except Exception as exc:
        elapsed = (time.monotonic() - t0) * 1000
        return {
            "status": 0,
            "length": 0,
            "body": "",
            "headers": {},
            "elapsed_ms": elapsed,
            "cookies": {},
            "error": str(exc)[:300],
        }


# ── Singleton ─────────────────────────────────────────────────────────────────

_replay_engine: Optional[ContextReplayEngine] = None


def get_replay_engine() -> ContextReplayEngine:
    global _replay_engine
    if _replay_engine is None:
        _replay_engine = ContextReplayEngine()
    return _replay_engine
