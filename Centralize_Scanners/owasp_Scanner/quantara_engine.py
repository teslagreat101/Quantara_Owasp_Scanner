"""
Quantara Template Engine v2.0
=====================================

A production-grade YAML template execution engine powering Quantara Enterprise Scanner's
Quantara scanner. Supports the full Quantara template schema with async HTTP execution,
multi-mode fuzzing, and a comprehensive DSL evaluator.

Architecture:
  ┌─────────────────────────────────────────────────────────────┐
  │  TemplateLoader  ─→  QuantaraTemplate                        │
  │  VariableResolver  ─→  resolves {{BaseURL}}, {{randstr}}   │
  │  DSLEvaluator  ─→  handles contains(), regex(), etc.       │
  │  FuzzingEngine  ─→  sniper / clusterbomb payload modes     │
  │  HTTPEngine  ─→  async httpx with retry + timeout          │
  │  MatcherEngine  ─→  status / word / regex / dsl / binary   │
  │  ExtractorEngine  ─→  extracts named data from responses   │
  │  TemplateRunner  ─→  orchestrates per-template execution   │
  └─────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import itertools
import logging
import random
import re
import string
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs, urljoin

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

try:
    import requests as _requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

logger = logging.getLogger("owasp_scanner.quantara_engine")

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_TIMEOUT = 15.0          # seconds per request
MAX_CONCURRENT = 10             # max concurrent requests
MAX_PATHS_PER_TEMPLATE = 30     # cap on path variants
MAX_PAYLOADS_PER_FUZZ = 50      # cap on payloads per fuzz slot

SCANNER_UA = (
    "Mozilla/5.0 (compatible; Quantara/5.0; +https://security-research)"
)

INTERACTSH_PLACEHOLDER = "oast.fun"  # placeholder when interactsh not configured


# ─────────────────────────────────────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class QuantaraResponse:
    """Normalized HTTP response for matcher/extractor evaluation."""
    url: str
    status_code: int
    headers: dict[str, str]             # lowercase keys
    body: str
    raw: str                            # "HEADER\r\n\r\nBODY"
    duration_ms: float
    redirect_chain: list[str] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def header_str(self) -> str:
        """Headers as flat lowercase string for word/regex matching."""
        return "\n".join(f"{k}: {v}" for k, v in self.headers.items()).lower()

    @property
    def all_str(self) -> str:
        return self.header_str + "\n\n" + self.body


@dataclass
class TemplateMatch:
    """Result of running a template against a URL."""
    template_id: str
    template_name: str
    url: str
    matched_url: str
    severity: str
    tags: list[str]
    description: str
    reference: list[str]
    classification: dict
    matched: bool
    matched_content: str = ""
    extracted_values: dict[str, list[str]] = field(default_factory=dict)
    curl_command: str = ""
    matcher_name: str = ""
    owasp: str = ""
    cwe: str = ""


# ─────────────────────────────────────────────────────────────────────────────
# Template Data Structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class QuantaraMatcher:
    type: str                           # status, word, regex, dsl, binary
    part: str = "body"                  # body, header, all, status
    words: list[str] = field(default_factory=list)
    regex: list[str] = field(default_factory=list)
    status: list[int] = field(default_factory=list)
    dsl: list[str] = field(default_factory=list)
    binary: list[str] = field(default_factory=list)
    condition: str = "or"              # and / or
    negative: bool = False
    name: str = ""
    case_insensitive: bool = False
    encoding: str = ""


@dataclass
class QuantaraExtractor:
    type: str                           # regex, kval, json, xpath, dsl
    name: str = ""
    part: str = "body"
    regex: list[str] = field(default_factory=list)
    group: int = 0
    kval: list[str] = field(default_factory=list)
    json_path: list[str] = field(default_factory=list)
    xpath: list[str] = field(default_factory=list)
    dsl: list[str] = field(default_factory=list)
    internal: bool = False              # if True, result used for next request only


@dataclass
class QuantaraHTTPRequest:
    method: str = "GET"
    paths: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    raw: list[str] = field(default_factory=list)
    payloads: dict[str, list[str]] = field(default_factory=dict)
    fuzzing: list[dict] = field(default_factory=list)
    matchers: list[QuantaraMatcher] = field(default_factory=list)
    matchers_condition: str = "or"
    extractors: list[QuantaraExtractor] = field(default_factory=list)
    redirects: bool = True
    max_redirects: int = 10
    stop_at_first_match: bool = False
    attack: str = "sniper"              # sniper, clusterbomb, pitchfork, battering-ram
    pre_condition: list[dict] = field(default_factory=list)


@dataclass
class QuantaraTemplate:
    id: str
    name: str
    author: str = ""
    severity: str = "info"
    description: str = ""
    reference: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    classification: dict = field(default_factory=dict)
    variables: dict[str, Any] = field(default_factory=dict)
    http_requests: list[QuantaraHTTPRequest] = field(default_factory=list)
    owasp: str = ""
    cwe: str = ""
    metadata: dict = field(default_factory=dict)


# ─────────────────────────────────────────────────────────────────────────────
# YAML Template Loader
# ─────────────────────────────────────────────────────────────────────────────

class TemplateLoader:
    """Parse Quantara YAML templates into QuantaraTemplate objects."""

    @staticmethod
    def load_file(path: Path) -> Optional[QuantaraTemplate]:
        if not YAML_AVAILABLE:
            logger.warning("PyYAML not available; cannot load templates")
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if not data or not isinstance(data, dict):
                return None
            return TemplateLoader._parse(data, str(path))
        except Exception as e:
            logger.debug(f"Failed to load template {path}: {e}")
            return None

    @staticmethod
    def load_directory(directory: Path) -> list[QuantaraTemplate]:
        templates = []
        for yaml_file in sorted(directory.glob("*.yaml")):
            t = TemplateLoader.load_file(yaml_file)
            if t:
                templates.append(t)
        for yaml_file in sorted(directory.glob("*.yml")):
            t = TemplateLoader.load_file(yaml_file)
            if t:
                templates.append(t)
        return templates

    @staticmethod
    def _parse(data: dict, source: str = "") -> Optional[QuantaraTemplate]:
        template_id = str(data.get("id", "unknown"))
        info = data.get("info", {})
        if not isinstance(info, dict):
            info = {}

        # Extract classification
        classification = info.get("classification", {}) or {}
        cwe_list = classification.get("cwe-id", []) or []
        if isinstance(cwe_list, str):
            cwe_list = [cwe_list]
        owasp_list = classification.get("owasp-id", []) or []
        if isinstance(owasp_list, str):
            owasp_list = [owasp_list]

        cwe = ", ".join(cwe_list) if cwe_list else ""
        owasp = ", ".join(owasp_list) if owasp_list else _infer_owasp(template_id, info.get("tags", []))

        template = QuantaraTemplate(
            id=template_id,
            name=str(info.get("name", template_id)),
            author=str(info.get("author", "")),
            severity=str(info.get("severity", "info")).lower(),
            description=str(info.get("description", "")),
            reference=_to_list(info.get("reference", [])),
            tags=_to_list(info.get("tags", [])),
            classification=classification,
            variables=data.get("variables", {}) or {},
            owasp=owasp,
            cwe=cwe,
            metadata=info.get("metadata", {}) or {},
        )

        # Parse HTTP requests (supports both 'http' and 'requests' keys)
        http_data_list = data.get("http", data.get("requests", []))
        if isinstance(http_data_list, dict):
            http_data_list = [http_data_list]
        if not isinstance(http_data_list, list):
            http_data_list = []

        for http_data in http_data_list:
            req = TemplateLoader._parse_http_request(http_data)
            if req:
                template.http_requests.append(req)

        return template

    @staticmethod
    def _parse_http_request(data: dict) -> Optional[QuantaraHTTPRequest]:
        if not data or not isinstance(data, dict):
            return None

        req = QuantaraHTTPRequest(
            method=str(data.get("method", "GET")).upper(),
            redirects=bool(data.get("redirects", True)),
            max_redirects=int(data.get("max-redirects", 10)),
            stop_at_first_match=bool(data.get("stop-at-first-match", False)),
            attack=str(data.get("attack", "sniper")).lower(),
            matchers_condition=str(data.get("matchers-condition", "or")).lower(),
        )

        # Paths
        path_data = data.get("path", [])
        if isinstance(path_data, str):
            path_data = [path_data]
        req.paths = [str(p) for p in (path_data or [])][:MAX_PATHS_PER_TEMPLATE]

        # Raw HTTP requests
        raw_data = data.get("raw", [])
        if isinstance(raw_data, str):
            raw_data = [raw_data]
        req.raw = [str(r) for r in (raw_data or [])]

        # If we have raw requests, extract paths from them
        if req.raw and not req.paths:
            for raw_req in req.raw:
                first_line = raw_req.strip().split("\n")[0]
                parts = first_line.split()
                if len(parts) >= 2:
                    req.method = parts[0].strip()
                    # The path will be resolved with template variables later

        # Headers
        headers_data = data.get("headers", {}) or {}
        req.headers = {str(k): str(v) for k, v in headers_data.items()}

        # Body
        req.body = str(data.get("body", ""))

        # Payloads
        payloads_data = data.get("payloads", {}) or {}
        for key, val in payloads_data.items():
            if isinstance(val, list):
                req.payloads[str(key)] = [str(v) for v in val][:MAX_PAYLOADS_PER_FUZZ]
            elif isinstance(val, str):
                req.payloads[str(key)] = [val]

        # Fuzzing
        fuzzing_data = data.get("fuzzing", []) or []
        if isinstance(fuzzing_data, dict):
            fuzzing_data = [fuzzing_data]
        req.fuzzing = [f for f in fuzzing_data if isinstance(f, dict)]

        # Matchers
        matchers_data = data.get("matchers", []) or []
        if isinstance(matchers_data, dict):
            matchers_data = [matchers_data]
        for m_data in matchers_data:
            m = TemplateLoader._parse_matcher(m_data)
            if m:
                req.matchers.append(m)

        # Extractors
        extractors_data = data.get("extractors", []) or []
        if isinstance(extractors_data, dict):
            extractors_data = [extractors_data]
        for e_data in extractors_data:
            e = TemplateLoader._parse_extractor(e_data)
            if e:
                req.extractors.append(e)

        # Pre-conditions
        pre_cond = data.get("pre-condition", []) or []
        if isinstance(pre_cond, dict):
            pre_cond = [pre_cond]
        req.pre_condition = [p for p in pre_cond if isinstance(p, dict)]

        return req

    @staticmethod
    def _parse_matcher(data: dict) -> Optional[QuantaraMatcher]:
        if not data or not isinstance(data, dict):
            return None
        matcher_type = str(data.get("type", "")).lower()
        if not matcher_type:
            return None
        return QuantaraMatcher(
            type=matcher_type,
            part=str(data.get("part", "body")).lower(),
            words=_to_list(data.get("words", [])),
            regex=_to_list(data.get("regex", [])),
            status=[int(s) for s in _to_list(data.get("status", []))],
            dsl=_to_list(data.get("dsl", [])),
            binary=_to_list(data.get("binary", [])),
            condition=str(data.get("condition", "or")).lower(),
            negative=bool(data.get("negative", False)),
            name=str(data.get("name", "")),
            case_insensitive=bool(data.get("case-insensitive", False)),
            encoding=str(data.get("encoding", "")),
        )

    @staticmethod
    def _parse_extractor(data: dict) -> Optional[QuantaraExtractor]:
        if not data or not isinstance(data, dict):
            return None
        ext_type = str(data.get("type", "")).lower()
        if not ext_type:
            return None
        return QuantaraExtractor(
            type=ext_type,
            name=str(data.get("name", "")),
            part=str(data.get("part", "body")).lower(),
            regex=_to_list(data.get("regex", [])),
            group=int(data.get("group", 0)),
            kval=_to_list(data.get("kval", [])),
            json_path=_to_list(data.get("json", [])),
            dsl=_to_list(data.get("dsl", [])),
            internal=bool(data.get("internal", False)),
        )


# ─────────────────────────────────────────────────────────────────────────────
# Variable Resolver
# ─────────────────────────────────────────────────────────────────────────────

class VariableResolver:
    """Resolves Quantara template variables like {{BaseURL}}, {{Hostname}}, etc."""

    def __init__(self, base_url: str, extra_vars: dict = None):
        parsed = urlparse(base_url)
        hostname = parsed.hostname or ""
        port = parsed.port
        scheme = parsed.scheme or "https"

        # Root domain (tld+1)
        parts = hostname.split(".")
        rdn = ".".join(parts[-2:]) if len(parts) >= 2 else hostname

        self._vars = {
            "BaseURL":  base_url.rstrip("/"),
            "RootURL":  f"{scheme}://{parsed.netloc}",
            "Hostname": parsed.netloc,
            "Host":     parsed.netloc,
            "FQDN":     hostname,
            "RDN":      rdn,
            "Scheme":   scheme,
            "Port":     str(port) if port else ("443" if scheme == "https" else "80"),
            "Path":     parsed.path or "/",
            "interactsh-url": f"{_rand_str(8)}.{INTERACTSH_PLACEHOLDER}",
        }
        if extra_vars:
            self._vars.update(extra_vars)

    def resolve(self, text: str, payload_vars: dict = None) -> str:
        """Resolve all {{var}} and {{func(...)}} references in text."""
        all_vars = dict(self._vars)
        if payload_vars:
            all_vars.update(payload_vars)

        def replacer(m):
            expr = m.group(1).strip()
            # First check plain variable
            if expr in all_vars:
                return str(all_vars[expr])
            # Try function expressions like {{tolower(rand_base(5))}}
            try:
                return str(_eval_template_func(expr, all_vars))
            except Exception:
                return m.group(0)  # leave unreplaced on error

        return re.sub(r"\{\{([^}]+)\}\}", replacer, text)

    def get_var(self, name: str) -> str:
        return self._vars.get(name, "")


def _eval_template_func(expr: str, vars_: dict) -> str:
    """Evaluate simple inline template function expressions."""
    expr = expr.strip()

    # Nested: tolower(rand_base(5)) etc.
    # rand_base(N)
    m = re.match(r"rand_base\((\d+)\)", expr)
    if m:
        return _rand_str(int(m.group(1)))

    # randstr
    if expr == "randstr":
        return _rand_str(8)

    # tolower(...)
    m = re.match(r"tolower\((.+)\)$", expr)
    if m:
        inner = _eval_template_func(m.group(1), vars_)
        return inner.lower()

    # toupper(...)
    m = re.match(r"toupper\((.+)\)$", expr)
    if m:
        inner = _eval_template_func(m.group(1), vars_)
        return inner.upper()

    # base64(...)
    m = re.match(r"base64\((.+)\)$", expr)
    if m:
        inner = _eval_template_func(m.group(1), vars_)
        return base64.b64encode(inner.encode()).decode()

    # url_encode(...)
    m = re.match(r"url_encode\((.+)\)$", expr)
    if m:
        inner = _eval_template_func(m.group(1), vars_)
        return urllib.parse.quote(inner, safe="")

    # md5(...)
    m = re.match(r"md5\((.+)\)$", expr)
    if m:
        inner = _eval_template_func(m.group(1), vars_)
        return hashlib.md5(inner.encode()).hexdigest()

    # Variable reference
    if expr in vars_:
        return str(vars_[expr])

    return expr


# ─────────────────────────────────────────────────────────────────────────────
# DSL Evaluator
# ─────────────────────────────────────────────────────────────────────────────

class DSLEvaluator:
    """
    Evaluates Quantara DSL expressions against a response context.

    Supported functions:
      contains(a, b), regex(pattern, text), len(x), starts_with(a, prefix),
      ends_with(a, suffix), tolower(s), toupper(s), base64(s), base64_decode(s),
      url_encode(s), url_decode(s), md5(s), sha256(s), concat(...),
      to_number(s), to_string(x), rand_base(n)

    Supported variables:
      body, header, headers, status_code, all, duration
    """

    def __init__(self, response: QuantaraResponse, payload_vars: dict = None):
        self._resp = response
        self._payload_vars = payload_vars or {}

    def evaluate(self, expression: str) -> bool:
        """Evaluate a DSL expression and return bool result."""
        try:
            result = self._eval_expr(expression.strip())
            return bool(result)
        except Exception as e:
            logger.debug(f"DSL eval error on '{expression}': {e}")
            return False

    def _get_context(self) -> dict:
        ctx = {
            "body": self._resp.body,
            "header": self._resp.header_str,
            "headers": self._resp.header_str,
            "all": self._resp.all_str,
            "status_code": self._resp.status_code,
            "duration": self._resp.duration_ms / 1000.0,
            "content_length": len(self._resp.body),
            "response_time": self._resp.duration_ms / 1000.0,
        }
        ctx.update(self._payload_vars)
        return ctx

    def _eval_expr(self, expr: str) -> Any:
        """Recursively evaluate a DSL expression."""
        expr = expr.strip()
        ctx = self._get_context()

        # Handle logical operators: && and ||
        # Simple split on top-level && / ||
        for logical_op in [" && ", " || "]:
            parts = _split_logical(expr, logical_op)
            if len(parts) > 1:
                results = [bool(self._eval_expr(p.strip())) for p in parts]
                if logical_op == " && ":
                    return all(results)
                else:
                    return any(results)

        # String literals
        m = re.match(r"^'(.*)'$", expr) or re.match(r'^"(.*)"$', expr)
        if m:
            return m.group(1)

        # Integer literal
        if re.match(r"^\d+$", expr):
            return int(expr)

        # contains(a, b)
        m = re.match(r"^contains\((.+)\)$", expr, re.DOTALL)
        if m:
            args = _split_args(m.group(1))
            if len(args) == 2:
                a = self._eval_expr(args[0])
                b = self._eval_expr(args[1])
                return str(b).lower() in str(a).lower()

        # starts_with(a, prefix)
        m = re.match(r"^starts_with\((.+)\)$", expr, re.DOTALL)
        if m:
            args = _split_args(m.group(1))
            if len(args) == 2:
                return str(self._eval_expr(args[0])).startswith(str(self._eval_expr(args[1])))

        # ends_with(a, suffix)
        m = re.match(r"^ends_with\((.+)\)$", expr, re.DOTALL)
        if m:
            args = _split_args(m.group(1))
            if len(args) == 2:
                return str(self._eval_expr(args[0])).endswith(str(self._eval_expr(args[1])))

        # regex(pattern, text)
        m = re.match(r"^regex\((.+)\)$", expr, re.DOTALL)
        if m:
            args = _split_args(m.group(1))
            if len(args) == 2:
                pattern = str(self._eval_expr(args[0]))
                text = str(self._eval_expr(args[1]))
                try:
                    return bool(re.search(pattern, text, re.IGNORECASE))
                except re.error:
                    return False

        # len(x)
        m = re.match(r"^len\((.+)\)$", expr)
        if m:
            return len(str(self._eval_expr(m.group(1))))

        # tolower(s)
        m = re.match(r"^tolower\((.+)\)$", expr)
        if m:
            return str(self._eval_expr(m.group(1))).lower()

        # toupper(s)
        m = re.match(r"^toupper\((.+)\)$", expr)
        if m:
            return str(self._eval_expr(m.group(1))).upper()

        # base64(s)
        m = re.match(r"^base64\((.+)\)$", expr)
        if m:
            s = str(self._eval_expr(m.group(1)))
            return base64.b64encode(s.encode()).decode()

        # base64_decode(s)
        m = re.match(r"^base64_decode\((.+)\)$", expr)
        if m:
            s = str(self._eval_expr(m.group(1)))
            try:
                return base64.b64decode(s).decode("utf-8", errors="ignore")
            except Exception:
                return ""

        # url_encode(s)
        m = re.match(r"^url_encode\((.+)\)$", expr)
        if m:
            return urllib.parse.quote(str(self._eval_expr(m.group(1))), safe="")

        # url_decode(s)
        m = re.match(r"^url_decode\((.+)\)$", expr)
        if m:
            return urllib.parse.unquote(str(self._eval_expr(m.group(1))))

        # md5(s)
        m = re.match(r"^md5\((.+)\)$", expr)
        if m:
            s = str(self._eval_expr(m.group(1)))
            return hashlib.md5(s.encode()).hexdigest()

        # sha256(s)
        m = re.match(r"^sha256\((.+)\)$", expr)
        if m:
            s = str(self._eval_expr(m.group(1)))
            return hashlib.sha256(s.encode()).hexdigest()

        # to_number(s)
        m = re.match(r"^to_number\((.+)\)$", expr)
        if m:
            try:
                return int(str(self._eval_expr(m.group(1))))
            except ValueError:
                return 0

        # concat(a, b, ...)
        m = re.match(r"^concat\((.+)\)$", expr, re.DOTALL)
        if m:
            args = _split_args(m.group(1))
            return "".join(str(self._eval_expr(a)) for a in args)

        # Comparison operators: ==, !=, >=, <=, >, <
        for op in ["==", "!=", ">=", "<=", ">", "<"]:
            if op in expr:
                idx = expr.find(op)
                lhs = expr[:idx].strip()
                rhs = expr[idx + len(op):].strip()
                lval = self._eval_expr(lhs)
                rval = self._eval_expr(rhs)
                try:
                    lnum = float(lval) if not isinstance(lval, (int, float)) else lval
                    rnum = float(rval) if not isinstance(rval, (int, float)) else rval
                    if op == "==": return lnum == rnum
                    if op == "!=": return lnum != rnum
                    if op == ">=": return lnum >= rnum
                    if op == "<=": return lnum <= rnum
                    if op == ">":  return lnum > rnum
                    if op == "<":  return lnum < rnum
                except (TypeError, ValueError):
                    if op == "==": return str(lval) == str(rval)
                    if op == "!=": return str(lval) != str(rval)

        # Context variable lookup
        if expr in ctx:
            return ctx[expr]

        # Try numeric literal with decimals
        try:
            return float(expr)
        except ValueError:
            pass

        # Bare string
        return expr


# ─────────────────────────────────────────────────────────────────────────────
# Matcher Engine
# ─────────────────────────────────────────────────────────────────────────────

class MatcherEngine:
    """Apply Quantara matchers to a response."""

    def match_all(
        self,
        response: QuantaraResponse,
        matchers: list[QuantaraMatcher],
        condition: str,
        payload_vars: dict = None,
    ) -> tuple[bool, str, str]:
        """
        Apply all matchers and return (matched, matched_content, matcher_name).
        condition: 'and' requires ALL to match; 'or' requires ANY.
        """
        if not matchers:
            return True, "", ""

        results: list[tuple[bool, str, str]] = []
        for m in matchers:
            matched, content, name = self._apply_matcher(m, response, payload_vars or {})
            results.append((matched, content, name or m.name or m.type))

        if condition == "and":
            overall = all(r[0] for r in results)
        else:
            overall = any(r[0] for r in results)

        # Collect matched evidence
        evidence = [content for (matched, content, _) in results if matched and content]
        first_name = next((name for matched, _, name in results if matched), "")

        return overall, " | ".join(evidence[:3]), first_name

    def _apply_matcher(
        self,
        matcher: QuantaraMatcher,
        response: QuantaraResponse,
        payload_vars: dict,
    ) -> tuple[bool, str, str]:
        """Apply a single matcher and return (matched, evidence, name)."""
        result, evidence = False, ""

        target = self._get_target(matcher.part, response)

        if matcher.type == "status":
            result = response.status_code in matcher.status
            evidence = str(response.status_code) if result else ""

        elif matcher.type == "word":
            words = matcher.words
            flags = re.IGNORECASE if matcher.case_insensitive else 0
            if matcher.condition == "and":
                matched_words = []
                for w in words:
                    if re.search(re.escape(w), target, flags):
                        matched_words.append(w)
                result = len(matched_words) == len(words)
                evidence = " | ".join(matched_words[:3])
            else:
                for w in words:
                    if re.search(re.escape(w), target, flags):
                        result = True
                        evidence = w[:100]
                        break

        elif matcher.type == "regex":
            compiled_patterns = []
            for pattern in matcher.regex:
                try:
                    compiled_patterns.append(re.compile(pattern, re.IGNORECASE | re.DOTALL))
                except re.error:
                    continue

            if matcher.condition == "and":
                hits = []
                for cp in compiled_patterns:
                    m = cp.search(target)
                    if m:
                        hits.append(m.group(0)[:80])
                result = len(hits) == len(compiled_patterns)
                evidence = " | ".join(hits[:3])
            else:
                for cp in compiled_patterns:
                    m_hit = cp.search(target)
                    if m_hit:
                        result = True
                        evidence = m_hit.group(0)[:100]
                        break

        elif matcher.type == "dsl":
            evaluator = DSLEvaluator(response, payload_vars)
            if matcher.condition == "and":
                result = all(evaluator.evaluate(expr) for expr in matcher.dsl)
            else:
                result = any(evaluator.evaluate(expr) for expr in matcher.dsl)
            evidence = " | ".join(matcher.dsl[:2]) if result else ""

        elif matcher.type == "binary":
            body_bytes = response.body.encode("utf-8", errors="ignore")
            for hex_str in matcher.binary:
                try:
                    needle = bytes.fromhex(hex_str.replace(" ", ""))
                    if needle in body_bytes:
                        result = True
                        evidence = f"binary:{hex_str[:20]}"
                        break
                except ValueError:
                    continue

        # Apply negative flag
        if matcher.negative:
            result = not result
            if result:
                evidence = f"NOT: {evidence}"

        return result, evidence, matcher.name

    def _get_target(self, part: str, response: QuantaraResponse) -> str:
        part = (part or "body").lower()
        if part == "header":
            return response.header_str
        elif part == "all":
            return response.all_str
        elif part == "status":
            return str(response.status_code)
        else:  # body (default)
            return response.body


# ─────────────────────────────────────────────────────────────────────────────
# Extractor Engine
# ─────────────────────────────────────────────────────────────────────────────

class ExtractorEngine:
    """Extract named values from responses for template chaining or reporting."""

    def extract_all(
        self,
        response: QuantaraResponse,
        extractors: list[QuantaraExtractor],
        payload_vars: dict = None,
    ) -> dict[str, list[str]]:
        all_extracted: dict[str, list[str]] = {}
        for ext in extractors:
            values = self._apply_extractor(ext, response, payload_vars or {})
            if values:
                key = ext.name or ext.type
                all_extracted[key] = values
        return all_extracted

    def _apply_extractor(
        self,
        extractor: QuantaraExtractor,
        response: QuantaraResponse,
        payload_vars: dict,
    ) -> list[str]:
        target = self._get_target(extractor.part, response)
        results = []

        if extractor.type == "regex":
            for pattern in extractor.regex:
                try:
                    cp = re.compile(pattern, re.IGNORECASE | re.DOTALL)
                    for m in cp.finditer(target):
                        try:
                            val = m.group(extractor.group) if extractor.group else m.group(0)
                        except IndexError:
                            val = m.group(0)
                        if val:
                            results.append(val[:200])
                except re.error:
                    continue

        elif extractor.type == "kval":
            # Key-value extraction from headers
            for key in extractor.kval:
                val = response.headers.get(key.lower(), "")
                if val:
                    results.append(val)

        elif extractor.type == "dsl":
            evaluator = DSLEvaluator(response, payload_vars)
            for expr in extractor.dsl:
                try:
                    val = evaluator._eval_expr(expr)
                    if val:
                        results.append(str(val)[:200])
                except Exception:
                    pass

        return results

    def _get_target(self, part: str, response: QuantaraResponse) -> str:
        part = (part or "body").lower()
        if part == "header":
            return response.header_str
        elif part == "all":
            return response.all_str
        else:
            return response.body


# ─────────────────────────────────────────────────────────────────────────────
# Fuzzing Engine
# ─────────────────────────────────────────────────────────────────────────────

class FuzzingEngine:
    """
    Generate fuzzed URL/body/header variants from fuzzing configs.
    Supports: part=query|body|header|path|cookie, mode=single|replace
    """

    def generate_variants(
        self,
        original_url: str,
        fuzzing: list[dict],
        payloads: dict[str, list[str]],
        attack: str = "sniper",
    ) -> list[tuple[str, dict, str, dict]]:
        """
        Returns list of (fuzzed_url, extra_headers, fuzzed_body, payload_vars).
        """
        if not fuzzing or not payloads:
            return []

        variants = []
        parsed = urlparse(original_url)
        qs = parse_qs(parsed.query, keep_blank_values=True)

        for fuzz_config in fuzzing:
            part = str(fuzz_config.get("part", "query")).lower()
            fuzz_type = str(fuzz_config.get("type", "replace")).lower()
            mode = str(fuzz_config.get("mode", "single")).lower()
            fuzz_defs = fuzz_config.get("fuzz", []) or []
            keys_filter = fuzz_config.get("keys", []) or []  # filter by param key

            # Resolve fuzz templates to actual payloads
            resolved_payloads = self._resolve_fuzz_payloads(fuzz_defs, payloads)

            if part == "query":
                param_keys = list(qs.keys()) if qs else ["q", "id", "page", "search", "url"]
                if keys_filter:
                    param_keys = [k for k in param_keys if k in keys_filter]
                    if not param_keys:
                        param_keys = keys_filter[:5]  # add synthetic params

                for key in param_keys[:10]:
                    for payload in resolved_payloads[:MAX_PAYLOADS_PER_FUZZ]:
                        new_qs = dict(qs)
                        orig_val = new_qs.get(key, [""])[0]
                        if fuzz_type == "postfix":
                            new_qs[key] = [orig_val + str(payload)]
                        elif fuzz_type == "prefix":
                            new_qs[key] = [str(payload) + orig_val]
                        else:  # replace
                            new_qs[key] = [str(payload)]

                        new_query = urlencode(
                            {k: v[0] for k, v in new_qs.items()}, safe="'\"()!@#%"
                        )
                        new_parsed = parsed._replace(query=new_query)
                        fuzzed_url = urlunparse(new_parsed)
                        p_vars = {k: str(v) for k, v in payloads.items()
                                  if isinstance(v, list) and v}
                        p_vars[key] = str(payload)
                        variants.append((fuzzed_url, {}, "", p_vars))

            elif part == "header":
                header_names = keys_filter or ["X-Forwarded-For", "Referer", "Origin", "User-Agent"]
                for hdr in header_names[:5]:
                    for payload in resolved_payloads[:20]:
                        extra_headers = {hdr: str(payload)}
                        variants.append((original_url, extra_headers, "", {"header_payload": str(payload)}))

            elif part == "cookie":
                for payload in resolved_payloads[:20]:
                    extra_headers = {"Cookie": f"session={urllib.parse.quote(str(payload))}"}
                    variants.append((original_url, extra_headers, "", {"cookie_payload": str(payload)}))

            elif part == "body":
                for payload in resolved_payloads[:20]:
                    body = f"data={urllib.parse.quote(str(payload))}"
                    variants.append((original_url, {}, body, {"body_payload": str(payload)}))

        return variants[:MAX_PATHS_PER_TEMPLATE * 3]

    def _resolve_fuzz_payloads(self, fuzz_defs: list, payloads: dict) -> list[str]:
        """Resolve {{payloadname}} references in fuzz definitions."""
        resolved = []
        for fuzz_item in fuzz_defs:
            fuzz_str = str(fuzz_item)
            # Check if it references a payload variable like {{sqloscuridad}}
            m = re.match(r"^\{\{(\w+)\}\}$", fuzz_str.strip())
            if m:
                var_name = m.group(1)
                if var_name in payloads:
                    resolved.extend(payloads[var_name])
                else:
                    resolved.append(fuzz_str)
            else:
                resolved.append(fuzz_str)
        return resolved[:MAX_PAYLOADS_PER_FUZZ]


# ─────────────────────────────────────────────────────────────────────────────
# HTTP Engine
# ─────────────────────────────────────────────────────────────────────────────

class HTTPEngine:
    """Async HTTP engine for template execution."""

    def __init__(self, timeout: float = DEFAULT_TIMEOUT, verify_ssl: bool = False):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self._headers = {
            "User-Agent": SCANNER_UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }

    async def send(
        self,
        method: str,
        url: str,
        headers: dict = None,
        body: str = None,
        follow_redirects: bool = True,
        max_redirects: int = 5,
    ) -> Optional[QuantaraResponse]:
        """Send HTTP request and return QuantaraResponse."""
        merged_headers = dict(self._headers)
        if headers:
            merged_headers.update(headers)

        start = time.monotonic()
        redirect_chain = []

        if HTTPX_AVAILABLE:
            return await self._send_httpx(
                method, url, merged_headers, body, follow_redirects,
                max_redirects, redirect_chain, start
            )
        elif REQUESTS_AVAILABLE:
            return await self._send_requests_async(
                method, url, merged_headers, body, follow_redirects, redirect_chain, start
            )
        else:
            logger.error("No HTTP client available (httpx or requests required)")
            return None

    async def _send_httpx(
        self, method, url, headers, body, follow_redirects, max_redirects,
        redirect_chain, start
    ) -> Optional[QuantaraResponse]:
        try:
            async with httpx.AsyncClient(
                verify=self.verify_ssl,
                timeout=self.timeout,
                follow_redirects=follow_redirects,
                max_redirects=max_redirects,
            ) as client:
                content = body.encode() if body else None
                resp = await client.request(method, url, headers=headers, content=content)
                duration_ms = (time.monotonic() - start) * 1000

                response_headers = {k.lower(): v for k, v in resp.headers.items()}
                body_text = ""
                try:
                    body_text = resp.text
                except Exception:
                    body_text = resp.content.decode("utf-8", errors="ignore")

                raw = (
                    f"HTTP/{resp.http_version} {resp.status_code}\r\n"
                    + "\r\n".join(f"{k}: {v}" for k, v in resp.headers.items())
                    + "\r\n\r\n"
                    + body_text[:5000]
                )

                return QuantaraResponse(
                    url=str(resp.url),
                    status_code=resp.status_code,
                    headers=response_headers,
                    body=body_text,
                    raw=raw,
                    duration_ms=duration_ms,
                    redirect_chain=[str(r.url) for r in resp.history],
                )
        except Exception as e:
            logger.debug(f"HTTP request failed {url}: {e}")
            return QuantaraResponse(
                url=url, status_code=0, headers={}, body="", raw="",
                duration_ms=(time.monotonic() - start) * 1000, error=str(e)
            )

    async def _send_requests_async(
        self, method, url, headers, body, follow_redirects, redirect_chain, start
    ) -> Optional[QuantaraResponse]:
        """Async wrapper around requests using thread executor."""
        import asyncio
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            lambda: self._send_requests_sync(
                method, url, headers, body, follow_redirects, redirect_chain, start
            )
        )

    def _send_requests_sync(
        self, method, url, headers, body, follow_redirects, redirect_chain, start
    ) -> QuantaraResponse:
        import warnings
        warnings.filterwarnings("ignore", message="Unverified HTTPS request")
        try:
            resp = _requests.request(
                method, url,
                headers=headers,
                data=body.encode() if body else None,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=follow_redirects,
            )
            duration_ms = (time.monotonic() - start) * 1000
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            body_text = resp.text or ""
            raw = (
                f"HTTP/1.1 {resp.status_code}\r\n"
                + "\r\n".join(f"{k}: {v}" for k, v in resp.headers.items())
                + "\r\n\r\n"
                + body_text[:5000]
            )
            return QuantaraResponse(
                url=resp.url,
                status_code=resp.status_code,
                headers=resp_headers,
                body=body_text,
                raw=raw,
                duration_ms=duration_ms,
                redirect_chain=[r.url for r in resp.history],
            )
        except Exception as e:
            return QuantaraResponse(
                url=url, status_code=0, headers={}, body="", raw="",
                duration_ms=(time.monotonic() - start) * 1000, error=str(e)
            )


# ─────────────────────────────────────────────────────────────────────────────
# Template Runner
# ─────────────────────────────────────────────────────────────────────────────

class TemplateRunner:
    """
    Execute a single QuantaraTemplate against a target URL.
    Handles multi-request templates, fuzzing, and extraction chaining.
    """

    def __init__(
        self,
        http_engine: HTTPEngine,
        matcher_engine: MatcherEngine,
        extractor_engine: ExtractorEngine,
        fuzzing_engine: FuzzingEngine,
    ):
        self.http = http_engine
        self.matcher = matcher_engine
        self.extractor = extractor_engine
        self.fuzzer = fuzzing_engine

    async def run(self, template: QuantaraTemplate, base_url: str) -> list[TemplateMatch]:
        """Run a template against base_url. Returns list of matches (usually 0 or 1)."""
        matches = []
        resolver = VariableResolver(base_url, template.variables)
        extracted_vars: dict[str, str] = {}  # chained extraction across requests

        for req_def in template.http_requests:
            req_matches = await self._run_request(template, req_def, base_url, resolver, extracted_vars)
            matches.extend(req_matches)
            if req_matches and req_def.stop_at_first_match:
                break

        return matches

    async def _run_request(
        self,
        template: QuantaraTemplate,
        req_def: QuantaraHTTPRequest,
        base_url: str,
        resolver: VariableResolver,
        extracted_vars: dict,
    ) -> list[TemplateMatch]:
        matches = []

        # Build list of (url, extra_headers, body, payload_vars) tuples to execute
        tasks: list[tuple[str, str, dict, str, dict]] = []  # (method, url, headers, body, payload_vars)

        if req_def.fuzzing and req_def.payloads:
            # Fuzzing mode: generate variants
            first_path = req_def.paths[0] if req_def.paths else base_url
            first_url = resolver.resolve(first_path, extracted_vars)
            variants = self.fuzzer.generate_variants(
                first_url, req_def.fuzzing, req_def.payloads, req_def.attack
            )
            for fuzz_url, extra_headers, fuzz_body, payload_vars in variants:
                merged_headers = {**req_def.headers, **extra_headers}
                merged_headers = {k: resolver.resolve(v, {**payload_vars, **extracted_vars})
                                  for k, v in merged_headers.items()}
                body = fuzz_body or req_def.body
                body = resolver.resolve(body, {**payload_vars, **extracted_vars})
                tasks.append((
                    req_def.method, fuzz_url, merged_headers, body,
                    {**payload_vars, **extracted_vars}
                ))
        elif req_def.payloads and not req_def.fuzzing:
            # Payload substitution mode (payloads injected via template variable)
            for path in (req_def.paths or [base_url]):
                payload_combinations = self._build_payload_combinations(
                    req_def.payloads, req_def.attack
                )
                for combo in payload_combinations[:MAX_PATHS_PER_TEMPLATE]:
                    payload_vars = dict(combo)
                    payload_vars.update(extracted_vars)
                    url = resolver.resolve(path, payload_vars)
                    headers = {k: resolver.resolve(v, payload_vars)
                               for k, v in req_def.headers.items()}
                    body = resolver.resolve(req_def.body, payload_vars)
                    tasks.append((req_def.method, url, headers, body, payload_vars))
        elif req_def.raw:
            # Raw HTTP request mode
            for raw_template in req_def.raw:
                url, headers, body = self._parse_raw_request(
                    raw_template, base_url, resolver, extracted_vars, req_def.payloads
                )
                if url:
                    tasks.append((req_def.method, url, headers, body, extracted_vars))
        else:
            # Simple path list mode
            for path in (req_def.paths or [base_url]):
                url = resolver.resolve(path, extracted_vars)
                headers = {k: resolver.resolve(v, extracted_vars)
                           for k, v in req_def.headers.items()}
                body = resolver.resolve(req_def.body, extracted_vars)
                tasks.append((req_def.method, url, headers, body, {}))

        # Execute all tasks
        for method, url, headers, body, payload_vars in tasks[:MAX_PATHS_PER_TEMPLATE]:
            try:
                response = await self.http.send(
                    method=method,
                    url=url,
                    headers=headers,
                    body=body if body else None,
                    follow_redirects=req_def.redirects,
                    max_redirects=req_def.max_redirects,
                )
                if response is None or response.error:
                    continue

                # Check pre-conditions
                if req_def.pre_condition:
                    if not self._check_preconditions(req_def.pre_condition, response, payload_vars):
                        continue

                # Apply extractors (for chaining)
                new_extracted = self.extractor.extract_all(response, req_def.extractors, payload_vars)
                for k, vals in new_extracted.items():
                    if vals:
                        extracted_vars[k] = vals[0]

                # Apply matchers
                matched, evidence, matcher_name = self.matcher.match_all(
                    response, req_def.matchers, req_def.matchers_condition, payload_vars
                )

                if matched:
                    match = TemplateMatch(
                        template_id=template.id,
                        template_name=template.name,
                        url=url,
                        matched_url=url,
                        severity=template.severity,
                        tags=template.tags,
                        description=template.description,
                        reference=template.reference,
                        classification=template.classification,
                        matched=True,
                        matched_content=evidence[:300],
                        extracted_values=new_extracted,
                        curl_command=self._build_curl(method, url, headers, body),
                        matcher_name=matcher_name,
                        owasp=template.owasp,
                        cwe=template.cwe,
                    )
                    matches.append(match)

                    if req_def.stop_at_first_match:
                        break

            except Exception as e:
                logger.debug(f"Template {template.id} request error for {url}: {e}")
                continue

        return matches

    def _build_payload_combinations(
        self,
        payloads: dict[str, list[str]],
        attack: str,
    ) -> list[dict[str, str]]:
        """Generate payload dictionaries based on attack mode."""
        if not payloads:
            return [{}]

        keys = list(payloads.keys())
        values = [payloads[k] for k in keys]

        if attack == "clusterbomb":
            # All combinations
            combos = list(itertools.product(*values))[:MAX_PAYLOADS_PER_FUZZ]
            return [dict(zip(keys, combo)) for combo in combos]
        elif attack == "pitchfork":
            # Parallel (zip)
            combos = list(zip(*values))[:MAX_PAYLOADS_PER_FUZZ]
            return [dict(zip(keys, combo)) for combo in combos]
        else:
            # Sniper: one payload slot at a time, others use first value
            defaults = {k: v[0] if v else "" for k, v in payloads.items()}
            result = []
            for key, vals in payloads.items():
                for val in vals[:MAX_PAYLOADS_PER_FUZZ // len(keys) or 5]:
                    combo = dict(defaults)
                    combo[key] = val
                    result.append(combo)
            return result

    def _parse_raw_request(
        self,
        raw_template: str,
        base_url: str,
        resolver: VariableResolver,
        extracted_vars: dict,
        payloads: dict,
    ) -> tuple[str, dict, str]:
        """Parse a raw HTTP request template into (url, headers, body)."""
        # Resolve all variables first
        combo = {}
        if payloads:
            combo = {k: v[0] for k, v in payloads.items() if v}
        combo.update(extracted_vars)

        raw = resolver.resolve(raw_template, combo)
        lines = raw.strip().split("\n")
        if not lines:
            return base_url, {}, ""

        # Parse first line: "METHOD /path HTTP/1.1"
        first_line = lines[0].strip()
        parts = first_line.split()
        method = parts[0] if parts else "GET"
        path = parts[1] if len(parts) > 1 else "/"

        # Build full URL
        parsed = urlparse(base_url)
        if path.startswith("http"):
            url = path
        else:
            url = f"{parsed.scheme}://{parsed.netloc}{path}"

        # Parse headers (until blank line)
        headers = {}
        body_lines = []
        in_body = False
        for line in lines[1:]:
            if in_body:
                body_lines.append(line)
            elif line.strip() == "":
                in_body = True
            elif ":" in line:
                k, _, v = line.partition(":")
                key = k.strip().lower()
                if key not in ("host",):  # skip Host, we'll let httpx handle it
                    headers[k.strip()] = v.strip()

        body = "\n".join(body_lines).strip()
        return url, headers, body

    def _check_preconditions(
        self, pre_conditions: list[dict], response: QuantaraResponse, payload_vars: dict
    ) -> bool:
        """Check if all pre-conditions are satisfied."""
        for pc in pre_conditions:
            pc_type = str(pc.get("type", "dsl")).lower()
            if pc_type == "dsl":
                dsl_exprs = _to_list(pc.get("dsl", []))
                evaluator = DSLEvaluator(response, payload_vars)
                condition = str(pc.get("condition", "or")).lower()
                results = [evaluator.evaluate(expr) for expr in dsl_exprs]
                if condition == "and" and not all(results):
                    return False
                if condition != "and" and not any(results):
                    return False
        return True

    def _build_curl(self, method: str, url: str, headers: dict, body: str) -> str:
        """Build a curl command for the request."""
        parts = [f"curl -X {method}"]
        for k, v in headers.items():
            if k.lower() not in ("user-agent",):
                parts.append(f"-H '{k}: {v}'")
        if body:
            parts.append(f"-d '{body[:100]}'")
        parts.append(f"'{url}'")
        return " ".join(parts)


# ─────────────────────────────────────────────────────────────────────────────
# Quantara Engine (Top-level orchestrator)
# ─────────────────────────────────────────────────────────────────────────────

class QuantaraEngine:
    """
    Top-level engine: load templates and execute them concurrently against a URL.
    """

    def __init__(
        self,
        templates_dir: Optional[Path] = None,
        timeout: float = DEFAULT_TIMEOUT,
        max_concurrent: int = MAX_CONCURRENT,
        severity_filter: Optional[list[str]] = None,
        tag_filter: Optional[list[str]] = None,
        template_id_filter: Optional[list[str]] = None,
    ):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.severity_filter = [s.lower() for s in (severity_filter or [])]
        self.tag_filter = [t.lower() for t in (tag_filter or [])]
        self.template_id_filter = template_id_filter or []

        self._templates: list[QuantaraTemplate] = []
        self._http = HTTPEngine(timeout=timeout)
        self._matcher = MatcherEngine()
        self._extractor = ExtractorEngine()
        self._fuzzer = FuzzingEngine()
        self._runner = TemplateRunner(self._http, self._matcher, self._extractor, self._fuzzer)

        if templates_dir and templates_dir.exists():
            self.load_templates(templates_dir)

    def load_templates(self, directory: Path) -> int:
        """Load all YAML templates from directory. Returns count loaded."""
        loaded = TemplateLoader.load_directory(directory)
        self._templates.extend(loaded)
        logger.info(f"QuantaraEngine: loaded {len(loaded)} templates from {directory}")
        return len(loaded)

    def add_template(self, template: QuantaraTemplate):
        """Add a programmatically defined template."""
        self._templates.append(template)

    def add_templates(self, templates: list[QuantaraTemplate]):
        """Add multiple templates."""
        self._templates.extend(templates)

    def get_templates(self) -> list[QuantaraTemplate]:
        return list(self._templates)

    def _filter_templates(self, tech_hints: list[str] = None) -> list[QuantaraTemplate]:
        """Apply severity/tag/id filters and return relevant templates."""
        filtered = []
        tech_hints_lower = [t.lower() for t in (tech_hints or [])]

        for t in self._templates:
            # ID filter
            if self.template_id_filter and t.id not in self.template_id_filter:
                continue
            # Severity filter
            if self.severity_filter and t.severity.lower() not in self.severity_filter:
                continue
            # Tag filter
            if self.tag_filter:
                t_tags = [tag.lower() for tag in t.tags]
                if not any(tf in t_tags for tf in self.tag_filter):
                    continue
            filtered.append(t)
        return filtered

    async def scan_async(
        self,
        url: str,
        tech_hints: list[str] = None,
    ) -> list[TemplateMatch]:
        """
        Asynchronously scan a URL using all loaded templates.
        Returns list of TemplateMatch objects.
        """
        templates_to_run = self._filter_templates(tech_hints)
        if not templates_to_run:
            logger.debug(f"No templates matched filters for {url}")
            return []

        semaphore = asyncio.Semaphore(self.max_concurrent)
        all_matches: list[TemplateMatch] = []

        async def run_with_semaphore(template: QuantaraTemplate) -> list[TemplateMatch]:
            async with semaphore:
                try:
                    return await self._runner.run(template, url)
                except Exception as e:
                    logger.debug(f"Template {template.id} failed: {e}")
                    return []

        tasks = [run_with_semaphore(t) for t in templates_to_run]
        results = await asyncio.gather(*tasks, return_exceptions=False)

        for result_list in results:
            all_matches.extend(result_list)

        logger.info(
            f"QuantaraEngine scan complete: {len(templates_to_run)} templates, "
            f"{len(all_matches)} matches on {url}"
        )
        return all_matches

    def scan(self, url: str, tech_hints: list[str] = None) -> list[TemplateMatch]:
        """
        Synchronous scan — wraps the async version.
        Safe to call from non-async context or from thread executors.
        """
        try:
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                # No event loop in this thread - create a new one
                loop = None

            if loop is None:
                # No loop exists - run in a new loop directly
                return self._run_in_new_loop(url, tech_hints)

            if loop.is_running():
                # If already inside an event loop (e.g., FastAPI), use thread executor
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(self._run_in_new_loop, url, tech_hints)
                    return future.result(timeout=self.timeout * len(self._templates) + 30)
            else:
                return loop.run_until_complete(self.scan_async(url, tech_hints))
        except Exception as e:
            logger.error(f"QuantaraEngine.scan error: {e}")
            return []

    def _run_in_new_loop(self, url: str, tech_hints: list[str] = None) -> list[TemplateMatch]:
        """Run scan in a fresh event loop (used when called from async context or thread)."""
        new_loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(new_loop)
            return new_loop.run_until_complete(self.scan_async(url, tech_hints))
        finally:
            try:
                new_loop.close()
            except Exception:
                pass


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _to_list(val: Any) -> list:
    if val is None:
        return []
    if isinstance(val, list):
        return [str(v) for v in val]
    return [str(val)]


def _rand_str(length: int) -> str:
    chars = string.ascii_lowercase + string.digits
    return "".join(random.choices(chars, k=length))


def _split_logical(expr: str, op: str) -> list[str]:
    """Split on logical operator, respecting parentheses and strings."""
    parts = []
    depth = 0
    in_str = False
    str_char = None
    current = []
    i = 0
    while i < len(expr):
        c = expr[i]
        if in_str:
            current.append(c)
            if c == str_char and (i == 0 or expr[i-1] != "\\"):
                in_str = False
        elif c in ('"', "'"):
            in_str = True
            str_char = c
            current.append(c)
        elif c == "(":
            depth += 1
            current.append(c)
        elif c == ")":
            depth -= 1
            current.append(c)
        elif depth == 0 and expr[i:i+len(op)] == op:
            parts.append("".join(current))
            current = []
            i += len(op)
            continue
        else:
            current.append(c)
        i += 1
    if current:
        parts.append("".join(current))
    return parts


def _split_args(expr: str) -> list[str]:
    """Split function arguments by comma, respecting nesting and strings."""
    args = []
    depth = 0
    in_str = False
    str_char = None
    current = []
    for i, c in enumerate(expr):
        if in_str:
            current.append(c)
            if c == str_char and (i == 0 or expr[i-1] != "\\"):
                in_str = False
        elif c in ('"', "'"):
            in_str = True
            str_char = c
            current.append(c)
        elif c == "(":
            depth += 1
            current.append(c)
        elif c == ")":
            depth -= 1
            current.append(c)
        elif c == "," and depth == 0:
            args.append("".join(current).strip())
            current = []
        else:
            current.append(c)
    if current:
        args.append("".join(current).strip())
    return args


def _infer_owasp(template_id: str, tags: Any) -> str:
    """Infer OWASP category from template id and tags."""
    combined = (template_id + " " + " ".join(_to_list(tags))).lower()
    if any(k in combined for k in ("sqli", "sql", "nosql", "ldap", "xxe", "injection", "xss", "ssti", "crlf")):
        return "A03:2021"
    if any(k in combined for k in ("auth", "jwt", "session", "brute", "password", "oauth")):
        return "A07:2021"
    if any(k in combined for k in ("secret", "key", "token", "credential", "aws", "stripe")):
        return "A02:2021"
    if any(k in combined for k in ("cors", "misconfig", "header", "debug", "iis", "nginx")):
        return "A05:2021"
    if any(k in combined for k in ("ssrf", "request-forgery", "redirect", "open-redirect")):
        return "A10:2021"
    if any(k in combined for k in ("idor", "access", "authorization", "privilege")):
        return "A01:2021"
    if any(k in combined for k in ("supply", "dependency", "outdated")):
        return "A06:2021"
    if any(k in combined for k in ("log", "monitor", "audit")):
        return "A09:2021"
    if any(k in combined for k in ("crypto", "tls", "ssl", "cert", "hash", "md5", "sha1")):
        return "A02:2021"
    if any(k in combined for k in ("takeover", "s3", "bucket", "cloud", "aws")):
        return "A05:2021"
    if any(k in combined for k in ("upload", "zip", "backup", "file")):
        return "A05:2021"
    return "A05:2021"
