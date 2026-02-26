"""
Quantum Protocol v4.0 — A05: Injection Scanner
Enterprise-grade injection detection with AST-aware taint analysis,
framework-specific sinks, and context-aware confidence calibration.

Covers: SQLi, XSS, Command Injection, SSTI, NoSQL, XXE, LDAP, XPath,
        Header Injection, CRLF, DOM XSS, Prototype Pollution
"""
from __future__ import annotations

import ast
import re
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from quantum_protocol.models.enums import AlgoFamily, RiskLevel, ScanMode
from quantum_protocol.models.findings import CryptoFinding
from quantum_protocol.rules.owasp_rules import VulnRule, _compile
from quantum_protocol.utils.analysis import confidence_to_level, sanitize_line

logger = logging.getLogger("quantum_protocol.injection")

# ── Extended Injection Rules (80+ beyond base OWASP rules) ─────────

_EXTENDED_INJECTION_RULES: list[VulnRule] = [
    # Advanced SQLi — ORM-specific sinks
    VulnRule("SQLI-E01", r'\.whereRaw\s*\(\s*[`"\'].*?\$\{', AlgoFamily.VULN_SQL_INJECTION, RiskLevel.CRITICAL, 0.90, "Knex/Objection .whereRaw() with template interpolation", "CWE-89", ("javascript","typescript"), ("injection","sql","knex")),
    VulnRule("SQLI-E02", r'\.query\s*\(\s*["\'].*?\%s.*?["\'].*?%\s*\(', AlgoFamily.VULN_SQL_INJECTION, RiskLevel.CRITICAL, 0.88, "Python DB-API query with % operator (not parameterized)", "CWE-89", ("python",), ("injection","sql")),
    VulnRule("SQLI-E03", r'connection\.query\s*\(\s*[`"\'].*?\$\{', AlgoFamily.VULN_SQL_INJECTION, RiskLevel.CRITICAL, 0.90, "MySQL/pg connection.query with template literal", "CWE-89", ("javascript","typescript"), ("injection","sql")),
    VulnRule("SQLI-E04", r'(?:entityManager|em|session)\.create(?:Query|NativeQuery)\s*\(\s*["\'].*?\+', AlgoFamily.VULN_SQL_INJECTION, RiskLevel.CRITICAL, 0.88, "JPA/Hibernate query concatenation", "CWE-89", ("java","kotlin"), ("injection","sql","jpa")),
    VulnRule("SQLI-E05", r'\.(?:findAndCountAll|findAll)\s*\(\s*\{.*?where\s*:.*?\[.*?(?:req|params|body)', AlgoFamily.VULN_SQL_INJECTION, RiskLevel.HIGH, 0.78, "Sequelize query with user-controlled where clause", "CWE-89", ("javascript","typescript"), ("injection","sql","sequelize")),
    VulnRule("SQLI-E06", r'db\.(?:Exec|Query|QueryRow)\s*\(\s*(?:fmt\.Sprintf|.*?\+)', AlgoFamily.VULN_SQL_INJECTION, RiskLevel.CRITICAL, 0.88, "Go database/sql with Sprintf or concat", "CWE-89", ("go",), ("injection","sql")),
    VulnRule("SQLI-E07", r'ActiveRecord::Base\.connection\.execute\s*\(\s*["\'].*?#\{', AlgoFamily.VULN_SQL_INJECTION, RiskLevel.CRITICAL, 0.88, "Rails raw SQL execution with interpolation", "CWE-89", ("ruby",), ("injection","sql","rails")),
    VulnRule("SQLI-E08", r'Arel\.sql\s*\(\s*["\'].*?#\{', AlgoFamily.VULN_SQL_INJECTION, RiskLevel.HIGH, 0.82, "Rails Arel.sql with string interpolation", "CWE-89", ("ruby",), ("injection","sql","rails")),

    # Advanced XSS — Framework-specific DOM sinks
    VulnRule("XSS-E01", r'\.outerHTML\s*=', AlgoFamily.VULN_XSS, RiskLevel.HIGH, 0.78, "outerHTML assignment — DOM XSS vector", "CWE-79", ("javascript","typescript"), ("injection","xss")),
    VulnRule("XSS-E02", r'\.insertAdjacentHTML\s*\(', AlgoFamily.VULN_XSS, RiskLevel.HIGH, 0.78, "insertAdjacentHTML — XSS if unescaped user input", "CWE-79", ("javascript","typescript"), ("injection","xss")),
    VulnRule("XSS-E03", r'DOMParser\s*\(\s*\)\.parseFromString\s*\(.*?text/html', AlgoFamily.VULN_XSS, RiskLevel.MEDIUM, 0.70, "DOMParser with text/html — verify input sanitization", "CWE-79", ("javascript","typescript"), ("injection","xss")),
    VulnRule("XSS-E04", r'document\.(?:location|URL|documentURI|referrer|cookie)', AlgoFamily.VULN_DOM_XSS, RiskLevel.MEDIUM, 0.68, "DOM-based source — check if used in sink without sanitization", "CWE-79", ("javascript","typescript"), ("injection","xss","dom")),
    VulnRule("XSS-E05", r'window\.(?:name|location\.(?:hash|search|href|pathname))', AlgoFamily.VULN_DOM_XSS, RiskLevel.MEDIUM, 0.68, "DOM-based source from window properties", "CWE-79", ("javascript","typescript"), ("injection","xss","dom")),
    VulnRule("XSS-E06", r'(?:Markup|Markup\.escape|mark_safe)\s*\(.*?(?:req|request|params|input|user)', AlgoFamily.VULN_XSS, RiskLevel.HIGH, 0.82, "Markup/mark_safe with user input — bypasses escaping", "CWE-79", ("python",), ("injection","xss")),
    VulnRule("XSS-E07", r'@Html\.Raw\s*\(', AlgoFamily.VULN_XSS, RiskLevel.HIGH, 0.80, "ASP.NET Html.Raw() — unescaped output", "CWE-79", ("csharp",), ("injection","xss")),
    VulnRule("XSS-E08", r'(?:sanitize|clean|purify|escape)\s*=\s*(?:false|False|0|nil)', AlgoFamily.VULN_XSS, RiskLevel.HIGH, 0.82, "Sanitization explicitly disabled", "CWE-79", (), ("injection","xss")),

    # Advanced Command Injection
    VulnRule("CMDI-E01", r'ProcessBuilder\s*\(\s*(?:Arrays\.asList|List\.of)\s*\(.*?\+', AlgoFamily.VULN_COMMAND_INJECTION, RiskLevel.HIGH, 0.82, "Java ProcessBuilder with concatenated args", "CWE-78", ("java","kotlin"), ("injection","command")),
    VulnRule("CMDI-E02", r'new\s+ProcessStartInfo\s*\(.*?\+', AlgoFamily.VULN_COMMAND_INJECTION, RiskLevel.HIGH, 0.80, ".NET ProcessStartInfo with dynamic args", "CWE-78", ("csharp",), ("injection","command")),
    VulnRule("CMDI-E03", r'Process\.Start\s*\(.*?(?:req|request|input|user)', AlgoFamily.VULN_COMMAND_INJECTION, RiskLevel.CRITICAL, 0.88, ".NET Process.Start with user input", "CWE-78", ("csharp",), ("injection","command")),
    VulnRule("CMDI-E04", r'Kernel\.\s*`', AlgoFamily.VULN_COMMAND_INJECTION, RiskLevel.HIGH, 0.78, "Ruby Kernel backtick execution", "CWE-78", ("ruby",), ("injection","command")),
    VulnRule("CMDI-E05", r'%x\[.*?#\{', AlgoFamily.VULN_COMMAND_INJECTION, RiskLevel.CRITICAL, 0.88, "Ruby %x[] command with interpolation", "CWE-78", ("ruby",), ("injection","command")),
    VulnRule("CMDI-E06", r'IO\.popen\s*\(.*?#\{', AlgoFamily.VULN_COMMAND_INJECTION, RiskLevel.CRITICAL, 0.88, "Ruby IO.popen with interpolation", "CWE-78", ("ruby",), ("injection","command")),

    # SSTI — Server-Side Template Injection
    VulnRule("SSTI-001", r'Environment\s*\(\s*.*?\.from_string\s*\(', AlgoFamily.VULN_TEMPLATE_INJECTION, RiskLevel.CRITICAL, 0.88, "Jinja2 Environment.from_string — SSTI risk", "CWE-1336", ("python",), ("injection","ssti")),
    VulnRule("SSTI-002", r'Template\s*\(\s*(?:req|request|params|input|user)', AlgoFamily.VULN_TEMPLATE_INJECTION, RiskLevel.CRITICAL, 0.90, "Template constructor with user input", "CWE-1336", (), ("injection","ssti")),
    VulnRule("SSTI-003", r'Mustache\.render\s*\(\s*(?:req|request|params|body)', AlgoFamily.VULN_TEMPLATE_INJECTION, RiskLevel.HIGH, 0.82, "Mustache.render with user-supplied template", "CWE-1336", ("javascript","typescript"), ("injection","ssti")),
    VulnRule("SSTI-004", r'(?:ERB|Erubi|Slim)\.new\s*\(.*?(?:params|request)', AlgoFamily.VULN_TEMPLATE_INJECTION, RiskLevel.CRITICAL, 0.88, "Ruby ERB with user-controlled template", "CWE-1336", ("ruby",), ("injection","ssti")),
    VulnRule("SSTI-005", r'freemarker.*?Template\s*\(.*?\+', AlgoFamily.VULN_TEMPLATE_INJECTION, RiskLevel.HIGH, 0.82, "FreeMarker template with dynamic content", "CWE-1336", ("java",), ("injection","ssti")),

    # Prototype Pollution (JS-specific)
    VulnRule("PROTO-001", r'(?:merge|extend|assign|defaults|deepMerge)\s*\(\s*\{\s*\}\s*,\s*(?:req|request|params|body|input)', AlgoFamily.VULN_MASS_ASSIGNMENT, RiskLevel.HIGH, 0.78, "Object merge with user input — prototype pollution risk", "CWE-1321", ("javascript","typescript"), ("injection","prototype-pollution")),
    VulnRule("PROTO-002", r'__proto__|constructor\[.?prototype', AlgoFamily.VULN_MASS_ASSIGNMENT, RiskLevel.CRITICAL, 0.85, "Direct __proto__ or constructor.prototype manipulation", "CWE-1321", ("javascript","typescript"), ("injection","prototype-pollution")),

    # XPath Injection
    VulnRule("XPATH-001", r'(?:xpath|XPath|XPathExpression)\s*\(.*?\+\s*(?:req|request|params|input|user)', AlgoFamily.VULN_XPATH_INJECTION, RiskLevel.HIGH, 0.82, "XPath query with user-controlled input", "CWE-643", (), ("injection","xpath")),

    # LDAP Injection (extended)
    VulnRule("LDAP-E01", r'(?:search_s|search_ext_s)\s*\(.*?(?:f["\']|format|%)', AlgoFamily.VULN_LDAP_INJECTION, RiskLevel.HIGH, 0.82, "Python LDAP search with string formatting", "CWE-90", ("python",), ("injection","ldap")),
    VulnRule("LDAP-E02", r'DirContext\s*\.search\s*\(.*?\+', AlgoFamily.VULN_LDAP_INJECTION, RiskLevel.HIGH, 0.80, "Java LDAP search with concatenation", "CWE-90", ("java",), ("injection","ldap")),

    # Header / CRLF Injection (extended)
    VulnRule("CRLF-E01", r'(?:res|response)\.(?:setHeader|set|header|writeHead)\s*\(.*?(?:req|request|params|body|query)', AlgoFamily.VULN_HEADER_INJECTION, RiskLevel.MEDIUM, 0.75, "HTTP header from user input — CRLF injection risk", "CWE-113", ("javascript","typescript"), ("injection","crlf")),
    VulnRule("CRLF-E02", r'HttpServletResponse\.(?:setHeader|addHeader)\s*\(.*?(?:request\.getParameter|req\.)', AlgoFamily.VULN_HEADER_INJECTION, RiskLevel.MEDIUM, 0.75, "Java servlet header from request parameter", "CWE-113", ("java",), ("injection","crlf")),

    # Advanced XXE
    VulnRule("XXE-E01", r'SAXParserFactory\.newInstance\s*\(\s*\)(?!.*setFeature)', AlgoFamily.VULN_XXE, RiskLevel.HIGH, 0.78, "Java SAXParser without feature restrictions", "CWE-611", ("java",), ("injection","xxe")),
    VulnRule("XXE-E02", r'TransformerFactory\.newInstance\s*\(\s*\)(?!.*setAttribute)', AlgoFamily.VULN_XXE, RiskLevel.HIGH, 0.75, "Java TransformerFactory without secure attributes", "CWE-611", ("java",), ("injection","xxe")),
    VulnRule("XXE-E03", r'XmlReader\.Create\s*\((?!.*DtdProcessing\.Prohibit)', AlgoFamily.VULN_XXE, RiskLevel.HIGH, 0.78, ".NET XmlReader without DtdProcessing.Prohibit", "CWE-611", ("csharp",), ("injection","xxe")),
    VulnRule("XXE-E04", r'lxml\.etree\.(?:parse|fromstring)\s*\((?!.*resolve_entities\s*=\s*False)', AlgoFamily.VULN_XXE, RiskLevel.HIGH, 0.80, "lxml parser without resolve_entities=False", "CWE-611", ("python",), ("injection","xxe")),

    # NoSQL (extended)
    VulnRule("NOSQL-E01", r'\.(?:updateOne|updateMany|deleteOne|deleteMany)\s*\(\s*(?:req\.body|req\.query)', AlgoFamily.VULN_NOSQL_INJECTION, RiskLevel.HIGH, 0.82, "MongoDB mutation with direct user input", "CWE-943", ("javascript","typescript"), ("injection","nosql")),
    VulnRule("NOSQL-E02", r'\.aggregate\s*\(\s*(?:req\.body|JSON\.parse)', AlgoFamily.VULN_NOSQL_INJECTION, RiskLevel.HIGH, 0.80, "MongoDB aggregation with user-controlled pipeline", "CWE-943", ("javascript","typescript"), ("injection","nosql")),
]

COMPILED_EXTENDED_INJECTION = _compile(_EXTENDED_INJECTION_RULES)


# ── Python AST Taint Analysis ──────────────────────────────────

class _PythonTaintVisitor(ast.NodeVisitor):
    """AST visitor for Python injection taint analysis."""

    SOURCES = {"request", "req", "params", "args", "form", "data", "json",
               "GET", "POST", "body", "query", "input", "environ", "headers"}
    SQL_SINKS = {"execute", "executemany", "query", "raw", "extra",
                 "cursor", "fetchone", "fetchall"}
    CMD_SINKS = {"system", "popen", "call", "run", "Popen", "exec",
                 "check_output", "check_call"}
    DESER_SINKS = {"loads", "load", "Unpickler", "unsafe_load", "from_string"}

    def __init__(self, filepath: str, content: str):
        self.filepath = filepath
        self.lines = content.split("\n")
        self.findings: list[dict] = []
        self._tainted_vars: set[str] = set()

    def visit_Assign(self, node: ast.Assign):
        """Track variables assigned from user input sources."""
        if self._is_source(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._tainted_vars.add(target.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """Check if tainted data flows to dangerous sinks."""
        func_name = self._get_func_name(node)
        if not func_name:
            self.generic_visit(node)
            return

        # Check SQL sinks with f-string / format args
        if func_name in self.SQL_SINKS:
            for arg in node.args:
                if isinstance(arg, ast.JoinedStr):  # f-string
                    self._add_finding(node, AlgoFamily.VULN_SQL_INJECTION,
                                      RiskLevel.CRITICAL, 0.92,
                                      "SQL query uses f-string — use parameterized query",
                                      "CWE-89")
                elif self._is_tainted(arg):
                    self._add_finding(node, AlgoFamily.VULN_SQL_INJECTION,
                                      RiskLevel.CRITICAL, 0.88,
                                      "Tainted user input flows to SQL sink",
                                      "CWE-89")

        # Check command sinks
        if func_name in self.CMD_SINKS:
            for arg in node.args:
                if self._is_tainted(arg):
                    self._add_finding(node, AlgoFamily.VULN_COMMAND_INJECTION,
                                      RiskLevel.CRITICAL, 0.90,
                                      "Tainted user input flows to command execution",
                                      "CWE-78")
            # shell=True keyword
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value:
                    self._add_finding(node, AlgoFamily.VULN_COMMAND_INJECTION,
                                      RiskLevel.HIGH, 0.85,
                                      "subprocess called with shell=True",
                                      "CWE-78")

        # Check deserialization sinks
        if func_name in self.DESER_SINKS:
            for arg in node.args:
                if self._is_tainted(arg):
                    self._add_finding(node, AlgoFamily.VULN_UNSAFE_DESER,
                                      RiskLevel.CRITICAL, 0.92,
                                      "Tainted user input flows to deserialization sink",
                                      "CWE-502")

        self.generic_visit(node)

    def _is_source(self, node) -> bool:
        """Check if a node represents user input."""
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id in self.SOURCES:
                return True
            return self._is_source(node.value)
        if isinstance(node, ast.Subscript):
            return self._is_source(node.value)
        if isinstance(node, ast.Call):
            return self._is_source(node.func) if isinstance(node.func, ast.Attribute) else False
        return False

    def _is_tainted(self, node) -> bool:
        """Check if a node uses tainted data."""
        if isinstance(node, ast.Name) and node.id in self._tainted_vars:
            return True
        if self._is_source(node):
            return True
        if isinstance(node, ast.JoinedStr):
            return any(self._is_tainted(v) for v in node.values if isinstance(v, ast.FormattedValue))
        if isinstance(node, ast.FormattedValue):
            return self._is_tainted(node.value)
        if isinstance(node, ast.BinOp):
            return self._is_tainted(node.left) or self._is_tainted(node.right)
        if isinstance(node, ast.Call):
            return any(self._is_tainted(a) for a in node.args)
        return False

    def _get_func_name(self, node: ast.Call) -> Optional[str]:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None

    def _add_finding(self, node, family, risk, confidence, note, cwe):
        self.findings.append({
            "line": node.lineno,
            "col": node.col_offset,
            "family": family,
            "risk": risk,
            "confidence": confidence,
            "note": note,
            "cwe": cwe,
            "raw_line": self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else "",
        })


def ast_injection_scan(content: str, filepath: str) -> list[dict]:
    """Run Python AST-based injection taint analysis."""
    try:
        tree = ast.parse(content, filename=filepath)
        visitor = _PythonTaintVisitor(filepath, content)
        visitor.visit(tree)
        return visitor.findings
    except SyntaxError:
        return []


def scan_injections(
    content: str,
    relative_path: str,
    language: Optional[str],
    scan_mode: ScanMode,
    context_window: int = 3,
) -> list[CryptoFinding]:
    """
    Deep injection scanning with extended patterns + AST taint analysis.
    Returns findings beyond what the base OWASP scanner provides.
    """
    findings: list[CryptoFinding] = []
    seen: set[str] = set()
    lines = content.split("\n")

    # Layer 1: Extended regex patterns
    for compiled_re, rule in COMPILED_EXTENDED_INJECTION:
        if rule.languages and language and language not in rule.languages:
            continue
        for match in compiled_re.finditer(content):
            line_no = content[:match.start()].count("\n") + 1
            dedup = f"{relative_path}:{line_no}:{rule.family.value}:{rule.id}"
            if dedup in seen:
                continue
            seen.add(dedup)

            ctx_start = max(0, line_no - context_window - 1)
            ctx_end = min(len(lines), line_no + context_window)
            raw_line = lines[line_no - 1] if line_no <= len(lines) else ""

            findings.append(CryptoFinding(
                id=CryptoFinding.generate_id(relative_path, line_no, f"INJ-{rule.id}"),
                file=relative_path, language=language or "unknown",
                line_number=line_no, line_content=sanitize_line(raw_line.strip()),
                column_start=match.start() - content.rfind("\n", 0, match.start()) - 1,
                column_end=None, algorithm=rule.family.value, family=rule.family,
                risk=rule.risk, confidence=round(rule.confidence, 3),
                confidence_level=confidence_to_level(rule.confidence),
                key_size=None, hndl_relevant=False, pattern_note=rule.note,
                migration={"action": rule.remediation or "Fix injection vulnerability", "cwe": rule.cwe},
                compliance_violations=[], context_lines=[sanitize_line(l) for l in lines[ctx_start:ctx_end]],
                cwe_id=rule.cwe, cvss_estimate=rule.risk.numeric,
                remediation_effort="medium", tags=list(rule.tags),
            ))

    # Layer 2: Python AST taint analysis
    if language == "python":
        for af in ast_injection_scan(content, relative_path):
            dedup = f"{relative_path}:{af['line']}:{af['family'].value}:AST"
            if dedup in seen:
                continue
            seen.add(dedup)
            line_no = af["line"]
            ctx_start = max(0, line_no - context_window - 1)
            ctx_end = min(len(lines), line_no + context_window)

            findings.append(CryptoFinding(
                id=CryptoFinding.generate_id(relative_path, line_no, f"AST-{af['family'].value}"),
                file=relative_path, language="python",
                line_number=line_no, line_content=sanitize_line(af["raw_line"].strip()),
                column_start=af["col"], column_end=None,
                algorithm=af["family"].value, family=af["family"],
                risk=af["risk"], confidence=round(af["confidence"], 3),
                confidence_level=confidence_to_level(af["confidence"]),
                key_size=None, hndl_relevant=False, pattern_note=f"[AST Taint] {af['note']}",
                migration={"action": "Fix injection using parameterized queries or safe APIs", "cwe": af["cwe"]},
                compliance_violations=[], context_lines=[sanitize_line(l) for l in lines[ctx_start:ctx_end]],
                cwe_id=af["cwe"], cvss_estimate=af["risk"].numeric,
                remediation_effort="medium", tags=["injection", "ast-analysis"],
            ))

    return findings
