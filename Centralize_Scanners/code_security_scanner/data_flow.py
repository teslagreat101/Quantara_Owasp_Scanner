"""
Code Security Scanner — Data Flow Analysis Engine
===================================================

Enterprise-grade taint analysis that traces how untrusted data moves
through an application, from sources (user input, HTTP params, file reads)
through transformations to security-sensitive sinks (SQL queries, command
execution, HTML rendering).

This module builds a Data Flow Graph (DFG) that:
  1. Identifies taint sources across multiple frameworks
  2. Tracks taint propagation through variable assignments and function calls
  3. Detects sanitization barriers that neutralize taint
  4. Identifies dangerous sinks where unsanitized taint is consumed
  5. Produces TaintFlow traces for the Discovery Agent
"""

"""
Enterprise Data Flow Analysis Engine — Taint Tracking System
=============================================================
Production-Ready Refactoring:
- Hybrid Analysis (Regex + AST)
- Cross-File Taint Propagation
- Parallel Processing with Caching
- Structured Observability
- Configurable via Environment Variables
"""

from __future__ import annotations

import ast
import hashlib
import json
import logging
import os
import re
import sys
import time
import traceback
from abc import ABC, abstractmethod
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

# Enterprise Dependencies
try:
    from pydantic import BaseModel, Field, validator
    from pydantic_settings import BaseSettings
except ImportError:
    class BaseModel: pass
    class BaseSettings: pass
    def Field(*args, **kwargs): return None

# ────────────────────────────────────────────────────────────────────────────
# 1. Configuration & Settings
# ────────────────────────────────────────────────────────────────────────────

class DataFlowSettings(BaseSettings):
    """
    Centralized configuration for Data Flow Analysis.
    Load from ENV variables (e.g., DFA_MAX_FILE_SIZE=1048576)
    """
    max_file_size: int = 10 * 1024 * 1024  # 10MB
    max_workers: int = os.cpu_count() or 4
    analysis_timeout_seconds: int = 30
    enable_ast_analysis: bool = True
    enable_cross_file_analysis: bool = True
    cache_enabled: bool = True
    cache_ttl_seconds: int = 3600
    log_level: str = "INFO"
    log_format: str = "json"
    max_propagation_depth: int = 10
    confidence_threshold: float = 0.50
    
    class Config:
        env_prefix = "DFA_"
        case_sensitive = False

# ────────────────────────────────────────────────────────────────────────────
# 2. Enhanced Data Models
# ────────────────────────────────────────────────────────────────────────────

class TaintType(str, Enum):
    HTTP_PARAM = "HTTP_PARAM"
    HTTP_HEADER = "HTTP_HEADER"
    HTTP_COOKIE = "HTTP_COOKIE"
    FILE_READ = "FILE_READ"
    USER_INPUT = "USER_INPUT"
    CLI_ARGUMENT = "CLI_ARGUMENT"
    ENV_VARIABLE = "ENV_VARIABLE"
    EXTERNAL_API = "EXTERNAL_API"
    DESERIALIZED = "DESERIALIZED"
    WEBSOCKET = "WEBSOCKET"
    DATABASE = "DATABASE"
    UNKNOWN = "UNKNOWN"

class SanitizerType(str, Enum):
    PARAMETERIZED_QUERY = "PARAMETERIZED_QUERY"
    HTML_ENCODING = "HTML_ENCODING"
    ESCAPING = "ESCAPING"
    PATH_NORMALIZATION = "PATH_NORMALIZATION"
    URL_ENCODING = "URL_ENCODING"
    TYPE_COERCION = "TYPE_COERCION"
    FRAMEWORK_PROTECTION = "FRAMEWORK_PROTECTION"
    INPUT_VALIDATION = "INPUT_VALIDATION"
    CSP_HEADER = "CSP_HEADER"
    UNKNOWN = "UNKNOWN"

class VulnerabilityClass(str, Enum):
    SQL_INJECTION = "SQL_INJECTION"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    XSS_REFLECTED = "XSS_REFLECTED"
    XSS_STORED = "XSS_STORED"
    XSS_DOM = "XSS_DOM"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    SSRF = "SSRF"
    OPEN_REDIRECT = "OPEN_REDIRECT"
    INSECURE_DESERIALIZATION = "INSECURE_DESERIALIZATION"
    TEMPLATE_INJECTION = "TEMPLATE_INJECTION"
    PROTOTYPE_POLLUTION = "PROTOTYPE_POLLUTION"
    NOSQL_INJECTION = "NOSQL_INJECTION"
    LDAP_INJECTION = "LDAP_INJECTION"
    XML_INJECTION = "XML_INJECTION"
    BROKEN_AUTH = "BROKEN_AUTH"
    BROKEN_ACCESS = "BROKEN_ACCESS"
    IDOR = "IDOR"
    SENSITIVE_DATA_EXPOSURE = "SENSITIVE_DATA_EXPOSURE"
    SECURITY_MISCONFIG = "SECURITY_MISCONFIG"
    INSUFFICIENT_LOGGING = "INSUFFICIENT_LOGGING"
    CRYPTO_WEAKNESS = "CRYPTO_WEAKNESS"
    HARDCODED_SECRET = "HARDCODED_SECRET"
    RACE_CONDITION = "RACE_CONDITION"
    MASS_ASSIGNMENT = "MASS_ASSIGNMENT"
    UNSAFE_REFLECTION = "UNSAFE_REFLECTION"
    INFORMATION_LEAKAGE = "INFORMATION_LEAKAGE"
    SUPPLY_CHAIN = "SUPPLY_CHAIN"
    INSECURE_DESIGN = "INSECURE_DESIGN"

@dataclass
class TaintSource:
    file: str
    line: int
    column: int
    variable: str
    taint_type: TaintType
    framework_api: Optional[str] = None
    snippet: str = ""
    scope: Optional[str] = None  # Function/method name
    confidence: float = 0.85
    ast_node_type: Optional[str] = None

@dataclass
class TaintSink:
    file: str
    line: int
    column: int
    function: str
    vuln_class: VulnerabilityClass
    framework_api: Optional[str] = None
    snippet: str = ""
    scope: Optional[str] = None
    confidence: float = 0.90
    ast_node_type: Optional[str] = None

@dataclass
class TaintPropagator:
    file: str
    line: int
    function: str
    transforms_taint: bool
    is_sanitizer: bool = False
    sanitizer_type: Optional[SanitizerType] = None
    source_vars: List[str] = field(default_factory=list)
    sink_vars: List[str] = field(default_factory=list)

@dataclass
class TaintFlow:
    source: TaintSource
    sink: TaintSink
    propagators: List[TaintPropagator] = field(default_factory=list)
    is_sanitized: bool = False
    sanitization_gaps: List[str] = field(default_factory=list)
    path_length: int = 0
    confidence: float = 0.0
    fingerprint: Optional[str] = None
    cross_file: bool = False
    
    def __post_init__(self):
        if not self.fingerprint:
            content = f"{self.source.file}:{self.source.line}:{self.sink.file}:{self.sink.line}:{self.sink.vuln_class.value}"
            self.fingerprint = hashlib.sha256(content.encode()).hexdigest()[:16]
        self.path_length = len(self.propagators) + 2  # source + propagators + sink
        # Calculate confidence based on path characteristics
        self.confidence = self._calculate_confidence()
    
    def _calculate_confidence(self) -> float:
        base = (self.source.confidence + self.sink.confidence) / 2
        # Penalize long propagation chains
        path_penalty = min(0.3, self.path_length * 0.05)
        # Boost if same scope
        scope_bonus = 0.1 if self.source.scope == self.sink.scope else 0.0
        # Penalize cross-file (less certain)
        cross_file_penalty = 0.15 if self.cross_file else 0.0
        return max(0.0, min(1.0, base - path_penalty + scope_bonus - cross_file_penalty))

# ────────────────────────────────────────────────────────────────────────────
# 3. Observability (Logging & Metrics)
# ────────────────────────────────────────────────────────────────────────────

class StructuredLogger:
    def __init__(self, name: str, settings: DataFlowSettings):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, settings.log_level.upper()))
        self.logger.handlers = []
        
        handler = logging.StreamHandler(sys.stdout)
        if settings.log_format == "json":
            formatter = logging.Formatter('%(message)s')
            self.logger.addFilter(self.JsonFilter())
        else:
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    class JsonFilter(logging.Filter):
        def filter(self, record):
            record.msg = json.dumps({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
                "analysis_id": os.environ.get("DFA_ANALYSIS_ID", "unknown")
            })
            return True

    def info(self, msg, **kwargs): self.logger.info(msg, extra=kwargs)
    def error(self, msg, **kwargs): self.logger.error(msg, extra=kwargs)
    def warning(self, msg, **kwargs): self.logger.warning(msg, extra=kwargs)
    def debug(self, msg, **kwargs): self.logger.debug(msg, extra=kwargs)

@dataclass
class AnalysisMetrics:
    start_time: float = field(default_factory=time.time)
    files_analyzed: int = 0
    sources_found: int = 0
    sinks_found: int = 0
    flows_traced: int = 0
    flows_sanitized: int = 0
    flows_unsanitized: int = 0
    ast_analyses: int = 0
    regex_analyses: int = 0
    cross_file_flows: int = 0
    errors: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    
    def to_dict(self) -> dict:
        duration = time.time() - self.start_time
        return {
            "duration_seconds": round(duration, 2),
            "files_analyzed": self.files_analyzed,
            "sources_found": self.sources_found,
            "sinks_found": self.sinks_found,
            "flows_traced": self.flows_traced,
            "flows_unsanitized": self.flows_unsanitized,
            "sanitization_rate": round(self.flows_sanitized / max(1, self.flows_traced), 2),
            "ast_analyses": self.ast_analyses,
            "regex_analyses": self.regex_analyses,
            "cross_file_flows": self.cross_file_flows,
            "errors": self.errors,
            "cache_efficiency": round(self.cache_hits / max(1, self.cache_hits + self.cache_misses), 2)
        }

# ────────────────────────────────────────────────────────────────────────────
# 4. Pattern Definitions (Optimized)
# ────────────────────────────────────────────────────────────────────────────

# Pre-compiled pattern storage
class PatternRegistry:
    _sources: Dict[str, List[Tuple[re.Pattern, dict]]] = {}
    _sinks: Dict[str, List[Tuple[re.Pattern, dict]]] = {}
    _sanitizers: Dict[str, List[Tuple[re.Pattern, dict]]] = {}
    _initialized = False
    
    @classmethod
    def initialize(cls):
        if cls._initialized:
            return
        
        # Sources
        raw_sources = {
            "python": [
                {"pattern": r"request\.args\.get\s*\(", "type": TaintType.HTTP_PARAM, "framework": "flask.request.args.get"},
                {"pattern": r"request\.form\.get\s*\(", "type": TaintType.HTTP_PARAM, "framework": "flask.request.form.get"},
                {"pattern": r"request\.json", "type": TaintType.HTTP_PARAM, "framework": "flask.request.json"},
                {"pattern": r"request\.GET\.get\s*\(", "type": TaintType.HTTP_PARAM, "framework": "django.request.GET"},
                {"pattern": r"request\.POST\.get\s*\(", "type": TaintType.HTTP_PARAM, "framework": "django.request.POST"},
                {"pattern": r"(?:Query|Path|Body|Header|Cookie|Form)\s*\(", "type": TaintType.HTTP_PARAM, "framework": "fastapi.params"},
                {"pattern": r"input\s*\(", "type": TaintType.USER_INPUT, "framework": "builtin.input"},
                {"pattern": r"sys\.argv", "type": TaintType.CLI_ARGUMENT, "framework": "sys.argv"},
                {"pattern": r"os\.environ\.get\s*\(", "type": TaintType.ENV_VARIABLE, "framework": "os.environ"},
                {"pattern": r"open\s*\(.+\)\.read", "type": TaintType.FILE_READ, "framework": "builtin.open"},
                {"pattern": r"pickle\.loads?\s*\(", "type": TaintType.DESERIALIZED, "framework": "pickle.load"},
                {"pattern": r"yaml\.(?:unsafe_)?load\s*\(", "type": TaintType.DESERIALIZED, "framework": "yaml.load"},
            ],
            "javascript": [
                {"pattern": r"req\.params\.", "type": TaintType.HTTP_PARAM, "framework": "express.req.params"},
                {"pattern": r"req\.query\.", "type": TaintType.HTTP_PARAM, "framework": "express.req.query"},
                {"pattern": r"req\.body\.", "type": TaintType.HTTP_PARAM, "framework": "express.req.body"},
                {"pattern": r"document\.location", "type": TaintType.USER_INPUT, "framework": "dom.location"},
                {"pattern": r"window\.location", "type": TaintType.USER_INPUT, "framework": "dom.window.location"},
                {"pattern": r"useSearchParams\s*\(", "type": TaintType.HTTP_PARAM, "framework": "next.useSearchParams"},
                {"pattern": r"process\.env\.", "type": TaintType.ENV_VARIABLE, "framework": "node.process.env"},
            ],
        }
        
        for lang, patterns in raw_sources.items():
            cls._sources[lang] = []
            for p in patterns:
                try:
                    cls._sources[lang].append((re.compile(p["pattern"], re.IGNORECASE), p))
                except re.error:
                    pass
        
        # Sinks
        raw_sinks = {
            "python": [
                {"pattern": r"cursor\.execute\s*\(\s*f['\"]", "vuln": VulnerabilityClass.SQL_INJECTION, "function": "cursor.execute (f-string)"},
                {"pattern": r"cursor\.execute\s*\(.+%\s", "vuln": VulnerabilityClass.SQL_INJECTION, "function": "cursor.execute (% format)"},
                {"pattern": r"os\.system\s*\(", "vuln": VulnerabilityClass.COMMAND_INJECTION, "function": "os.system"},
                {"pattern": r"subprocess\.(?:call|run|Popen)\s*\(.+shell\s*=\s*True", "vuln": VulnerabilityClass.COMMAND_INJECTION, "function": "subprocess (shell=True)"},
                {"pattern": r"eval\s*\(", "vuln": VulnerabilityClass.COMMAND_INJECTION, "function": "eval"},
                {"pattern": r"exec\s*\(", "vuln": VulnerabilityClass.COMMAND_INJECTION, "function": "exec"},
                {"pattern": r"open\s*\(\s*(?:os\.path\.join|f['\"])", "vuln": VulnerabilityClass.PATH_TRAVERSAL, "function": "open (user path)"},
                {"pattern": r"requests\.(?:get|post|put|patch|delete)\s*\(", "vuln": VulnerabilityClass.SSRF, "function": "requests (user URL)"},
                {"pattern": r"render_template_string\s*\(", "vuln": VulnerabilityClass.XSS_STORED, "function": "flask.render_template_string"},
                {"pattern": r"mark_safe\s*\(", "vuln": VulnerabilityClass.XSS_STORED, "function": "django.mark_safe"},
            ],
            "javascript": [
                {"pattern": r"\.query\s*\(\s*`", "vuln": VulnerabilityClass.SQL_INJECTION, "function": "db.query (template literal)"},
                {"pattern": r"child_process\.exec\s*\(", "vuln": VulnerabilityClass.COMMAND_INJECTION, "function": "child_process.exec"},
                {"pattern": r"eval\s*\(", "vuln": VulnerabilityClass.COMMAND_INJECTION, "function": "eval"},
                {"pattern": r"\.innerHTML\s*=", "vuln": VulnerabilityClass.XSS_DOM, "function": "element.innerHTML"},
                {"pattern": r"dangerouslySetInnerHTML", "vuln": VulnerabilityClass.XSS_REFLECTED, "function": "react.dangerouslySetInnerHTML"},
                {"pattern": r"fs\.readFile(?:Sync)?\s*\(", "vuln": VulnerabilityClass.PATH_TRAVERSAL, "function": "fs.readFile"},
                {"pattern": r"fetch\s*\(", "vuln": VulnerabilityClass.SSRF, "function": "fetch (user URL)"},
                {"pattern": r"res\.redirect\s*\(", "vuln": VulnerabilityClass.OPEN_REDIRECT, "function": "express.res.redirect"},
            ],
        }
        
        for lang, patterns in raw_sinks.items():
            cls._sinks[lang] = []
            for p in patterns:
                try:
                    cls._sinks[lang].append((re.compile(p["pattern"], re.IGNORECASE), p))
                except re.error:
                    pass
        
        # Sanitizers
        raw_sanitizers = {
            "python": [
                {"pattern": r"parameterized|%s|:\w+", "type": SanitizerType.PARAMETERIZED_QUERY, "neutralizes": [VulnerabilityClass.SQL_INJECTION]},
                {"pattern": r"escape\s*\(|html\.escape|bleach\.clean", "type": SanitizerType.HTML_ENCODING, "neutralizes": [VulnerabilityClass.XSS_REFLECTED, VulnerabilityClass.XSS_STORED]},
                {"pattern": r"shlex\.quote|shlex\.split", "type": SanitizerType.ESCAPING, "neutralizes": [VulnerabilityClass.COMMAND_INJECTION]},
                {"pattern": r"os\.path\.(?:basename|normpath|realpath)", "type": SanitizerType.PATH_NORMALIZATION, "neutralizes": [VulnerabilityClass.PATH_TRAVERSAL]},
                {"pattern": r"int\s*\(|float\s*\(|bool\s*\(", "type": SanitizerType.TYPE_COERCION, "neutralizes": [VulnerabilityClass.SQL_INJECTION, VulnerabilityClass.COMMAND_INJECTION]},
            ],
            "javascript": [
                {"pattern": r"DOMPurify\.sanitize|escapeHtml|textContent", "type": SanitizerType.HTML_ENCODING, "neutralizes": [VulnerabilityClass.XSS_DOM, VulnerabilityClass.XSS_REFLECTED]},
                {"pattern": r"encodeURIComponent|encodeURI", "type": SanitizerType.URL_ENCODING, "neutralizes": [VulnerabilityClass.OPEN_REDIRECT, VulnerabilityClass.SSRF]},
                {"pattern": r"parseInt|parseFloat|Number\s*\(", "type": SanitizerType.TYPE_COERCION, "neutralizes": [VulnerabilityClass.SQL_INJECTION, VulnerabilityClass.COMMAND_INJECTION]},
                {"pattern": r"path\.(?:normalize|resolve)", "type": SanitizerType.PATH_NORMALIZATION, "neutralizes": [VulnerabilityClass.PATH_TRAVERSAL]},
            ],
        }
        
        for lang, patterns in raw_sanitizers.items():
            cls._sanitizers[lang] = []
            for p in patterns:
                try:
                    cls._sanitizers[lang].append((re.compile(p["pattern"], re.IGNORECASE), p))
                except re.error:
                    pass
        
        cls._initialized = True
    
    @classmethod
    def get_sources(cls, lang: str) -> List[Tuple[re.Pattern, dict]]:
        cls.initialize()
        return cls._sources.get(lang, [])
    
    @classmethod
    def get_sinks(cls, lang: str) -> List[Tuple[re.Pattern, dict]]:
        cls.initialize()
        return cls._sinks.get(lang, [])
    
    @classmethod
    def get_sanitizers(cls, lang: str) -> List[Tuple[re.Pattern, dict]]:
        cls.initialize()
        return cls._sanitizers.get(lang, [])

# CWE & OWASP Mappings
VULN_CWE_MAP: Dict[VulnerabilityClass, Tuple[str, str]] = {
    VulnerabilityClass.SQL_INJECTION: ("CWE-89", "SQL Injection"),
    VulnerabilityClass.COMMAND_INJECTION: ("CWE-78", "OS Command Injection"),
    VulnerabilityClass.XSS_REFLECTED: ("CWE-79", "Cross-site Scripting (Reflected)"),
    VulnerabilityClass.XSS_STORED: ("CWE-79", "Cross-site Scripting (Stored)"),
    VulnerabilityClass.XSS_DOM: ("CWE-79", "Cross-site Scripting (DOM)"),
    VulnerabilityClass.PATH_TRAVERSAL: ("CWE-22", "Path Traversal"),
    VulnerabilityClass.SSRF: ("CWE-918", "Server-Side Request Forgery"),
    VulnerabilityClass.OPEN_REDIRECT: ("CWE-601", "Open Redirect"),
    VulnerabilityClass.INSECURE_DESERIALIZATION: ("CWE-502", "Insecure Deserialization"),
    VulnerabilityClass.TEMPLATE_INJECTION: ("CWE-1336", "Template Injection"),
    VulnerabilityClass.PROTOTYPE_POLLUTION: ("CWE-1321", "Prototype Pollution"),
    VulnerabilityClass.NOSQL_INJECTION: ("CWE-943", "NoSQL Injection"),
    VulnerabilityClass.BROKEN_AUTH: ("CWE-287", "Improper Authentication"),
    VulnerabilityClass.BROKEN_ACCESS: ("CWE-862", "Missing Authorization"),
    VulnerabilityClass.HARDCODED_SECRET: ("CWE-798", "Hardcoded Credentials"),
}

VULN_OWASP_MAP: Dict[VulnerabilityClass, str] = {
    VulnerabilityClass.BROKEN_ACCESS: "A01:2021 - Broken Access Control",
    VulnerabilityClass.CRYPTO_WEAKNESS: "A02:2021 - Cryptographic Failures",
    VulnerabilityClass.HARDCODED_SECRET: "A02:2021 - Cryptographic Failures",
    VulnerabilityClass.SQL_INJECTION: "A03:2021 - Injection",
    VulnerabilityClass.COMMAND_INJECTION: "A03:2021 - Injection",
    VulnerabilityClass.XSS_REFLECTED: "A03:2021 - Injection",
    VulnerabilityClass.XSS_STORED: "A03:2021 - Injection",
    VulnerabilityClass.XSS_DOM: "A03:2021 - Injection",
    VulnerabilityClass.SSRF: "A10:2021 - SSRF",
    VulnerabilityClass.INSECURE_DESERIALIZATION: "A08:2021 - Integrity Failures",
}

# ────────────────────────────────────────────────────────────────────────────
# 5. AST-Based Analysis Engine
# ────────────────────────────────────────────────────────────────────────────

class ASTTaintAnalyzer:
    """
    AST-based taint analysis for higher accuracy.
    Complements regex-based detection with semantic understanding.
    """
    
    def __init__(self, settings: DataFlowSettings, logger: StructuredLogger):
        self.settings = settings
        self.logger = logger
        self._scope_stack: List[str] = []
        self._variable_assignments: Dict[str, List[Tuple[int, str]]] = defaultdict(list)
    
    def analyze(self, content: str, file_path: str, language: str) -> Tuple[List[TaintSource], List[TaintSink], List[TaintPropagator]]:
        """Perform AST-based analysis on Python code."""
        if language != "python" or not self.settings.enable_ast_analysis:
            return [], [], []
        
        try:
            tree = ast.parse(content)
            sources, sinks, propagators = [], [], []
            
            self._variable_assignments.clear()
            self._scope_stack = []
            
            self._visit_node(tree, file_path, sources, sinks, propagators)
            
            return sources, sinks, propagators
            
        except SyntaxError as e:
            self.logger.debug(f"AST parse failed for {file_path}: {e}")
            return [], [], []
        except Exception as e:
            self.logger.error(f"AST analysis error for {file_path}: {e}")
            return [], [], []
    
    def _visit_node(self, node: ast.AST, file_path: str, 
                    sources: List[TaintSource], 
                    sinks: List[TaintSink], 
                    propagators: List[TaintPropagator]):
        """Recursively visit AST nodes."""
        
        # Track function scopes
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._scope_stack.append(node.name)
            for child in ast.iter_child_nodes(node):
                self._visit_node(child, file_path, sources, sinks, propagators)
            self._scope_stack.pop()
            return
        
        # Detect sources
        source = self._check_source_node(node, file_path)
        if source:
            sources.append(source)
        
        # Detect sinks
        sink = self._check_sink_node(node, file_path)
        if sink:
            sinks.append(sink)
        
        # Detect propagators (assignments, function calls)
        propagator = self._check_propagator_node(node, file_path)
        if propagator:
            propagators.append(propagator)
        
        # Recurse
        for child in ast.iter_child_nodes(node):
            self._visit_node(child, file_path, sources, sinks, propagators)
    
    def _check_source_node(self, node: ast.AST, file_path: str) -> Optional[TaintSource]:
        """Check if AST node represents a taint source."""
        current_scope = self._scope_stack[-1] if self._scope_stack else None
        
        # Check for function calls
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
                # Flask/Django request objects
                if func_name in ("get", "GET", "POST", "json", "form", "args", "headers", "cookies"):
                    if isinstance(node.func.value, ast.Name) and node.func.value.id == "request":
                        return TaintSource(
                            file=file_path,
                            line=node.lineno,
                            column=node.col_offset,
                            variable="_request_data",
                            taint_type=TaintType.HTTP_PARAM,
                            framework_api=f"request.{func_name}",
                            snippet=ast.unparse(node) if hasattr(ast, 'unparse') else "",
                            scope=current_scope,
                            ast_node_type="Call"
                        )
            # Check for input()
            if isinstance(node.func, ast.Name) and node.func.id == "input":
                return TaintSource(
                    file=file_path,
                    line=node.lineno,
                    column=node.col_offset,
                    variable="_user_input",
                    taint_type=TaintType.USER_INPUT,
                    framework_api="builtin.input",
                    snippet=ast.unparse(node) if hasattr(ast, 'unparse') else "",
                    scope=current_scope,
                    ast_node_type="Call"
                )
        
        # Check for subscript access (e.g., request.args['key'])
        if isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Attribute):
                if node.value.attr in ("args", "form", "GET", "POST", "headers", "cookies"):
                    return TaintSource(
                        file=file_path,
                        line=node.lineno,
                        column=node.col_offset,
                        variable="_request_data",
                        taint_type=TaintType.HTTP_PARAM,
                        framework_api=f"request.{node.value.attr}",
                        snippet=ast.unparse(node) if hasattr(ast, 'unparse') else "",
                        scope=current_scope,
                        ast_node_type="Subscript"
                    )
        
        return None
    
    def _check_sink_node(self, node: ast.AST, file_path: str) -> Optional[TaintSink]:
        """Check if AST node represents a taint sink."""
        current_scope = self._scope_stack[-1] if self._scope_stack else None
        
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
                # SQL execution
                if func_name == "execute":
                    # Check if first argument is f-string or format
                    if node.args and self._is_unsafe_string(node.args[0]):
                        return TaintSink(
                            file=file_path,
                            line=node.lineno,
                            column=node.col_offset,
                            function="cursor.execute",
                            vuln_class=VulnerabilityClass.SQL_INJECTION,
                            framework_api="db.cursor.execute",
                            snippet=ast.unparse(node) if hasattr(ast, 'unparse') else "",
                            scope=current_scope,
                            ast_node_type="Call"
                        )
                # OS command
                if func_name in ("system", "popen"):
                    if isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                        return TaintSink(
                            file=file_path,
                            line=node.lineno,
                            column=node.col_offset,
                            function=f"os.{func_name}",
                            vuln_class=VulnerabilityClass.COMMAND_INJECTION,
                            framework_api="os.system",
                            snippet=ast.unparse(node) if hasattr(ast, 'unparse') else "",
                            scope=current_scope,
                            ast_node_type="Call"
                        )
                # Eval/Exec
                if func_name in ("eval", "exec"):
                    return TaintSink(
                        file=file_path,
                        line=node.lineno,
                        column=node.col_offset,
                        function=func_name,
                        vuln_class=VulnerabilityClass.COMMAND_INJECTION,
                        framework_api=f"builtin.{func_name}",
                        snippet=ast.unparse(node) if hasattr(ast, 'unparse') else "",
                        scope=current_scope,
                        ast_node_type="Call"
                    )
        
        return None
    
    def _check_propagator_node(self, node: ast.AST, file_path: str) -> Optional[TaintPropagator]:
        """Check if AST node propagates taint."""
        if isinstance(node, ast.Assign):
            targets = []
            for target in node.targets:
                if isinstance(target, ast.Name):
                    targets.append(target.id)
            
            return TaintPropagator(
                file=file_path,
                line=node.lineno,
                function="assignment",
                transforms_taint=True,
                is_sanitizer=False,
                source_vars=[],
                sink_vars=targets
            )
        return None
    
    def _is_unsafe_string(self, node: ast.AST) -> bool:
        """Check if a string node is unsafe (f-string, format, %)."""
        if isinstance(node, ast.JoinedStr):  # f-string
            return True
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            return True
        return False

# ────────────────────────────────────────────────────────────────────────────
# 6. Cross-File Taint Tracker
# ────────────────────────────────────────────────────────────────────────────

class CrossFileTaintTracker:
    """
    Tracks taint propagation across file boundaries.
    Essential for detecting vulnerabilities in multi-module applications.
    """
    
    def __init__(self, settings: DataFlowSettings, logger: StructuredLogger):
        self.settings = settings
        self.logger = logger
        self._function_signatures: Dict[str, Dict[str, Any]] = {}
        self._import_map: Dict[str, Set[str]] = defaultdict(set)
        self._exported_sources: List[TaintSource] = []
        self._exported_sinks: List[TaintSink] = []
    
    def register_file(self, file_path: str, sources: List[TaintSource], 
                      sinks: List[TaintSink], functions: Dict[str, Dict]):
        """Register a file's taint information for cross-file analysis."""
        for source in sources:
            if source.scope:
                self._exported_sources.append(source)
        
        for sink in sinks:
            if sink.scope:
                self._exported_sinks.append(sink)
        
        self._function_signatures.update(functions)
    
    def find_cross_file_flows(self, file_sources: List[TaintSource], 
                              file_sinks: List[TaintSink]) -> List[TaintFlow]:
        """Find taint flows that cross file boundaries."""
        flows = []
        
        if not self.settings.enable_cross_file_analysis:
            return flows
        
        # Match exported sources to local sinks
        for source in self._exported_sources:
            for sink in file_sinks:
                if source.file != sink.file:
                    flow = self._create_cross_file_flow(source, sink)
                    if flow:
                        flows.append(flow)
        
        # Match local sources to exported sinks
        for source in file_sources:
            for sink in self._exported_sinks:
                if source.file != sink.file:
                    flow = self._create_cross_file_flow(source, sink)
                    if flow:
                        flows.append(flow)
        
        return flows
    
    def _create_cross_file_flow(self, source: TaintSource, sink: TaintSink) -> Optional[TaintFlow]:
        """Create a cross-file taint flow."""
        # Basic heuristic: same vulnerability class potential
        if source.taint_type in (TaintType.HTTP_PARAM, TaintType.USER_INPUT):
            if sink.vuln_class in (VulnerabilityClass.SQL_INJECTION, 
                                   VulnerabilityClass.COMMAND_INJECTION,
                                   VulnerabilityClass.XSS_REFLECTED,
                                   VulnerabilityClass.SSRF):
                return TaintFlow(
                    source=source,
                    sink=sink,
                    propagators=[],
                    is_sanitized=False,
                    sanitization_gaps=["Cross-file analysis - sanitization may exist in intermediate files"],
                    cross_file=True
                )
        return None

# ────────────────────────────────────────────────────────────────────────────
# 7. Main Data Flow Graph Engine
# ────────────────────────────────────────────────────────────────────────────

class DataFlowGraph:
    """
    Enterprise Data Flow Graph for Taint Analysis.
    
    Features:
    - Hybrid analysis (Regex + AST)
    - Cross-file taint tracking
    - Parallel processing
    - Result caching
    - Comprehensive metrics
    """
    
    def __init__(self, settings: Optional[DataFlowSettings] = None):
        self.settings = settings or DataFlowSettings()
        self.logger = StructuredLogger("DataFlowGraph", self.settings)
        self.metrics = AnalysisMetrics()
        
        # Initialize pattern registry
        PatternRegistry.initialize()
        
        # Initialize components
        self.ast_analyzer = ASTTaintAnalyzer(self.settings, self.logger)
        self.cross_file_tracker = CrossFileTaintTracker(self.settings, self.logger)
        
        # Storage
        self.sources: List[TaintSource] = []
        self.sinks: List[TaintSink] = []
        self.propagators: List[TaintPropagator] = []
        self.flows: List[TaintFlow] = []
        
        # Cache
        self._cache: Dict[str, Tuple[List[TaintSource], List[TaintSink], List[TaintPropagator]]] = {}
        self._cache_timestamps: Dict[str, float] = {}
    
    def _get_cache_key(self, content: str, file_path: str, language: str) -> str:
        """Generate cache key for file analysis."""
        content_hash = hashlib.md5(content.encode()).hexdigest()
        return f"{file_path}:{content_hash}:{language}"
    
    def _get_from_cache(self, key: str) -> Optional[Tuple[List[TaintSource], List[TaintSink], List[TaintPropagator]]]:
        """Retrieve from cache if valid."""
        if not self.settings.cache_enabled:
            return None
        
        if key in self._cache:
            age = time.time() - self._cache_timestamps.get(key, 0)
            if age < self.settings.cache_ttl_seconds:
                self.metrics.cache_hits += 1
                return self._cache[key]
        
        self.metrics.cache_misses += 1
        return None
    
    def _store_in_cache(self, key: str, value: Tuple[List[TaintSource], List[TaintSink], List[TaintPropagator]]):
        """Store analysis result in cache."""
        if self.settings.cache_enabled:
            self._cache[key] = value
            self._cache_timestamps[key] = time.time()
    
    def analyze_file(
        self,
        content: str,
        file_path: str,
        language: str,
        context_window: int = 5,
    ) -> List[TaintFlow]:
        """
        Analyze a single file for taint flows.
        
        Enterprise Features:
        - Timeout protection
        - Caching
        - Hybrid analysis (Regex + AST)
        - Error isolation
        """
        start_time = time.time()
        norm_lang = self._normalize_language(language)
        lines = content.splitlines()
        flows: List[TaintFlow] = []
        
        # Check file size
        if len(content) > self.settings.max_file_size:
            self.logger.warning(f"File skipped (too large): {file_path}")
            return flows
        
        # Check cache
        cache_key = self._get_cache_key(content, file_path, norm_lang)
        cached = self._get_from_cache(cache_key)
        if cached:
            file_sources, file_sinks, file_sanitizers = cached
        else:
            try:
                # Phase 1: Regex-based discovery (fast)
                file_sources = self._find_sources_regex(content, lines, file_path, norm_lang)
                file_sinks = self._find_sinks_regex(content, lines, file_path, norm_lang)
                file_sanitizers = self._find_sanitizers_regex(content, lines, file_path, norm_lang)
                
                # Phase 2: AST-based discovery (accurate)
                if self.settings.enable_ast_analysis and norm_lang == "python":
                    ast_sources, ast_sinks, ast_propagators = self.ast_analyzer.analyze(
                        content, file_path, norm_lang
                    )
                    self.metrics.ast_analyses += 1
                    
                    # Merge AST findings with regex findings
                    file_sources.extend(ast_sources)
                    file_sinks.extend(ast_sinks)
                    self.propagators.extend(ast_propagators)
                else:
                    self.metrics.regex_analyses += 1
                
                # Store in cache
                self._store_in_cache(cache_key, (file_sources, file_sinks, file_sanitizers))
                
            except Exception as e:
                self.metrics.errors += 1
                self.logger.error(f"Analysis failed for {file_path}: {e}")
                return flows
        
        # Update metrics
        self.metrics.sources_found += len(file_sources)
        self.metrics.sinks_found += len(file_sinks)
        self.metrics.files_analyzed += 1
        
        # Register for cross-file analysis
        self.cross_file_tracker.register_file(
            file_path, file_sources, file_sinks, 
            self._extract_function_signatures(content, norm_lang)
        )
        
        # Phase 3: Build flows
        for source in file_sources:
            for sink in file_sinks:
                # Timeout check
                if time.time() - start_time > self.settings.analysis_timeout_seconds:
                    self.logger.warning(f"Analysis timeout for {file_path}")
                    break
                
                flow = self._trace_flow(
                    source, sink, file_sanitizers, content, lines,
                    file_path, context_window
                )
                if flow:
                    flows.append(flow)
        
        # Phase 4: Cross-file flows
        if self.settings.enable_cross_file_analysis:
            cross_flows = self.cross_file_tracker.find_cross_file_flows(file_sources, file_sinks)
            flows.extend(cross_flows)
            self.metrics.cross_file_flows += len(cross_flows)
        
        # Update global state
        self.sources.extend(file_sources)
        self.sinks.extend(file_sinks)
        self.flows.extend(flows)
        
        # Update flow metrics
        self.metrics.flows_traced += len(flows)
        self.metrics.flows_sanitized += sum(1 for f in flows if f.is_sanitized)
        self.metrics.flows_unsanitized += sum(1 for f in flows if not f.is_sanitized)
        
        return flows
    
    def analyze_directory(self, root_path: str, file_extensions: Optional[List[str]] = None) -> List[TaintFlow]:
        """
        Analyze all files in a directory with parallel processing.
        """
        if file_extensions is None:
            file_extensions = ['.py', '.js', '.ts', '.java', '.go']
        
        files = []
        for path in Path(root_path).rglob('*'):
            if path.is_file() and path.suffix in file_extensions:
                files.append(str(path))
        
        all_flows = []
        
        with ProcessPoolExecutor(max_workers=self.settings.max_workers) as executor:
            future_to_file = {}
            
            for file_path in files:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    lang = path.suffix.replace('.', '')
                    future = executor.submit(self.analyze_file, content, file_path, lang)
                    future_to_file[future] = file_path
                    
                except Exception as e:
                    self.metrics.errors += 1
                    self.logger.error(f"Failed to read {file_path}: {e}")
            
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    flows = future.result()
                    all_flows.extend(flows)
                except Exception as e:
                    self.metrics.errors += 1
                    self.logger.error(f"Analysis failed for {file_path}: {e}")
        
        return all_flows
    
    def _normalize_language(self, language: str) -> str:
        """Normalize language name."""
        lang_lower = language.lower()
        if lang_lower in ("javascript", "typescript", "jsx", "tsx"):
            return "javascript"
        if lang_lower in ("python", "py"):
            return "python"
        if lang_lower in ("java", "kotlin"):
            return "java"
        if lang_lower in ("go", "golang"):
            return "go"
        return lang_lower
    
    def _find_sources_regex(self, content: str, lines: List[str], 
                            file_path: str, language: str) -> List[TaintSource]:
        """Find taint sources using regex patterns."""
        sources = []
        compiled = PatternRegistry.get_sources(language)
        
        for regex, meta in compiled:
            try:
                for match in regex.finditer(content):
                    line_no = content[:match.start()].count("\n") + 1
                    col = match.start() - content.rfind("\n", 0, match.start()) - 1
                    raw_line = lines[line_no - 1] if line_no <= len(lines) else ""
                    variable = self._extract_variable(raw_line, match.group())
                    
                    source = TaintSource(
                        file=file_path,
                        line=line_no,
                        column=col,
                        variable=variable,
                        taint_type=meta["type"],
                        framework_api=meta.get("framework"),
                        snippet=raw_line.strip(),
                    )
                    sources.append(source)
            except Exception:
                continue
        
        return sources
    
    def _find_sinks_regex(self, content: str, lines: List[str], 
                          file_path: str, language: str) -> List[TaintSink]:
        """Find taint sinks using regex patterns."""
        sinks = []
        compiled = PatternRegistry.get_sinks(language)
        
        for regex, meta in compiled:
            try:
                for match in regex.finditer(content):
                    line_no = content[:match.start()].count("\n") + 1
                    col = match.start() - content.rfind("\n", 0, match.start()) - 1
                    raw_line = lines[line_no - 1] if line_no <= len(lines) else ""
                    
                    sink = TaintSink(
                        file=file_path,
                        line=line_no,
                        column=col,
                        function=meta["function"],
                        vuln_class=meta["vuln"],
                        framework_api=meta.get("framework"),
                        snippet=raw_line.strip(),
                    )
                    sinks.append(sink)
            except Exception:
                continue
        
        return sinks
    
    def _find_sanitizers_regex(self, content: str, lines: List[str], 
                               file_path: str, language: str) -> List[TaintPropagator]:
        """Find sanitizers using regex patterns."""
        sanitizers = []
        compiled = PatternRegistry.get_sanitizers(language)
        
        for regex, meta in compiled:
            try:
                for match in regex.finditer(content):
                    line_no = content[:match.start()].count("\n") + 1
                    
                    sanitizer = TaintPropagator(
                        file=file_path,
                        line=line_no,
                        function=match.group(),
                        transforms_taint=True,
                        is_sanitizer=True,
                        sanitizer_type=meta["type"],
                    )
                    sanitizers.append(sanitizer)
            except Exception:
                continue
        
        return sanitizers
    
    def _trace_flow(self, source: TaintSource, sink: TaintSink, 
                    sanitizers: List[TaintPropagator], content: str,
                    lines: List[str], file_path: str, 
                    context_window: int) -> Optional[TaintFlow]:
        """Trace a potential flow from source to sink."""
        if source.file != sink.file:
            return None
        if source.line >= sink.line:
            return None
        
        source_var = source.variable
        if not source_var or source_var == "_unknown_":
            return None
        
        # Check variable usage
        relevant_lines = lines[source.line:sink.line]
        relevant_text = "\n".join(relevant_lines)
        sink_line = lines[sink.line - 1] if sink.line <= len(lines) else ""
        
        if source_var not in sink_line and source_var not in relevant_text:
            return None
        
        # Check sanitizers
        active_sanitizers = [s for s in sanitizers if source.line <= s.line <= sink.line]
        
        is_sanitized = False
        sanitization_gaps = []
        
        for sanitizer in active_sanitizers:
            if sanitizer.sanitizer_type:
                lang_sanitizers = PatternRegistry.get_sanitizers(
                    self._normalize_language(Path(file_path).suffix)
                )
                for pattern_meta in lang_sanitizers:
                    if pattern_meta["type"] == sanitizer.sanitizer_type:
                        neutralized = pattern_meta.get("neutralizes", [])
                        if sink.vuln_class in neutralized:
                            is_sanitized = True
                            break
                if is_sanitized:
                    break
        
        if not is_sanitized and not active_sanitizers:
            sanitization_gaps.append(
                f"No sanitization found between source (line {source.line}) and sink (line {sink.line})"
            )
        
        return TaintFlow(
            source=source,
            sink=sink,
            propagators=active_sanitizers,
            is_sanitized=is_sanitized,
            sanitization_gaps=sanitization_gaps,
        )
    
    @staticmethod
    def _extract_variable(line: str, match_text: str) -> str:
        """Extract variable name from assignment."""
        assign_match = re.match(r"\s*(\w+)\s*=\s*", line)
        if assign_match:
            return assign_match.group(1)
        
        typed_match = re.match(r"\s*(?:var|let|const|val)\s+(\w+)", line)
        if typed_match:
            return typed_match.group(1)
        
        return "_unknown_"
    
    def _extract_function_signatures(self, content: str, language: str) -> Dict[str, Dict]:
        """Extract function signatures for cross-file analysis."""
        signatures = {}
        if language != "python":
            return signatures
        
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    signatures[node.name] = {
                        "args": [arg.arg for arg in node.args.args],
                        "line": node.lineno,
                    }
        except SyntaxError:
            pass
        
        return signatures
    
    def get_flow_summary(self) -> dict:
        """Get summary statistics."""
        total = len(self.flows)
        unsanitized = sum(1 for f in self.flows if not f.is_sanitized)
        by_vuln: Dict[str, int] = {}
        
        for flow in self.flows:
            if not flow.is_sanitized:
                vc = flow.sink.vuln_class.value
                by_vuln[vc] = by_vuln.get(vc, 0) + 1
        
        return {
            "total_flows": total,
            "unsanitized_flows": unsanitized,
            "sanitized_flows": total - unsanitized,
            "flows_by_vulnerability": by_vuln,
            "total_sources": len(self.sources),
            "total_sinks": len(self.sinks),
            "total_sanitizers": len(self.propagators),
        }
    
    def get_metrics(self) -> dict:
        """Get analysis metrics."""
        return self.metrics.to_dict()
    
    def reset(self) -> None:
        """Reset all discovered data."""
        self.sources.clear()
        self.sinks.clear()
        self.propagators.clear()
        self.flows.clear()
        self.metrics = AnalysisMetrics()
        if self.settings.cache_enabled:
            self._cache.clear()
            self._cache_timestamps.clear()

# ────────────────────────────────────────────────────────────────────────────
# 8. Entry Point & Integration
# ────────────────────────────────────────────────────────────────────────────

def main():
    """CLI entry point for standalone usage."""
    import sys
    
    settings = DataFlowSettings()
    dfg = DataFlowGraph(settings)
    
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    
    print(f"Starting Data Flow Analysis on: {target}")
    print(f"Settings: max_workers={settings.max_workers}, ast_enabled={settings.enable_ast_analysis}")
    
    try:
        flows = dfg.analyze_directory(target)
        
        print(f"\n{'='*60}")
        print("ANALYSIS COMPLETE")
        print(f"{'='*60}")
        print(f"Total Flows: {len(flows)}")
        print(f"Unsanitized: {sum(1 for f in flows if not f.is_sanitized)}")
        print(f"Sanitized: {sum(1 for f in flows if f.is_sanitized)}")
        print(f"Cross-File: {dfg.metrics.cross_file_flows}")
        
        print(f"\n{'='*60}")
        print("METRICS")
        print(f"{'='*60}")
        print(json.dumps(dfg.get_metrics(), indent=2))
        
        # Output top findings
        print(f"\n{'='*60}")
        print("TOP FINDINGS")
        print(f"{'='*60}")
        
        unsanitized = [f for f in flows if not f.is_sanitized]
        unsanitized.sort(key=lambda x: x.confidence, reverse=True)
        
        for flow in unsanitized[:10]:
            print(f"\n[{flow.sink.vuln_class.value}] {flow.source.file}:{flow.source.line} → {flow.sink.file}:{flow.sink.line}")
            print(f"  Confidence: {flow.confidence:.2f}")
            print(f"  Source: {flow.source.framework_api}")
            print(f"  Sink: {flow.sink.function}")
            if flow.sanitization_gaps:
                print(f"  Gap: {flow.sanitization_gaps[0]}")
        
        # Exit code for CI/CD
        if any(f.sink.vuln_class in (VulnerabilityClass.SQL_INJECTION, 
                                     VulnerabilityClass.COMMAND_INJECTION) 
               and not f.is_sanitized for f in flows):
            sys.exit(1)
        
    except KeyboardInterrupt:
        print("\nAnalysis interrupted.")
        sys.exit(130)
    except Exception as e:
        print(f"Critical Error: {e}")
        traceback.print_exc()
        sys.exit(2)

if __name__ == "__main__":
    main()
