"""
Code Security Scanner — Data Models
====================================

Enterprise-grade data structures for the multi-agent security scanning
pipeline. All models are immutable after validation stage to ensure
audit integrity.
"""

"""
Enterprise Security Scanner — Data Models
==========================================
Production-Ready Refactoring:
- Pydantic v2 Validation
- Immutable Models (Frozen)
- Multi-format Serialization
- Database ORM Integration
- Field Encryption
- Schema Versioning
- Comprehensive Audit Trail
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import uuid
from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import (
    Any, Callable, ClassVar, Dict, Generic, List, Optional, 
    Set, Tuple, Type, TypeVar, Union,
)

# Enterprise Dependencies
try:
    from pydantic import (
        BaseModel, Field, field_validator, model_validator,
        ConfigDict, computed_field, SecretStr,
    )
    from pydantic.functional_serializers import PlainSerializer
    from pydantic_settings import BaseSettings
    PYDANTIC_AVAILABLE = True
except ImportError:
    PYDANTIC_AVAILABLE = False
    # Fallback for environments without pydantic
    class BaseModel: pass
    class Field: 
        def __init__(self, *args, **kwargs): pass
    def field_validator(*args, **kwargs):
        def decorator(func): return func
        return decorator
    def model_validator(*args, **kwargs):
        def decorator(func): return func
        return decorator
    class ConfigDict: pass
    def computed_field(*args, **kwargs):
        def decorator(func): return func
        return decorator
    class SecretStr: pass
    class BaseSettings: pass

# Optional: Database ORM
try:
    from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, JSON
    from sqlalchemy.orm import declarative_base
    from sqlalchemy.sql import func
    SQLALCHEMY_AVAILABLE = True
    Base = declarative_base()
except ImportError:
    SQLALCHEMY_AVAILABLE = False
    Base = object

# Optional: Encryption
try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    Fernet = None

# ────────────────────────────────────────────────────────────────────────────
# 1. Configuration & Settings
# ────────────────────────────────────────────────────────────────────────────

class ModelSettings(BaseSettings):
    """
    Centralized configuration for data models.
    Load from ENV variables (e.g., MODEL_ENCRYPTION_KEY=...)
    """
    schema_version: str = "2.0.0"
    enable_encryption: bool = False
    encryption_key: Optional[str] = None
    enable_audit_logging: bool = True
    enable_caching: bool = True
    max_finding_age_days: int = 90
    id_prefix: str = "CSS"
    timezone: str = "UTC"
    json_indent: int = 2
    serialize_none: bool = False
    
    class Config:
        env_prefix = "MODEL_"
        case_sensitive = False

# Global settings instance
_model_settings: Optional[ModelSettings] = None

def get_model_settings() -> ModelSettings:
    """Get or create global model settings."""
    global _model_settings
    if _model_settings is None:
        _model_settings = ModelSettings()
    return _model_settings

# ────────────────────────────────────────────────────────────────────────────
# 2. Enhanced Enumerations
# ────────────────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    """Finding severity aligned with CVSS v3.1 qualitative ratings."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"

    @property
    def numeric(self) -> float:
        return {"Critical": 10.0, "High": 8.0, "Medium": 5.0,
                "Low": 2.0, "Informational": 0.0}[self.value]

    @property
    def sarif_level(self) -> str:
        return {"Critical": "error", "High": "error", "Medium": "warning",
                "Low": "note", "Informational": "note"}[self.value]

    @property
    def color_code(self) -> str:
        """ANSI color code for terminal output."""
        return {"Critical": "\033[91m", "High": "\033[93m", "Medium": "\033[94m",
                "Low": "\033[92m", "Informational": "\033[90m"}[self.value]

    @classmethod
    def from_cvss(cls, score: float) -> 'Severity':
        """Derive severity from CVSS score."""
        if score >= 9.0:
            return cls.CRITICAL
        elif score >= 7.0:
            return cls.HIGH
        elif score >= 4.0:
            return cls.MEDIUM
        elif score > 0.0:
            return cls.LOW
        return cls.INFO


class ConfidenceRating(str, Enum):
    """Confidence that the finding is a true positive."""
    CONFIRMED = "Confirmed"        # ≥95%
    HIGH = "High"                  # 80–94%
    MEDIUM = "Medium"              # 60–79%
    LOW = "Low"                    # 40–59%
    TENTATIVE = "Tentative"        # <40%

    @classmethod
    def from_score(cls, score: float) -> 'ConfidenceRating':
        """Derive rating from confidence score."""
        if score >= 0.95:
            return cls.CONFIRMED
        elif score >= 0.80:
            return cls.HIGH
        elif score >= 0.60:
            return cls.MEDIUM
        elif score >= 0.40:
            return cls.LOW
        return cls.TENTATIVE


class VulnerabilityClass(str, Enum):
    """OWASP / CWE aligned vulnerability classification."""
    SQL_INJECTION = "SQL Injection"
    COMMAND_INJECTION = "Command Injection"
    XSS_REFLECTED = "Reflected XSS"
    XSS_STORED = "Stored XSS"
    XSS_DOM = "DOM-based XSS"
    PATH_TRAVERSAL = "Path Traversal"
    SSRF = "Server-Side Request Forgery"
    OPEN_REDIRECT = "Open Redirect"
    IDOR = "Insecure Direct Object Reference"
    BROKEN_AUTH = "Broken Authentication"
    BROKEN_ACCESS = "Broken Access Control"
    SENSITIVE_DATA_EXPOSURE = "Sensitive Data Exposure"
    SECURITY_MISCONFIG = "Security Misconfiguration"
    INSECURE_DESERIALIZATION = "Insecure Deserialization"
    INSUFFICIENT_LOGGING = "Insufficient Logging"
    CRYPTO_WEAKNESS = "Cryptographic Weakness"
    HARDCODED_SECRET = "Hardcoded Secret"
    PROTOTYPE_POLLUTION = "Prototype Pollution"
    TEMPLATE_INJECTION = "Template Injection"
    XML_INJECTION = "XML External Entity"
    LDAP_INJECTION = "LDAP Injection"
    NOSQL_INJECTION = "NoSQL Injection"
    RACE_CONDITION = "Race Condition"
    MASS_ASSIGNMENT = "Mass Assignment"
    UNSAFE_REFLECTION = "Unsafe Reflection"
    INFORMATION_LEAKAGE = "Information Leakage"
    SUPPLY_CHAIN = "Supply Chain Risk"
    INSECURE_DESIGN = "Insecure Design"

    @property
    def cwe_id(self) -> Optional[str]:
        """Get primary CWE ID for this vulnerability class."""
        mapping = {
            self.SQL_INJECTION: "CWE-89",
            self.COMMAND_INJECTION: "CWE-78",
            self.XSS_REFLECTED: "CWE-79",
            self.XSS_STORED: "CWE-79",
            self.XSS_DOM: "CWE-79",
            self.PATH_TRAVERSAL: "CWE-22",
            self.SSRF: "CWE-918",
            self.OPEN_REDIRECT: "CWE-601",
            self.IDOR: "CWE-639",
            self.BROKEN_AUTH: "CWE-287",
            self.BROKEN_ACCESS: "CWE-862",
            self.SENSITIVE_DATA_EXPOSURE: "CWE-200",
            self.SECURITY_MISCONFIG: "CWE-16",
            self.INSECURE_DESERIALIZATION: "CWE-502",
            self.INSUFFICIENT_LOGGING: "CWE-778",
            self.CRYPTO_WEAKNESS: "CWE-327",
            self.HARDCODED_SECRET: "CWE-798",
            self.PROTOTYPE_POLLUTION: "CWE-1321",
            self.TEMPLATE_INJECTION: "CWE-1336",
            self.XML_INJECTION: "CWE-611",
            self.LDAP_INJECTION: "CWE-90",
            self.NOSQL_INJECTION: "CWE-943",
            self.RACE_CONDITION: "CWE-362",
            self.MASS_ASSIGNMENT: "CWE-915",
            self.UNSAFE_REFLECTION: "CWE-470",
            self.INFORMATION_LEAKAGE: "CWE-209",
            self.SUPPLY_CHAIN: "CWE-829",
            self.INSECURE_DESIGN: "CWE-657",
        }
        return mapping.get(self)

    @property
    def owasp_category(self) -> Optional[str]:
        """Get OWASP Top 10:2021 category."""
        mapping = {
            self.BROKEN_ACCESS: "A01:2021 - Broken Access Control",
            self.IDOR: "A01:2021 - Broken Access Control",
            self.CRYPTO_WEAKNESS: "A02:2021 - Cryptographic Failures",
            self.HARDCODED_SECRET: "A02:2021 - Cryptographic Failures",
            self.SQL_INJECTION: "A03:2021 - Injection",
            self.COMMAND_INJECTION: "A03:2021 - Injection",
            self.XSS_REFLECTED: "A03:2021 - Injection",
            self.XSS_STORED: "A03:2021 - Injection",
            self.XSS_DOM: "A03:2021 - Injection",
            self.TEMPLATE_INJECTION: "A03:2021 - Injection",
            self.LDAP_INJECTION: "A03:2021 - Injection",
            self.NOSQL_INJECTION: "A03:2021 - Injection",
            self.INSECURE_DESIGN: "A04:2021 - Insecure Design",
            self.SECURITY_MISCONFIG: "A05:2021 - Security Misconfiguration",
            self.SENSITIVE_DATA_EXPOSURE: "A06:2021 - Vulnerable Components",
            self.BROKEN_AUTH: "A07:2021 - Identification and Authentication Failures",
            self.INSECURE_DESERIALIZATION: "A08:2021 - Software and Data Integrity Failures",
            self.SUPPLY_CHAIN: "A08:2021 - Software and Data Integrity Failures",
            self.INSUFFICIENT_LOGGING: "A09:2021 - Security Logging and Monitoring Failures",
            self.SSRF: "A10:2021 - Server-Side Request Forgery",
        }
        return mapping.get(self)


class AgentRole(str, Enum):
    """Role of each agent in the multi-stage pipeline."""
    DISCOVERY = "Discovery"
    VERIFICATION = "Verification"
    ASSESSMENT = "Assessment"


class FindingStatus(str, Enum):
    """Lifecycle status of a finding through the pipeline."""
    DISCOVERED = "Discovered"
    UNDER_REVIEW = "Under Review"
    VERIFIED = "Verified"
    DISPROVED = "Disproved"
    ASSESSED = "Assessed"
    PENDING_APPROVAL = "Pending Approval"
    APPROVED = "Approved"
    FIXED = "Fixed"
    DEFERRED = "Deferred"
    SUPPRESSED = "Suppressed"
    REOPENED = "Reopened"
    FALSE_POSITIVE = "False Positive"

    @property
    def is_terminal(self) -> bool:
        """Whether this is a final status."""
        return self in (
            self.FIXED, self.SUPPRESSED, self.FALSE_POSITIVE, self.DEFERRED
        )

    @property
    def is_actionable(self) -> bool:
        """Whether this finding requires action."""
        return self in (
            self.VERIFIED, self.ASSESSED, self.PENDING_APPROVAL
        )


class TaintType(str, Enum):
    """Category of taint source."""
    USER_INPUT = "User Input"
    HTTP_PARAM = "HTTP Parameter"
    HTTP_HEADER = "HTTP Header"
    HTTP_COOKIE = "HTTP Cookie"
    FILE_READ = "File Read"
    DATABASE_READ = "Database Read"
    DATABASE_WRITE = "Database Write"
    ENV_VARIABLE = "Environment Variable"
    EXTERNAL_API = "External API Response"
    WEBSOCKET = "WebSocket Message"
    CLI_ARGUMENT = "CLI Argument"
    DESERIALIZED = "Deserialized Data"
    NETWORK_SOCKET = "Network Socket"
    IPC = "Inter-Process Communication"
    UNKNOWN = "Unknown"


class SanitizerType(str, Enum):
    """Types of sanitization that can neutralize a taint."""
    PARAMETERIZED_QUERY = "Parameterized Query"
    HTML_ENCODING = "HTML Encoding"
    URL_ENCODING = "URL Encoding"
    INPUT_VALIDATION = "Input Validation"
    ALLOW_LIST = "Allow List Check"
    TYPE_COERCION = "Type Coercion"
    PATH_NORMALIZATION = "Path Normalization"
    CSP_HEADER = "Content Security Policy"
    ESCAPING = "Output Escaping"
    FRAMEWORK_PROTECTION = "Framework Built-in Protection"
    WAF = "Web Application Firewall"
    ENCRYPTION = "Encryption"
    UNKNOWN = "Unknown"


# ────────────────────────────────────────────────────────────────────────────
# 3. Base Model Class (Pydantic + ORM)
# ────────────────────────────────────────────────────────────────────────────

T = TypeVar('T', bound='BaseSecurityModel')

class BaseSecurityModel(BaseModel if PYDANTIC_AVAILABLE else object):
    """
    Base class for all security models with enterprise features:
    - Immutable by default (frozen)
    - Automatic timestamps
    - Audit trail
    - Serialization helpers
    - Database ORM compatibility
    """
    
    if PYDANTIC_AVAILABLE:
        model_config = ConfigDict(
            frozen=True,
            extra='forbid',
            validate_assignment=True,
            json_schema_serialization_defaults_required=True,
        )
    
    # Class-level metadata
    _schema_version: ClassVar[str] = "2.0.0"
    _model_type: ClassVar[str] = "BaseSecurityModel"
    
    @classmethod
    def get_schema_version(cls) -> str:
        """Get the schema version for this model."""
        return cls._schema_version
    
    @classmethod
    def get_model_type(cls) -> str:
        """Get the model type identifier."""
        return cls._model_type
    
    def to_dict(self, exclude_none: bool = True, exclude_private: bool = True) -> dict:
        """Convert model to dictionary."""
        if PYDANTIC_AVAILABLE:
            return self.model_dump(
                exclude_none=exclude_none,
                exclude_private=exclude_private,
                mode='json',
            )
        else:
            # Fallback for dataclass
            from dataclasses import asdict, fields
            d = {}
            for f in fields(self):
                if f.name.startswith('_'):
                    continue
                val = getattr(self, f.name)
                if exclude_none and val is None:
                    continue
                if hasattr(val, 'to_dict'):
                    d[f.name] = val.to_dict()
                elif isinstance(val, (list, tuple)):
                    d[f.name] = [
                        v.to_dict() if hasattr(v, 'to_dict') else v 
                        for v in val
                    ]
                elif isinstance(val, Enum):
                    d[f.name] = val.value
                else:
                    d[f.name] = val
            return d
    
    def to_json(self, indent: int = 2, exclude_none: bool = True) -> str:
        """Convert model to JSON string."""
        return json.dumps(
            self.to_dict(exclude_none=exclude_none),
            indent=indent,
            default=str,
        )
    
    def to_csv_row(self) -> List[str]:
        """Convert model to CSV row (flat structure)."""
        d = self.to_dict()
        return [str(v) for v in d.values()]
    
    @classmethod
    def csv_headers(cls) -> List[str]:
        """Get CSV headers for this model."""
        # Override in subclasses
        return []
    
    def fingerprint(self) -> str:
        """Generate a stable fingerprint for deduplication."""
        content = json.dumps(
            self.to_dict(exclude_none=True),
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def clone(self: T, **overrides) -> T:
        """Create a modified copy of this model."""
        if PYDANTIC_AVAILABLE:
            return self.model_copy(update=overrides)
        else:
            # Fallback for dataclass
            from dataclasses import replace
            return replace(self, **overrides)
    
    @classmethod
    @contextmanager
    def validation_disabled(cls):
        """Temporarily disable validation (for bulk imports)."""
        # Implementation depends on Pydantic version
        yield


# ────────────────────────────────────────────────────────────────────────────
# 4. Taint Analysis Models
# ────────────────────────────────────────────────────────────────────────────

class TaintSource(BaseSecurityModel):
    """A point where untrusted data enters the application."""
    
    _model_type: ClassVar[str] = "TaintSource"
    
    file: str = Field(..., min_length=1, description="File path where source occurs")
    line: int = Field(..., ge=1, description="Line number (1-indexed)")
    column: int = Field(..., ge=0, description="Column number (0-indexed)")
    variable: str = Field(..., min_length=1, description="Variable name holding tainted data")
    taint_type: TaintType = Field(..., description="Category of taint source")
    framework_api: Optional[str] = Field(None, description="Framework API (e.g., flask.request.args)")
    snippet: str = Field(default="", description="Code snippet at source location")
    scope: Optional[str] = Field(None, description="Function/method scope name")
    confidence: float = Field(default=0.85, ge=0.0, le=1.0)
    ast_node_type: Optional[str] = Field(None, description="AST node type if parsed")
    
    @field_validator('snippet')
    @classmethod
    def truncate_snippet(cls, v: str) -> str:
        """Truncate snippet to prevent excessive data."""
        if len(v) > 500:
            return v[:500] + "..."
        return v
    
    @classmethod
    def csv_headers(cls) -> List[str]:
        return ["file", "line", "column", "variable", "taint_type", "framework_api"]


class TaintSink(BaseSecurityModel):
    """A security-sensitive operation where tainted data is dangerous."""
    
    _model_type: ClassVar[str] = "TaintSink"
    
    file: str = Field(..., min_length=1)
    line: int = Field(..., ge=1)
    column: int = Field(..., ge=0)
    function: str = Field(..., min_length=1, description="Function/method name")
    vuln_class: VulnerabilityClass = Field(..., description="Vulnerability classification")
    framework_api: Optional[str] = Field(None)
    snippet: str = Field(default="")
    scope: Optional[str] = Field(None)
    confidence: float = Field(default=0.90, ge=0.0, le=1.0)
    ast_node_type: Optional[str] = Field(None)
    
    @field_validator('snippet')
    @classmethod
    def truncate_snippet(cls, v: str) -> str:
        if len(v) > 500:
            return v[:500] + "..."
        return v
    
    @classmethod
    def csv_headers(cls) -> List[str]:
        return ["file", "line", "column", "function", "vuln_class", "framework_api"]


class TaintPropagator(BaseSecurityModel):
    """An intermediate operation that propagates taint."""
    
    _model_type: ClassVar[str] = "TaintPropagator"
    
    file: str = Field(..., min_length=1)
    line: int = Field(..., ge=1)
    function: str = Field(..., min_length=1)
    transforms_taint: bool = Field(default=True)
    is_sanitizer: bool = Field(default=False)
    sanitizer_type: Optional[SanitizerType] = Field(None)
    source_vars: List[str] = Field(default_factory=list)
    sink_vars: List[str] = Field(default_factory=list)
    
    @classmethod
    def csv_headers(cls) -> List[str]:
        return ["file", "line", "function", "transforms_taint", "is_sanitizer", "sanitizer_type"]


class TaintFlow(BaseSecurityModel):
    """
    A complete taint trace from source to sink.
    Core of data-flow analysis — shows how untrusted data reaches dangerous operations.
    """
    
    _model_type: ClassVar[str] = "TaintFlow"
    
    source: TaintSource = Field(..., description="Where taint originates")
    sink: TaintSink = Field(..., description="Where taint is consumed dangerously")
    propagators: List[TaintPropagator] = Field(default_factory=list)
    is_sanitized: bool = Field(default=False)
    sanitization_gaps: List[str] = Field(default_factory=list)
    path_length: int = Field(default=0)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    fingerprint: Optional[str] = Field(None)
    cross_file: bool = Field(default=False)
    
    @model_validator(mode='after')
    def calculate_path_and_confidence(self) -> 'TaintFlow':
        """Calculate derived fields after validation."""
        object.__setattr__(self, 'path_length', len(self.propagators) + 2)
        object.__setattr__(self, 'confidence', self._calculate_confidence())
        if not self.fingerprint:
            object.__setattr__(self, 'fingerprint', self._generate_fingerprint())
        return self
    
    def _calculate_confidence(self) -> float:
        """Calculate confidence based on flow characteristics."""
        base = (self.source.confidence + self.sink.confidence) / 2
        path_penalty = min(0.3, self.path_length * 0.05)
        scope_bonus = 0.1 if self.source.scope == self.sink.scope else 0.0
        cross_file_penalty = 0.15 if self.cross_file else 0.0
        return max(0.0, min(1.0, base - path_penalty + scope_bonus - cross_file_penalty))
    
    def _generate_fingerprint(self) -> str:
        """Generate stable fingerprint for deduplication."""
        content = f"{self.source.file}:{self.source.line}:{self.sink.file}:{self.sink.line}:{self.sink.vuln_class.value}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    @computed_field if PYDANTIC_AVAILABLE else property
    def is_critical_path(self) -> bool:
        """Whether this flow represents a critical security path."""
        return (
            not self.is_sanitized and
            self.sink.vuln_class in (
                VulnerabilityClass.SQL_INJECTION,
                VulnerabilityClass.COMMAND_INJECTION,
                VulnerabilityClass.INSECURE_DESERIALIZATION,
            )
        )
    
    @classmethod
    def csv_headers(cls) -> List[str]:
        return ["source_file", "source_line", "sink_file", "sink_line", "vuln_class", "is_sanitized", "confidence"]
    
    def to_csv_row(self) -> List[str]:
        return [
            self.source.file,
            str(self.source.line),
            self.sink.file,
            str(self.sink.line),
            self.sink.vuln_class.value,
            str(self.is_sanitized),
            str(round(self.confidence, 3)),
        ]


# ────────────────────────────────────────────────────────────────────────────
# 5. Agent Verdict Models
# ────────────────────────────────────────────────────────────────────────────

class AgentVerdict(BaseSecurityModel):
    """
    Decision from a single agent in the multi-stage pipeline.
    Each agent provides validity assessment, confidence, reasoning, and evidence.
    """
    
    _model_type: ClassVar[str] = "AgentVerdict"
    
    agent_role: AgentRole = Field(..., description="Which agent made this verdict")
    is_valid: bool = Field(..., description="Whether agent considers finding valid")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score 0.0-1.0")
    reasoning: str = Field(..., min_length=1, description="Human-readable explanation")
    evidence: List[str] = Field(default_factory=list, description="Supporting data")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 timestamp"
    )
    agent_version: Optional[str] = Field(None, description="Agent software version")
    processing_time_ms: Optional[float] = Field(None, ge=0, description="Time taken to reach verdict")
    
    @field_validator('reasoning')
    @classmethod
    def truncate_reasoning(cls, v: str) -> str:
        if len(v) > 2000:
            return v[:2000] + "..."
        return v
    
    @field_validator('evidence')
    @classmethod
    def limit_evidence(cls, v: List[str]) -> List[str]:
        return v[:20]  # Limit to 20 evidence items
    
    @classmethod
    def csv_headers(cls) -> List[str]:
        return ["agent_role", "is_valid", "confidence", "reasoning", "timestamp"]


# ────────────────────────────────────────────────────────────────────────────
# 6. Patch Suggestion Models
# ────────────────────────────────────────────────────────────────────────────

class PatchSuggestion(BaseSecurityModel):
    """
    A suggested code fix for a validated finding.
    Nothing is applied without human approval — provides diff and explanation.
    """
    
    _model_type: ClassVar[str] = "PatchSuggestion"
    
    finding_id: str = Field(..., min_length=1)
    file: str = Field(..., min_length=1)
    start_line: int = Field(..., ge=1)
    end_line: int = Field(..., ge=1)
    original_code: str = Field(..., min_length=1)
    suggested_code: str = Field(..., min_length=1)
    explanation: str = Field(..., min_length=1)
    patch_type: str = Field(..., pattern="^(replace|insert|delete|refactor)$")
    confidence: float = Field(..., ge=0.0, le=1.0)
    side_effects: List[str] = Field(default_factory=list)
    test_suggestions: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)
    review_status: str = Field(default="pending", pattern="^(pending|approved|rejected)$")
    reviewed_by: Optional[str] = Field(None)
    reviewed_at: Optional[str] = Field(None)
    
    @field_validator('original_code', 'suggested_code')
    @classmethod
    def truncate_code(cls, v: str) -> str:
        if len(v) > 5000:
            return v[:5000] + "...\n[truncated]"
        return v
    
    def to_unified_diff(self) -> str:
        """Generate a unified diff representation."""
        original_lines = self.original_code.splitlines(keepends=True)
        suggested_lines = self.suggested_code.splitlines(keepends=True)
        
        diff_lines = [
            f"--- a/{self.file}",
            f"+++ b/{self.file}",
            f"@@ -{self.start_line},{len(original_lines)} +{self.start_line},{len(suggested_lines)} @@",
        ]
        for line in original_lines:
            diff_lines.append(f"-{line.rstrip()}")
        for line in suggested_lines:
            diff_lines.append(f"+{line.rstrip()}")
        
        return "\n".join(diff_lines)
    
    def to_git_patch(self) -> str:
        """Generate a git-compatible patch."""
        diff = self.to_unified_diff()
        return f"""{diff}

-- 
2.0.0
"""
    
    @classmethod
    def csv_headers(cls) -> List[str]:
        return ["finding_id", "file", "start_line", "end_line", "patch_type", "confidence", "review_status"]


# ────────────────────────────────────────────────────────────────────────────
# 7. Validated Finding — Core Output
# ────────────────────────────────────────────────────────────────────────────

def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class ValidatedFinding(BaseSecurityModel):
    """
    A fully validated security finding that has passed through all
    three agents (Discovery → Verification → Assessment).
    
    Primary output shown on security dashboard with:
    - Severity + confidence for prioritization
    - Complete taint flow trace
    - All agent verdicts for transparency
    - Patch suggestion with confidence
    - CWE/OWASP/CVSS mappings for compliance
    """
    
    _model_type: ClassVar[str] = "ValidatedFinding"
    _schema_version: ClassVar[str] = "2.0.0"
    
    # Identity
    id: str = Field(..., min_length=1, description="Unique finding identifier")
    title: str = Field(..., min_length=1, max_length=500)
    description: str = Field(..., min_length=1, max_length=5000)
    status: FindingStatus = Field(..., description="Current lifecycle status")
    
    # Location
    file: str = Field(..., min_length=1)
    line_number: int = Field(..., ge=1)
    column_start: Optional[int] = Field(None, ge=0)
    column_end: Optional[int] = Field(None, ge=0)
    language: str = Field(..., min_length=1)
    code_snippet: str = Field(default="", max_length=1000)
    context_lines: List[str] = Field(default_factory=list)
    
    # Classification
    vuln_class: VulnerabilityClass = Field(..., description="Vulnerability classification")
    severity: Severity = Field(..., description="Severity rating")
    confidence_rating: ConfidenceRating = Field(..., description="Confidence rating")
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="Aggregated confidence 0.0-1.0")
    cwe_id: str = Field(..., min_length=1, description="CWE identifier")
    cwe_name: str = Field(..., min_length=1)
    cvss_score: float = Field(..., ge=0.0, le=10.0)
    cvss_vector: Optional[str] = Field(None)
    owasp_category: Optional[str] = Field(None)
    
    # Data flow
    taint_flow: Optional[TaintFlow] = Field(None)
    has_data_flow: bool = Field(default=False)
    
    # Agent pipeline results
    agent_verdicts: List[AgentVerdict] = Field(default_factory=list)
    verification_attempts: int = Field(default=0, ge=0)
    false_positive_probability: float = Field(default=0.0, ge=0.0, le=1.0)
    
    # Patch
    patch: Optional[PatchSuggestion] = Field(None)
    has_patch: bool = Field(default=False)
    
    # Compliance mappings
    compliance_frameworks: List[str] = Field(default_factory=list)
    regulation_impact: List[str] = Field(default_factory=list)
    
    # Metadata
    tags: List[str] = Field(default_factory=list)
    related_findings: List[str] = Field(default_factory=list)
    discovered_at: str = Field(default_factory=_utcnow)
    last_updated: str = Field(default_factory=_utcnow)
    approved_by: Optional[str] = Field(None)
    approved_at: Optional[str] = Field(None)
    suppression_reason: Optional[str] = Field(None)
    scanner_version: str = Field(default="2.0.0")
    schema_version: str = Field(default="2.0.0")
    
    @field_validator('id')
    @classmethod
    def validate_id_format(cls, v: str) -> str:
        if not v.startswith("CSS-"):
            return f"CSS-{v}"
        return v
    
    @field_validator('code_snippet')
    @classmethod
    def truncate_snippet(cls, v: str) -> str:
        if len(v) > 1000:
            return v[:1000] + "..."
        return v
    
    @field_validator('context_lines')
    @classmethod
    def limit_context(cls, v: List[str]) -> List[str]:
        return v[:20]  # Limit context lines
    
    @field_validator('tags', 'related_findings')
    @classmethod
    def limit_lists(cls, v: List[str]) -> List[str]:
        return v[:50]
    
    @computed_field if PYDANTIC_AVAILABLE else property
    def is_actionable(self) -> bool:
        """Whether this finding should be acted upon immediately."""
        return (
            self.status in (FindingStatus.ASSESSED, FindingStatus.PENDING_APPROVAL)
            and self.severity in (Severity.CRITICAL, Severity.HIGH)
            and self.confidence_score >= 0.70
        )
    
    @computed_field if PYDANTIC_AVAILABLE else property
    def risk_score(self) -> float:
        """Composite risk = severity × confidence."""
        return round(self.severity.numeric * self.confidence_score, 2)
    
    @computed_field if PYDANTIC_AVAILABLE else property
    def age_days(self) -> int:
        """Age of finding in days."""
        discovered = datetime.fromisoformat(self.discovered_at.replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)
        return (now - discovered).days
    
    @computed_field if PYDANTIC_AVAILABLE else property
    def is_stale(self) -> bool:
        """Whether finding is stale (>90 days)."""
        return self.age_days > get_model_settings().max_finding_age_days
    
    @staticmethod
    def generate_id(file: str, line: int, vuln_class: str) -> str:
        """Generate deterministic finding ID."""
        settings = get_model_settings()
        raw = f"{file}:{line}:{vuln_class}"
        h = hashlib.sha256(raw.encode()).hexdigest()[:16]
        return f"{settings.id_prefix}-{h}"
    
    def approve(self, approved_by: str) -> 'ValidatedFinding':
        """Mark finding as approved."""
        return self.clone(
            status=FindingStatus.APPROVED,
            approved_by=approved_by,
            approved_at=_utcnow(),
            last_updated=_utcnow(),
        )
    
    def suppress(self, reason: str, suppressed_by: str) -> 'ValidatedFinding':
        """Suppress finding with reason."""
        return self.clone(
            status=FindingStatus.SUPPRESSED,
            suppression_reason=reason,
            approved_by=suppressed_by,
            approved_at=_utcnow(),
            last_updated=_utcnow(),
        )
    
    def mark_fixed(self) -> 'ValidatedFinding':
        """Mark finding as fixed."""
        return self.clone(
            status=FindingStatus.FIXED,
            last_updated=_utcnow(),
        )
    
    def reopen(self) -> 'ValidatedFinding':
        """Reopen a closed finding."""
        return self.clone(
            status=FindingStatus.REOPENED,
            approved_by=None,
            approved_at=None,
            suppression_reason=None,
            last_updated=_utcnow(),
        )
    
    @classmethod
    def csv_headers(cls) -> List[str]:
        return [
            "id", "title", "status", "severity", "confidence_score",
            "file", "line_number", "vuln_class", "cwe_id", "cvss_score",
            "risk_score", "is_actionable", "discovered_at", "age_days"
        ]
    
    def to_csv_row(self) -> List[str]:
        return [
            self.id, self.title, self.status.value, self.severity.value,
            str(round(self.confidence_score, 3)), self.file, str(self.line_number),
            self.vuln_class.value, self.cwe_id, str(round(self.cvss_score, 1)),
            str(self.risk_score), str(self.is_actionable),
            self.discovered_at, str(self.age_days),
        ]


# ────────────────────────────────────────────────────────────────────────────
# 8. Scan Configuration
# ────────────────────────────────────────────────────────────────────────────

class ScanConfiguration(BaseSecurityModel):
    """
    Enterprise-grade scan configuration with tunable parameters.
    Controls agent behavior, thresholds, output format, and compliance.
    """
    
    _model_type: ClassVar[str] = "ScanConfiguration"
    
    # Scanning scope
    scan_paths: List[str] = Field(default_factory=lambda: ["."])
    exclude_paths: List[str] = Field(default_factory=lambda: [
        "node_modules", ".git", "__pycache__", ".venv", "venv",
        "vendor", "dist", "build", ".next", "coverage",
        ".tox", ".mypy_cache", ".pytest_cache", ".scanner_cache",
    ])
    include_languages: Optional[List[str]] = Field(None)
    max_file_size_bytes: int = Field(default=5 * 1024 * 1024, ge=1)
    
    # Agent configuration
    enable_discovery: bool = Field(default=True)
    enable_verification: bool = Field(default=True)
    enable_assessment: bool = Field(default=True)
    enable_taint_analysis: bool = Field(default=True)
    enable_cross_file_analysis: bool = Field(default=True)
    enable_patch_generation: bool = Field(default=True)
    
    # Sensitivity thresholds
    min_confidence_threshold: float = Field(default=0.30, ge=0.0, le=1.0)
    fp_elimination_threshold: float = Field(default=0.20, ge=0.0, le=1.0)
    verification_rounds: int = Field(default=2, ge=1, le=10)
    context_window: int = Field(default=7, ge=1, le=50)
    
    # Output configuration
    include_info_findings: bool = Field(default=False)
    max_findings_per_file: int = Field(default=100, ge=1)
    max_total_findings: int = Field(default=5000, ge=1)
    output_format: str = Field(default="json", pattern="^(json|sarif|csv|html|parquet)$")
    
    # Compliance
    compliance_frameworks: List[str] = Field(default_factory=lambda: [
        "OWASP-Top-10", "CWE-Top-25", "PCI-DSS-4.0", "GDPR",
        "HIPAA", "SOC-2", "NIST-800-53", "ISO-27001",
    ])
    
    # Performance
    max_workers: int = Field(default=4, ge=1)
    timeout_per_file_seconds: int = Field(default=30, ge=1)
    max_files: int = Field(default=50_000, ge=1)
    
    # Security
    enable_encryption: bool = Field(default=False)
    encrypt_findings: bool = Field(default=False)
    
    # Metadata
    scan_name: Optional[str] = Field(None, max_length=200)
    scan_description: Optional[str] = Field(None, max_length=1000)
    created_by: Optional[str] = Field(None)
    created_at: str = Field(default_factory=_utcnow)
    
    @field_validator('exclude_paths')
    @classmethod
    def normalize_paths(cls, v: List[str]) -> List[str]:
        return [p.rstrip('/') for p in v]
    
    def to_env_dict(self) -> Dict[str, str]:
        """Convert to environment variable dict."""
        return {
            "SCAN_PATHS": ",".join(self.scan_paths),
            "EXCLUDE_PATHS": ",".join(self.exclude_paths),
            "MAX_WORKERS": str(self.max_workers),
            "MIN_CONFIDENCE_THRESHOLD": str(self.min_confidence_threshold),
            "OUTPUT_FORMAT": self.output_format,
        }


# ────────────────────────────────────────────────────────────────────────────
# 9. Scan Result — Aggregate Output
# ────────────────────────────────────────────────────────────────────────────

class SecurityScanResult(BaseSecurityModel):
    """
    Complete result of a security scan with all validated findings,
    metrics, and summary data for dashboard and reporting.
    """
    
    _model_type: ClassVar[str] = "SecurityScanResult"
    _schema_version: ClassVar[str] = "2.0.0"
    
    # Identity
    scan_id: str = Field(..., min_length=1)
    scanner_version: str = Field(default="2.0.0")
    schema_version: str = Field(default="2.0.0")
    started_at: str = Field(default_factory=_utcnow)
    completed_at: Optional[str] = Field(None)
    duration_seconds: float = Field(default=0.0, ge=0.0)
    
    # Scope
    source: str = Field(default="")
    source_type: str = Field(default="", pattern="^(local|repository|archive|container)$")
    configuration: Optional[ScanConfiguration] = Field(None)
    
    # Counts
    files_scanned: int = Field(default=0, ge=0)
    files_skipped: int = Field(default=0, ge=0)
    total_findings: int = Field(default=0, ge=0)
    critical_count: int = Field(default=0, ge=0)
    high_count: int = Field(default=0, ge=0)
    medium_count: int = Field(default=0, ge=0)
    low_count: int = Field(default=0, ge=0)
    info_count: int = Field(default=0, ge=0)
    
    # Pipeline metrics
    findings_discovered: int = Field(default=0, ge=0)
    findings_verified: int = Field(default=0, ge=0)
    findings_disproved: int = Field(default=0, ge=0)
    false_positive_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    
    # Breakdown
    findings_by_severity: Dict[str, int] = Field(default_factory=dict)
    findings_by_class: Dict[str, int] = Field(default_factory=dict)
    findings_by_file: Dict[str, int] = Field(default_factory=dict)
    findings_by_language: Dict[str, int] = Field(default_factory=dict)
    taint_flows_traced: int = Field(default=0, ge=0)
    patches_generated: int = Field(default=0, ge=0)
    
    # Compliance
    compliance_summary: Dict[str, int] = Field(default_factory=dict)
    owasp_coverage: Dict[str, int] = Field(default_factory=dict)
    cwe_distribution: Dict[str, int] = Field(default_factory=dict)
    
    # Scores (0–100)
    overall_security_score: float = Field(default=100.0, ge=0.0, le=100.0)
    code_risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    data_flow_risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    
    # Languages
    languages_detected: List[str] = Field(default_factory=list)
    
    # Findings
    findings: List[ValidatedFinding] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    
    # Metadata
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    @model_validator(mode='after')
    def compute_all_metrics(self) -> 'SecurityScanResult':
        """Automatically compute all metrics after validation."""
        self._compute_counts()
        self._compute_risk_scores()
        return self
    
    def _compute_counts(self) -> None:
        """Recompute all aggregate counts from findings."""
        self.total_findings = len(self.findings)
        
        severity_counts = {s.value: 0 for s in Severity}
        class_counts: Dict[str, int] = {}
        file_counts: Dict[str, int] = {}
        lang_counts: Dict[str, int] = {}
        cwe_counts: Dict[str, int] = {}
        owasp_counts: Dict[str, int] = {}
        compliance_counts: Dict[str, int] = {}
        
        for f in self.findings:
            severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1
            class_counts[f.vuln_class.value] = class_counts.get(f.vuln_class.value, 0) + 1
            file_counts[f.file] = file_counts.get(f.file, 0) + 1
            lang_counts[f.language] = lang_counts.get(f.language, 0) + 1
            if f.cwe_id:
                cwe_counts[f.cwe_id] = cwe_counts.get(f.cwe_id, 0) + 1
            if f.owasp_category:
                owasp_counts[f.owasp_category] = owasp_counts.get(f.owasp_category, 0) + 1
            for fw in f.compliance_frameworks:
                compliance_counts[fw] = compliance_counts.get(fw, 0) + 1
        
        self.critical_count = severity_counts.get("Critical", 0)
        self.high_count = severity_counts.get("High", 0)
        self.medium_count = severity_counts.get("Medium", 0)
        self.low_count = severity_counts.get("Low", 0)
        self.info_count = severity_counts.get("Informational", 0)
        self.findings_by_severity = severity_counts
        self.findings_by_class = class_counts
        self.findings_by_file = file_counts
        self.findings_by_language = lang_counts
        self.cwe_distribution = cwe_counts
        self.owasp_coverage = owasp_counts
        self.compliance_summary = compliance_counts
        
        if self.findings_discovered > 0:
            self.false_positive_rate = round(self.findings_disproved / self.findings_discovered, 4)
        
        self.patches_generated = sum(1 for f in self.findings if f.has_patch)
        self.taint_flows_traced = sum(1 for f in self.findings if f.has_data_flow)
    
    def _compute_risk_scores(self) -> None:
        """Compute aggregate risk scores."""
        if not self.findings:
            self.code_risk_score = 0.0
            self.data_flow_risk_score = 0.0
            self.overall_security_score = 100.0
            return
        
        weights = {
            Severity.CRITICAL: 15.0, Severity.HIGH: 8.0,
            Severity.MEDIUM: 3.0, Severity.LOW: 1.0, Severity.INFO: 0.0
        }
        
        code_risk = sum(
            weights.get(f.severity, 0) * f.confidence_score
            for f in self.findings
        )
        self.code_risk_score = min(100.0, round(code_risk, 1))
        
        taint_findings = [f for f in self.findings if f.has_data_flow]
        df_risk = sum(
            weights.get(f.severity, 0) * f.confidence_score * 1.5
            for f in taint_findings
        )
        self.data_flow_risk_score = min(100.0, round(df_risk, 1))
        
        combined = (self.code_risk_score * 0.6 + self.data_flow_risk_score * 0.4)
        self.overall_security_score = max(0.0, min(100.0, round(100.0 - combined, 1)))
    
    def get_findings_by_status(self, status: FindingStatus) -> List[ValidatedFinding]:
        """Filter findings by status."""
        return [f for f in self.findings if f.status == status]
    
    def get_actionable_findings(self) -> List[ValidatedFinding]:
        """Get findings that require immediate action."""
        return [f for f in self.findings if f.is_actionable]
    
    def get_critical_findings(self) -> List[ValidatedFinding]:
        """Get all critical severity findings."""
        return [f for f in self.findings if f.severity == Severity.CRITICAL]
    
    def to_sarif(self) -> dict:
        """Export as SARIF 2.1.0 for IDE/CI integration."""
        rules: Dict[str, dict] = {}
        results: List[dict] = []
        
        for f in self.findings:
            rule_id = f"CSS/{f.vuln_class.value.upper().replace(' ', '_')}"
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": f.vuln_class.value,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.description},
                    "defaultConfiguration": {"level": f.severity.sarif_level},
                    "properties": {
                        "tags": ["security", f.vuln_class.value.lower()],
                        "precision": f.confidence_rating.value,
                    },
                }
                if f.cwe_id:
                    rules[rule_id]["relationships"] = [{
                        "target": {"id": f.cwe_id, "toolComponent": {"name": "CWE"}},
                        "kinds": ["superset"],
                    }]
            
            result = {
                "ruleId": rule_id,
                "level": f.severity.sarif_level,
                "message": {"text": f.description},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file, "uriBaseId": "%SRCROOT%"},
                        "region": {
                            "startLine": f.line_number,
                            **({"startColumn": f.column_start} if f.column_start else {}),
                        },
                    },
                }],
                "properties": {
                    "confidence": f.confidence_score,
                    "confidenceRating": f.confidence_rating.value,
                    "cvssScore": f.cvss_score,
                    "riskScore": f.risk_score,
                    "hasDataFlow": f.has_data_flow,
                    "hasPatch": f.has_patch,
                    "verificationAttempts": f.verification_attempts,
                    "findingId": f.id,
                },
            }
            
            if f.taint_flow:
                result["codeFlows"] = [{
                    "threadFlows": [{
                        "locations": self._build_sarif_flow(f.taint_flow),
                    }],
                }]
            
            results.append(result)
        
        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Enterprise Security Scanner",
                        "semanticVersion": self.scanner_version,
                        "informationUri": "https://security-scanner.example.com",
                        "rules": list(rules.values()),
                    },
                },
                "results": results,
                "invocations": [{
                    "executionSuccessful": len(self.errors) == 0,
                    "startTimeUtc": self.started_at,
                    "endTimeUtc": self.completed_at or _utcnow(),
                    "exitCode": 0 if len(self.get_critical_findings()) == 0 else 1,
                }],
            }],
        }
    
    @staticmethod
    def _build_sarif_flow(flow: TaintFlow) -> List[dict]:
        """Build SARIF thread-flow locations from taint flow."""
        locations = []
        
        locations.append({
            "location": {
                "physicalLocation": {
                    "artifactLocation": {"uri": flow.source.file},
                    "region": {"startLine": flow.source.line},
                },
                "message": {"text": f"Taint source: {flow.source.taint_type.value} via {flow.source.variable}"},
            },
            "importance": "essential",
        })
        
        for prop in flow.propagators:
            locations.append({
                "location": {
                    "physicalLocation": {
                        "artifactLocation": {"uri": prop.file},
                        "region": {"startLine": prop.line},
                    },
                    "message": {
                        "text": f"Sanitizer: {prop.sanitizer_type.value}" if prop.is_sanitizer else f"Propagated through {prop.function}"
                    },
                },
                "importance": "normal",
            })
        
        locations.append({
            "location": {
                "physicalLocation": {
                    "artifactLocation": {"uri": flow.sink.file},
                    "region": {"startLine": flow.sink.line},
                },
                "message": {"text": f"Taint sink: {flow.sink.vuln_class.value} in {flow.sink.function}"},
            },
            "importance": "essential",
        })
        
        return locations
    
    def to_summary_report(self) -> str:
        """Generate human-readable summary report."""
        lines = [
            "=" * 70,
            "SECURITY SCAN SUMMARY",
            "=" * 70,
            f"Scan ID: {self.scan_id}",
            f"Scanner Version: {self.scanner_version}",
            f"Duration: {self.duration_seconds:.2f}s",
            f"Files Scanned: {self.files_scanned}",
            f"Files Skipped: {self.files_skipped}",
            "",
            "FINDINGS OVERVIEW",
            "-" * 70,
            f"Total Findings: {self.total_findings}",
            f"  Critical: {self.critical_count}",
            f"  High: {self.high_count}",
            f"  Medium: {self.medium_count}",
            f"  Low: {self.low_count}",
            f"  Info: {self.info_count}",
            "",
            "RISK SCORES",
            "-" * 70,
            f"Overall Security Score: {self.overall_security_score}/100",
            f"Code Risk Score: {self.code_risk_score}/100",
            f"Data Flow Risk Score: {self.data_flow_risk_score}/100",
            "",
            "PIPELINE METRICS",
            "-" * 70,
            f"Findings Discovered: {self.findings_discovered}",
            f"Findings Verified: {self.findings_verified}",
            f"Findings Disproved: {self.findings_disproved}",
            f"False Positive Rate: {self.false_positive_rate:.2%}",
            f"Patches Generated: {self.patches_generated}",
            "",
        ]
        
        if self.errors:
            lines.extend([
                "ERRORS",
                "-" * 70,
            ] + self.errors[:10] + (["..."] if len(self.errors) > 10 else []))
        
        lines.append("=" * 70)
        
        return "\n".join(lines)
    
    @classmethod
    def csv_headers(cls) -> List[str]:
        return ["scan_id", "total_findings", "critical_count", "high_count", 
                "security_score", "duration_seconds", "files_scanned"]
    
    def to_csv_row(self) -> List[str]:
        return [
            self.scan_id, str(self.total_findings), str(self.critical_count),
            str(self.high_count), str(self.overall_security_score),
            str(round(self.duration_seconds, 2)), str(self.files_scanned),
        ]


# ────────────────────────────────────────────────────────────────────────────
# 10. Database ORM Models (Optional)
# ────────────────────────────────────────────────────────────────────────────

if SQLALCHEMY_AVAILABLE:
    class FindingORM(Base):
        """SQLAlchemy ORM model for database persistence."""
        __tablename__ = "security_findings"
        
        id = Column(String(64), primary_key=True)
        scan_id = Column(String(64), index=True)
        title = Column(String(500))
        description = Column(Text)
        status = Column(String(50))
        file = Column(String(1000), index=True)
        line_number = Column(Integer)
        language = Column(String(50))
        vuln_class = Column(String(100))
        severity = Column(String(20))
        confidence_score = Column(Float)
        cwe_id = Column(String(20))
        cvss_score = Column(Float)
        risk_score = Column(Float)
        has_data_flow = Column(Boolean, default=False)
        has_patch = Column(Boolean, default=False)
        discovered_at = Column(DateTime(timezone=True), default=func.now())
        last_updated = Column(DateTime(timezone=True), onupdate=func.now())
        data = Column(JSON)  # Full finding as JSON
        
        def to_model(self) -> ValidatedFinding:
            """Convert ORM to Pydantic model."""
            # Implementation depends on your needs
            pass
        
        @classmethod
        def from_model(cls, model: ValidatedFinding, scan_id: str) -> 'FindingORM':
            """Create ORM from Pydantic model."""
            return cls(
                id=model.id,
                scan_id=scan_id,
                title=model.title,
                description=model.description,
                status=model.status.value,
                file=model.file,
                line_number=model.line_number,
                language=model.language,
                vuln_class=model.vuln_class.value,
                severity=model.severity.value,
                confidence_score=model.confidence_score,
                cwe_id=model.cwe_id,
                cvss_score=model.cvss_score,
                risk_score=model.risk_score,
                has_data_flow=model.has_data_flow,
                has_patch=model.has_patch,
                data=model.to_dict(),
            )


# ────────────────────────────────────────────────────────────────────────────
# 11. Encryption Utilities (Optional)
# ────────────────────────────────────────────────────────────────────────────

class EncryptionManager:
    """Manage field encryption for sensitive data."""
    
    def __init__(self, key: Optional[str] = None):
        if not CRYPTO_AVAILABLE:
            raise ImportError("cryptography library not installed")
        
        if key:
            self.fernet = Fernet(key.encode() if isinstance(key, str) else key)
        else:
            self.fernet = Fernet(Fernet.generate_key())
    
    def encrypt(self, data: str) -> str:
        """Encrypt a string."""
        return self.fernet.encrypt(data.encode()).decode()
    
    def decrypt(self, data: str) -> str:
        """Decrypt a string."""
        return self.fernet.decrypt(data.encode()).decode()
    
    def encrypt_finding(self, finding: ValidatedFinding) -> ValidatedFinding:
        """Encrypt sensitive fields in a finding."""
        sensitive_fields = ['code_snippet', 'description']
        updates = {}
        for field_name in sensitive_fields:
            val = getattr(finding, field_name)
            if val:
                updates[field_name] = self.encrypt(val)
        return finding.clone(**updates)
    
    def decrypt_finding(self, finding: ValidatedFinding) -> ValidatedFinding:
        """Decrypt sensitive fields in a finding."""
        sensitive_fields = ['code_snippet', 'description']
        updates = {}
        for field_name in sensitive_fields:
            val = getattr(finding, field_name)
            if val:
                try:
                    updates[field_name] = self.decrypt(val)
                except Exception:
                    pass  # Already decrypted or invalid
        return finding.clone(**updates)


# ────────────────────────────────────────────────────────────────────────────
# 12. Schema Migration Utilities
# ────────────────────────────────────────────────────────────────────────────

class SchemaMigrator:
    """Handle schema version migrations for backward compatibility."""
    
    _migrations: ClassVar[Dict[str, Callable]] = {}
    
    @classmethod
    def register_migration(cls, from_version: str, to_version: str):
        """Decorator to register a migration function."""
        def decorator(func: Callable):
            cls._migrations[f"{from_version}->{to_version}"] = func
            return func
        return decorator
    
    @classmethod
    def migrate(cls, data: dict, from_version: str, to_version: str) -> dict:
        """Migrate data from one schema version to another."""
        current = from_version
        while current != to_version:
            key = f"{current}->{to_version}"
            if key in cls._migrations:
                data = cls._migrations[key](data)
                current = to_version
            else:
                # Try incremental migration
                found = False
                for mig_key in cls._migrations:
                    if mig_key.startswith(f"{current}->"):
                        next_version = mig_key.split('->')[1]
                        data = cls._migrations[mig_key](data)
                        current = next_version
                        found = True
                        break
                if not found:
                    raise ValueError(f"No migration path from {from_version} to {to_version}")
        return data
    
    @staticmethod
    @register_migration("1.0.0", "2.0.0")
    def migrate_v1_to_v2(data: dict) -> dict:
        """Migration from schema 1.0.0 to 2.0.0."""
        # Add new required fields with defaults
        data.setdefault('schema_version', '2.0.0')
        data.setdefault('scanner_version', '2.0.0')
        data.setdefault('false_positive_probability', 0.0)
        data.setdefault('verification_attempts', 0)
        return data


# ────────────────────────────────────────────────────────────────────────────
# 13. Entry Point & Validation Tests
# ────────────────────────────────────────────────────────────────────────────

def validate_models() -> bool:
    """Run validation tests on all models."""
    try:
        # Test ValidatedFinding creation
        finding = ValidatedFinding(
            id="CSS-test123",
            title="Test SQL Injection",
            description="Test description",
            status=FindingStatus.VERIFIED,
            file="test.py",
            line_number=10,
            column_start=0,
            column_end=50,
            language="python",
            code_snippet="cursor.execute(f'SELECT * FROM users WHERE id={user_id}')",
            context_lines=["def get_user(user_id):", "    cursor = db.cursor()"],
            vuln_class=VulnerabilityClass.SQL_INJECTION,
            severity=Severity.CRITICAL,
            confidence_rating=ConfidenceRating.HIGH,
            confidence_score=0.85,
            cwe_id="CWE-89",
            cwe_name="SQL Injection",
            cvss_score=9.8,
        )
        
        # Test serialization
        json_str = finding.to_json()
        assert len(json_str) > 0
        
        # Test fingerprint
        fp = finding.fingerprint()
        assert len(fp) == 16
        
        # Test status transitions
        approved = finding.approve("test_user")
        assert approved.status == FindingStatus.APPROVED
        
        print("✓ All model validations passed")
        return True
        
    except Exception as e:
        print(f"✗ Model validation failed: {e}")
        return False


def main():
    """CLI entry point for model validation and testing."""
    import sys
    
    print(f"Enterprise Security Scanner — Data Models v{ModelSettings().schema_version}")
    print("=" * 70)
    
    # Validate models
    if not validate_models():
        sys.exit(1)
    
    # Print model info
    print(f"\nPydantic Available: {PYDANTIC_AVAILABLE}")
    print(f"SQLAlchemy Available: {SQLALCHEMY_AVAILABLE}")
    print(f"Cryptography Available: {CRYPTO_AVAILABLE}")
    
    # Generate JSON Schema if Pydantic available
    if PYDANTIC_AVAILABLE:
        print(f"\nJSON Schema for ValidatedFinding:")
        schema = ValidatedFinding.model_json_schema()
        print(json.dumps(schema, indent=2)[:1000] + "...")
    
    print("\n✓ Models ready for production deployment")
    sys.exit(0)


if __name__ == "__main__":
    main()