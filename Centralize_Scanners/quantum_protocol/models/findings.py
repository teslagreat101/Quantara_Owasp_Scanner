"""
Quantum Protocol v4.0 — Data Models
Extended with OWASP Top 10:2025, vulnerability categories, and enhanced reporting.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional

from quantum_protocol.models.enums import (
    AlgoFamily, ComplianceFramework, ConfidenceLevel,
    PQC_REPLACEMENTS, RiskLevel, COMPLIANCE_VIOLATIONS,
    VulnCategory, OwaspCategory,
)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


# CWE Map — unified for crypto + secrets + OWASP
CWE_MAP: dict[AlgoFamily, tuple[str, str]] = {
    AlgoFamily.RSA:           ("CWE-327", "Use of Broken Crypto Algorithm"),
    AlgoFamily.ECC:           ("CWE-327", "Use of Broken Crypto Algorithm"),
    AlgoFamily.ECDSA:         ("CWE-327", "Use of Broken Crypto Algorithm"),
    AlgoFamily.DSA:           ("CWE-327", "Use of Broken Crypto Algorithm"),
    AlgoFamily.DH:            ("CWE-327", "Use of Broken Crypto Algorithm"),
    AlgoFamily.MD5:           ("CWE-328", "Use of Weak Hash"),
    AlgoFamily.SHA1:          ("CWE-328", "Use of Weak Hash"),
    AlgoFamily.MD4:           ("CWE-328", "Use of Weak Hash"),
    AlgoFamily.DES:           ("CWE-327", "Use of Broken Crypto Algorithm"),
    AlgoFamily.RC4:           ("CWE-327", "Use of Broken Crypto Algorithm"),
    AlgoFamily.AES_ECB:       ("CWE-329", "Predictable IV"),
    AlgoFamily.HARDCODED_KEY: ("CWE-321", "Hard-coded Crypto Key"),
    AlgoFamily.WEAK_RANDOM:   ("CWE-338", "Weak PRNG"),
    AlgoFamily.SECRET_AWS:         ("CWE-798", "Hard-coded Credentials"),
    AlgoFamily.SECRET_GCP:         ("CWE-798", "Hard-coded Credentials"),
    AlgoFamily.SECRET_AZURE:       ("CWE-798", "Hard-coded Credentials"),
    AlgoFamily.SECRET_GITHUB:      ("CWE-798", "Hard-coded Credentials"),
    AlgoFamily.SECRET_STRIPE:      ("CWE-798", "Hard-coded Credentials"),
    AlgoFamily.SECRET_DB_CONNSTR:  ("CWE-798", "Hard-coded Credentials"),
    AlgoFamily.SECRET_POSTGRES:    ("CWE-798", "Hard-coded Credentials"),
    AlgoFamily.SECRET_MYSQL:       ("CWE-798", "Hard-coded Credentials"),
    AlgoFamily.SECRET_MONGODB:     ("CWE-798", "Hard-coded Credentials"),
    AlgoFamily.SECRET_SLACK:       ("CWE-798", "Hard-coded Credentials"),
    AlgoFamily.SECRET_JWT:         ("CWE-798", "Hard-coded Credentials"),
    AlgoFamily.SECRET_SSH_KEY:     ("CWE-321", "Hard-coded Crypto Key"),
    AlgoFamily.SECRET_GENERIC_API: ("CWE-798", "Hard-coded Credentials"),
    AlgoFamily.SECRET_GENERIC_PASSWORD: ("CWE-798", "Hard-coded Credentials"),
    AlgoFamily.SECRET_GENERIC_SECRET:   ("CWE-798", "Hard-coded Credentials"),
}


@dataclass(frozen=False)
class CryptoFinding:
    """A single vulnerability, secret, or crypto finding."""
    id: str
    file: str
    language: str
    line_number: int
    line_content: str
    column_start: Optional[int]
    column_end: Optional[int]
    algorithm: str
    family: AlgoFamily
    risk: RiskLevel
    confidence: float
    confidence_level: ConfidenceLevel
    key_size: Optional[int]
    hndl_relevant: bool
    pattern_note: str
    migration: dict
    compliance_violations: list[str]
    context_lines: list[str]
    cwe_id: Optional[str] = None
    cvss_estimate: Optional[float] = None
    remediation_effort: Optional[str] = None
    secret_provider: Optional[str] = None
    secret_type: Optional[str] = None
    attack_surface: Optional[str] = None
    is_secret: bool = False
    tags: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=_utcnow)

    @property
    def is_vuln(self) -> bool:
        return self.family.is_vuln

    @property
    def is_recon(self) -> bool:
        return self.family.is_recon

    @property
    def vuln_category(self) -> VulnCategory:
        return self.family.vuln_category

    def to_dict(self) -> dict:
        d = asdict(self)
        d["family"] = self.family.value
        d["risk"] = self.risk.value
        d["confidence_level"] = self.confidence_level.value
        d["vuln_category"] = self.family.vuln_category.value
        return d

    @staticmethod
    def generate_id(filepath: str, line: int, family: str) -> str:
        h = hashlib.sha256(f"{filepath}:{line}:{family}".encode()).hexdigest()[:16]
        return f"QP-{h}"


def estimate_remediation_effort(family: AlgoFamily) -> str:
    if family.is_secret:
        return "low"
    if family.is_vuln:
        cat = family.vuln_category
        if cat in (VulnCategory.MISCONFIG, VulnCategory.LOGGING):
            return "low"
        if cat == VulnCategory.INSECURE_DESIGN:
            return "high"
        return "medium"
    if family in (AlgoFamily.MD5, AlgoFamily.SHA1):
        return "low"
    if family in (AlgoFamily.HARDCODED_KEY, AlgoFamily.WEAK_RANDOM, AlgoFamily.AES_ECB):
        return "medium"
    if family.is_quantum_broken:
        return "high"
    return "medium"


@dataclass
class FileReport:
    path: str
    language: str
    findings_count: int
    critical_count: int
    high_count: int
    secrets_count: int
    vuln_count: int  # NEW: OWASP vulnerability count
    risk_score: float
    findings: list[CryptoFinding]
    has_pqc_adoption: bool


@dataclass
class ScanSummary:
    scan_id: str
    scanner_version: str
    source: str
    source_type: str
    scan_mode: str
    started_at: str
    completed_at: str
    duration_seconds: float
    files_scanned: int
    files_skipped: int
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    hndl_count: int
    pqc_ready_count: int
    secrets_count: int
    secrets_critical: int
    secrets_by_provider: dict[str, int]
    attack_surface_summary: dict[str, int]
    # v4.0 additions
    vuln_count: int = 0
    vuln_by_category: dict[str, int] = field(default_factory=dict)
    owasp_coverage: dict[str, int] = field(default_factory=dict)
    recon_count: int = 0
    # Scores
    quantum_risk_score: float = 0.0
    crypto_agility_score: float = 0.0
    secrets_exposure_score: float = 0.0
    vuln_risk_score: float = 0.0      # NEW
    overall_security_score: float = 0.0
    languages_detected: list[str] = field(default_factory=list)
    compliance_summary: dict[str, int] = field(default_factory=dict)
    findings: list[CryptoFinding] = field(default_factory=list)
    file_reports: list[FileReport] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scan_policy: Optional[dict] = None
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["findings"] = [f.to_dict() for f in self.findings]
        return d

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def to_sarif(self) -> dict:
        rules: dict[str, dict] = {}
        results: list[dict] = []
        for f in self.findings:
            rule_id = f"QP/{f.family.value.upper().replace('-','_').replace(' ','_').replace('/','_')}"
            if rule_id not in rules:
                cwe = CWE_MAP.get(f.family)
                rule_def: dict[str, Any] = {
                    "id": rule_id,
                    "name": f.family.value,
                    "shortDescription": {"text": f"{f.family.vuln_category.value}: {f.family.value}"},
                    "fullDescription": {"text": f.pattern_note},
                    "defaultConfiguration": {"level": f.risk.sarif_level},
                    "properties": {"tags": ["security", f.family.vuln_category.value.lower().replace("/", "-")]},
                }
                if cwe:
                    rule_def["relationships"] = [{"target": {"id": cwe[0], "toolComponent": {"name": "CWE"}}, "kinds": ["superset"]}]
                rules[rule_id] = rule_def
            results.append({
                "ruleId": rule_id,
                "level": f.risk.sarif_level,
                "message": {"text": f"{f.pattern_note}. Risk: {f.risk.value}. Confidence: {f.confidence:.0%}"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": f.file, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": f.line_number, **({"startColumn": f.column_start} if f.column_start else {})},
                }}],
                "properties": {
                    "confidence": f.confidence,
                    "vulnCategory": f.family.vuln_category.value,
                    "isSecret": f.is_secret,
                    "complianceViolations": f.compliance_violations,
                },
            })
        return {
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {
                "name": "Quantum Protocol Scanner",
                "semanticVersion": "4.0.0",
                "rules": list(rules.values()),
            }}, "results": results}],
        }

    def to_csv_rows(self) -> list[dict]:
        rows = []
        for f in self.findings:
            rows.append({
                "id": f.id, "file": f.file, "line": f.line_number,
                "algorithm": f.algorithm, "family": f.family.value,
                "risk": f.risk.value, "confidence": f.confidence,
                "vuln_category": f.family.vuln_category.value,
                "is_secret": f.is_secret,
                "secret_provider": f.secret_provider or "",
                "cwe": f.cwe_id or "",
                "compliance": "; ".join(f.compliance_violations),
                "note": f.pattern_note,
            })
        return rows
