"""
Quantum Protocol v5.0 — PQSI Agent Base Class

Abstract base for all Post-Quantum Security Intelligence agents.
Each agent scans files/directories and returns CryptoFinding objects
that flow through the existing normalization pipeline.
"""
from __future__ import annotations

import logging
import os
import re
from abc import ABC, abstractmethod
from typing import Optional

from quantum_protocol.models.enums import (
    AlgoFamily, ConfidenceLevel, RiskLevel,
    COMPLIANCE_VIOLATIONS, SKIP_DIRS, MAX_FILE_SIZE_BYTES, LANGUAGE_MAP,
)
from quantum_protocol.models.findings import (
    CryptoFinding, CWE_MAP, estimate_remediation_effort,
)

logger = logging.getLogger(__name__)

# Reverse-map extensions to language names
_EXT_TO_LANG: dict[str, str] = {}
for _lang, _exts in LANGUAGE_MAP.items():
    for _ext in _exts:
        _EXT_TO_LANG[_ext.lower()] = _lang

# Files to scan regardless of extension
_SPECIAL_FILENAMES: set[str] = {
    "dockerfile", "containerfile", "docker-compose.yml", "docker-compose.yaml",
    "nginx.conf", "haproxy.cfg", "httpd.conf", "apache2.conf",
    "requirements.txt", "pyproject.toml", "pipfile", "setup.py", "setup.cfg",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "go.mod", "go.sum", "cargo.toml", "cargo.lock",
    "pom.xml", "build.gradle", "build.gradle.kts",
    "sbom.json", "bom.xml", "cyclonedx.json",
    "makefile", "cmakelists.txt",
}


def _detect_language(filepath: str) -> str:
    """Detect language from file extension or special filename."""
    basename = os.path.basename(filepath).lower()
    if basename in _SPECIAL_FILENAMES:
        if basename.startswith("dockerfile") or basename == "containerfile":
            return "dockerfile"
        if basename.endswith((".yml", ".yaml")):
            return "config"
        if basename in ("requirements.txt", "pyproject.toml", "pipfile", "setup.py", "setup.cfg"):
            return "python"
        if basename in ("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
            return "javascript"
        if basename in ("go.mod", "go.sum"):
            return "go"
        if basename in ("cargo.toml", "cargo.lock"):
            return "rust"
        if basename in ("pom.xml", "build.gradle", "build.gradle.kts"):
            return "java"
        if basename in ("sbom.json", "bom.xml", "cyclonedx.json"):
            return "config"
        return "config"
    _, ext = os.path.splitext(filepath)
    return _EXT_TO_LANG.get(ext.lower(), "unknown")


class PQSIAgent(ABC):
    """Abstract base class for Post-Quantum Security Intelligence agents."""

    agent_name: str = "pqsi_base"
    agent_version: str = "1.0.0"
    description: str = "Base PQSI agent"

    def __init__(self) -> None:
        self.logger = logging.getLogger(f"pqsi.{self.agent_name}")

    @abstractmethod
    def scan_file(self, content: str, filepath: str, language: str) -> list[CryptoFinding]:
        """Scan a single file's content and return findings."""

    def scan_directory(self, target_dir: str) -> list[CryptoFinding]:
        """Walk a directory tree and scan all eligible files."""
        findings: list[CryptoFinding] = []
        if not os.path.isdir(target_dir):
            self.logger.warning("Not a directory: %s", target_dir)
            return findings

        for root, dirs, files in os.walk(target_dir):
            # Prune skip dirs in-place
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    fsize = os.path.getsize(fpath)
                    if fsize > MAX_FILE_SIZE_BYTES or fsize == 0:
                        continue
                except OSError:
                    continue

                lang = _detect_language(fpath)
                if lang == "unknown":
                    continue

                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except (OSError, UnicodeDecodeError):
                    continue

                file_findings = self.scan_file(content, fpath, lang)
                findings.extend(file_findings)

        return findings

    def _create_finding(
        self,
        filepath: str,
        line_number: int,
        line_content: str,
        algorithm: str,
        family: AlgoFamily,
        risk: RiskLevel,
        confidence: float,
        pattern_note: str,
        language: str = "unknown",
        key_size: Optional[int] = None,
        hndl_relevant: bool = False,
        migration: Optional[dict] = None,
        tags: Optional[list[str]] = None,
        column_start: Optional[int] = None,
        column_end: Optional[int] = None,
        # PQSI fields
        data_longevity_estimate: Optional[str] = None,
        hndl_probability_score: Optional[float] = None,
        future_decryption_risk: Optional[str] = None,
        quantum_exposure_years: Optional[float] = None,
        migration_urgency: Optional[str] = None,
        pqc_adoption_index: Optional[float] = None,
    ) -> CryptoFinding:
        """Factory method to create a CryptoFinding with proper defaults."""
        from quantum_protocol.models.findings import estimate_remediation_effort

        fid = CryptoFinding.generate_id(filepath, line_number, family.value)
        cwe = CWE_MAP.get(family)
        compliance = [fw.value for fw in COMPLIANCE_VIOLATIONS.get(family, [])]

        return CryptoFinding(
            id=fid,
            file=filepath,
            language=language,
            line_number=line_number,
            line_content=line_content[:500],
            column_start=column_start,
            column_end=column_end,
            algorithm=algorithm,
            family=family,
            risk=risk,
            confidence=confidence,
            confidence_level=ConfidenceLevel.HIGH if confidence >= 0.8
                else ConfidenceLevel.MEDIUM if confidence >= 0.5
                else ConfidenceLevel.LOW,
            key_size=key_size,
            hndl_relevant=hndl_relevant,
            pattern_note=pattern_note,
            migration=migration or {},
            compliance_violations=compliance,
            context_lines=[],
            cwe_id=cwe[0] if cwe else None,
            remediation_effort=estimate_remediation_effort(family),
            tags=tags or [],
            data_longevity_estimate=data_longevity_estimate,
            hndl_probability_score=hndl_probability_score,
            future_decryption_risk=future_decryption_risk,
            quantum_exposure_years=quantum_exposure_years,
            migration_urgency=migration_urgency,
            pqc_adoption_index=pqc_adoption_index,
        )
