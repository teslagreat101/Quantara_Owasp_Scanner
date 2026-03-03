"""
Quantum Protocol v5.0 — PQSI Agent 3: PQC Library Intelligence Engine

Detects adoption maturity of post-quantum cryptography by scanning dependency
manifests, container definitions, imports, and SBOM files. Computes a
Post_Quantum_Adoption_Index (0-100) reflecting organizational PQC readiness.
"""
from __future__ import annotations

import json
import os
import re
from typing import Optional

from quantum_protocol.models.enums import AlgoFamily, RiskLevel
from quantum_protocol.agents.base_agent import PQSIAgent
from quantum_protocol.models.findings import CryptoFinding

# ─── Load PQC Library Database ─────────────────────────────────────────────────

_DB_PATH = os.path.join(os.path.dirname(__file__), "pqc_library_db.json")

_PQC_LIB_DB: dict = {}
try:
    with open(_DB_PATH, "r", encoding="utf-8") as _f:
        _PQC_LIB_DB = json.load(_f)
except (OSError, json.JSONDecodeError):
    pass

# ─── Maturity Level Scoring ────────────────────────────────────────────────────

_MATURITY_SCORES = {
    "experimental": 15,
    "pilot": 35,
    "enterprise": 65,
    "production": 90,
    "reference": 10,
}

_MATURITY_RISK = {
    "experimental": RiskLevel.INFO,
    "pilot": RiskLevel.INFO,
    "enterprise": RiskLevel.INFO,
    "production": RiskLevel.INFO,
    "reference": RiskLevel.INFO,
}

# ─── Dependency Manifest Patterns ──────────────────────────────────────────────

# Build a flat list of (pattern, lib_name, maturity, algorithms)
_DEP_PATTERNS: list[tuple[re.Pattern, str, str, list[str]]] = []

for lib_name, lib_info in _PQC_LIB_DB.items():
    maturity = lib_info.get("maturity", "experimental")
    algorithms = lib_info.get("algorithms", [])

    # Python packages
    for pkg in lib_info.get("pip", []):
        _DEP_PATTERNS.append((
            re.compile(rf"\b{re.escape(pkg)}\b", re.IGNORECASE),
            lib_name, maturity, algorithms,
        ))

    # NPM packages
    for pkg in lib_info.get("npm", []):
        _DEP_PATTERNS.append((
            re.compile(rf'["\']?{re.escape(pkg)}["\']?', re.IGNORECASE),
            lib_name, maturity, algorithms,
        ))

    # Go modules
    for pkg in lib_info.get("go", []):
        _DEP_PATTERNS.append((
            re.compile(rf"\b{re.escape(pkg)}\b", re.IGNORECASE),
            lib_name, maturity, algorithms,
        ))

    # Rust crates
    for pkg in lib_info.get("rust", []):
        _DEP_PATTERNS.append((
            re.compile(rf'\b{re.escape(pkg)}\b', re.IGNORECASE),
            lib_name, maturity, algorithms,
        ))

    # Java artifacts
    for pkg in lib_info.get("java", []):
        _DEP_PATTERNS.append((
            re.compile(rf'{re.escape(pkg)}', re.IGNORECASE),
            lib_name, maturity, algorithms,
        ))

    # Docker images
    for img in lib_info.get("docker", []):
        _DEP_PATTERNS.append((
            re.compile(rf"\b{re.escape(img)}\b", re.IGNORECASE),
            lib_name, maturity, algorithms,
        ))

    # Config patterns (TLS configs, build flags, etc.)
    for cfg in lib_info.get("config_patterns", []):
        _DEP_PATTERNS.append((
            re.compile(rf"\b{re.escape(cfg)}\b", re.IGNORECASE),
            lib_name, maturity, algorithms,
        ))


# Dependency manifest filenames to scan
_MANIFEST_FILES = {
    "requirements.txt", "pyproject.toml", "pipfile", "setup.py", "setup.cfg",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "go.mod", "go.sum",
    "cargo.toml", "cargo.lock",
    "pom.xml", "build.gradle", "build.gradle.kts",
    "dockerfile", "containerfile",
    "sbom.json", "bom.xml", "cyclonedx.json",
    "docker-compose.yml", "docker-compose.yaml",
}


class PQCLibraryEngine(PQSIAgent):
    """
    Agent 3 — PQC Library Intelligence Engine

    Scans dependency manifests, container images, imports, and SBOM files
    for post-quantum cryptography library adoption. Computes the
    Post-Quantum Adoption Index (0-100).
    """

    agent_name = "pqsi_library"
    agent_version = "1.0.0"
    description = "PQC library adoption scanning with Post-Quantum Adoption Index (0-100)"

    def scan_directory(self, target_dir: str) -> list[CryptoFinding]:
        """Override to track adoption index across all files."""
        findings = super().scan_directory(target_dir)

        # Compute aggregate Post-Quantum Adoption Index
        adoption_index = self._compute_adoption_index(findings)

        # Tag all findings with the aggregate index
        for f in findings:
            f.pqc_adoption_index = adoption_index

        return findings

    def scan_file(self, content: str, filepath: str, language: str) -> list[CryptoFinding]:
        findings: list[CryptoFinding] = []
        seen_keys: set[str] = set()
        basename = os.path.basename(filepath).lower()

        # Prioritize manifest files but scan all eligible files
        is_manifest = basename in _MANIFEST_FILES
        lines = content.split("\n")

        for line_idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue

            for pattern, lib_name, maturity, algorithms in _DEP_PATTERNS:
                match = pattern.search(line)
                if match:
                    dedup_key = f"{filepath}:{lib_name}"
                    if dedup_key in seen_keys:
                        continue
                    seen_keys.add(dedup_key)

                    algo_str = ", ".join(algorithms[:4])
                    maturity_score = _MATURITY_SCORES.get(maturity, 10)

                    findings.append(self._create_finding(
                        filepath=filepath,
                        line_number=line_idx,
                        line_content=stripped,
                        algorithm=f"PQC-Library:{lib_name}",
                        family=AlgoFamily.PQC_ADOPTION,
                        risk=_MATURITY_RISK.get(maturity, RiskLevel.INFO),
                        confidence=0.90 if is_manifest else 0.70,
                        pattern_note=(
                            f"PQC library '{lib_name}' detected (maturity: {maturity}). "
                            f"Supports: {algo_str}. Adoption score: {maturity_score}/100."
                        ),
                        language=language,
                        hndl_relevant=False,
                        migration={
                            "action": f"Validate PQC library '{lib_name}' deployment — maturity: {maturity}",
                            "library": lib_name,
                            "maturity": maturity,
                            "algorithms": algorithms,
                        },
                        tags=[
                            "PQC_ADOPTION",
                            f"MATURITY_{maturity.upper()}",
                            f"LIB_{lib_name.upper().replace('-', '_')}",
                        ],
                        column_start=match.start(),
                        column_end=match.end(),
                        pqc_adoption_index=float(maturity_score),
                    ))

        return findings

    def _compute_adoption_index(self, findings: list[CryptoFinding]) -> float:
        """
        Compute Post-Quantum Adoption Index (0-100).

        Factors:
          - Highest maturity PQC library found (40%)
          - Number of distinct PQC libraries (20%)
          - Presence in deployment configs (containers, TLS) (20%)
          - Crypto agility signals (20%)
        """
        if not findings:
            return 0.0

        # Highest maturity score
        maturity_scores = []
        distinct_libs: set[str] = set()
        deployment_signals = 0
        agility_signals = 0

        for f in findings:
            if f.family == AlgoFamily.PQC_ADOPTION:
                lib_name = f.migration.get("library", "")
                maturity = f.migration.get("maturity", "experimental")
                distinct_libs.add(lib_name)
                maturity_scores.append(_MATURITY_SCORES.get(maturity, 10))

                # Check if in deployment config
                basename = os.path.basename(f.file).lower()
                if basename in ("dockerfile", "containerfile", "docker-compose.yml",
                                "docker-compose.yaml", "nginx.conf", "haproxy.cfg"):
                    deployment_signals += 1

            elif f.family == AlgoFamily.CRYPTO_AGILITY_SIGNAL:
                agility_signals += 1

        highest_maturity = max(maturity_scores) if maturity_scores else 0
        lib_diversity = min(100, len(distinct_libs) * 20)
        deploy_score = min(100, deployment_signals * 25)
        agility_score = min(100, agility_signals * 20)

        index = (
            highest_maturity * 0.40
            + lib_diversity * 0.20
            + deploy_score * 0.20
            + agility_score * 0.20
        )
        return round(min(100.0, max(0.0, index)), 1)
