"""
Quantum Protocol v5.0 — PQSI Agent 4: Quantum Threat Timeline Engine

Post-processing engine that enriches existing crypto findings with:
  - Quantum Exposure Timeline (estimated year of quantum break)
  - Years Until Quantum Risk
  - Migration Urgency Score (immediate/urgent/planned/monitoring)
  - Data longevity estimation based on context

This is NOT a scanner — it's a post-processor that operates on findings
produced by other agents and the existing quantum_pqc scanner.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional

from quantum_protocol.models.enums import AlgoFamily, RiskLevel
from quantum_protocol.models.findings import CryptoFinding

# ─── Quantum Break Estimates ──────────────────────────────────────────────────
#
# Based on NIST / IBM / Google quantum computing roadmaps (2024-2026 projections).
# "break_year" = median estimate for cryptographically-relevant quantum computer.
# Range reflects uncertainty.

_QUANTUM_BREAK_ESTIMATES: dict[AlgoFamily, dict] = {
    # Asymmetric — all broken by Shor's algorithm
    AlgoFamily.RSA:       {"break_year": 2037, "range": (2033, 2042), "basis": "Shor's algorithm (factoring)"},
    AlgoFamily.RSA_OAEP:  {"break_year": 2037, "range": (2033, 2042), "basis": "Shor's algorithm (factoring)"},
    AlgoFamily.ECC:       {"break_year": 2035, "range": (2031, 2040), "basis": "Shor's algorithm (ECDLP)"},
    AlgoFamily.ECDSA:     {"break_year": 2035, "range": (2031, 2040), "basis": "Shor's algorithm (ECDLP)"},
    AlgoFamily.ECDH:      {"break_year": 2035, "range": (2031, 2040), "basis": "Shor's algorithm (ECDLP)"},
    AlgoFamily.DSA:       {"break_year": 2035, "range": (2031, 2040), "basis": "Shor's algorithm (DLP)"},
    AlgoFamily.DH:        {"break_year": 2037, "range": (2033, 2042), "basis": "Shor's algorithm (DLP)"},
    AlgoFamily.ELGAMAL:   {"break_year": 2037, "range": (2033, 2042), "basis": "Shor's algorithm (DLP)"},
    AlgoFamily.X25519:    {"break_year": 2035, "range": (2031, 2040), "basis": "Shor's algorithm (ECDLP)"},
    AlgoFamily.ED25519:   {"break_year": 2035, "range": (2031, 2040), "basis": "Shor's algorithm (ECDLP)"},
    AlgoFamily.ED448:     {"break_year": 2036, "range": (2032, 2041), "basis": "Shor's algorithm (ECDLP)"},
    AlgoFamily.X448:      {"break_year": 2036, "range": (2032, 2041), "basis": "Shor's algorithm (ECDLP)"},
    # Symmetric — Grover's halves effective key length
    AlgoFamily.AES_128:   {"break_year": 2045, "range": (2040, 2055), "basis": "Grover's algorithm (64-bit security)"},
    AlgoFamily.DES:       {"break_year": 2030, "range": (2028, 2033), "basis": "Classically broken + Grover"},
    AlgoFamily.TRIPLE_DES: {"break_year": 2035, "range": (2032, 2040), "basis": "Grover reduces to 56-bit"},
    AlgoFamily.RC4:       {"break_year": 2028, "range": (2026, 2030), "basis": "Classically broken"},
    # Hashes — Grover's provides quadratic speedup
    AlgoFamily.MD5:       {"break_year": 2028, "range": (2026, 2030), "basis": "Classically broken + Grover"},
    AlgoFamily.SHA1:      {"break_year": 2030, "range": (2028, 2033), "basis": "Classically broken + Grover"},
}

# ─── Data Longevity Context ───────────────────────────────────────────────────
#
# Estimate how long different types of data need protection based on file/path context.

_DATA_LONGEVITY_RULES: list[tuple[re.Pattern, str, int]] = [
    (re.compile(r"(?:patient|health|medical|hipaa|ehr|dicom)", re.IGNORECASE),
     "Healthcare/Medical data — 50+ year protection required", 50),
    (re.compile(r"(?:financial|banking|payment|trading|ledger|account)", re.IGNORECASE),
     "Financial data — 20+ year protection required", 20),
    (re.compile(r"(?:customer|user[_\-]?data|pii|personal|gdpr)", re.IGNORECASE),
     "Personal/PII data — 15-25 year protection required", 20),
    (re.compile(r"(?:classified|secret|top[_\-]?secret|confidential)", re.IGNORECASE),
     "Classified data — 25+ year protection required", 25),
    (re.compile(r"(?:contract|legal|compliance|audit|regulatory)", re.IGNORECASE),
     "Legal/Compliance data — 10-20 year protection required", 15),
    (re.compile(r"(?:database|db[_\-]?config|migration|schema)", re.IGNORECASE),
     "Database credentials — 5-10 year protection required", 7),
    (re.compile(r"(?:auth|session|token|jwt|oauth|cookie)", re.IGNORECASE),
     "Authentication tokens — 1-3 year protection required", 2),
    (re.compile(r"(?:tls|ssl|certificate|handshake|cipher)", re.IGNORECASE),
     "TLS/Certificate data — 5-10 year protection required", 7),
    (re.compile(r"(?:backup|archive|snapshot|dump)", re.IGNORECASE),
     "Backup/Archive data — 10-20 year protection required", 15),
    (re.compile(r"(?:api[_\-]?key|secret[_\-]?key|access[_\-]?key)", re.IGNORECASE),
     "API credentials — 3-5 year protection required", 4),
]

_DEFAULT_LONGEVITY = ("General data — 7-10 year protection assumed", 10)


class QuantumTimelineEngine:
    """
    Agent 4 — Quantum Threat Timeline Engine

    Post-processing engine that enriches existing crypto findings with
    quantum exposure timeline data, estimated break years, and migration
    urgency scores.
    """

    def __init__(self) -> None:
        self._current_year = datetime.now(timezone.utc).year

    def compute_timeline(self, findings: list[CryptoFinding]) -> list[CryptoFinding]:
        """
        Enrich findings with quantum exposure timeline data.

        For each finding with a quantum-vulnerable algorithm:
          - Estimates the year the algorithm will be broken
          - Calculates years until quantum risk
          - Assesses data longevity requirements
          - Determines migration urgency
          - Sets future decryption risk
        """
        for finding in findings:
            estimate = _QUANTUM_BREAK_ESTIMATES.get(finding.family)
            if estimate is None:
                # Not a quantum-vulnerable algorithm
                continue

            break_year = estimate["break_year"]
            years_until_risk = break_year - self._current_year

            # Data longevity estimation from file path context
            longevity_desc, longevity_years = self._estimate_data_longevity(finding.file)

            # Quantum exposure years = years until break
            finding.quantum_exposure_years = float(max(0, years_until_risk))

            # Data longevity estimate
            finding.data_longevity_estimate = longevity_desc

            # Migration urgency based on exposure window vs data longevity
            finding.migration_urgency = self._compute_urgency(
                years_until_risk, longevity_years
            )

            # HNDL probability — if data will outlive quantum timeline, HNDL is relevant
            if longevity_years > years_until_risk:
                finding.hndl_relevant = True
                hndl_score = min(1.0, (longevity_years - years_until_risk) / 10.0)
                finding.hndl_probability_score = round(hndl_score, 2)
                finding.future_decryption_risk = (
                    "critical" if hndl_score >= 0.8
                    else "high" if hndl_score >= 0.5
                    else "medium"
                )
            else:
                finding.future_decryption_risk = (
                    "medium" if years_until_risk < 10
                    else "low"
                )

        return findings

    def generate_exposure_summary(self, findings: list[CryptoFinding]) -> dict:
        """
        Generate aggregated quantum exposure summary.

        Returns:
            {
                "algorithms": {algo: {count, earliest_break_year, urgency_distribution}},
                "earliest_risk_year": int,
                "average_exposure_years": float,
                "migration_urgency_distribution": {urgency: count},
                "assets_at_risk": int,
                "critical_assets": int,
            }
        """
        algo_data: dict[str, dict] = {}
        urgency_dist: dict[str, int] = {
            "immediate": 0, "urgent": 0, "planned": 0, "monitoring": 0,
        }
        exposure_years_list: list[float] = []
        earliest_year = 9999
        critical_assets = 0

        for f in findings:
            estimate = _QUANTUM_BREAK_ESTIMATES.get(f.family)
            if estimate is None:
                continue

            algo_key = f.family.value
            if algo_key not in algo_data:
                algo_data[algo_key] = {
                    "count": 0,
                    "break_year": estimate["break_year"],
                    "break_range": list(estimate["range"]),
                    "basis": estimate["basis"],
                }
            algo_data[algo_key]["count"] += 1

            if estimate["break_year"] < earliest_year:
                earliest_year = estimate["break_year"]

            if f.quantum_exposure_years is not None:
                exposure_years_list.append(f.quantum_exposure_years)

            urgency = f.migration_urgency or "monitoring"
            urgency_dist[urgency] = urgency_dist.get(urgency, 0) + 1

            if urgency in ("immediate", "urgent"):
                critical_assets += 1

        return {
            "algorithms": algo_data,
            "earliest_risk_year": earliest_year if earliest_year < 9999 else None,
            "average_exposure_years": (
                round(sum(exposure_years_list) / len(exposure_years_list), 1)
                if exposure_years_list else None
            ),
            "migration_urgency_distribution": urgency_dist,
            "assets_at_risk": len(exposure_years_list),
            "critical_assets": critical_assets,
        }

    def _estimate_data_longevity(self, filepath: str) -> tuple[str, int]:
        """Estimate how long data at this path needs protection."""
        for pattern, description, years in _DATA_LONGEVITY_RULES:
            if pattern.search(filepath):
                return description, years
        return _DEFAULT_LONGEVITY

    @staticmethod
    def _compute_urgency(years_until_risk: int, data_longevity_years: int) -> str:
        """
        Determine migration urgency.

        Factors:
          - Years until quantum computer can break the algorithm
          - How long the data needs to remain confidential
          - If data longevity exceeds quantum timeline → IMMEDIATE
        """
        effective_window = years_until_risk - data_longevity_years

        if effective_window <= 0:
            return "immediate"
        if effective_window <= 5:
            return "urgent"
        if effective_window <= 10:
            return "planned"
        return "monitoring"
