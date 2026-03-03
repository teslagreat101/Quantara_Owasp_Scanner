"""Tests for Quantum Threat Timeline Engine (Agent 4)."""
from __future__ import annotations

import pytest
from quantum_protocol.intelligence.quantum_timeline import QuantumTimelineEngine
from quantum_protocol.models.enums import AlgoFamily, RiskLevel
from quantum_protocol.models.findings import CryptoFinding


def _make_finding(family: AlgoFamily, filepath: str = "app/crypto.py") -> CryptoFinding:
    """Helper to create a minimal CryptoFinding for testing."""
    return CryptoFinding(
        file=filepath,
        line=1,
        algorithm=family.value,
        family=family,
        risk=RiskLevel.HIGH,
        confidence=0.95,
        pattern_note="Test finding",
        language="python",
        hndl_relevant=False,
        migration={"action": "Migrate to PQC"},
    )


@pytest.fixture
def engine():
    return QuantumTimelineEngine()


class TestQuantumTimelineEngine:
    """Test quantum exposure timeline computation."""

    def test_rsa_timeline(self, engine):
        findings = [_make_finding(AlgoFamily.RSA)]
        enriched = engine.compute_timeline(findings)
        assert len(enriched) == 1
        f = enriched[0]
        assert f.quantum_exposure_years is not None
        assert f.quantum_exposure_years > 0
        assert f.migration_urgency in ("immediate", "urgent", "planned", "monitoring")

    def test_ecc_breaks_earlier_than_rsa(self, engine):
        rsa_findings = engine.compute_timeline([_make_finding(AlgoFamily.RSA)])
        ecc_findings = engine.compute_timeline([_make_finding(AlgoFamily.ECC)])
        # ECC estimated to break earlier than RSA
        assert ecc_findings[0].quantum_exposure_years <= rsa_findings[0].quantum_exposure_years

    def test_healthcare_data_gets_immediate_urgency(self, engine):
        findings = [_make_finding(AlgoFamily.RSA, "patient_records/encrypt.py")]
        enriched = engine.compute_timeline(findings)
        # Healthcare data with 50-year longevity should flag as immediate
        assert enriched[0].migration_urgency == "immediate"
        assert enriched[0].data_longevity_estimate is not None
        assert "Healthcare" in enriched[0].data_longevity_estimate or "Medical" in enriched[0].data_longevity_estimate

    def test_auth_token_gets_monitoring(self, engine):
        findings = [_make_finding(AlgoFamily.RSA, "auth/session_token.py")]
        enriched = engine.compute_timeline(findings)
        # Auth tokens only need 1-3 year protection; RSA breaks ~2037 → plenty of time
        assert enriched[0].migration_urgency in ("planned", "monitoring")

    def test_hndl_relevance_for_long_lived_data(self, engine):
        findings = [_make_finding(AlgoFamily.ECC, "financial/ledger_encryption.py")]
        enriched = engine.compute_timeline(findings)
        f = enriched[0]
        # Financial data (20y longevity) with ECC (breaks ~2035) → HNDL relevant
        assert f.hndl_relevant is True
        assert f.hndl_probability_score is not None
        assert f.hndl_probability_score > 0
        assert f.future_decryption_risk in ("critical", "high", "medium")

    def test_pqc_safe_algorithms_unaffected(self, engine):
        findings = [_make_finding(AlgoFamily.PQC_KYBER)]
        enriched = engine.compute_timeline(findings)
        f = enriched[0]
        # PQC algorithms shouldn't get timeline enrichment
        assert f.quantum_exposure_years is None
        assert f.migration_urgency is None

    def test_classically_broken_algorithms(self, engine):
        findings = [_make_finding(AlgoFamily.MD5)]
        enriched = engine.compute_timeline(findings)
        f = enriched[0]
        assert f.quantum_exposure_years is not None
        # MD5 estimated break is very soon
        assert f.quantum_exposure_years <= 5

    def test_exposure_summary_aggregation(self, engine):
        findings = [
            _make_finding(AlgoFamily.RSA, "server/tls.py"),
            _make_finding(AlgoFamily.ECC, "auth/sign.py"),
            _make_finding(AlgoFamily.RSA, "database/encrypt.py"),
        ]
        enriched = engine.compute_timeline(findings)
        summary = engine.generate_exposure_summary(enriched)

        assert summary["algorithms"] is not None
        assert "RSA" in summary["algorithms"]
        assert summary["algorithms"]["RSA"]["count"] == 2
        assert summary["earliest_risk_year"] is not None
        assert summary["assets_at_risk"] == 3
        assert isinstance(summary["migration_urgency_distribution"], dict)

    def test_empty_findings(self, engine):
        enriched = engine.compute_timeline([])
        assert len(enriched) == 0
        summary = engine.generate_exposure_summary([])
        assert summary["earliest_risk_year"] is None
        assert summary["assets_at_risk"] == 0
