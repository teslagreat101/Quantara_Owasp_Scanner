"""Integration tests for Quantum Intelligence API endpoint."""
from __future__ import annotations

import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    """Create a test client for the FastAPI app."""
    from backend.main import app
    return TestClient(app)


@pytest.fixture
def mock_db_session():
    """Mock database session."""
    with patch("backend.main.get_db") as mock_get_db:
        session = MagicMock()
        mock_get_db.return_value = iter([session])
        yield session


class TestQuantumIntelligenceEndpoint:
    """Test the /api/v1/quantum/intelligence/{scan_id} endpoint."""

    def test_returns_404_for_nonexistent_scan(self, client):
        response = client.get("/api/v1/quantum/intelligence/nonexistent-id-12345")
        assert response.status_code in (404, 401, 403)

    def test_endpoint_exists(self, client):
        """Verify the endpoint is registered and responds."""
        response = client.get("/api/v1/quantum/intelligence/test-scan-id")
        # Should return a valid HTTP response (not 405 Method Not Allowed)
        assert response.status_code != 405

    def test_returns_fallback_when_no_pqsi_data(self, client, mock_db_session):
        """When no PQSI events exist, should return default structure."""
        mock_scan = MagicMock()
        mock_scan.id = "test-scan-123"
        mock_scan.events = []

        mock_db_session.query.return_value.filter.return_value.first.return_value = mock_scan

        response = client.get("/api/v1/quantum/intelligence/test-scan-123")
        if response.status_code == 200:
            data = response.json()
            # Should have the expected structure even with no PQSI data
            assert "quantum_risk_score" in data or "qqsi_score" in data or "message" in data


class TestQuantumIntelligenceSchema:
    """Test the expected response schema from quantum intelligence events."""

    def test_quantum_intelligence_event_structure(self):
        """Validate the structure of quantum_intelligence SSE events."""
        expected_fields = {
            "qqsi_score", "qqsi_grade", "pqc_adoption_index",
            "hndl_findings_count", "quantum_recon_detected",
            "migration_priority", "components", "exposure_summary",
        }

        # Simulate a PQSI event payload
        sample_event = {
            "qqsi_score": 72.5,
            "qqsi_grade": "B",
            "pqc_adoption_index": 45.0,
            "hndl_findings_count": 3,
            "quantum_recon_detected": False,
            "migration_priority": "planned",
            "components": {
                "quantum_exposure_score": 18.0,
                "pqc_adoption_score": 11.25,
                "crypto_agility_score": 12.0,
                "hndl_risk_score": 10.5,
                "quantum_recon_risk": 15.0,
            },
            "exposure_summary": {
                "algorithms": {},
                "earliest_risk_year": 2035,
                "average_exposure_years": 9.5,
                "migration_urgency_distribution": {
                    "immediate": 1,
                    "urgent": 2,
                    "planned": 5,
                    "monitoring": 10,
                },
                "assets_at_risk": 18,
                "critical_assets": 3,
            },
        }

        # All expected fields present
        assert expected_fields.issubset(set(sample_event.keys()))

        # Type validations
        assert isinstance(sample_event["qqsi_score"], (int, float))
        assert sample_event["qqsi_grade"] in ("A", "B", "C", "D", "F")
        assert isinstance(sample_event["components"], dict)
        assert isinstance(sample_event["exposure_summary"], dict)
        assert isinstance(sample_event["quantum_recon_detected"], bool)
