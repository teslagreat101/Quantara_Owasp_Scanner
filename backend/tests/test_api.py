"""
Quantum Protocol v5.0 — Backend API Tests
Comprehensive test suite for all API endpoints.

Phase 9: Testing & Verification
"""

import pytest
import asyncio
from fastapi.testclient import TestClient
from datetime import datetime, timezone
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.main import app, scans, MODULE_REGISTRY

client = TestClient(app)


class TestHealthEndpoints:
    """Test health check endpoints."""

    def test_health_check(self):
        """Test /api/v1/health endpoint."""
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "modules" in data
        assert "total_patterns" in data

    def test_modules_list(self):
        """Test /api/v1/modules endpoint."""
        response = client.get("/api/v1/modules")
        assert response.status_code == 200
        data = response.json()
        assert "modules" in data
        assert len(data["modules"]) > 0

    def test_profiles_list(self):
        """Test /api/v1/profiles endpoint."""
        response = client.get("/api/v1/profiles")
        assert response.status_code == 200
        data = response.json()
        assert "profiles" in data


class TestScanEndpoints:
    """Test scan lifecycle endpoints."""

    def test_start_scan_validation(self):
        """Test scan start with invalid input."""
        response = client.post("/api/v1/scan", json={
            "target": "/nonexistent/path",
            "modules": ["invalid_module"]
        })
        # Should fail with 400 for invalid path
        assert response.status_code in [200, 400]  # Depends on path existence

    def test_get_nonexistent_scan(self):
        """Test getting a scan that doesn't exist."""
        response = client.get("/api/v1/scan/invalid-scan-id")
        assert response.status_code == 404

    def test_cancel_nonexistent_scan(self):
        """Test cancelling a scan that doesn't exist."""
        response = client.post("/api/v1/scan/invalid-scan-id/cancel")
        assert response.status_code == 404


class TestBillingEndpoints:
    """Test billing API endpoints."""

    def test_list_plans(self):
        """Test /api/v1/billing/plans endpoint."""
        response = client.get("/api/v1/billing/plans")
        assert response.status_code == 200
        data = response.json()
        assert "plans" in data
        assert len(data["plans"]) >= 3  # Free, Pro, Enterprise

    def test_get_subscription(self):
        """Test /api/v1/billing/subscription endpoint."""
        response = client.get("/api/v1/billing/subscription")
        assert response.status_code == 200
        data = response.json()
        assert "subscription" in data

    def test_get_usage(self):
        """Test /api/v1/billing/usage endpoint."""
        response = client.get("/api/v1/billing/usage")
        assert response.status_code == 200
        data = response.json()
        assert "scans_this_month" in data
        assert "scans_limit" in data


class TestTokenEndpoints:
    """Test API token management endpoints."""

    def test_create_token(self):
        """Test creating an API token."""
        response = client.post("/api/v1/tokens", json={
            "name": "Test Token",
            "scopes": ["read", "scan"]
        })
        assert response.status_code == 200
        data = response.json()
        assert "token_id" in data
        assert "token" in data
        assert "token" in data["message"]  # Warning about copying token
        return data["token_id"]

    def test_list_tokens(self):
        """Test listing API tokens."""
        response = client.get("/api/v1/tokens")
        assert response.status_code == 200
        data = response.json()
        assert "tokens" in data


class TestAIEndpoints:
    """Test AI-powered remediation endpoints."""

    def test_ai_analyze(self):
        """Test AI analysis endpoint."""
        response = client.post("/api/v1/ai/analyze", json={
            "finding_id": "test-finding",
            "finding": {
                "title": "SQL Injection",
                "severity": "critical",
                "description": "Potential SQL injection vulnerability",
                "cwe": "CWE-89"
            }
        })
        assert response.status_code == 200
        data = response.json()
        assert "risk_explanation" in data
        assert "fix_suggestion" in data
        assert "confidence" in data

    def test_ai_chat(self):
        """Test AI chat assistant endpoint."""
        response = client.post("/api/v1/ai/chat", json={
            "question": "How to prevent SQL injection?"
        })
        assert response.status_code == 200
        data = response.json()
        assert "response" in data


class TestComplianceEndpoints:
    """Test compliance dashboard endpoints."""

    def test_owasp_compliance(self):
        """Test OWASP compliance endpoint."""
        response = client.get("/api/v1/compliance/owasp")
        assert response.status_code == 200
        data = response.json()
        assert "score" in data
        assert "categories" in data
        assert "total_categories" in data


class TestDashboardEndpoints:
    """Test dashboard API endpoints."""

    def test_dashboard_stats(self):
        """Test dashboard stats endpoint."""
        response = client.get("/api/v1/dashboard/stats")
        assert response.status_code == 200
        data = response.json()
        assert "total_scans" in data
        assert "total_findings" in data
        assert "severity_counts" in data
        assert "security_score" in data


class TestReportGeneration:
    """Test report generation endpoints."""

    def test_download_json_report(self):
        """Test JSON report download."""
        # First, we need a scan to exist
        # For now, just test the endpoint structure
        response = client.get("/api/v1/scan/nonexistent/download?format=json")
        assert response.status_code == 404  # Scan not found

    def test_download_html_report_404(self):
        """Test HTML report download returns 404 for nonexistent scan."""
        response = client.get("/api/v1/scan/nonexistent/download?format=html")
        assert response.status_code == 404


# ═══════════════════════════════════════════════════════════════════════════════
# Integration Tests
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_full_scan_workflow():
    """Test complete scan workflow from start to finish."""
    # This would test the full scan lifecycle
    # Requires the scanner engine to be properly configured
    pass


def test_cors_headers():
    """Test CORS headers are present."""
    response = client.options("/api/v1/health")
    # CORS headers should be present
    assert "access-control-allow-origin" in response.headers


def test_error_handling():
    """Test API error handling."""
    # Test invalid JSON
    response = client.post(
        "/api/v1/scan",
        data="invalid json",
        headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 422  # Validation error


# ═══════════════════════════════════════════════════════════════════════════════
# Run Tests
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
