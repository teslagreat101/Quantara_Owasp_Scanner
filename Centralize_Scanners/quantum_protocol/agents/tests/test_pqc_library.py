"""Tests for PQC Library Intelligence Engine (Agent 3)."""
from __future__ import annotations

import pytest
from quantum_protocol.agents.pqc_library_engine import PQCLibraryEngine
from quantum_protocol.models.enums import AlgoFamily


@pytest.fixture
def agent():
    return PQCLibraryEngine()


class TestPQCLibraryEngine:
    """Test PQC library detection in dependency manifests."""

    def test_detects_liboqs_in_requirements(self, agent):
        content = """
Flask==2.3.0
cryptography==41.0.0
liboqs-python==0.9.0
requests==2.31.0
"""
        findings = agent.scan_file(content, "requirements.txt", "text")
        assert len(findings) >= 1
        assert any(f.family == AlgoFamily.PQC_ADOPTION for f in findings)
        assert any("liboqs" in (f.migration.get("library", "") if f.migration else "") for f in findings)

    def test_detects_pqcrypto_in_cargo(self, agent):
        content = """
[dependencies]
pqcrypto = "0.17"
serde = "1.0"
tokio = { version = "1", features = ["full"] }
"""
        findings = agent.scan_file(content, "Cargo.toml", "toml")
        pqc_findings = [f for f in findings if f.family == AlgoFamily.PQC_ADOPTION]
        assert len(pqc_findings) >= 1

    def test_detects_oqs_openssl_docker(self, agent):
        content = """
FROM openquantumsafe/oqs-openssl:latest
RUN apt-get update && apt-get install -y nginx
COPY nginx.conf /etc/nginx/nginx.conf
"""
        findings = agent.scan_file(content, "Dockerfile", "dockerfile")
        assert len(findings) >= 1

    def test_detects_bouncy_castle_pq_maven(self, agent):
        content = """
<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcpqc-jdk18on</artifactId>
    <version>1.77</version>
</dependency>
"""
        findings = agent.scan_file(content, "pom.xml", "xml")
        assert len(findings) >= 1

    def test_computes_adoption_index(self, agent):
        content = """
liboqs-python==0.9.0
oqs-provider==0.5.0
"""
        findings = agent.scan_file(content, "requirements.txt", "text")
        # Should have findings with adoption index
        assert all(f.pqc_adoption_index is not None for f in findings if f.family == AlgoFamily.PQC_ADOPTION)

    def test_no_false_positive_on_standard_deps(self, agent):
        content = """
Flask==2.3.0
numpy==1.24.0
pandas==2.0.0
requests==2.31.0
"""
        findings = agent.scan_file(content, "requirements.txt", "text")
        pqc_findings = [f for f in findings if f.family == AlgoFamily.PQC_ADOPTION]
        assert len(pqc_findings) == 0

    def test_detects_aws_lc_in_go_mod(self, agent):
        content = """
module example.com/myapp

go 1.21

require (
    github.com/aws/aws-lc-go v1.0.0
    github.com/gin-gonic/gin v1.9.1
)
"""
        findings = agent.scan_file(content, "go.mod", "go")
        assert len(findings) >= 1
