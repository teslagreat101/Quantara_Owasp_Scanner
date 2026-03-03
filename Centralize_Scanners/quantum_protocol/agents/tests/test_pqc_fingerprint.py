"""Tests for PQC Fingerprint Agent (Agent 1)."""
from __future__ import annotations

import pytest
from quantum_protocol.agents.pqc_fingerprint_agent import PQCFingerprintAgent
from quantum_protocol.models.enums import AlgoFamily


@pytest.fixture
def agent():
    return PQCFingerprintAgent()


class TestPQCFingerprintAgent:
    """Test PQC detection patterns across various file types."""

    def test_detects_kyber_tls_config(self, agent):
        content = """
ssl_protocols TLSv1.3;
ssl_ecdh_curve X25519Kyber768Draft00:X25519:P-256;
ssl_ciphers HIGH:!aNULL:!MD5;
"""
        findings = agent.scan_file(content, "nginx.conf", "config")
        assert len(findings) >= 1
        kyber_findings = [f for f in findings if "Kyber" in f.algorithm or "HYBRID" in str(f.tags)]
        assert len(kyber_findings) >= 1

    def test_detects_oqs_python_import(self, agent):
        content = """
import oqs
from oqs import KeyEncapsulation
kem = KeyEncapsulation("Kyber768")
"""
        findings = agent.scan_file(content, "crypto_module.py", "python")
        assert len(findings) >= 1
        assert any("PQC_ACTIVE" in (f.tags or []) or "PQC_EXPERIMENTAL" in (f.tags or []) for f in findings)

    def test_detects_dilithium_reference(self, agent):
        content = """
const signer = new Dilithium3();
const signature = signer.sign(message);
"""
        findings = agent.scan_file(content, "sign.ts", "typescript")
        dilithium = [f for f in findings if "Dilithium" in f.algorithm]
        assert len(dilithium) >= 1

    def test_detects_sphincs_plus(self, agent):
        content = 'algo = "SPHINCS+-SHA256-128f-simple"'
        findings = agent.scan_file(content, "config.py", "python")
        sphincs = [f for f in findings if "SPHINCS" in f.algorithm]
        assert len(sphincs) >= 1

    def test_no_false_positives_on_plain_text(self, agent):
        content = """
This is a regular README file.
It talks about security best practices.
No cryptographic algorithms here.
"""
        findings = agent.scan_file(content, "README.md", "markdown")
        assert len(findings) == 0

    def test_detects_hybrid_tls_negotiation(self, agent):
        content = """
groups = X25519Kyber768Draft00
provider = oqsprovider
"""
        findings = agent.scan_file(content, "openssl.cnf", "config")
        hybrid = [f for f in findings if any("HYBRID" in t for t in (f.tags or []))]
        assert len(hybrid) >= 1

    def test_detects_falcon_in_go_code(self, agent):
        content = """
package main
import "github.com/open-quantum-safe/liboqs-go/oqs"
func main() {
    signer, _ := oqs.NewSignature("Falcon-512")
}
"""
        findings = agent.scan_file(content, "main.go", "go")
        assert len(findings) >= 1

    def test_detects_docker_pqc_image(self, agent):
        content = """
FROM openquantumsafe/oqs-openssl:latest
COPY app /app
"""
        findings = agent.scan_file(content, "Dockerfile", "dockerfile")
        assert len(findings) >= 1
