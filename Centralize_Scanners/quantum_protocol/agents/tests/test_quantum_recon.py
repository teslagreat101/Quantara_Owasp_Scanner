"""Tests for Quantum Recon Detection Agent (Agent 5)."""
from __future__ import annotations

import pytest
from quantum_protocol.agents.quantum_recon_agent import QuantumReconAgent
from quantum_protocol.models.enums import RiskLevel


@pytest.fixture
def agent():
    return QuantumReconAgent()


class TestQuantumReconAgent:
    """Test quantum recon pattern detection and severity escalation."""

    def test_detects_cert_enumeration(self, agent):
        content = """
#!/bin/bash
# Enumerate all certs for target domains
for domain in $(cat domains.txt); do
    curl -s "https://crt.sh/?q=%25.$domain&output=json" >> certs.json
done
"""
        findings = agent.scan_file(content, "enum_certs.sh", "shell")
        assert len(findings) >= 1
        assert any("CRYPTO_ENUMERATION" in str(f.tags) or "ENUMERATION" in str(f.tags) for f in findings)

    def test_detects_mass_tls_probing(self, agent):
        content = """
sslyze --targets_in=hosts.txt --json_out=tls_results.json --regular
testssl.sh --csvfile results.csv --parallel target.example.com
"""
        findings = agent.scan_file(content, "probe_tls.sh", "shell")
        assert len(findings) >= 1

    def test_detects_key_discovery_automation(self, agent):
        content = """
import paramiko
for host in targets:
    key = paramiko.RSAKey.generate(2048)
    ssh = paramiko.SSHClient()
    ssh.connect(host, pkey=key)
    # Enumerate SSH host keys
    transport = ssh.get_transport()
    host_key = transport.get_remote_server_key()
    key_inventory.append({
        'host': host,
        'key_type': host_key.get_name(),
        'key_bits': host_key.get_bits(),
    })
"""
        findings = agent.scan_file(content, "key_scanner.py", "python")
        assert len(findings) >= 1

    def test_severity_escalation_multi_category(self, agent):
        content = """
#!/bin/bash
# Mass cert enumeration
curl "https://crt.sh/?q=%25.target.com&output=json" > certs.json

# TLS probing
sslyze --targets_in=hosts.txt --json_out=tls.json

# Key discovery
ssh-keyscan -t rsa,ecdsa target.com >> keys.txt

# Dataset indexing
find /captures -name "*.pcap" | xargs tshark -r -T json > indexed.json
"""
        findings = agent.scan_file(content, "full_recon.sh", "shell")
        assert len(findings) >= 3
        # Multi-category detection should escalate severity
        tags = set()
        for f in findings:
            tags.update(f.tags or [])
        assert any("RECON" in t or "ENUMERATION" in t for t in tags)

    def test_nation_state_detection(self, agent):
        content = """
#!/bin/bash
# Automated mass TLS probing + dataset indexing
masscan -p443 0.0.0.0/0 --rate=100000 | tee scan_results.txt
sslyze --targets_in=scan_results.txt --json_out=global_tls.json
# Index all captured data
find /data -name "*.pcap" -exec tshark -r {} -T json \; > indexed_captures.json
sqlite3 recon.db "INSERT INTO captures SELECT * FROM json_each(readfile('indexed_captures.json'))"
"""
        findings = agent.scan_file(content, "nation_state_recon.sh", "shell")
        assert len(findings) >= 2

    def test_no_false_positive_single_cert_check(self, agent):
        content = """
# Simple cert validation
openssl s_client -connect example.com:443 -servername example.com
"""
        findings = agent.scan_file(content, "check_cert.sh", "shell")
        # Single basic cert check shouldn't flag as recon
        recon_findings = [f for f in findings if any("RECON" in t for t in (f.tags or []))]
        assert len(recon_findings) == 0
