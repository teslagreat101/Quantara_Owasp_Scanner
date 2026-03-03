"""Tests for Crypto Harvest Behavior Analyzer (Agent 2)."""
from __future__ import annotations

import pytest
from quantum_protocol.agents.crypto_harvest_analyzer import CryptoHarvestAnalyzer
from quantum_protocol.models.enums import AlgoFamily


@pytest.fixture
def agent():
    return CryptoHarvestAnalyzer()


class TestCryptoHarvestAnalyzer:
    """Test HNDL/harvest behavior detection."""

    def test_detects_tcpdump_capture(self, agent):
        content = """
#!/bin/bash
tcpdump -i eth0 -w /data/captures/traffic.pcap port 443
"""
        findings = agent.scan_file(content, "capture.sh", "shell")
        assert len(findings) >= 1
        assert any(f.family == AlgoFamily.HNDL_HARVEST for f in findings)

    def test_detects_sslkeylogfile(self, agent):
        content = """
export SSLKEYLOGFILE=/tmp/ssl_keys.log
curl https://target.example.com
"""
        findings = agent.scan_file(content, "debug_tls.sh", "shell")
        assert len(findings) >= 1
        logging_findings = [f for f in findings if any("LOGGING" in str(t) or "COLLECTION" in str(t) for t in (f.tags or []))]
        assert len(logging_findings) >= 1

    def test_detects_traffic_mirroring(self, agent):
        content = """
resource "aws_ec2_traffic_mirror_session" "main" {
  network_interface_id = aws_instance.target.primary_network_interface_id
  traffic_mirror_filter_id = aws_ec2_traffic_mirror_filter.filter.id
  traffic_mirror_target_id = aws_ec2_traffic_mirror_target.target.id
}
"""
        findings = agent.scan_file(content, "mirror.tf", "terraform")
        assert len(findings) >= 1

    def test_detects_mitmproxy(self, agent):
        content = """
mitmproxy --mode transparent --save-stream-file captured.flow
"""
        findings = agent.scan_file(content, "intercept.sh", "shell")
        assert len(findings) >= 1

    def test_combo_detection_elevates_severity(self, agent):
        content = """
#!/bin/bash
# Capture traffic
tcpdump -i eth0 -w /data/traffic.pcap
# Log TLS keys
export SSLKEYLOGFILE=/data/keys.log
# Mirror traffic
iptables -t mangle -A PREROUTING -j TEE --gateway 10.0.0.100
# Store long-term
tar czf /archive/capture_$(date +%Y%m%d).tar.gz /data/
aws s3 cp /archive/ s3://long-term-storage/ --recursive
"""
        findings = agent.scan_file(content, "harvest_all.sh", "shell")
        assert len(findings) >= 3
        # Combo findings should have elevated severity or HNDL tags
        hndl_tags = set()
        for f in findings:
            hndl_tags.update(f.tags or [])
        assert any("HARVEST" in t or "HNDL" in t or "COLLECTION" in t for t in hndl_tags)

    def test_no_false_positive_on_normal_backup(self, agent):
        content = """
# Regular database backup
pg_dump mydb > /backups/db_$(date +%Y%m%d).sql
"""
        findings = agent.scan_file(content, "backup.sh", "shell")
        # Should not flag standard DB backups as harvest activity
        hndl_findings = [f for f in findings if f.family in (AlgoFamily.HNDL_HARVEST, AlgoFamily.HNDL_STORAGE)]
        assert len(hndl_findings) == 0

    def test_detects_wireshark_bulk_capture(self, agent):
        content = """
tshark -i any -f "tcp port 443" -w /captures/bulk_tls.pcapng -b filesize:100000
"""
        findings = agent.scan_file(content, "monitor.sh", "shell")
        assert len(findings) >= 1
