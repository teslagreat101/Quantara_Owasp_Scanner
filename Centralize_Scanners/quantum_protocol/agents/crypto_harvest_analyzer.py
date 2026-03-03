"""
Quantum Protocol v5.0 — PQSI Agent 2: Crypto Harvest Behavior Analyzer

Detects Harvest-Now-Decrypt-Later (HNDL) preparation activity by identifying
code patterns associated with encrypted traffic capture, TLS session logging,
certificate scraping, bulk ciphertext archival, and traffic mirroring.

Each finding includes:
  - data_longevity_estimate: estimated storage duration of captured data
  - hndl_probability_score: 0.0-1.0 likelihood of HNDL preparation
  - future_decryption_risk: low/medium/high/critical risk of future decryption
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from quantum_protocol.models.enums import AlgoFamily, RiskLevel
from quantum_protocol.agents.base_agent import PQSIAgent
from quantum_protocol.models.findings import CryptoFinding


# ─── Signal Categories ─────────────────────────────────────────────────────────

@dataclass
class _HNDLSignal:
    pattern: re.Pattern
    category: str  # capture | logging | mirroring | storage | proxy | scraping
    algo_name: str
    note: str
    base_score: float  # base HNDL probability contribution (0.0-1.0)
    risk: RiskLevel
    tags: list[str]


_SIGNALS: list[_HNDLSignal] = []


def _s(pattern: str, category: str, algo: str, note: str, score: float,
       risk: RiskLevel, tags: list[str]) -> None:
    _SIGNALS.append(_HNDLSignal(
        re.compile(pattern, re.IGNORECASE), category, algo, note, score, risk, tags,
    ))


# ── Network Capture ─────────────────────────────────────────────────────────
_s(r"\btcpdump\b.*-[wW]\s", "capture", "tcpdump-capture",
   "tcpdump packet capture to file detected — potential traffic harvesting",
   0.6, RiskLevel.HIGH, ["QUANTUM_PREPARATION_ACTIVITY", "ENCRYPTED_DATA_COLLECTION"])
_s(r"\btshark\b.*-[wW]\s", "capture", "tshark-capture",
   "tshark packet capture to file detected",
   0.6, RiskLevel.HIGH, ["QUANTUM_PREPARATION_ACTIVITY", "ENCRYPTED_DATA_COLLECTION"])
_s(r"\bdumpcap\b", "capture", "dumpcap",
   "dumpcap network capture tool usage detected",
   0.5, RiskLevel.MEDIUM, ["QUANTUM_PREPARATION_ACTIVITY"])
_s(r"\.pcap(?:ng)?\b", "capture", "pcap-file",
   "PCAP file reference detected — network capture artifact",
   0.4, RiskLevel.MEDIUM, ["ENCRYPTED_DATA_COLLECTION"])
_s(r"\bscapy\b.*(?:sniff|wrpcap|rdpcap)", "capture", "scapy-capture",
   "Scapy packet capture/analysis detected",
   0.5, RiskLevel.MEDIUM, ["QUANTUM_PREPARATION_ACTIVITY"])
_s(r"\bpcap[_\-]?collector\b", "capture", "pcap-collector",
   "PCAP collector service/script detected",
   0.7, RiskLevel.HIGH, ["QUANTUM_PREPARATION_ACTIVITY", "ENCRYPTED_DATA_COLLECTION"])
_s(r"\bpacket[_\-]?capture\b", "capture", "packet-capture",
   "Generic packet capture reference detected",
   0.3, RiskLevel.MEDIUM, ["QUANTUM_PREPARATION_ACTIVITY"])
_s(r"\bnetwork[_\-]?tap\b", "capture", "network-tap",
   "Network tap reference detected — passive traffic interception",
   0.7, RiskLevel.HIGH, ["QUANTUM_PREPARATION_ACTIVITY", "ENCRYPTED_DATA_COLLECTION"])

# ── TLS Session Logging ────────────────────────────────────────────────────
_s(r"\bSSLKEYLOGFILE\b", "logging", "SSLKEYLOGFILE",
   "SSLKEYLOGFILE usage detected — TLS session keys being logged for decryption",
   0.9, RiskLevel.CRITICAL, ["QUANTUM_PREPARATION_ACTIVITY", "ENCRYPTED_DATA_COLLECTION"])
_s(r"\bssl[_\-]?log[_\-]?master[_\-]?secret\b", "logging", "ssl-master-secret-log",
   "SSL master secret logging detected — enables TLS traffic decryption",
   0.9, RiskLevel.CRITICAL, ["QUANTUM_PREPARATION_ACTIVITY", "ENCRYPTED_DATA_COLLECTION"])
_s(r"\bkeylog[_\-]?file\b", "logging", "keylog-file",
   "TLS key log file reference detected",
   0.7, RiskLevel.HIGH, ["QUANTUM_PREPARATION_ACTIVITY"])
_s(r"\btls[_\-]?session[_\-]?log\b", "logging", "tls-session-log",
   "TLS session logging detected",
   0.6, RiskLevel.HIGH, ["QUANTUM_PREPARATION_ACTIVITY"])
_s(r"\bpre[_\-]?master[_\-]?secret\b", "logging", "pre-master-secret",
   "TLS pre-master secret reference detected",
   0.8, RiskLevel.CRITICAL, ["QUANTUM_PREPARATION_ACTIVITY", "ENCRYPTED_DATA_COLLECTION"])
_s(r"\bssl[_\-]?debug\b.*(?:secret|key)", "logging", "ssl-debug-keys",
   "SSL debug with key/secret logging detected",
   0.6, RiskLevel.HIGH, ["QUANTUM_PREPARATION_ACTIVITY"])

# ── Traffic Mirroring ──────────────────────────────────────────────────────
_s(r"\bport[_\-]?mirror\b", "mirroring", "port-mirror",
   "Network port mirroring detected — passive traffic duplication",
   0.6, RiskLevel.HIGH, ["QUANTUM_PREPARATION_ACTIVITY", "ENCRYPTED_DATA_COLLECTION"])
_s(r"\bspan[_\-]?port\b", "mirroring", "span-port",
   "SPAN port configuration detected — switch-level traffic mirroring",
   0.6, RiskLevel.HIGH, ["QUANTUM_PREPARATION_ACTIVITY", "ENCRYPTED_DATA_COLLECTION"])
_s(r"\btraffic[_\-]?mirror\b", "mirroring", "traffic-mirror",
   "Traffic mirroring configuration detected",
   0.6, RiskLevel.HIGH, ["QUANTUM_PREPARATION_ACTIVITY", "ENCRYPTED_DATA_COLLECTION"])
_s(r"\bvpc[_\-]?mirror\b", "mirroring", "vpc-mirror",
   "AWS VPC traffic mirroring detected",
   0.7, RiskLevel.HIGH, ["QUANTUM_PREPARATION_ACTIVITY", "ENCRYPTED_DATA_COLLECTION"])
_s(r"\bpacket[_\-]?broker\b", "mirroring", "packet-broker",
   "Network packet broker reference detected",
   0.5, RiskLevel.MEDIUM, ["QUANTUM_PREPARATION_ACTIVITY"])

# ── Proxy Dumps ────────────────────────────────────────────────────────────
_s(r"\bmitmproxy\b.*(?:dump|save|record|log)", "proxy", "mitmproxy-dump",
   "mitmproxy traffic dump/recording detected",
   0.6, RiskLevel.HIGH, ["QUANTUM_PREPARATION_ACTIVITY", "ENCRYPTED_DATA_COLLECTION"])
_s(r"\bfiddler\b.*(?:capture|save|export|dump)", "proxy", "fiddler-capture",
   "Fiddler traffic capture/export detected",
   0.5, RiskLevel.MEDIUM, ["QUANTUM_PREPARATION_ACTIVITY"])
_s(r"\bproxy\b.*(?:log|dump|record).*tls", "proxy", "proxy-tls-dump",
   "Proxy TLS traffic logging detected",
   0.6, RiskLevel.HIGH, ["QUANTUM_PREPARATION_ACTIVITY"])
_s(r"\bcharles\b.*(?:export|save|record)", "proxy", "charles-proxy",
   "Charles Proxy traffic recording detected",
   0.4, RiskLevel.MEDIUM, ["QUANTUM_PREPARATION_ACTIVITY"])
_s(r"\bburp\b.*(?:save|export|log).*(?:traffic|request)", "proxy", "burp-suite",
   "Burp Suite traffic export detected",
   0.3, RiskLevel.LOW, ["QUANTUM_PREPARATION_ACTIVITY"])

# ── Long-Term Storage ──────────────────────────────────────────────────────
_s(r"\bs3\b.*\.pcap\b", "storage", "s3-pcap-upload",
   "PCAP files uploaded to S3 — long-term encrypted traffic storage",
   0.8, RiskLevel.HIGH, ["LONG_TERM_CIPHERTEXT_STORAGE", "ENCRYPTED_DATA_COLLECTION"])
_s(r"\.pcap\b.*\bs3\b", "storage", "pcap-s3-storage",
   "PCAP to S3 storage pipeline detected",
   0.8, RiskLevel.HIGH, ["LONG_TERM_CIPHERTEXT_STORAGE", "ENCRYPTED_DATA_COLLECTION"])
_s(r"\barchive\b.*(?:encrypt|cipher|tls|ssl)", "storage", "encrypted-archive",
   "Encrypted data archival detected",
   0.5, RiskLevel.MEDIUM, ["LONG_TERM_CIPHERTEXT_STORAGE"])
_s(r"(?:compress|gzip|tar|zip)\b.*(?:capture|pcap|traffic)", "storage", "compressed-traffic",
   "Compressed network capture storage detected",
   0.6, RiskLevel.HIGH, ["LONG_TERM_CIPHERTEXT_STORAGE", "ENCRYPTED_DATA_COLLECTION"])
_s(r"\bciphertext[_\-]?(?:storage|archive|backup)\b", "storage", "ciphertext-storage",
   "Ciphertext long-term storage detected",
   0.7, RiskLevel.HIGH, ["LONG_TERM_CIPHERTEXT_STORAGE"])
_s(r"\bencrypted[_\-]?data[_\-]?(?:lake|warehouse|store)\b", "storage", "encrypted-data-store",
   "Encrypted data lake/warehouse detected — potential long-term ciphertext storage",
   0.5, RiskLevel.MEDIUM, ["LONG_TERM_CIPHERTEXT_STORAGE"])
_s(r"\bretention[_\-]?(?:policy|period|days)\b.*(?:encrypt|cipher|capture)", "storage", "retention-policy",
   "Data retention policy for encrypted/captured data detected",
   0.4, RiskLevel.MEDIUM, ["LONG_TERM_CIPHERTEXT_STORAGE"])

# ── Certificate Scraping ──────────────────────────────────────────────────
_s(r"\bcert(?:ificate)?[_\-]?scrap(?:e|er|ing)\b", "scraping", "cert-scraper",
   "Certificate scraping activity detected",
   0.6, RiskLevel.HIGH, ["QUANTUM_PREPARATION_ACTIVITY", "ENCRYPTED_DATA_COLLECTION"])
_s(r"\bcert(?:ificate)?[_\-]?harvest(?:er|ing)?\b", "scraping", "cert-harvester",
   "Certificate harvesting activity detected",
   0.7, RiskLevel.HIGH, ["QUANTUM_PREPARATION_ACTIVITY", "ENCRYPTED_DATA_COLLECTION"])
_s(r"(?:for|while)\b.*(?:ssl|tls|x509).*(?:cert|certificate)", "scraping", "cert-scraping-loop",
   "Certificate scraping loop detected",
   0.5, RiskLevel.MEDIUM, ["QUANTUM_PREPARATION_ACTIVITY"])

# ── HNDL Category Mappings ─────────────────────────────────────────────────

_CATEGORY_WEIGHTS = {
    "capture": 0.3,
    "logging": 0.3,
    "mirroring": 0.2,
    "storage": 0.15,
    "proxy": 0.05,
    "scraping": 0.1,
}

_LONGEVITY_ESTIMATES = {
    "capture": "5-15 years (network captures typically retained for analysis)",
    "logging": "1-10 years (TLS session logs enable future decryption)",
    "mirroring": "indefinite (mirrored traffic often archived long-term)",
    "storage": "10-20+ years (long-term ciphertext storage)",
    "proxy": "1-5 years (proxy dumps for debugging/analysis)",
    "scraping": "5-10 years (certificate collections for crypto inventory)",
}


class CryptoHarvestAnalyzer(PQSIAgent):
    """
    Agent 2 — Crypto Harvest Behavior Analyzer

    Detects Harvest-Now-Decrypt-Later (HNDL) preparation activity by identifying
    patterns of encrypted traffic capture, TLS session key logging, traffic
    mirroring, and long-term ciphertext storage.
    """

    agent_name = "pqsi_harvest"
    agent_version = "1.0.0"
    description = "Detects HNDL preparation: packet capture, TLS session logging, traffic mirroring, ciphertext storage"

    def scan_file(self, content: str, filepath: str, language: str) -> list[CryptoFinding]:
        findings: list[CryptoFinding] = []
        seen_keys: set[str] = set()
        categories_found: set[str] = set()
        lines = content.split("\n")

        # First pass: detect individual signals
        for line_idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue

            for signal in _SIGNALS:
                match = signal.pattern.search(line)
                if match:
                    dedup_key = f"{filepath}:{line_idx}:{signal.algo_name}"
                    if dedup_key in seen_keys:
                        continue
                    seen_keys.add(dedup_key)
                    categories_found.add(signal.category)

                    # Determine HNDL family based on category
                    family = (AlgoFamily.HNDL_STORAGE
                              if signal.category == "storage"
                              else AlgoFamily.HNDL_HARVEST)

                    findings.append(self._create_finding(
                        filepath=filepath,
                        line_number=line_idx,
                        line_content=stripped,
                        algorithm=signal.algo_name,
                        family=family,
                        risk=signal.risk,
                        confidence=0.80,
                        pattern_note=signal.note,
                        language=language,
                        hndl_relevant=True,
                        migration={
                            "action": "Investigate HNDL activity — ensure encrypted data capture is authorized and necessary",
                            "cwe": "CWE-327",
                        },
                        tags=signal.tags,
                        column_start=match.start(),
                        column_end=match.end(),
                        data_longevity_estimate=_LONGEVITY_ESTIMATES.get(signal.category, "unknown"),
                        hndl_probability_score=signal.base_score,
                        future_decryption_risk=self._risk_from_score(signal.base_score),
                    ))

        # Second pass: combo detection — elevated risk when multiple categories found
        if len(categories_found) >= 3:
            self._elevate_combo_findings(findings, categories_found, filepath)
        elif len(categories_found) >= 2 and {"capture", "storage"}.issubset(categories_found):
            self._elevate_combo_findings(findings, categories_found, filepath)

        return findings

    def _elevate_combo_findings(
        self,
        findings: list[CryptoFinding],
        categories: set[str],
        filepath: str,
    ) -> None:
        """Elevate finding severity when HNDL signal categories are combined."""
        combo_score = min(1.0, sum(_CATEGORY_WEIGHTS.get(c, 0.05) for c in categories))

        for f in findings:
            if f.file == filepath:
                # Boost probability score
                if f.hndl_probability_score is not None:
                    f.hndl_probability_score = min(1.0, f.hndl_probability_score + 0.2)
                else:
                    f.hndl_probability_score = combo_score

                # Elevate risk for combo detection
                if f.risk == RiskLevel.MEDIUM:
                    f.risk = RiskLevel.HIGH
                elif f.risk == RiskLevel.HIGH and combo_score >= 0.6:
                    f.risk = RiskLevel.CRITICAL

                f.future_decryption_risk = self._risk_from_score(
                    f.hndl_probability_score or combo_score
                )

                # Add combo tag
                if "HNDL_COMBO_DETECTED" not in f.tags:
                    f.tags.append("HNDL_COMBO_DETECTED")

    @staticmethod
    def _risk_from_score(score: float) -> str:
        if score >= 0.8:
            return "critical"
        if score >= 0.6:
            return "high"
        if score >= 0.4:
            return "medium"
        return "low"
