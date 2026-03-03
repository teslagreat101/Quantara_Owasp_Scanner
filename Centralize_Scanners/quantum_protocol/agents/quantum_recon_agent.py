"""
Quantum Protocol v5.0 — PQSI Agent 5: Quantum Recon Detection Agent (Elite Layer)

Detects tooling or software behaving like future quantum reconnaissance systems:
  - Large-scale certificate enumeration
  - Key discovery automation
  - Crypto inventory scanning
  - Mass TLS probing
  - Encrypted dataset indexing

Severity escalation:
  - Single signal = INFO
  - Combined signals = MEDIUM
  - Automated scripts + storage = HIGH
  - Nation-state pattern match = CRITICAL
"""
from __future__ import annotations

import re
from typing import Optional

from quantum_protocol.models.enums import AlgoFamily, RiskLevel
from quantum_protocol.agents.base_agent import PQSIAgent
from quantum_protocol.models.findings import CryptoFinding

# ─── Recon Signal Patterns ─────────────────────────────────────────────────────

_RECON_PATTERNS: list[tuple[re.Pattern, str, str, str, RiskLevel, list[str]]] = []
# Each: (pattern, category, algo_name, note, base_risk, tags)


def _r(pattern: str, category: str, algo: str, note: str,
       risk: RiskLevel, tags: list[str]) -> None:
    _RECON_PATTERNS.append((
        re.compile(pattern, re.IGNORECASE), category, algo, note, risk, tags,
    ))


# ── Certificate Enumeration ────────────────────────────────────────────────
_r(r"\bcertbot\b.*(?:batch|mass|bulk|range|all)", "cert_enum", "certbot-batch",
   "Batch certificate enumeration via certbot detected",
   RiskLevel.MEDIUM, ["QUANTUM_RECON_ACTIVITY", "CRYPTO_ENUMERATION_ENGINE"])
_r(r"\bcrt\.sh\b.*(?:bulk|batch|mass|all|dump)", "cert_enum", "crtsh-bulk",
   "Bulk certificate transparency log query (crt.sh) detected",
   RiskLevel.MEDIUM, ["QUANTUM_RECON_ACTIVITY", "CRYPTO_ENUMERATION_ENGINE"])
_r(r"\bcert(?:ificate)?[_\-]?enum(?:erat(?:e|ion|or))?\b", "cert_enum", "cert-enumeration",
   "Certificate enumeration pattern detected",
   RiskLevel.INFO, ["QUANTUM_RECON_ACTIVITY"])
_r(r"\bcert(?:ificate)?[_\-]?(?:census|survey|inventory)\b", "cert_enum", "cert-census",
   "Certificate census/inventory scanning detected",
   RiskLevel.MEDIUM, ["QUANTUM_RECON_ACTIVITY", "CRYPTO_ENUMERATION_ENGINE"])
_r(r"\bcensys\b.*(?:cert|tls|ssl|search)", "cert_enum", "censys-cert-search",
   "Censys certificate/TLS search detected",
   RiskLevel.MEDIUM, ["QUANTUM_RECON_ACTIVITY", "CRYPTO_ENUMERATION_ENGINE"])
_r(r"\bshodan\b.*(?:cert|ssl|tls|crypto)", "cert_enum", "shodan-cert-search",
   "Shodan certificate/crypto search detected",
   RiskLevel.MEDIUM, ["QUANTUM_RECON_ACTIVITY", "CRYPTO_ENUMERATION_ENGINE"])
_r(r"\bcertificate[_\-]?transparency\b.*(?:monitor|scan|search|bulk)", "cert_enum", "ct-log-scan",
   "Certificate transparency log monitoring/scanning detected",
   RiskLevel.INFO, ["QUANTUM_RECON_ACTIVITY"])

# ── Key Discovery Automation ──────────────────────────────────────────────
_r(r"\benum(?:erat)?e?[_\-]?(?:public[_\-]?)?keys?\b", "key_discovery", "key-enumeration",
   "Public key enumeration pattern detected",
   RiskLevel.INFO, ["QUANTUM_RECON_ACTIVITY"])
_r(r"\bdiscover[_\-]?(?:cert(?:ificate)?s?|keys?)\b", "key_discovery", "key-discovery",
   "Key/certificate discovery automation detected",
   RiskLevel.INFO, ["QUANTUM_RECON_ACTIVITY"])
_r(r"\bharvest[_\-]?(?:public[_\-]?keys?|cert(?:ificate)?s?)\b", "key_discovery", "key-harvester",
   "Public key/certificate harvesting detected",
   RiskLevel.MEDIUM, ["QUANTUM_RECON_ACTIVITY", "CRYPTO_ENUMERATION_ENGINE"])
_r(r"\bkey[_\-]?(?:inventory|catalog|index)\b", "key_discovery", "key-inventory",
   "Cryptographic key inventory/catalog detected",
   RiskLevel.INFO, ["QUANTUM_RECON_ACTIVITY"])
_r(r"\bcollect[_\-]?(?:public[_\-]?keys?|cert(?:ificate)?s?|crypto)\b", "key_discovery", "crypto-collection",
   "Cryptographic material collection pattern detected",
   RiskLevel.MEDIUM, ["QUANTUM_RECON_ACTIVITY"])

# ── Crypto Inventory Scanning ─────────────────────────────────────────────
_r(r"\bcrypto[_\-]?audit\b", "crypto_inventory", "crypto-audit",
   "Cryptographic audit tool/script detected",
   RiskLevel.INFO, ["QUANTUM_RECON_ACTIVITY"])
_r(r"\bcipher[_\-]?suite[_\-]?scan\b", "crypto_inventory", "cipher-suite-scan",
   "Cipher suite scanning detected",
   RiskLevel.INFO, ["QUANTUM_RECON_ACTIVITY"])
_r(r"\balgorithm[_\-]?(?:inventory|audit|scan)\b", "crypto_inventory", "algo-inventory",
   "Cryptographic algorithm inventory scanning detected",
   RiskLevel.INFO, ["QUANTUM_RECON_ACTIVITY"])
_r(r"\bkey[_\-]?rotation[_\-]?(?:check|audit|scan)\b", "crypto_inventory", "key-rotation-check",
   "Key rotation audit/check detected",
   RiskLevel.INFO, ["QUANTUM_RECON_ACTIVITY"])
_r(r"\bcrypto[_\-]?(?:inventory|discovery|scan(?:ner)?)\b", "crypto_inventory", "crypto-scanner",
   "Cryptographic inventory/discovery scanner detected",
   RiskLevel.INFO, ["QUANTUM_RECON_ACTIVITY"])
_r(r"\bcryptographic[_\-]?(?:assessment|evaluation|analysis)\b", "crypto_inventory", "crypto-assessment",
   "Cryptographic assessment tool detected",
   RiskLevel.INFO, ["QUANTUM_RECON_ACTIVITY"])

# ── Mass TLS Probing ──────────────────────────────────────────────────────
_r(r"\bsslyze\b.*(?:bulk|batch|targets|range|\-\-targets)", "tls_probing", "sslyze-bulk",
   "SSLyze bulk/batch TLS scanning detected",
   RiskLevel.MEDIUM, ["QUANTUM_RECON_ACTIVITY", "CRYPTO_ENUMERATION_ENGINE"])
_r(r"\btestssl\b.*(?:batch|mass|range|serial|parallel)", "tls_probing", "testssl-batch",
   "testssl.sh batch TLS testing detected",
   RiskLevel.MEDIUM, ["QUANTUM_RECON_ACTIVITY", "CRYPTO_ENUMERATION_ENGINE"])
_r(r"\bssl[_\-]?scan\b.*(?:range|batch|subnet|cidr|all)", "tls_probing", "ssl-scan-range",
   "SSL scan across IP range/subnet detected",
   RiskLevel.MEDIUM, ["QUANTUM_RECON_ACTIVITY", "CRYPTO_ENUMERATION_ENGINE"])
_r(r"\bmasscan\b.*(?:443|8443|tls|ssl)", "tls_probing", "masscan-tls",
   "masscan TLS port scanning detected — internet-wide probing",
   RiskLevel.HIGH, ["QUANTUM_RECON_ACTIVITY", "CRYPTO_ENUMERATION_ENGINE", "POSSIBLE_NATION_STATE_COLLECTION"])
_r(r"\bnmap\b.*(?:ssl[_\-]?enum|ssl[_\-]?cert|\-\-script\s+ssl)", "tls_probing", "nmap-ssl-enum",
   "nmap SSL enumeration script detected",
   RiskLevel.MEDIUM, ["QUANTUM_RECON_ACTIVITY", "CRYPTO_ENUMERATION_ENGINE"])
_r(r"\btls[_\-]?fingerprint\b.*(?:mass|bulk|batch|range)", "tls_probing", "tls-fingerprint-mass",
   "Mass TLS fingerprinting detected",
   RiskLevel.HIGH, ["QUANTUM_RECON_ACTIVITY", "CRYPTO_ENUMERATION_ENGINE", "POSSIBLE_NATION_STATE_COLLECTION"])
_r(r"\bzgrab\b.*(?:tls|ssl|443)", "tls_probing", "zgrab-tls",
   "ZGrab TLS scanning detected — internet-scale probing tool",
   RiskLevel.HIGH, ["QUANTUM_RECON_ACTIVITY", "CRYPTO_ENUMERATION_ENGINE", "POSSIBLE_NATION_STATE_COLLECTION"])

# ── Encrypted Dataset Indexing ────────────────────────────────────────────
_r(r"\bindex[_\-]?(?:encrypt(?:ed)?|cipher(?:text)?)\b", "dataset_indexing", "encrypted-index",
   "Encrypted data indexing detected — cataloging ciphertext for future analysis",
   RiskLevel.MEDIUM, ["QUANTUM_RECON_ACTIVITY", "POSSIBLE_NATION_STATE_COLLECTION"])
_r(r"\bcatalog[_\-]?(?:cipher(?:text)?|encrypt(?:ed)?)\b", "dataset_indexing", "ciphertext-catalog",
   "Ciphertext cataloging detected",
   RiskLevel.MEDIUM, ["QUANTUM_RECON_ACTIVITY"])
_r(r"\bencrypt(?:ed)?[_\-]?(?:asset|data)[_\-]?(?:inventory|index|catalog)\b", "dataset_indexing",
   "encrypted-asset-inventory",
   "Encrypted asset inventory/catalog detected",
   RiskLevel.MEDIUM, ["QUANTUM_RECON_ACTIVITY", "POSSIBLE_NATION_STATE_COLLECTION"])
_r(r"\bciphertext[_\-]?(?:database|db|index|store)\b", "dataset_indexing", "ciphertext-db",
   "Ciphertext database/index detected — long-term encrypted data store for future analysis",
   RiskLevel.HIGH, ["QUANTUM_RECON_ACTIVITY", "POSSIBLE_NATION_STATE_COLLECTION"])

# ── Recon category set for combo detection ─────────────────────────────────
_RECON_CATEGORIES = {"cert_enum", "key_discovery", "crypto_inventory", "tls_probing", "dataset_indexing"}


class QuantumReconAgent(PQSIAgent):
    """
    Agent 5 — Quantum Recon Detection Agent (Elite Layer)

    Detects tooling or software behaving like quantum reconnaissance systems.
    Identifies patterns of large-scale certificate enumeration, key discovery
    automation, crypto inventory scanning, mass TLS probing, and encrypted
    dataset indexing.
    """

    agent_name = "pqsi_recon"
    agent_version = "1.0.0"
    description = "Detects quantum reconnaissance: mass cert enumeration, crypto inventory scanning, TLS probing"

    def scan_file(self, content: str, filepath: str, language: str) -> list[CryptoFinding]:
        findings: list[CryptoFinding] = []
        seen_keys: set[str] = set()
        categories_found: set[str] = set()
        lines = content.split("\n")

        for line_idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue

            for pattern, category, algo, note, risk, tags in _RECON_PATTERNS:
                match = pattern.search(line)
                if match:
                    dedup_key = f"{filepath}:{line_idx}:{algo}"
                    if dedup_key in seen_keys:
                        continue
                    seen_keys.add(dedup_key)
                    categories_found.add(category)

                    family = (AlgoFamily.CRYPTO_ENUMERATION
                              if category in ("cert_enum", "key_discovery", "crypto_inventory")
                              else AlgoFamily.QUANTUM_RECON)

                    findings.append(self._create_finding(
                        filepath=filepath,
                        line_number=line_idx,
                        line_content=stripped,
                        algorithm=algo,
                        family=family,
                        risk=risk,
                        confidence=0.75,
                        pattern_note=note,
                        language=language,
                        hndl_relevant=False,
                        migration={
                            "action": "Investigate quantum reconnaissance activity — verify authorization and intent",
                            "cwe": "CWE-200",
                        },
                        tags=tags,
                        column_start=match.start(),
                        column_end=match.end(),
                    ))

        # Severity escalation for combined recon categories
        if len(categories_found) >= 3:
            self._escalate_severity(findings, filepath, categories_found)
        elif len(categories_found) >= 2 and "tls_probing" in categories_found:
            self._escalate_severity(findings, filepath, categories_found)

        return findings

    def _escalate_severity(
        self,
        findings: list[CryptoFinding],
        filepath: str,
        categories: set[str],
    ) -> None:
        """Escalate severity when multiple recon categories are combined."""
        has_nation_state = "tls_probing" in categories and "dataset_indexing" in categories

        for f in findings:
            if f.file != filepath:
                continue

            if has_nation_state:
                f.risk = RiskLevel.CRITICAL
                f.confidence = min(1.0, f.confidence + 0.15)
                if "POSSIBLE_NATION_STATE_COLLECTION" not in f.tags:
                    f.tags.append("POSSIBLE_NATION_STATE_COLLECTION")
            elif f.risk == RiskLevel.INFO:
                f.risk = RiskLevel.MEDIUM
            elif f.risk == RiskLevel.MEDIUM:
                f.risk = RiskLevel.HIGH

            if "RECON_COMBO_DETECTED" not in f.tags:
                f.tags.append("RECON_COMBO_DETECTED")
