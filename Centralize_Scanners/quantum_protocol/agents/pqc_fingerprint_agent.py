"""
Quantum Protocol v5.0 — PQSI Agent 1: PQC Fingerprint Agent

Detects real-world deployment of post-quantum or hybrid cryptographic protocols.
Scans TLS configs, library imports, dependency manifests, container images,
and code for PQC algorithm usage and hybrid crypto negotiation patterns.
"""
from __future__ import annotations

import re
from typing import Optional

from quantum_protocol.models.enums import AlgoFamily, RiskLevel
from quantum_protocol.agents.base_agent import PQSIAgent
from quantum_protocol.models.findings import CryptoFinding

# ─── Pattern Groups ────────────────────────────────────────────────────────────

# Each pattern: (compiled_regex, algo_name, AlgoFamily, RiskLevel, note, tags)
_PQC_PATTERNS: list[tuple[re.Pattern, str, AlgoFamily, RiskLevel, str, list[str]]] = []


def _p(pattern: str, algo: str, family: AlgoFamily, risk: RiskLevel, note: str, tags: list[str]) -> None:
    _PQC_PATTERNS.append((re.compile(pattern, re.IGNORECASE), algo, family, risk, note, tags))


# ── Hybrid TLS Negotiation ──────────────────────────────────────────────────
_p(r"\bX25519Kyber768\b", "X25519+Kyber768", AlgoFamily.PQC_HYBRID, RiskLevel.INFO,
   "Hybrid X25519+Kyber768 key exchange detected — PQC-ready TLS",
   ["PQC_ACTIVE", "HYBRID_CRYPTO_DEPLOYED"])
_p(r"\bX25519MLKEM768\b", "X25519+ML-KEM-768", AlgoFamily.PQC_HYBRID, RiskLevel.INFO,
   "Hybrid X25519+ML-KEM-768 (FIPS 203) key exchange detected",
   ["PQC_ACTIVE", "HYBRID_CRYPTO_DEPLOYED"])
_p(r"\becdh[_\-]?x25519[_\-]?kyber\b", "ECDH-X25519-Kyber", AlgoFamily.PQC_HYBRID, RiskLevel.INFO,
   "ECDH+X25519+Kyber hybrid negotiation detected",
   ["PQC_ACTIVE", "HYBRID_CRYPTO_DEPLOYED"])
_p(r"\bP256[_\+]?Kyber768\b", "P-256+Kyber768", AlgoFamily.PQC_HYBRID, RiskLevel.INFO,
   "Hybrid P-256+Kyber768 key exchange detected",
   ["PQC_ACTIVE", "HYBRID_CRYPTO_DEPLOYED"])
_p(r"\bSecP256r1MLKEM768\b", "SecP256r1+ML-KEM-768", AlgoFamily.PQC_HYBRID, RiskLevel.INFO,
   "Hybrid SecP256r1+ML-KEM-768 negotiation detected",
   ["PQC_ACTIVE", "HYBRID_CRYPTO_DEPLOYED"])
_p(r"\bhybrid[_\-]?tls\b", "Hybrid-TLS", AlgoFamily.PQC_HYBRID, RiskLevel.INFO,
   "Hybrid TLS configuration reference detected",
   ["PQC_EXPERIMENTAL", "HYBRID_CRYPTO_DEPLOYED"])
_p(r"\bpq[_\-]?hybrid\b", "PQ-Hybrid", AlgoFamily.PQC_HYBRID, RiskLevel.INFO,
   "Post-quantum hybrid scheme reference detected",
   ["PQC_EXPERIMENTAL", "HYBRID_CRYPTO_DEPLOYED"])

# ── TLS Config Patterns ────────────────────────────────────────────────────
_p(r"\bssl_ecdh_curve\s+.*[Kk]yber", "Kyber-TLS-Config", AlgoFamily.PQC_KYBER, RiskLevel.INFO,
   "Nginx/OpenSSL TLS config with Kyber curve detected",
   ["PQC_ACTIVE", "HYBRID_CRYPTO_DEPLOYED"])
_p(r"\bCipherSuites?\s*[=:].*[Kk]yber", "Kyber-CipherSuite", AlgoFamily.PQC_KYBER, RiskLevel.INFO,
   "TLS cipher suite configuration with Kyber detected",
   ["PQC_ACTIVE"])
_p(r"\bquic[_\-]?params?\b.*[Kk]yber", "QUIC-Kyber", AlgoFamily.PQC_KYBER, RiskLevel.INFO,
   "QUIC protocol with Kyber key exchange detected",
   ["PQC_ACTIVE", "HYBRID_CRYPTO_DEPLOYED"])
_p(r"\btls\.enable[_\-]?kyber\b", "Kyber-TLS-Flag", AlgoFamily.PQC_KYBER, RiskLevel.INFO,
   "TLS Kyber enable flag detected (browser/client)",
   ["PQC_EXPERIMENTAL"])
_p(r"\bGroups\s*=.*[Kk]yber", "Kyber-TLS-Group", AlgoFamily.PQC_KYBER, RiskLevel.INFO,
   "TLS supported groups with Kyber configured",
   ["PQC_ACTIVE"])

# ── OQS Provider / Library ─────────────────────────────────────────────────
_p(r"\boqsprovider\b", "OQS-Provider", AlgoFamily.PQC_KYBER, RiskLevel.INFO,
   "OQS OpenSSL 3.x provider detected — full PQC algorithm suite",
   ["PQC_ACTIVE"])
_p(r"\boqs[_\-]?provider\b", "OQS-Provider", AlgoFamily.PQC_KYBER, RiskLevel.INFO,
   "OQS provider reference detected",
   ["PQC_ACTIVE"])
_p(r"\bliboqs\b", "liboqs", AlgoFamily.PQC_KYBER, RiskLevel.INFO,
   "liboqs library reference detected — Open Quantum Safe",
   ["PQC_ACTIVE"])
_p(r"\bOQS[_\-]?OpenSSL\b", "OQS-OpenSSL", AlgoFamily.PQC_KYBER, RiskLevel.INFO,
   "OQS-OpenSSL fork detected — hybrid PQC TLS",
   ["PQC_ACTIVE", "HYBRID_CRYPTO_DEPLOYED"])
_p(r"\bopen[_\-]?quantum[_\-]?safe\b", "Open-Quantum-Safe", AlgoFamily.PQC_KYBER, RiskLevel.INFO,
   "Open Quantum Safe project reference detected",
   ["PQC_EXPERIMENTAL"])

# ── Library Imports ─────────────────────────────────────────────────────────
_p(r"(?:from|import)\s+oqs\b", "liboqs-python", AlgoFamily.PQC_KYBER, RiskLevel.INFO,
   "Python liboqs import detected — PQC library in use",
   ["PQC_ACTIVE"])
_p(r"require\s*\(\s*['\"](?:liboqs|@openquantumsafe)", "liboqs-node", AlgoFamily.PQC_KYBER, RiskLevel.INFO,
   "Node.js liboqs import detected",
   ["PQC_ACTIVE"])
_p(r"(?:from|import)\s+pqcrypto\b", "pqcrypto-python", AlgoFamily.PQC_KYBER, RiskLevel.INFO,
   "Python pqcrypto import detected",
   ["PQC_EXPERIMENTAL"])
_p(r"\buse\s+oqs\b", "liboqs-rust", AlgoFamily.PQC_KYBER, RiskLevel.INFO,
   "Rust liboqs crate usage detected",
   ["PQC_ACTIVE"])
_p(r"github\.com/open-quantum-safe", "liboqs-go", AlgoFamily.PQC_KYBER, RiskLevel.INFO,
   "Go liboqs module import detected",
   ["PQC_ACTIVE"])
_p(r"github\.com/cloudflare/circl", "circl", AlgoFamily.PQC_KYBER, RiskLevel.INFO,
   "Cloudflare CIRCL crypto library (PQC-capable) detected",
   ["PQC_ACTIVE"])
_p(r"org\.openquantumsafe", "liboqs-java", AlgoFamily.PQC_KYBER, RiskLevel.INFO,
   "Java liboqs binding detected",
   ["PQC_ACTIVE"])
_p(r"org\.bouncycastle.*pqc\b", "BouncyCastle-PQC", AlgoFamily.PQC_KYBER, RiskLevel.INFO,
   "Bouncy Castle PQC provider detected",
   ["PQC_ACTIVE"])

# ── CRYSTALS-Kyber ──────────────────────────────────────────────────────────
_p(r"\bCRYSTALS[_\-\s]?Kyber\b", "CRYSTALS-Kyber", AlgoFamily.PQC_KYBER, RiskLevel.INFO,
   "CRYSTALS-Kyber KEM algorithm reference detected",
   ["PQC_ACTIVE"])
_p(r"\bML[_\-]?KEM[_\-]?(?:512|768|1024)\b", "ML-KEM", AlgoFamily.PQC_KYBER, RiskLevel.INFO,
   "ML-KEM (FIPS 203) algorithm reference detected",
   ["PQC_ACTIVE"])
_p(r"\bKyber[_\-]?(?:512|768|1024)\b", "Kyber", AlgoFamily.PQC_KYBER, RiskLevel.INFO,
   "Kyber KEM variant detected",
   ["PQC_ACTIVE"])

# ── CRYSTALS-Dilithium ─────────────────────────────────────────────────────
_p(r"\bCRYSTALS[_\-\s]?Dilithium\b", "CRYSTALS-Dilithium", AlgoFamily.PQC_DILITHIUM, RiskLevel.INFO,
   "CRYSTALS-Dilithium signature algorithm reference detected",
   ["PQC_ACTIVE"])
_p(r"\bML[_\-]?DSA[_\-]?(?:44|65|87)\b", "ML-DSA", AlgoFamily.PQC_DILITHIUM, RiskLevel.INFO,
   "ML-DSA (FIPS 204) algorithm reference detected",
   ["PQC_ACTIVE"])
_p(r"\bDilithium[_\-]?(?:2|3|5)\b", "Dilithium", AlgoFamily.PQC_DILITHIUM, RiskLevel.INFO,
   "Dilithium signature variant detected",
   ["PQC_ACTIVE"])

# ── Falcon ──────────────────────────────────────────────────────────────────
_p(r"\bFalcon[_\-]?(?:512|1024)\b", "Falcon", AlgoFamily.PQC_FALCON, RiskLevel.INFO,
   "Falcon signature algorithm detected",
   ["PQC_ACTIVE"])
_p(r"\bFN[_\-]?DSA\b", "FN-DSA", AlgoFamily.PQC_FALCON, RiskLevel.INFO,
   "FN-DSA (Falcon-based) algorithm reference detected",
   ["PQC_ACTIVE"])

# ── SPHINCS+ ───────────────────────────────────────────────────────────────
_p(r"\bSPHINCS\+?\b", "SPHINCS+", AlgoFamily.PQC_SPHINCS, RiskLevel.INFO,
   "SPHINCS+ hash-based signature algorithm detected",
   ["PQC_ACTIVE"])
_p(r"\bSLH[_\-]?DSA\b", "SLH-DSA", AlgoFamily.PQC_SPHINCS, RiskLevel.INFO,
   "SLH-DSA (FIPS 205, SPHINCS+) algorithm reference detected",
   ["PQC_ACTIVE"])

# ── BIKE ────────────────────────────────────────────────────────────────────
_p(r"\bBIKE[_\-]?(?:L[1-3]|128|192|256)\b", "BIKE", AlgoFamily.PQC_BIKE, RiskLevel.INFO,
   "BIKE code-based KEM detected",
   ["PQC_EXPERIMENTAL"])
_p(r"\bBIKE\b(?!.*(?:bicycle|motor|pedal))", "BIKE", AlgoFamily.PQC_BIKE, RiskLevel.INFO,
   "BIKE KEM reference detected",
   ["PQC_EXPERIMENTAL"])

# ── Classic McEliece ────────────────────────────────────────────────────────
_p(r"\bClassic[_\-\s]?McEliece\b", "Classic-McEliece", AlgoFamily.PQC_MCELIECE, RiskLevel.INFO,
   "Classic McEliece code-based KEM detected",
   ["PQC_EXPERIMENTAL"])
_p(r"\bmceliece[_\-]?(?:348864|460896|6688128|6960119|8192128)\b",
   "McEliece", AlgoFamily.PQC_MCELIECE, RiskLevel.INFO,
   "McEliece KEM variant parameter set detected",
   ["PQC_EXPERIMENTAL"])

# ── K8s Secrets / PQC Config ───────────────────────────────────────────────
_p(r"\bpqc[_\-]?tls[_\-]?cert\b", "PQC-TLS-Cert-Secret", AlgoFamily.PQC_HYBRID, RiskLevel.INFO,
   "Kubernetes PQC TLS certificate secret reference detected",
   ["PQC_ACTIVE", "HYBRID_CRYPTO_DEPLOYED"])
_p(r"\bquantum[_\-]?safe[_\-]?key\b", "Quantum-Safe-Key", AlgoFamily.PQC_HYBRID, RiskLevel.INFO,
   "Quantum-safe key reference detected",
   ["PQC_ACTIVE"])
_p(r"\bpost[_\-]?quantum\b", "Post-Quantum-Ref", AlgoFamily.PQC_HYBRID, RiskLevel.INFO,
   "Post-quantum cryptography reference detected",
   ["PQC_EXPERIMENTAL"])

# ── API Gateway / Load Balancer ─────────────────────────────────────────────
_p(r"\bpqc[_\-]?algorithm\b", "PQC-Algorithm-Config", AlgoFamily.PQC_HYBRID, RiskLevel.INFO,
   "PQC algorithm configuration reference detected",
   ["PQC_ACTIVE"])
_p(r"\bcrypto[_\-]?agility\b", "Crypto-Agility-Config", AlgoFamily.CRYPTO_AGILITY_SIGNAL, RiskLevel.INFO,
   "Crypto agility configuration detected — supports algorithm migration",
   ["PQC_EXPERIMENTAL"])

# ── Container / Docker ──────────────────────────────────────────────────────
_p(r"openquantumsafe/", "OQS-Docker-Image", AlgoFamily.PQC_KYBER, RiskLevel.INFO,
   "Open Quantum Safe Docker image reference detected",
   ["PQC_ACTIVE", "HYBRID_CRYPTO_DEPLOYED"])
_p(r"(?:apt|apk|yum|dnf)\s+install.*liboqs", "liboqs-System-Install", AlgoFamily.PQC_KYBER, RiskLevel.INFO,
   "System-level liboqs installation detected",
   ["PQC_ACTIVE"])

# ── Production PQC Libraries ───────────────────────────────────────────────
_p(r"\bwolfSSL[_\-]?PQC\b", "wolfSSL-PQC", AlgoFamily.PQC_KYBER, RiskLevel.INFO,
   "wolfSSL PQC support detected — production-grade",
   ["PQC_ACTIVE"])
_p(r"\bWOLFSSL_HAVE_KYBER\b", "wolfSSL-Kyber", AlgoFamily.PQC_KYBER, RiskLevel.INFO,
   "wolfSSL Kyber compile flag detected",
   ["PQC_ACTIVE"])
_p(r"\baws[_\-]?lc\b", "AWS-LC", AlgoFamily.PQC_KYBER, RiskLevel.INFO,
   "AWS LibCrypto (AWS-LC) with PQC support detected",
   ["PQC_ACTIVE"])
_p(r"\bAWS_LC_FIPS\b", "AWS-LC-FIPS", AlgoFamily.PQC_KYBER, RiskLevel.INFO,
   "AWS-LC FIPS mode with PQC detected",
   ["PQC_ACTIVE"])
_p(r"\bs2n[_\-]?tls\b.*(?:PQ|pq|kyber|Kyber)", "s2n-TLS-PQ", AlgoFamily.PQC_KYBER, RiskLevel.INFO,
   "AWS s2n-tls with post-quantum support detected",
   ["PQC_ACTIVE"])
_p(r"\brustls[_\-]?post[_\-]?quantum\b", "rustls-PQ", AlgoFamily.PQC_KYBER, RiskLevel.INFO,
   "rustls post-quantum TLS support detected",
   ["PQC_ACTIVE"])

# ── Compile out unreachable BIKE pattern (avoid matching prose about bicycles)
# Already handled via negative lookahead above


class PQCFingerprintAgent(PQSIAgent):
    """
    Agent 1 — PQC Protocol Fingerprinting Agent

    Detects real-world deployment of post-quantum and hybrid cryptographic
    protocols across TLS configs, library imports, K8s secrets, API gateways,
    QUIC stacks, and container definitions.
    """

    agent_name = "pqc_fingerprint"
    agent_version = "1.0.0"
    description = "Detects PQC deployments: Kyber, Dilithium, Falcon, SPHINCS+, hybrid TLS, oqsprovider"

    def scan_file(self, content: str, filepath: str, language: str) -> list[CryptoFinding]:
        findings: list[CryptoFinding] = []
        seen_keys: set[str] = set()
        lines = content.split("\n")

        for line_idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") and language not in ("python", "shell", "config"):
                continue

            for pattern, algo, family, risk, note, tags in _PQC_PATTERNS:
                match = pattern.search(line)
                if match:
                    dedup_key = f"{filepath}:{line_idx}:{family.value}"
                    if dedup_key in seen_keys:
                        continue
                    seen_keys.add(dedup_key)

                    findings.append(self._create_finding(
                        filepath=filepath,
                        line_number=line_idx,
                        line_content=stripped,
                        algorithm=algo,
                        family=family,
                        risk=risk,
                        confidence=0.85,
                        pattern_note=note,
                        language=language,
                        hndl_relevant=False,
                        migration={"action": "PQC deployment detected — validate algorithm parameters and hybrid negotiation"},
                        tags=tags,
                        column_start=match.start(),
                        column_end=match.end(),
                    ))

        return findings
