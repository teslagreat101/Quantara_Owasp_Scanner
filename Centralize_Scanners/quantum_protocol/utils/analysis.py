"""
Quantum Protocol v3 — Utility Functions

Includes:
  - Shannon entropy analysis for secret detection
  - Chi-squared uniformity test
  - Key-size extraction and risk calibration
  - Line sanitization
  - Language detection
  - File hashing
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from pathlib import Path
from typing import Optional

from quantum_protocol.models.enums import (
    AlgoFamily, RiskLevel, LANGUAGE_MAP, ConfidenceLevel,
)
from quantum_protocol.rules.patterns import KEY_SIZE_PATTERNS


# ────────────────────────────────────────────────────────────────────────────
# Entropy Analysis — detect hardcoded secrets
# ────────────────────────────────────────────────────────────────────────────

def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string (bits per character)."""
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


def chi_squared_uniformity(data: str) -> float:
    """
    Chi-squared test for byte uniformity.
    Returns p-value approximation; high values suggest random/encrypted data.
    Values > 0.01 are suspicious for hardcoded secrets.
    """
    if len(data) < 16:
        return 0.0

    observed = Counter(data.encode("utf-8", errors="ignore"))
    n = sum(observed.values())
    expected = n / 256.0

    chi2 = sum(
        (observed.get(i, 0) - expected) ** 2 / expected
        for i in range(256)
    )

    # Simplified: compare to critical value for df=255, alpha=0.05 (~293)
    # Normalize to 0–1 where higher = more uniform = more likely random
    return max(0.0, min(1.0, 1.0 - (chi2 / 1000.0)))


def is_high_entropy_string(value: str, threshold: float = 4.0) -> bool:
    """Check if a string has suspiciously high entropy (likely a secret)."""
    if len(value) < 16:
        return False
    return shannon_entropy(value) >= threshold


def entropy_confidence_boost(value: str) -> float:
    """Return a confidence boost based on entropy analysis."""
    ent = shannon_entropy(value)
    if ent >= 5.0:
        return 0.25  # very high entropy
    if ent >= 4.5:
        return 0.15
    if ent >= 4.0:
        return 0.10
    return 0.0


# ────────────────────────────────────────────────────────────────────────────
# Key-Size Extraction and Risk Calibration
# ────────────────────────────────────────────────────────────────────────────

def extract_key_size(line: str, context: str) -> Optional[int]:
    """Extract numeric key size from code context."""
    for pattern in KEY_SIZE_PATTERNS:
        for m in pattern.finditer(context):
            for g in m.groups():
                if g:
                    v = int(g)
                    if 56 <= v <= 32768:
                        return v
    # Also check the immediate line
    for pattern in KEY_SIZE_PATTERNS:
        for m in pattern.finditer(line):
            for g in m.groups():
                if g:
                    v = int(g)
                    if 56 <= v <= 32768:
                        return v
    return None


def key_size_risk(family: AlgoFamily, key_size: Optional[int]) -> tuple[RiskLevel, str]:
    """Determine risk level based on algorithm family and key size."""

    # Quantum-broken asymmetric — always CRITICAL regardless of key size
    if family in (AlgoFamily.RSA, AlgoFamily.RSA_OAEP):
        if key_size is None:
            return RiskLevel.CRITICAL, "RSA — quantum-broken (Shor's algorithm), key size unknown"
        if key_size < 1024:
            return RiskLevel.CRITICAL, f"RSA-{key_size} — classically broken TODAY and quantum-broken"
        if key_size < 2048:
            return RiskLevel.CRITICAL, f"RSA-{key_size} — classically weak and quantum-broken"
        return RiskLevel.CRITICAL, f"RSA-{key_size} — quantum-broken regardless of key size"

    if family in (AlgoFamily.ECC, AlgoFamily.ECDSA, AlgoFamily.ECDH,
                  AlgoFamily.ED25519, AlgoFamily.ED448, AlgoFamily.X25519, AlgoFamily.X448):
        return RiskLevel.CRITICAL, f"{family.value} — quantum-broken (Shor's algorithm on ECDLP)"

    if family == AlgoFamily.DSA:
        return RiskLevel.CRITICAL, "DSA — deprecated by NIST AND quantum-broken"

    if family == AlgoFamily.DH:
        if key_size and key_size < 2048:
            return RiskLevel.CRITICAL, f"DH-{key_size} — classically weak AND quantum-broken"
        return RiskLevel.CRITICAL, f"DH — quantum-broken (Shor's algorithm on DLP)"

    if family == AlgoFamily.ELGAMAL:
        return RiskLevel.CRITICAL, "ElGamal — quantum-broken (discrete log)"

    # Symmetric — Grover halves effective key length
    if family == AlgoFamily.AES_128:
        return RiskLevel.MEDIUM, "AES-128 provides only 64-bit quantum security (Grover). Use AES-256."

    if family == AlgoFamily.DES:
        return RiskLevel.CRITICAL, "DES (56-bit) — classically broken. Immediate removal required."

    if family == AlgoFamily.TRIPLE_DES:
        return RiskLevel.HIGH, "3DES — deprecated by NIST. Migrate to AES-256-GCM."

    if family == AlgoFamily.RC4:
        return RiskLevel.CRITICAL, "RC4 — classically broken. Remove from all contexts."

    if family == AlgoFamily.RC2:
        return RiskLevel.CRITICAL, "RC2 — obsolete and broken."

    if family == AlgoFamily.BLOWFISH:
        return RiskLevel.HIGH, "Blowfish — 64-bit block size enables birthday attacks."

    # Hashes
    if family == AlgoFamily.MD5:
        return RiskLevel.HIGH, "MD5 — collision-broken. Remove from security contexts."

    if family == AlgoFamily.MD4:
        return RiskLevel.CRITICAL, "MD4 — catastrophically broken."

    if family == AlgoFamily.SHA1:
        return RiskLevel.HIGH, "SHA-1 — collision-broken (SHAttered attack)."

    if family == AlgoFamily.RIPEMD160:
        return RiskLevel.MEDIUM, "RIPEMD-160 — not NIST approved. Use SHA-256."

    if family == AlgoFamily.AES_ECB:
        return RiskLevel.HIGH, "AES-ECB — deterministic mode leaks plaintext patterns."

    if family == AlgoFamily.HARDCODED_KEY:
        return RiskLevel.CRITICAL, "Hardcoded cryptographic key — exposed in source/binaries."

    if family == AlgoFamily.WEAK_RANDOM:
        return RiskLevel.HIGH, "Non-cryptographic PRNG used where CSPRNG required."

    if family == AlgoFamily.PROTOCOL:
        return RiskLevel.HIGH, "Insecure protocol configuration."

    return RiskLevel.MEDIUM, f"{family.value} — review required"


def confidence_to_level(confidence: float) -> ConfidenceLevel:
    """Convert numeric confidence to enum."""
    if confidence >= 0.95:
        return ConfidenceLevel.CONFIRMED
    if confidence >= 0.80:
        return ConfidenceLevel.HIGH
    if confidence >= 0.60:
        return ConfidenceLevel.MEDIUM
    if confidence >= 0.40:
        return ConfidenceLevel.LOW
    return ConfidenceLevel.TENTATIVE


# ────────────────────────────────────────────────────────────────────────────
# Language Detection
# ────────────────────────────────────────────────────────────────────────────

def detect_language(path: Path) -> Optional[str]:
    """Detect programming language from file extension or name."""
    suffix = path.suffix.lower()
    name = path.name.lower()
    for lang, exts in LANGUAGE_MAP.items():
        if suffix in exts or name in exts:
            return lang
    return None


# ────────────────────────────────────────────────────────────────────────────
# Line Sanitization — remove secrets before storage
# ────────────────────────────────────────────────────────────────────────────

_REDACT_PATTERNS = [
    re.compile(
        r"((?:key|secret|password|token|credential|api_key|private_key|access_key)"
        r"\s*[=:]\s*)['\"][^'\"]{8,}['\"]",
        re.IGNORECASE,
    ),
    re.compile(
        r"(Bearer\s+)\S{20,}",
        re.IGNORECASE,
    ),
    re.compile(
        r"(Authorization:\s*(?:Basic|Bearer)\s+)\S{10,}",
        re.IGNORECASE,
    ),
]


def sanitize_line(line: str) -> str:
    """Remove potential secrets from a line before storing in findings."""
    result = line
    for pat in _REDACT_PATTERNS:
        result = pat.sub(r"\1[REDACTED]", result)
    return result


# ────────────────────────────────────────────────────────────────────────────
# File Hashing
# ────────────────────────────────────────────────────────────────────────────

def file_sha256(path: Path) -> str:
    """Compute SHA-256 hash of a file for deduplication / caching."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()
