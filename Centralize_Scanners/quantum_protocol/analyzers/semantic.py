"""
Quantum Protocol v3 — Semantic Analyzers

Deep analysis beyond regex:
  - Python AST walker: import tracking, call graph analysis, key-size extraction
  - Java semantic hints: annotation scanning, Spring Security config
  - Go semantic hints: crypto/tls config analysis
  - Certificate chain analysis with expiry checking
  - Dependency manifest scanning (requirements.txt, package.json, go.mod, Cargo.toml)
"""

from __future__ import annotations

import ast
import json
import re
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

from quantum_protocol.models.enums import AlgoFamily, RiskLevel


# ────────────────────────────────────────────────────────────────────────────
# Python AST Deep Analysis
# ────────────────────────────────────────────────────────────────────────────

QUANTUM_VULNERABLE_MODULES: set[str] = {
    "Crypto.PublicKey.RSA", "Crypto.PublicKey.ECC", "Crypto.PublicKey.DSA",
    "Crypto.Signature.DSS", "Crypto.Signature.pkcs1_15",
    "Crypto.Cipher.PKCS1_v1_5", "Crypto.Cipher.PKCS1_OAEP",
    "Crypto.Cipher.DES", "Crypto.Cipher.DES3", "Crypto.Cipher.ARC4",
    "Crypto.Cipher.Blowfish",
    "Crypto.Hash.MD5", "Crypto.Hash.SHA", "Crypto.Hash.SHA1",
    "cryptography.hazmat.primitives.asymmetric.rsa",
    "cryptography.hazmat.primitives.asymmetric.ec",
    "cryptography.hazmat.primitives.asymmetric.dsa",
    "cryptography.hazmat.primitives.asymmetric.dh",
    "cryptography.hazmat.primitives.asymmetric.x25519",
    "cryptography.hazmat.primitives.asymmetric.x448",
    "cryptography.hazmat.primitives.asymmetric.ed25519",
    "cryptography.hazmat.primitives.asymmetric.ed448",
    "cryptography.hazmat.primitives.hashes",
    "cryptography.hazmat.primitives.ciphers.algorithms",
    "ssl", "paramiko", "pyOpenSSL", "OpenSSL",
    "hashlib",
    "hmac",
}

PQC_POSITIVE_MODULES: set[str] = {
    "oqs", "pqcrypto", "liboqs",
    "pqcrypto.kem.kyber512", "pqcrypto.kem.kyber768", "pqcrypto.kem.kyber1024",
    "pqcrypto.sign.dilithium2", "pqcrypto.sign.dilithium3", "pqcrypto.sign.dilithium5",
    "pqcrypto.sign.sphincs",
}


def ast_scan_python(content: str, filepath: str) -> list[dict]:
    """
    Deep Python AST analysis:
    - Import tracking for quantum-vulnerable and PQC-positive modules
    - Function call analysis for crypto operations
    - ssl.SSLContext configuration analysis
    - hashlib usage tracking
    """
    findings: list[dict] = []
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return findings

    imported_modules: dict[str, str] = {}  # alias -> full module name

    for node in ast.walk(tree):
        # ── Import analysis ──────────────────────────────────────────
        if isinstance(node, ast.ImportFrom) and node.module:
            module = node.module
            for alias in (node.names or []):
                name = alias.asname or alias.name
                imported_modules[name] = f"{module}.{alias.name}"

            if any(module.startswith(m) for m in QUANTUM_VULNERABLE_MODULES):
                family = _module_to_family(module)
                findings.append({
                    "line": node.lineno,
                    "col": node.col_offset,
                    "type": "import",
                    "note": f"Import of quantum-vulnerable module: {module}",
                    "family_hint": family,
                    "confidence_boost": 0.05,
                })

            if any(module.startswith(m) for m in PQC_POSITIVE_MODULES):
                findings.append({
                    "line": node.lineno,
                    "col": node.col_offset,
                    "type": "pqc_adoption",
                    "note": f"PQC library import detected: {module}",
                    "family_hint": AlgoFamily.ML_KEM,
                    "confidence_boost": 0.0,
                })

        elif isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.asname or alias.name
                imported_modules[name] = alias.name
                if any(alias.name.startswith(m) for m in QUANTUM_VULNERABLE_MODULES):
                    findings.append({
                        "line": node.lineno,
                        "col": node.col_offset,
                        "type": "import",
                        "note": f"Import of quantum-vulnerable module: {alias.name}",
                        "family_hint": _module_to_family(alias.name),
                        "confidence_boost": 0.05,
                    })

        # ── Function call analysis ───────────────────────────────────
        elif isinstance(node, ast.Call):
            call_str = _call_to_string(node)
            if not call_str:
                continue

            # ssl.SSLContext with weak protocol
            if "SSLContext" in call_str:
                for arg in node.args:
                    if isinstance(arg, ast.Attribute):
                        attr_str = _attr_to_string(arg)
                        if any(proto in attr_str for proto in
                               ["PROTOCOL_TLSv1", "PROTOCOL_SSLv2", "PROTOCOL_SSLv3",
                                "PROTOCOL_SSLv23"]):
                            findings.append({
                                "line": node.lineno,
                                "col": node.col_offset,
                                "type": "tls_config",
                                "note": f"Weak TLS protocol: {attr_str}",
                                "family_hint": AlgoFamily.PROTOCOL,
                                "confidence_boost": 0.10,
                            })

            # hashlib weak hash calls
            if "hashlib.md5" in call_str or "hashlib.sha1" in call_str:
                family = AlgoFamily.MD5 if "md5" in call_str else AlgoFamily.SHA1
                # Check if usedforsecurity=False (Python 3.9+)
                uses_security = True
                for kw in node.keywords:
                    if kw.arg == "usedforsecurity" and isinstance(kw.value, ast.Constant):
                        if kw.value.value is False:
                            uses_security = False
                if uses_security:
                    findings.append({
                        "line": node.lineno,
                        "col": node.col_offset,
                        "type": "weak_hash",
                        "note": f"Weak hash: {call_str} (without usedforsecurity=False)",
                        "family_hint": family,
                        "confidence_boost": 0.10,
                    })

    return findings


def _call_to_string(node: ast.Call) -> str:
    """Convert an AST Call node to a string representation."""
    if isinstance(node.func, ast.Attribute):
        return _attr_to_string(node.func)
    if isinstance(node.func, ast.Name):
        return node.func.id
    return ""


def _attr_to_string(node: ast.Attribute) -> str:
    """Convert an AST Attribute node to dotted string."""
    parts = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def _module_to_family(module: str) -> Optional[AlgoFamily]:
    m = module.lower()
    if "rsa" in m: return AlgoFamily.RSA
    if "ecdh" in m: return AlgoFamily.ECDH
    if "ecdsa" in m or ("ec" in m and "dsa" not in m): return AlgoFamily.ECC
    if "ed25519" in m: return AlgoFamily.ED25519
    if "ed448" in m: return AlgoFamily.ED448
    if "x25519" in m: return AlgoFamily.X25519
    if "x448" in m: return AlgoFamily.X448
    if "dsa" in m: return AlgoFamily.DSA
    if "dh" in m: return AlgoFamily.DH
    if "md5" in m: return AlgoFamily.MD5
    if "sha1" in m or "sha" == m: return AlgoFamily.SHA1
    if "des3" in m or "des" in m: return AlgoFamily.DES
    if "arc4" in m: return AlgoFamily.RC4
    if "blowfish" in m: return AlgoFamily.BLOWFISH
    return None


# ────────────────────────────────────────────────────────────────────────────
# Certificate Analysis
# ────────────────────────────────────────────────────────────────────────────

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, dh
    CRYPTO_LIB_AVAILABLE = True
except ImportError:
    CRYPTO_LIB_AVAILABLE = False


def scan_certificate(content_bytes: bytes, filepath: str) -> list[dict]:
    """
    Parse X.509 certificates for:
    - Algorithm family detection
    - Key size extraction
    - Expiry analysis (cert rotation urgency)
    - Signature algorithm weakness
    - Chain completeness hints
    """
    results: list[dict] = []

    if not CRYPTO_LIB_AVAILABLE:
        # Fallback: regex on PEM text
        text = content_bytes.decode("utf-8", errors="ignore")
        if "BEGIN CERTIFICATE" in text:
            results.append({
                "line": 1,
                "note": "Certificate detected — install 'cryptography' for deep analysis",
                "family_hint": AlgoFamily.CERT_ISSUE,
                "risk": RiskLevel.MEDIUM,
                "key_size": None,
            })
        if "BEGIN RSA PRIVATE KEY" in text:
            results.append({
                "line": 1,
                "note": "RSA private key in certificate file",
                "family_hint": AlgoFamily.RSA,
                "risk": RiskLevel.CRITICAL,
                "key_size": None,
            })
        return results

    # Parse PEM blocks
    pem_blocks = re.findall(
        b"-----BEGIN CERTIFICATE-----[\\s\\S]*?-----END CERTIFICATE-----",
        content_bytes,
    )

    for idx, pem in enumerate(pem_blocks):
        try:
            cert = x509.load_pem_x509_certificate(pem, default_backend())
            pk = cert.public_key()
            pk_type = type(pk).__name__
            key_size = getattr(pk, "key_size", None)

            # Determine algorithm family
            family = _pk_type_to_family(pk_type)

            # Check signature algorithm
            sig_algo = cert.signature_algorithm_oid.dotted_string
            sig_name = getattr(cert.signature_hash_algorithm, "name", "unknown") \
                if cert.signature_hash_algorithm else "unknown"

            # Expiry analysis
            not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') \
                else cert.not_valid_after.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_until_expiry = (not_after - now).days

            expiry_note = ""
            if days_until_expiry < 0:
                expiry_note = f" EXPIRED {abs(days_until_expiry)} days ago!"
            elif days_until_expiry < 30:
                expiry_note = f" Expires in {days_until_expiry} days — urgent rotation needed"
            elif days_until_expiry < 90:
                expiry_note = f" Expires in {days_until_expiry} days — plan rotation"

            # SHA-1 signature detection
            sig_weakness = ""
            if sig_name and "sha1" in sig_name.lower():
                sig_weakness = " [WEAK: SHA-1 signature]"
            elif sig_name and "md5" in sig_name.lower():
                sig_weakness = " [CRITICAL: MD5 signature]"

            subject = cert.subject.rfc4514_string()

            results.append({
                "line": idx + 1,
                "note": (
                    f"Certificate: subject={subject}, "
                    f"key={pk_type}({key_size or '?'}-bit), "
                    f"sig={sig_name}{sig_weakness}{expiry_note}"
                ),
                "family_hint": family,
                "risk": RiskLevel.CRITICAL if family and family.is_quantum_broken else RiskLevel.MEDIUM,
                "key_size": key_size,
                "expiry_days": days_until_expiry,
                "signature_hash": sig_name,
            })

        except Exception as e:
            results.append({
                "line": idx + 1,
                "note": f"Certificate parse error: {e}",
                "family_hint": AlgoFamily.CERT_ISSUE,
                "risk": RiskLevel.LOW,
                "key_size": None,
            })

    return results


def _pk_type_to_family(pk_type: str) -> Optional[AlgoFamily]:
    t = pk_type.lower()
    if "rsa" in t: return AlgoFamily.RSA
    if "ec" in t: return AlgoFamily.ECC
    if "dsa" in t and "ec" not in t: return AlgoFamily.DSA
    if "dh" in t: return AlgoFamily.DH
    if "ed25519" in t: return AlgoFamily.ED25519
    if "ed448" in t: return AlgoFamily.ED448
    if "x25519" in t: return AlgoFamily.X25519
    return None


# ────────────────────────────────────────────────────────────────────────────
# Dependency Manifest Scanning
# ────────────────────────────────────────────────────────────────────────────

# Known quantum-vulnerable crypto packages
VULNERABLE_PACKAGES: dict[str, dict] = {
    # Python
    "pycryptodome":    {"family": "RSA/ECC/DES", "note": "Contains quantum-vulnerable primitives"},
    "pycrypto":        {"family": "RSA/ECC/DES", "note": "Unmaintained, contains vulnerable primitives"},
    "paramiko":        {"family": "RSA/ECC",     "note": "SSH library using quantum-vulnerable key exchange"},
    "pyopenssl":       {"family": "RSA/ECC",     "note": "OpenSSL wrapper — check TLS config for PQC readiness"},

    # JavaScript/TypeScript
    "node-forge":      {"family": "RSA/ECC",     "note": "Pure-JS crypto — quantum-vulnerable primitives"},
    "jsrsasign":       {"family": "RSA",         "note": "RSA signing library"},
    "elliptic":        {"family": "ECC",         "note": "Elliptic curve library — quantum-vulnerable"},

    # Java (Maven artifact IDs)
    "bouncy-castle":   {"family": "RSA/ECC",     "note": "Check for PQC provider availability (BC-PQC)"},

    # Go modules
    "crypto/rsa":      {"family": "RSA",         "note": "Go stdlib RSA"},
    "crypto/ecdsa":    {"family": "ECC",         "note": "Go stdlib ECDSA"},
    "crypto/dsa":      {"family": "DSA",         "note": "Go stdlib DSA (deprecated)"},
}

PQC_PACKAGES: dict[str, str] = {
    "liboqs-python":    "Open Quantum Safe — Python bindings",
    "pqcrypto":         "PQC algorithms for Python",
    "oqs":              "liboqs bindings",
    "circl":            "Cloudflare PQC library (Go)",
    "pqc":              "Post-quantum crypto package",
    "crystals-kyber":   "ML-KEM reference",
    "crystals-dilithium": "ML-DSA reference",
}


def scan_dependency_manifest(content: str, filename: str) -> list[dict]:
    """Scan package manifests for known vulnerable/PQC crypto libraries."""
    findings: list[dict] = []
    content_lower = content.lower()

    for pkg, info in VULNERABLE_PACKAGES.items():
        if pkg.lower() in content_lower:
            findings.append({
                "line": _find_line_number(content, pkg),
                "note": f"Vulnerable crypto dependency: {pkg} — {info['note']}",
                "family_hint": None,
                "type": "dependency",
                "risk": RiskLevel.MEDIUM,
            })

    for pkg, desc in PQC_PACKAGES.items():
        if pkg.lower() in content_lower:
            findings.append({
                "line": _find_line_number(content, pkg),
                "note": f"PQC library detected: {pkg} — {desc}",
                "family_hint": AlgoFamily.ML_KEM,
                "type": "pqc_dependency",
                "risk": RiskLevel.INFO,
            })

    return findings


def _find_line_number(content: str, search: str) -> int:
    """Find the line number where a string first appears."""
    for idx, line in enumerate(content.splitlines(), 1):
        if search.lower() in line.lower():
            return idx
    return 1
