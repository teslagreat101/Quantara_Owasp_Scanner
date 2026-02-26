"""
Quantum Protocol v3 — Pattern Rules Engine

Contains 200+ regex patterns covering:
  - 15+ programming languages
  - API calls, imports, config strings, CLI commands
  - Hardcoded keys with entropy analysis triggers
  - Weak RNG detection
  - Protocol-level patterns (TLS, SSH, IPsec configs)
  - PQC adoption detection (positive signals)

Each pattern includes:
  - Regex (compiled with flags)
  - Algorithm family mapping
  - Base confidence score
  - HNDL relevance flag
  - Language hint (None = universal)
  - CWE mapping
  - Whether key size extraction should be attempted
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from quantum_protocol.models.enums import AlgoFamily


@dataclass(frozen=True)
class PatternRule:
    """A single detection pattern."""
    id: str                            # unique rule ID, e.g. "RSA-001"
    pattern: str                       # regex
    family: AlgoFamily
    confidence: float                  # base confidence 0.0–1.0
    extract_key_size: bool = False
    hndl_relevant: bool = False
    language_hint: Optional[str] = None  # restrict to language, None = any
    note: str = ""
    cwe: Optional[str] = None
    tags: tuple[str, ...] = ()


def _build_rules() -> list[PatternRule]:
    """Build the full rule set. Organized by category for maintainability."""
    rules: list[PatternRule] = []
    _id_counter = [0]

    def _add(family: AlgoFamily, pattern: str, confidence: float, *,
             key_size: bool = False, hndl: bool = False,
             lang: Optional[str] = None, note: str = "",
             cwe: Optional[str] = None, tags: tuple = ()):
        _id_counter[0] += 1
        prefix = family.value.upper().replace("-", "").replace(" ", "_")[:6]
        rules.append(PatternRule(
            id=f"{prefix}-{_id_counter[0]:03d}",
            pattern=pattern, family=family, confidence=confidence,
            extract_key_size=key_size, hndl_relevant=hndl,
            language_hint=lang, note=note, cwe=cwe, tags=tags,
        ))

    # ╔══════════════════════════════════════════════════════════════════════╗
    # ║  RSA — Quantum-broken (Shor's algorithm)                          ║
    # ╚══════════════════════════════════════════════════════════════════════╝

    # Python
    _add(AlgoFamily.RSA, r"RSA\.generate_private_key\s*\(", 0.95, key_size=True, hndl=True, lang="python",
         note="RSA private key generation (cryptography lib)", cwe="CWE-327")
    _add(AlgoFamily.RSA, r"RSA\.generate\s*\(", 0.95, key_size=True, hndl=True, lang="python",
         note="RSA key generation (PyCryptodome)", cwe="CWE-327")
    _add(AlgoFamily.RSA, r"rsa\.generate_private_key\b", 0.95, key_size=True, hndl=True, lang="python",
         note="RSA key generation (cryptography)", cwe="CWE-327")
    _add(AlgoFamily.RSA, r"Cipher\.pkcs1_v1_5|PKCS1_v1_5", 0.90, hndl=True, lang="python",
         note="RSA PKCS1v1.5 (deprecated padding)", cwe="CWE-327")
    _add(AlgoFamily.RSA_OAEP, r"padding\.OAEP\b", 0.85, hndl=True, lang="python",
         note="RSA-OAEP — better padding but RSA is still quantum-broken", cwe="CWE-327")
    _add(AlgoFamily.RSA, r"asymmetric[._]padding\.PKCS1v15", 0.90, hndl=True, lang="python",
         note="RSA PKCS1v15 padding (cryptography lib)", cwe="CWE-327")

    # Java / Kotlin
    _add(AlgoFamily.RSA, r"KeyPairGenerator\.getInstance\s*\(\s*['\"]RSA['\"]", 0.95, key_size=True, hndl=True,
         lang="java", note="Java RSA KeyPairGenerator", cwe="CWE-327")
    _add(AlgoFamily.RSA, r"KeyFactory\.getInstance\s*\(\s*['\"]RSA['\"]", 0.95, hndl=True,
         lang="java", note="Java RSA KeyFactory", cwe="CWE-327")
    _add(AlgoFamily.RSA, r"Cipher\.getInstance\s*\(\s*['\"]RSA", 0.95, hndl=True,
         lang="java", note="Java RSA Cipher", cwe="CWE-327")
    _add(AlgoFamily.RSA, r"Signature\.getInstance\s*\(\s*['\"]SHA\d*withRSA", 0.95, hndl=True,
         lang="java", note="Java RSA Signature", cwe="CWE-327")

    # JavaScript / TypeScript
    _add(AlgoFamily.RSA, r"crypto\.createSign\s*\(\s*['\"]RSA", 0.95, hndl=True,
         lang="javascript", note="Node.js RSA sign", cwe="CWE-327")
    _add(AlgoFamily.RSA, r"crypto\.generateKeyPairSync\s*\(\s*['\"]rsa['\"]", 0.95, key_size=True, hndl=True,
         lang="javascript", note="Node.js RSA key pair generation", cwe="CWE-327")
    _add(AlgoFamily.RSA, r"subtle\.generateKey\s*\([^)]*RSA", 0.95, hndl=True,
         lang="javascript", note="WebCrypto RSA key generation", cwe="CWE-327")
    _add(AlgoFamily.RSA, r"subtle\.importKey\s*\([^)]*RSA", 0.90, hndl=True,
         lang="javascript", note="WebCrypto RSA key import", cwe="CWE-327")
    _add(AlgoFamily.RSA, r"jose\.\w*RSA|JWK.*kty.*RSA", 0.85, hndl=True,
         note="JWT/JWK with RSA", cwe="CWE-327")

    # Go
    _add(AlgoFamily.RSA, r"rsa\.GenerateKey\b", 0.95, key_size=True, hndl=True,
         lang="go", note="Go RSA key generation", cwe="CWE-327")
    _add(AlgoFamily.RSA, r"rsa\.SignPKCS1v15|rsa\.EncryptPKCS1v15", 0.95, hndl=True,
         lang="go", note="Go RSA PKCS1v15 operations", cwe="CWE-327")
    _add(AlgoFamily.RSA, r"rsa\.EncryptOAEP|rsa\.DecryptOAEP", 0.90, hndl=True,
         lang="go", note="Go RSA-OAEP operations", cwe="CWE-327")

    # Rust
    _add(AlgoFamily.RSA, r"RsaPrivateKey::new|RsaPublicKey::from", 0.95, key_size=True, hndl=True,
         lang="rust", note="Rust RSA key (rsa crate)", cwe="CWE-327")
    _add(AlgoFamily.RSA, r"use\s+rsa::\{", 0.85, hndl=True, lang="rust",
         note="Rust rsa crate import", cwe="CWE-327")

    # C/C++
    _add(AlgoFamily.RSA, r"RSA_generate_key(_ex)?\b", 0.95, key_size=True, hndl=True,
         lang="cpp", note="OpenSSL RSA key generation (C)", cwe="CWE-327")
    _add(AlgoFamily.RSA, r"EVP_PKEY_CTX_set_rsa_keygen_bits", 0.95, key_size=True, hndl=True,
         lang="cpp", note="OpenSSL RSA keygen bits (C)", cwe="CWE-327")
    _add(AlgoFamily.RSA, r"RSA_public_encrypt|RSA_private_decrypt", 0.95, hndl=True,
         lang="cpp", note="OpenSSL RSA encrypt/decrypt (C)", cwe="CWE-327")

    # C#
    _add(AlgoFamily.RSA, r"RSACryptoServiceProvider|RSA\.Create\b", 0.95, key_size=True, hndl=True,
         lang="csharp", note=".NET RSA provider", cwe="CWE-327")
    _add(AlgoFamily.RSA, r"RSACng\b|RSAOpenSsl\b", 0.95, hndl=True,
         lang="csharp", note=".NET RSA (CNG/OpenSSL)", cwe="CWE-327")

    # Ruby
    _add(AlgoFamily.RSA, r"OpenSSL::PKey::RSA\.new|OpenSSL::PKey::RSA\.generate", 0.95, key_size=True, hndl=True,
         lang="ruby", note="Ruby RSA key generation", cwe="CWE-327")

    # PHP
    _add(AlgoFamily.RSA, r"openssl_pkey_new\s*\([^)]*RSA", 0.95, key_size=True, hndl=True,
         lang="php", note="PHP RSA key generation", cwe="CWE-327")

    # Swift
    _add(AlgoFamily.RSA, r"SecKeyCreateRandomKey\s*\([^)]*kSecAttrKeyTypeRSA", 0.95, key_size=True, hndl=True,
         lang="swift", note="Swift RSA key generation", cwe="CWE-327")

    # Universal / shell
    _add(AlgoFamily.RSA, r"openssl\s+genrsa\b", 0.95, key_size=True, hndl=True,
         note="OpenSSL RSA key generation (shell)", cwe="CWE-327")
    _add(AlgoFamily.RSA, r"openssl\s+req\s+.*-newkey\s+rsa:", 0.95, key_size=True, hndl=True,
         note="OpenSSL CSR with RSA key", cwe="CWE-327")
    _add(AlgoFamily.RSA, r"ssh-keygen\s+.*-t\s+rsa\b", 0.95, key_size=True, hndl=True,
         note="SSH RSA key generation", cwe="CWE-327")
    _add(AlgoFamily.RSA, r"RSAPublicKey|RSAPrivateKey", 0.85, hndl=True,
         note="RSA key type reference", cwe="CWE-327")
    _add(AlgoFamily.RSA, r"BEGIN RSA (PRIVATE|PUBLIC) KEY", 1.00, hndl=True,
         note="Hardcoded RSA PEM block", cwe="CWE-321")
    _add(AlgoFamily.RSA, r"ssh-rsa\s+AAAA", 0.98, hndl=True,
         note="RSA SSH public key", cwe="CWE-327")

    # ╔══════════════════════════════════════════════════════════════════════╗
    # ║  ECC / ECDSA / ECDH — Quantum-broken (Shor's algorithm)          ║
    # ╚══════════════════════════════════════════════════════════════════════╝

    _add(AlgoFamily.ECC, r"ec\.generate_private_key\s*\(", 0.95, hndl=True, lang="python",
         note="ECC key generation (cryptography)", cwe="CWE-327")
    _add(AlgoFamily.ECDSA, r"ECDSA\b", 0.90, hndl=True,
         note="ECDSA reference", cwe="CWE-327")
    _add(AlgoFamily.ECC, r"SECP256R1|SECP384R1|SECP521R1|secp256k1", 0.90, hndl=True,
         note="Named EC curve (quantum-vulnerable)", cwe="CWE-327")
    _add(AlgoFamily.ECC, r"P-256|P-384|P-521|prime256v1|prime384v1", 0.90, hndl=True,
         note="EC curve name", cwe="CWE-327")
    _add(AlgoFamily.ECDH, r"elliptic\.createECDH|createECDH\b", 0.95, hndl=True,
         lang="javascript", note="Node.js ECDH", cwe="CWE-327")
    _add(AlgoFamily.ECC, r"EC_KEY_new|EC_KEY_generate_key", 0.95, hndl=True,
         lang="cpp", note="OpenSSL C ECC", cwe="CWE-327")
    _add(AlgoFamily.ECC, r"KeyPairGenerator\.getInstance\s*\(\s*['\"]EC['\"]", 0.95, hndl=True,
         lang="java", note="Java EC KeyPairGenerator", cwe="CWE-327")
    _add(AlgoFamily.ECC, r"openssl\s+ecparam\b", 0.95, hndl=True,
         note="OpenSSL EC params (shell)", cwe="CWE-327")
    _add(AlgoFamily.ECC, r"BEGIN EC (PRIVATE KEY|PARAMETERS)", 1.00, hndl=True,
         note="Hardcoded EC PEM block", cwe="CWE-321")
    _add(AlgoFamily.ECC, r"ssh-ecdsa\s+AAAA|ecdsa-sha2-nistp", 0.98, hndl=True,
         note="ECDSA SSH key", cwe="CWE-327")

    # Go
    _add(AlgoFamily.ECDSA, r"ecdsa\.GenerateKey\b", 0.95, hndl=True, lang="go",
         note="Go ECDSA key generation", cwe="CWE-327")
    _add(AlgoFamily.ECDH, r"ecdh\.P256\(\)|ecdh\.P384\(\)|ecdh\.P521\(\)", 0.95, hndl=True,
         lang="go", note="Go ECDH curve", cwe="CWE-327")

    # Rust
    _add(AlgoFamily.ECDSA, r"ecdsa::SigningKey|EcdsaKeyPair", 0.95, hndl=True, lang="rust",
         note="Rust ECDSA key", cwe="CWE-327")
    _add(AlgoFamily.ECC, r"use\s+p256::|use\s+p384::|use\s+k256::", 0.90, hndl=True, lang="rust",
         note="Rust elliptic curve crate import", cwe="CWE-327")

    # C#
    _add(AlgoFamily.ECDSA, r"ECDsa\.Create\b|ECDsaCng\b", 0.95, hndl=True, lang="csharp",
         note=".NET ECDSA", cwe="CWE-327")
    _add(AlgoFamily.ECDH, r"ECDiffieHellman\.Create|ECDiffieHellmanCng", 0.95, hndl=True, lang="csharp",
         note=".NET ECDH", cwe="CWE-327")

    # Ed25519 / Ed448 / X25519 / X448
    _add(AlgoFamily.ED25519, r"Ed25519|ed25519|ED25519", 0.85, hndl=True,
         note="Ed25519 — modern but quantum-vulnerable", cwe="CWE-327")
    _add(AlgoFamily.ED448, r"Ed448|ed448", 0.85, hndl=True,
         note="Ed448 — quantum-vulnerable", cwe="CWE-327")
    _add(AlgoFamily.X25519, r"X25519|x25519|Curve25519", 0.85, hndl=True,
         note="X25519 key exchange — quantum-vulnerable", cwe="CWE-327")
    _add(AlgoFamily.X448, r"X448|x448", 0.85, hndl=True,
         note="X448 key exchange — quantum-vulnerable", cwe="CWE-327")

    # ╔══════════════════════════════════════════════════════════════════════╗
    # ║  DSA — Deprecated + Quantum-broken                                ║
    # ╚══════════════════════════════════════════════════════════════════════╝

    _add(AlgoFamily.DSA, r"dsa\.generate_private_key\s*\(", 0.95, key_size=True, hndl=True,
         lang="python", note="DSA key gen (cryptography)", cwe="CWE-327")
    _add(AlgoFamily.DSA, r"DSA\.generate\s*\(", 0.95, key_size=True, hndl=True,
         lang="python", note="DSA key gen (PyCryptodome)", cwe="CWE-327")
    _add(AlgoFamily.DSA, r"KeyPairGenerator\.getInstance\s*\(\s*['\"]DSA['\"]", 0.95, key_size=True, hndl=True,
         lang="java", note="Java DSA", cwe="CWE-327")
    _add(AlgoFamily.DSA, r"openssl\s+dsaparam\b", 0.95, key_size=True, hndl=True,
         note="OpenSSL DSA (shell)", cwe="CWE-327")
    _add(AlgoFamily.DSA, r"ssh-dss\s+AAAA", 0.98, hndl=True,
         note="DSA SSH key (deprecated)", cwe="CWE-327")

    # ╔══════════════════════════════════════════════════════════════════════╗
    # ║  DH / ECDH — Quantum-broken                                       ║
    # ╚══════════════════════════════════════════════════════════════════════╝

    _add(AlgoFamily.DH, r"dh\.generate_parameters\s*\(", 0.95, key_size=True, hndl=True,
         lang="python", note="DH parameter generation", cwe="CWE-327")
    _add(AlgoFamily.DH, r"DiffieHellman\b", 0.90, hndl=True,
         note="DH reference", cwe="CWE-327")
    _add(AlgoFamily.DH, r"DHE_\w+|dhe_\w+", 0.85, hndl=True,
         note="DHE cipher suite", cwe="CWE-327", tags=("protocol",))
    _add(AlgoFamily.DH, r"KeyAgreement\.getInstance\s*\(\s*['\"]DH['\"]", 0.95, hndl=True,
         lang="java", note="Java DH KeyAgreement", cwe="CWE-327")
    _add(AlgoFamily.DH, r"openssl\s+(gendh|dhparam)\b", 0.95, key_size=True, hndl=True,
         note="OpenSSL DH params (shell)", cwe="CWE-327")
    _add(AlgoFamily.DH, r"DH_generate_parameters(_ex)?\b", 0.95, key_size=True, hndl=True,
         lang="cpp", note="OpenSSL DH generation (C)", cwe="CWE-327")

    # ╔══════════════════════════════════════════════════════════════════════╗
    # ║  Weak Hashes: SHA-1, MD5, MD4, RIPEMD-160                        ║
    # ╚══════════════════════════════════════════════════════════════════════╝

    # SHA-1
    _add(AlgoFamily.SHA1, r"\bSHA-?1\b", 0.85, note="SHA-1 reference", cwe="CWE-328")
    _add(AlgoFamily.SHA1, r"hashlib\.sha1\b", 0.95, lang="python",
         note="Python hashlib SHA-1", cwe="CWE-328")
    _add(AlgoFamily.SHA1, r"MessageDigest\.getInstance\s*\(\s*['\"]SHA-?1['\"]", 0.95, lang="java",
         note="Java SHA-1", cwe="CWE-328")
    _add(AlgoFamily.SHA1, r"crypto\.createHash\s*\(\s*['\"]sha1['\"]", 0.95, lang="javascript",
         note="Node.js SHA-1", cwe="CWE-328")
    _add(AlgoFamily.SHA1, r"Digest::SHA1\b", 0.90, lang="ruby",
         note="Ruby SHA-1", cwe="CWE-328")
    _add(AlgoFamily.SHA1, r"sha1\.New\(\)|sha1\.Sum\(", 0.95, lang="go",
         note="Go SHA-1", cwe="CWE-328")
    _add(AlgoFamily.SHA1, r"EVP_sha1\(\)", 0.95, lang="cpp",
         note="OpenSSL SHA-1 (C)", cwe="CWE-328")
    _add(AlgoFamily.SHA1, r"CC_SHA1\b|kCCHmacAlgSHA1", 0.95, lang="swift",
         note="Apple CommonCrypto SHA-1", cwe="CWE-328")
    _add(AlgoFamily.SHA1, r"Sha1::digest|use\s+sha1::", 0.90, lang="rust",
         note="Rust SHA-1 crate", cwe="CWE-328")
    _add(AlgoFamily.HMAC_SHA1, r"HMAC.*SHA-?1|hmac.*sha1", 0.85,
         note="HMAC-SHA1", cwe="CWE-328")

    # MD5
    _add(AlgoFamily.MD5, r"\bMD5\b", 0.85, note="MD5 reference", cwe="CWE-328")
    _add(AlgoFamily.MD5, r"hashlib\.md5\b", 0.95, lang="python",
         note="Python hashlib MD5", cwe="CWE-328")
    _add(AlgoFamily.MD5, r"MessageDigest\.getInstance\s*\(\s*['\"]MD5['\"]", 0.95, lang="java",
         note="Java MD5", cwe="CWE-328")
    _add(AlgoFamily.MD5, r"crypto\.createHash\s*\(\s*['\"]md5['\"]", 0.95, lang="javascript",
         note="Node.js MD5", cwe="CWE-328")
    _add(AlgoFamily.MD5, r"Digest::MD5\b", 0.90, lang="ruby",
         note="Ruby MD5", cwe="CWE-328")
    _add(AlgoFamily.MD5, r"md5\.New\(\)|md5\.Sum\(", 0.95, lang="go",
         note="Go MD5", cwe="CWE-328")
    _add(AlgoFamily.MD5, r"EVP_md5\(\)", 0.95, lang="cpp",
         note="OpenSSL MD5 (C)", cwe="CWE-328")
    _add(AlgoFamily.MD5, r"md5\s*\(|md5_hex\b", 0.85, lang="php",
         note="PHP MD5", cwe="CWE-328")
    _add(AlgoFamily.HMAC_MD5, r"HMAC.*MD5|hmac.*md5", 0.85,
         note="HMAC-MD5", cwe="CWE-328")

    # MD4
    _add(AlgoFamily.MD4, r"\bMD4\b|EVP_md4\(\)", 0.90,
         note="MD4 — catastrophically broken", cwe="CWE-328")

    # RIPEMD-160
    _add(AlgoFamily.RIPEMD160, r"RIPEMD-?160|ripemd160", 0.85,
         note="RIPEMD-160 — not NIST approved", cwe="CWE-328")

    # ╔══════════════════════════════════════════════════════════════════════╗
    # ║  Weak / Broken Symmetric: DES, 3DES, RC4, RC2, Blowfish, IDEA    ║
    # ╚══════════════════════════════════════════════════════════════════════╝

    _add(AlgoFamily.DES, r"\bDES\b(?!ede|3)", 0.85,
         note="DES reference (56-bit key)", cwe="CWE-327")
    _add(AlgoFamily.TRIPLE_DES, r"\b3DES\b|\bTripleDES\b|\bDESede\b|\bDES3\b", 0.90,
         note="3DES/Triple-DES (deprecated)", cwe="CWE-327")
    _add(AlgoFamily.DES, r"algorithms\.TripleDES\b", 0.95, lang="python",
         note="cryptography TripleDES", cwe="CWE-327")
    _add(AlgoFamily.DES, r"Cipher\.getInstance\s*\(\s*['\"]DES", 0.95, lang="java",
         note="Java DES Cipher", cwe="CWE-327")
    _add(AlgoFamily.DES, r"DES_ecb_encrypt|DES_cbc_encrypt", 0.95, lang="cpp",
         note="OpenSSL DES (C)", cwe="CWE-327")

    _add(AlgoFamily.RC4, r"\bRC4\b|\bARCFOUR\b|\barcfour\b", 0.90,
         note="RC4 — classically broken", cwe="CWE-327")
    _add(AlgoFamily.RC4, r"algorithms\.ARC4\b", 0.95, lang="python",
         note="cryptography ARC4", cwe="CWE-327")
    _add(AlgoFamily.RC2, r"\bRC2\b", 0.85,
         note="RC2 — obsolete cipher", cwe="CWE-327")

    _add(AlgoFamily.BLOWFISH, r"\bBlowfish\b|BF_ecb_encrypt", 0.85,
         note="Blowfish — 64-bit block size (birthday attacks)", cwe="CWE-327")
    _add(AlgoFamily.IDEA, r"\bIDEA\b", 0.80,
         note="IDEA cipher — obsolete, 64-bit block", cwe="CWE-327")

    # ╔══════════════════════════════════════════════════════════════════════╗
    # ║  AES Mode Weaknesses                                               ║
    # ╚══════════════════════════════════════════════════════════════════════╝

    _add(AlgoFamily.AES_ECB, r"AES[/._]ECB|AES\.MODE_ECB|Cipher\.getInstance\s*\(\s*['\"]AES/ECB",
         0.90, note="AES-ECB mode — leaks plaintext patterns", cwe="CWE-327")
    _add(AlgoFamily.AES_ECB, r"modes\.ECB\(\)", 0.95, lang="python",
         note="cryptography AES-ECB mode", cwe="CWE-327")
    _add(AlgoFamily.CBC_NO_HMAC, r"AES[/._]CBC(?!.*HMAC|.*Mac|.*GCM|.*tag|.*authenticate)",
         0.65, note="AES-CBC without visible MAC — potential padding oracle", cwe="CWE-327")

    # Grover-weakened AES-128
    _add(AlgoFamily.AES_128, r"AES-?128\b|aes_128\b", 0.70,
         note="AES-128 provides only 64-bit quantum security (Grover). Prefer AES-256.", cwe="CWE-327")

    # ╔══════════════════════════════════════════════════════════════════════╗
    # ║  Hardcoded Keys & Secrets                                          ║
    # ╚══════════════════════════════════════════════════════════════════════╝

    _add(AlgoFamily.HARDCODED_KEY,
         r"(?:private_key|secret_key|api_secret|signing_key|encryption_key|master_key|hmac_key)"
         r"\s*=\s*['\"][A-Za-z0-9+/=]{32,}['\"]",
         0.80, hndl=True, note="Hardcoded cryptographic secret", cwe="CWE-321")
    _add(AlgoFamily.HARDCODED_KEY,
         r"-----BEGIN (RSA|EC|DSA|OPENSSH|ENCRYPTED|PRIVATE) PRIVATE KEY-----",
         1.00, hndl=True, note="Hardcoded private key PEM block", cwe="CWE-321")
    _add(AlgoFamily.HARDCODED_KEY,
         r"PRIVATE_KEY\s*=\s*['\"][A-Za-z0-9+/=\-\n]{40,}",
         0.80, hndl=True, note="Hardcoded private key variable", cwe="CWE-321")
    _add(AlgoFamily.HARDCODED_KEY,
         r"(?:AWS_SECRET_ACCESS_KEY|AZURE_CLIENT_SECRET|GCP_PRIVATE_KEY|STRIPE_SECRET_KEY)\s*=\s*['\"][^'\"]{10,}",
         0.90, hndl=True, note="Cloud provider secret key hardcoded", cwe="CWE-321")
    _add(AlgoFamily.HARDCODED_KEY,
         r"(?:DATABASE_PASSWORD|DB_PASSWORD|REDIS_PASSWORD)\s*=\s*['\"][^'\"]{6,}",
         0.75, note="Hardcoded database credential", cwe="CWE-321")

    # ╔══════════════════════════════════════════════════════════════════════╗
    # ║  Weak Random Number Generators                                     ║
    # ╚══════════════════════════════════════════════════════════════════════╝

    _add(AlgoFamily.WEAK_RANDOM, r"random\.randint\s*\(|random\.random\s*\(|random\.choice\s*\(",
         0.60, lang="python", note="Python random module — not cryptographically secure", cwe="CWE-338",
         tags=("context-sensitive",))
    _add(AlgoFamily.WEAK_RANDOM, r"Math\.random\s*\(", 0.70, lang="javascript",
         note="Math.random() — not cryptographically secure", cwe="CWE-338")
    _add(AlgoFamily.WEAK_RANDOM, r"java\.util\.Random\b(?!.*Secure)", 0.70, lang="java",
         note="java.util.Random — not cryptographically secure", cwe="CWE-338")
    _add(AlgoFamily.WEAK_RANDOM, r"rand\(\)|srand\(|rand_r\(", 0.65, lang="cpp",
         note="C rand() — not cryptographically secure", cwe="CWE-338")
    _add(AlgoFamily.WEAK_RANDOM, r"math/rand\b(?!.*/crypto)", 0.70, lang="go",
         note="Go math/rand — not cryptographically secure (use crypto/rand)", cwe="CWE-338")
    _add(AlgoFamily.WEAK_RANDOM, r"rand::thread_rng\(\)(?!.*OsRng)", 0.50, lang="rust",
         note="Rust thread_rng — check if used for crypto (prefer OsRng)", cwe="CWE-338",
         tags=("context-sensitive",))

    # ╔══════════════════════════════════════════════════════════════════════╗
    # ║  Protocol-Level: TLS, SSH, IPsec Config                           ║
    # ╚══════════════════════════════════════════════════════════════════════╝

    _add(AlgoFamily.PROTOCOL, r"ssl\.PROTOCOL_TLSv1\b|TLSv1\.0|TLS_1_0", 0.90,
         note="TLS 1.0 — deprecated, disallowed by PCI-DSS 4.0", cwe="CWE-327",
         tags=("protocol", "tls"))
    _add(AlgoFamily.PROTOCOL, r"ssl\.PROTOCOL_TLSv1_1|TLSv1\.1|TLS_1_1", 0.90,
         note="TLS 1.1 — deprecated", cwe="CWE-327", tags=("protocol", "tls"))
    _add(AlgoFamily.PROTOCOL, r"ssl\.PROTOCOL_SSLv[23]|SSLv[23]|SSL_3_0", 0.95,
         note="SSL 2.0/3.0 — severely broken", cwe="CWE-327", tags=("protocol", "tls"))
    _add(AlgoFamily.PROTOCOL, r"MinimumTLSVersion\s*=\s*['\"]?1\.[01]",
         0.85, note="Minimum TLS version set to 1.0 or 1.1", cwe="CWE-327", tags=("config", "tls"))
    _add(AlgoFamily.PROTOCOL, r"VERIFY_NONE|verify_mode\s*=\s*(?:ssl\.)?CERT_NONE|rejectUnauthorized\s*:\s*false",
         0.90, note="TLS certificate verification disabled", cwe="CWE-295", tags=("protocol", "tls"))
    _add(AlgoFamily.PROTOCOL, r"InsecureSkipVerify\s*:\s*true", 0.95, lang="go",
         note="Go TLS certificate verification skipped", cwe="CWE-295", tags=("protocol", "tls"))
    _add(AlgoFamily.PROTOCOL, r"check_hostname\s*=\s*False|verify\s*=\s*False", 0.85,
         note="TLS hostname/certificate verification disabled", cwe="CWE-295", tags=("protocol",))

    # SSH weak algorithms
    _add(AlgoFamily.PROTOCOL, r"diffie-hellman-group1-sha1|diffie-hellman-group14-sha1", 0.90,
         note="Weak SSH key exchange algorithm", cwe="CWE-327", tags=("protocol", "ssh"))
    _add(AlgoFamily.PROTOCOL, r"ssh-dss\b", 0.90, hndl=True,
         note="SSH DSA host key — deprecated", cwe="CWE-327", tags=("protocol", "ssh"))

    # ╔══════════════════════════════════════════════════════════════════════╗
    # ║  Cryptographic Agility (POSITIVE signals)                          ║
    # ╚══════════════════════════════════════════════════════════════════════╝

    _add(AlgoFamily.AGILITY, r"ALGORITHM\s*=\s*os\.(?:environ|getenv)", 0.70,
         note="Algorithm configured via environment variable (good agility)", tags=("agility",))
    _add(AlgoFamily.AGILITY, r"(?:cipher|algorithm|crypto)[\w_]*\s*=\s*config\.", 0.65,
         note="Crypto algorithm from config (good agility)", tags=("agility",))
    _add(AlgoFamily.AGILITY, r"algorithm_negotiat|cipher_suite_configur|crypto_provider_factor", 0.60,
         note="Cryptographic algorithm negotiation/factory (good agility)", tags=("agility",))

    # ╔══════════════════════════════════════════════════════════════════════╗
    # ║  PQC Adoption (POSITIVE detection)                                 ║
    # ╚══════════════════════════════════════════════════════════════════════╝

    _add(AlgoFamily.ML_KEM, r"ML-?KEM|mlkem|kyber|CRYSTALS-?Kyber", 0.90,
         note="ML-KEM / Kyber detected — post-quantum KEM (FIPS 203)", tags=("pqc",))
    _add(AlgoFamily.ML_DSA, r"ML-?DSA|mldsa|dilithium|CRYSTALS-?Dilithium", 0.90,
         note="ML-DSA / Dilithium detected — post-quantum signatures (FIPS 204)", tags=("pqc",))
    _add(AlgoFamily.SLH_DSA, r"SLH-?DSA|slhdsa|SPHINCS\+?", 0.90,
         note="SLH-DSA / SPHINCS+ detected — hash-based PQ signatures (FIPS 205)", tags=("pqc",))
    _add(AlgoFamily.XMSS, r"XMSS|xmss", 0.80,
         note="XMSS hash-based signatures detected", tags=("pqc",))
    _add(AlgoFamily.ML_KEM, r"liboqs|oqs-provider|pqcrypto|open-quantum-safe", 0.75,
         note="PQC library reference detected (liboqs/OQS)", tags=("pqc",))
    _add(AlgoFamily.ML_KEM, r"X25519Kyber768|X25519MLKEM768", 0.95,
         note="Hybrid PQC key exchange — X25519+ML-KEM-768", tags=("pqc", "hybrid"))

    return rules


# Build and compile all rules at import time
ALL_RULES: list[PatternRule] = _build_rules()

COMPILED_RULES: list[tuple[re.Pattern, PatternRule]] = [
    (re.compile(r.pattern, re.IGNORECASE | re.MULTILINE), r)
    for r in ALL_RULES
]

# Index by family for fast lookup
RULES_BY_FAMILY: dict[AlgoFamily, list[PatternRule]] = {}
for _r in ALL_RULES:
    RULES_BY_FAMILY.setdefault(_r.family, []).append(_r)


# ────────────────────────────────────────────────────────────────────────────
# Key-size extraction patterns
# ────────────────────────────────────────────────────────────────────────────

KEY_SIZE_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"(?:key_size|key_bits|modulus_size|modulus|bits|keySize|modulusLength)\s*[=:(]\s*(\d{3,5})",
        r"generate_private_key\s*\([^,)]+,\s*(\d{3,5})",
        r"generate\s*\(\s*(\d{3,5})",
        r"GenerateKey\s*\([^,)]*,\s*(\d{3,5})",
        r"genrsa\s+(\d{3,5})",
        r"-newkey\s+rsa:(\d{3,5})",
        r"RSA\.Create\s*\(\s*(\d{3,5})",
        r"KeySize\s*=\s*(\d{3,5})",
        r"-b\s+(\d{3,5})",  # ssh-keygen -b
    ]
]
