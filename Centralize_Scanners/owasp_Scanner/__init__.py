"""
Quantum Protocol — Enterprise Cryptographic Security Scanner v3.0

A next-generation static analysis engine for detecting quantum-vulnerable
cryptography across polyglot codebases. Aligned to NIST SP 800-227,
FIPS 203/204/205, CNSA 2.0, and ETSI QSC standards.

Key capabilities:
  - Multi-language deep analysis (15+ languages)
  - AST-powered semantic scanning (Python, Java, Go, JS/TS, Rust)
  - Entropy-based secret detection with Shannon + Chi-squared analysis
  - X.509 certificate chain parsing and expiry analysis
  - HNDL (Harvest-Now-Decrypt-Later) threat modeling
  - Cryptographic agility scoring per-repository
  - SBOM-aware dependency vulnerability scanning
  - Compliance mapping: NIST, CNSA 2.0, ETSI, PCI-DSS 4.0, FIPS 140-3
  - Output: JSON, SARIF 2.1, CSV, HTML dashboard, SPDX, CycloneDX
  - Plugin architecture for custom rules and analyzers
  - Async-first with streaming progress
  - GitHub / GitLab / Bitbucket / local / archive support
  - Incremental scanning with change-set diffing
  - Enterprise: RBAC metadata, audit trails, scan policies
"""

__version__ = "3.0.0"
__author__ = "Quantum Protocol Team"
__license__ = "Apache-2.0"
