"""
Quantum Protocol v5.0 — Unified Scanner Engine
Merges Owasp_Scanner_1 (modular analyzers, core engine, secrets, crypto)
with Owasp_Scanner_2 (OWASP Top 10 flat modules) into a single orchestrated
scanning pipeline.

Full coverage:
  - OWASP Top 10:2025 (A01–A10) with 1,200+ detection patterns
  - 120+ provider secret/credential patterns with entropy analysis
  - Quantum-vulnerable cryptography (NIST PQC / CNSA 2.0)
  - Cloud/IaC security (AWS, GCP, Azure, Terraform, Docker, K8s)
  - Frontend JS analysis (secrets, eval, source maps, env leaks)
  - API security (GraphQL, excessive data, BOLA)
  - Supply chain analysis (unpinned deps, typosquatting, CI/CD integrity)
  - Bug bounty reconnaissance (endpoint discovery, tech fingerprinting)
  - Server-Side Request Forgery (SSRF) detection
  - Security Logging & Monitoring Failures
  - Exception Handling & Fail-Open detection
  - Sensitive Data Exposure / PII detection
  - 15+ compliance framework mappings

Architecture:
  Phase 1: Scanner_2 flat modules (misconfig, injection, frontend_js, endpoint,
            auth, broken_access, cloud, api_security, supply_chain,
            insecure_design, integrity)
  Phase 2: Scanner_1 extended analyzers (logging, exception, sensitive_data, ssrf)
  Phase 3: Scanner_1 core engine (crypto, secrets, semantic, certificate, SBOM)
"""

__version__ = "5.0.0"
__author__ = "Quantum Protocol Team"
