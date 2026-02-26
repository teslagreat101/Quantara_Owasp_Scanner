"""Quantum Protocol v4.0 — Analyzer Modules"""
from quantum_protocol.analyzers.semantic import ast_scan_python, scan_certificate, scan_dependency_manifest
from quantum_protocol.analyzers.secrets_engine import (
    COMPILED_SECRET_RULES, SecretRule, VALIDATORS,
    is_likely_false_positive_path, redact_secret,
    shannon_entropy, entropy_confidence_boost, is_high_entropy,
)
from quantum_protocol.analyzers.owasp_scanner import scan_owasp
from quantum_protocol.analyzers.injection_scanner import scan_injections
from quantum_protocol.analyzers.frontend_js_analyzer import scan_frontend
from quantum_protocol.analyzers.cloud_misconfig import scan_cloud
from quantum_protocol.analyzers.supply_chain import scan_supply_chain
from quantum_protocol.analyzers.endpoint_extractor import scan_recon
from quantum_protocol.analyzers.sensitive_data_exposure import scan_sensitive_data
