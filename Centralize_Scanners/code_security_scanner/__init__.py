"""
Code Security Scanner — Multi-Agent Semantic Analysis Engine
=============================================================

Enterprise-grade security scanning that reads and reasons about code
the way a human security researcher would.

Usage:
    from quantum_protocol.core.code_security_scanner import CodeSecurityScanner
    scanner = CodeSecurityScanner()
    result = scanner.scan_directory("/path/to/project")
"""

__version__ = "1.0.0"
__author__ = "Quantum Protocol Team"

# Lazy imports to avoid circular dependencies — import from submodules directly
from quantum_protocol.core.code_security_scanner.models import (
    SecurityScanResult,
    ValidatedFinding,
    PatchSuggestion,
    ScanConfiguration,
    AgentVerdict,
    TaintFlow,
    TaintSource,
    TaintSink,
    TaintPropagator,
)
from quantum_protocol.core.code_security_scanner.data_flow import DataFlowGraph
from quantum_protocol.core.code_security_scanner.agents import (
    DiscoveryAgent,
    VerificationAgent,
    AssessmentAgent,
)
from quantum_protocol.core.code_security_scanner.scanner import CodeSecurityScanner

__all__ = [
    "CodeSecurityScanner",
    "SecurityScanResult",
    "ValidatedFinding",
    "PatchSuggestion",
    "ScanConfiguration",
    "AgentVerdict",
    "TaintFlow",
    "DiscoveryAgent",
    "VerificationAgent",
    "AssessmentAgent",
    "DataFlowGraph",
    "TaintSource",
    "TaintSink",
    "TaintPropagator",
]
