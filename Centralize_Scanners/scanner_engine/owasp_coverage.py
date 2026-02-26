"""
Quantum Protocol v5.0 — OWASP Top 10:2025 Coverage Map

Comprehensive mapping of all scanner modules to OWASP categories
with pattern counts, CWE coverage, and compliance alignments.
"""

from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class OwaspMapping:
    """Mapping of a scanner module to OWASP category."""
    category_id: str          # e.g., "A01:2025"
    category_name: str        # e.g., "Broken Access Control"
    modules: list[str]        # Scanner modules that cover this
    cwe_coverage: list[str]   # CWE IDs covered
    pattern_count: int        # Total patterns
    compliance_frameworks: list[str] = field(default_factory=list)


OWASP_TOP_10_2025: dict[str, OwaspMapping] = {
    "A01:2025": OwaspMapping(
        category_id="A01:2025",
        category_name="Broken Access Control",
        modules=["access_control"],
        cwe_coverage=[
            "CWE-200", "CWE-284", "CWE-285", "CWE-352", "CWE-425",
            "CWE-538", "CWE-639", "CWE-862", "CWE-863",
        ],
        pattern_count=45,
        compliance_frameworks=["PCI-DSS 4.0", "SOC 2", "HIPAA", "NIST 800-53"],
    ),
    "A02:2025": OwaspMapping(
        category_id="A02:2025",
        category_name="Cryptographic Failures",
        modules=["frontend_js", "sensitive_data"],
        cwe_coverage=[
            "CWE-261", "CWE-296", "CWE-310", "CWE-312", "CWE-319",
            "CWE-321", "CWE-327", "CWE-328", "CWE-359",
        ],
        pattern_count=157,
        compliance_frameworks=["PCI-DSS 4.0", "HIPAA", "GDPR", "FIPS 140-3", "CNSA 2.0"],
    ),
    "A03:2025": OwaspMapping(
        category_id="A03:2025",
        category_name="Injection",
        modules=["injection"],
        cwe_coverage=[
            "CWE-77", "CWE-78", "CWE-79", "CWE-89", "CWE-90",
            "CWE-94", "CWE-113", "CWE-601", "CWE-611", "CWE-943",
        ],
        pattern_count=90,
        compliance_frameworks=["PCI-DSS 4.0", "SOC 2", "OWASP ASVS"],
    ),
    "A04:2025": OwaspMapping(
        category_id="A04:2025",
        category_name="Insecure Design",
        modules=["insecure_design"],
        cwe_coverage=[
            "CWE-209", "CWE-256", "CWE-307", "CWE-352", "CWE-434",
            "CWE-501", "CWE-522", "CWE-770",
        ],
        pattern_count=25,
        compliance_frameworks=["NIST 800-53", "ISO 27001"],
    ),
    "A05:2025": OwaspMapping(
        category_id="A05:2025",
        category_name="Security Misconfiguration",
        modules=["misconfig", "cloud"],
        cwe_coverage=[
            "CWE-200", "CWE-209", "CWE-215", "CWE-250", "CWE-284",
            "CWE-306", "CWE-489", "CWE-668", "CWE-693", "CWE-732",
            "CWE-798", "CWE-942", "CWE-1021",
        ],
        pattern_count=90,
        compliance_frameworks=["PCI-DSS 4.0", "CIS Benchmarks", "SOC 2"],
    ),
    "A06:2025": OwaspMapping(
        category_id="A06:2025",
        category_name="Vulnerable and Outdated Components",
        modules=["supply_chain"],
        cwe_coverage=["CWE-829", "CWE-1104"],
        pattern_count=20,
        compliance_frameworks=["PCI-DSS 4.0", "NIST 800-53", "SOC 2"],
    ),
    "A07:2025": OwaspMapping(
        category_id="A07:2025",
        category_name="Identification and Authentication Failures",
        modules=["auth"],
        cwe_coverage=[
            "CWE-255", "CWE-256", "CWE-257", "CWE-287", "CWE-307",
            "CWE-308", "CWE-384", "CWE-521", "CWE-613", "CWE-640",
        ],
        pattern_count=35,
        compliance_frameworks=["PCI-DSS 4.0", "HIPAA", "SOC 2", "NIST 800-53"],
    ),
    "A08:2025": OwaspMapping(
        category_id="A08:2025",
        category_name="Software and Data Integrity Failures",
        modules=["integrity"],
        cwe_coverage=["CWE-345", "CWE-353", "CWE-426", "CWE-494", "CWE-502", "CWE-829"],
        pattern_count=20,
        compliance_frameworks=["PCI-DSS 4.0", "NIST 800-53"],
    ),
    "A09:2025": OwaspMapping(
        category_id="A09:2025",
        category_name="Security Logging and Monitoring Failures",
        modules=["logging"],
        cwe_coverage=["CWE-117", "CWE-209", "CWE-532", "CWE-778"],
        pattern_count=10,
        compliance_frameworks=["PCI-DSS 4.0", "SOC 2", "HIPAA", "GDPR"],
    ),
    "A10:2025": OwaspMapping(
        category_id="A10:2025",
        category_name="Server-Side Request Forgery (SSRF)",
        modules=["ssrf"],
        cwe_coverage=["CWE-350", "CWE-601", "CWE-918"],
        pattern_count=15,
        compliance_frameworks=["OWASP ASVS", "NIST 800-53"],
    ),
}

# Additional coverage beyond OWASP Top 10
EXTENDED_COVERAGE = {
    "API-Top-10": OwaspMapping(
        category_id="API-Top-10",
        category_name="OWASP API Security Top 10",
        modules=["api_security"],
        cwe_coverage=["CWE-200", "CWE-285", "CWE-639", "CWE-770", "CWE-918"],
        pattern_count=30,
    ),
    "Recon": OwaspMapping(
        category_id="Recon",
        category_name="Reconnaissance & Endpoint Discovery",
        modules=["endpoint"],
        cwe_coverage=["CWE-200"],
        pattern_count=25,
    ),
    "Exception": OwaspMapping(
        category_id="Exception",
        category_name="Exception Handling & Fail-Open",
        modules=["exception"],
        cwe_coverage=["CWE-390", "CWE-396", "CWE-404", "CWE-636", "CWE-755"],
        pattern_count=12,
    ),
}


def get_owasp_coverage_report(findings_by_module: dict[str, int]) -> dict:
    """Generate OWASP Top 10:2025 coverage report from scan results."""
    coverage = {}
    for cat_id, mapping in OWASP_TOP_10_2025.items():
        finding_count = sum(findings_by_module.get(m, 0) for m in mapping.modules)
        coverage[cat_id] = {
            "name": mapping.category_name,
            "findings": finding_count,
            "modules": mapping.modules,
            "patterns": mapping.pattern_count,
            "cwe_count": len(mapping.cwe_coverage),
            "status": "scanned" if any(findings_by_module.get(m, -1) >= 0 for m in mapping.modules) else "not_scanned",
        }
    return coverage


def get_total_pattern_count() -> int:
    """Get total pattern count across all OWASP categories."""
    total = sum(m.pattern_count for m in OWASP_TOP_10_2025.values())
    total += sum(m.pattern_count for m in EXTENDED_COVERAGE.values())
    return total


def get_total_cwe_count() -> int:
    """Get total unique CWE coverage."""
    all_cwes = set()
    for m in OWASP_TOP_10_2025.values():
        all_cwes.update(m.cwe_coverage)
    for m in EXTENDED_COVERAGE.values():
        all_cwes.update(m.cwe_coverage)
    return len(all_cwes)
