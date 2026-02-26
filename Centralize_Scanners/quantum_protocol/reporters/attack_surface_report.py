"""
Quantum Protocol v4.0 — Attack Surface Report
Bug bounty focused report with endpoint inventory, technology stack,
and prioritized attack vectors.
"""
from __future__ import annotations
import json
from quantum_protocol.models.findings import ScanSummary, CryptoFinding


def generate_attack_surface_report(summary: ScanSummary) -> str:
    """Generate attack surface report for penetration testing."""
    recon = [f for f in summary.findings if f.family.is_recon]
    secrets = [f for f in summary.findings if f.is_secret]
    vulns = [f for f in summary.findings if f.family.is_vuln]

    endpoints = set()
    admin_routes = set()
    internal_services = set()
    tech_stack = set()
    attack_vectors = []

    for f in recon:
        if "endpoint" in f.tags:
            endpoints.add(f.pattern_note)
        elif "admin" in str(f.tags):
            admin_routes.add(f.pattern_note)
        elif "internal" in str(f.tags):
            internal_services.add(f.pattern_note)
        elif "tech" in str(f.tags):
            tech_stack.add(f.pattern_note)

    # Build prioritized attack vectors
    crit_vulns = [f for f in vulns if f.risk.value == "Critical"]
    if crit_vulns:
        for v in crit_vulns[:10]:
            attack_vectors.append({
                "priority": "P0-CRITICAL",
                "type": v.family.vuln_category.value,
                "finding": v.pattern_note[:80],
                "file": v.file,
                "line": v.line_number,
                "cwe": v.cwe_id or "",
            })

    if secrets:
        for s in secrets[:10]:
            attack_vectors.append({
                "priority": "P1-HIGH",
                "type": "Credential Exposure",
                "finding": f"{s.family.value} in {s.file}",
                "file": s.file,
                "line": s.line_number,
            })

    report = {
        "title": "Attack Surface Assessment Report",
        "scanner": "Quantum Protocol v4.0",
        "source": summary.source,
        "summary": {
            "total_findings": summary.total_findings,
            "critical_vulns": summary.critical_count,
            "secrets_exposed": summary.secrets_count,
            "endpoints_discovered": len(endpoints),
            "admin_routes": len(admin_routes),
            "internal_services": len(internal_services),
            "technologies_identified": len(tech_stack),
        },
        "technology_stack": sorted(tech_stack),
        "endpoints": sorted(endpoints),
        "admin_routes": sorted(admin_routes),
        "internal_services": sorted(internal_services),
        "prioritized_attack_vectors": attack_vectors,
        "owasp_coverage": summary.owasp_coverage,
        "recommendations": _build_recommendations(summary),
    }
    return json.dumps(report, indent=2, default=str)


def _build_recommendations(summary: ScanSummary) -> list[str]:
    recs = []
    if summary.secrets_count > 0:
        recs.append(f"URGENT: Rotate {summary.secrets_count} exposed credentials immediately")
    if summary.critical_count > 0:
        recs.append(f"FIX: {summary.critical_count} critical vulnerabilities require immediate remediation")
    if summary.vuln_by_category.get("Injection", 0) > 0:
        recs.append("Implement parameterized queries and input validation across all endpoints")
    if summary.vuln_by_category.get("Access Control", 0) > 0:
        recs.append("Add server-side authorization checks and CORS origin validation")
    if summary.vuln_by_category.get("Cloud/Infrastructure", 0) > 0:
        recs.append("Review IaC configurations against CIS benchmarks")
    if summary.vuln_by_category.get("Authentication", 0) > 0:
        recs.append("Upgrade password hashing, fix JWT configuration, enable MFA")
    return recs
