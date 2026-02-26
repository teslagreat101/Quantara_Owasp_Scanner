"""
Quantum Protocol v4.0 — API Security Scanner (Extended)
OWASP API Top 10: BOLA, data exposure, rate limiting,
GraphQL security, mass assignment, pagination, versioning.
"""
from __future__ import annotations
import re, logging
from typing import Optional
from quantum_protocol.models.enums import AlgoFamily, RiskLevel, ScanMode
from quantum_protocol.models.findings import CryptoFinding
from quantum_protocol.rules.owasp_rules import VulnRule, _compile
from quantum_protocol.utils.analysis import confidence_to_level, sanitize_line

logger = logging.getLogger("quantum_protocol.api_security")

_EXTENDED_RULES: list[VulnRule] = [
    VulnRule("API-E01", "(?:@api_view|@action|@route).*?(?:retrieve|detail|get)\\b(?!.*(?:permission|IsAuthenticated|login_required))", AlgoFamily.VULN_BOLA, RiskLevel.MEDIUM, 0.65, "API view without explicit permission class", "CWE-639", ('python',), ('api', 'bola')),
    VulnRule("API-E02", "router\\.(?:get|delete|patch)\\s*\\(\\s*['\\\"].*?/:(?:id|userId|orderId|accountId)", AlgoFamily.VULN_BOLA, RiskLevel.MEDIUM, 0.68, "API with path ID param \u2014 verify object-level auth", "CWE-639", ('javascript', 'typescript'), ('api', 'bola')),
    VulnRule("API-E03", "(?:serializer|Serializer).*?Meta.*?fields\\s*=\\s*['\\\"]__all__['\\\"]", AlgoFamily.VULN_EXCESSIVE_DATA, RiskLevel.HIGH, 0.82, "DRF serializer exposes all fields", "CWE-200", ('python',), ('api', 'data-exposure')),
    VulnRule("API-E04", "(?:select|SELECT)\\s+\\*\\s+(?:from|FROM)\\b", AlgoFamily.VULN_EXCESSIVE_DATA, RiskLevel.MEDIUM, 0.65, "SELECT * may expose unnecessary columns", "CWE-200", (), ('api', 'data-exposure')),
    VulnRule("API-E05", "(?:graphql|GraphQL).*?(?:depthLimit|max_depth)\\s*[=:]\\s*(?:null|undefined|false|None|0)", AlgoFamily.VULN_GRAPHQL_DEPTH, RiskLevel.HIGH, 0.82, "GraphQL without depth limiting \u2014 DoS", "CWE-770", (), ('api', 'graphql')),
    VulnRule("API-E06", "(?:graphql|GraphQL).*?(?:costAnalysis|queryComplexity)\\s*[=:]\\s*(?:null|undefined|false|None)", AlgoFamily.VULN_GRAPHQL_DEPTH, RiskLevel.HIGH, 0.78, "GraphQL without complexity limiting", "CWE-770", (), ('api', 'graphql')),
    VulnRule("API-E07", "(?:introspection|IntrospectionQuery|__schema)\\s*[=:]\\s*(?:true|enabled|True)", AlgoFamily.VULN_GRAPHQL_INTROSPECTION, RiskLevel.MEDIUM, 0.85, "GraphQL introspection enabled", "CWE-200", (), ('api', 'graphql')),
    VulnRule("API-E08", "\\.findAll\\s*\\(\\s*\\)(?!.*(?:limit|take|top|pageSize|per_page))", AlgoFamily.VULN_NO_PAGINATION, RiskLevel.MEDIUM, 0.68, "Find-all without pagination \u2014 data dump risk", "CWE-770", (), ('api', 'pagination')),
    VulnRule("API-E09", "(?:response|res)\\.(?:json|send)\\s*\\(\\s*(?:user|users|account|customer|patient|employee)", AlgoFamily.VULN_EXCESSIVE_DATA, RiskLevel.MEDIUM, 0.65, "Full model in API response \u2014 filter sensitive fields", "CWE-200", (), ('api', 'data-exposure')),
    VulnRule("API-E10", "Content-Type.*?(?:text/xml|application/xml).*?(?:req|request|body)", AlgoFamily.VULN_XXE, RiskLevel.MEDIUM, 0.68, "API accepting XML \u2014 verify XXE protection", "CWE-611", (), ('api', 'xxe')),
    VulnRule("API-E11", "@swagger|@ApiOperation|openapi.*?produces|swagger.*?basePath", AlgoFamily.VULN_EXPOSED_DOCS, RiskLevel.INFO, 0.5, "API docs \u2014 ensure auth in production", "CWE-200", (), ('api', 'docs')),
    VulnRule("API-E12", "(?:batch|bulk|mass)\\s*(?:create|update|delete|import)\\b", AlgoFamily.VULN_NO_PAGINATION, RiskLevel.LOW, 0.55, "Batch operation \u2014 verify size limits", "CWE-770", (), ('api', 'batch')),
]

COMPILED_EXTENDED = _compile(_EXTENDED_RULES)

def scan_api_security(content, relative_path, language, scan_mode, context_window=3):
    """Run extended api_security analysis."""
    findings, seen, lines_list = [], set(), content.split("\n")
    for compiled_re, rule in COMPILED_EXTENDED:
        if rule.languages and language and language not in rule.languages:
            continue
        for match in compiled_re.finditer(content):
            ln = content[:match.start()].count("\n") + 1
            dk = f"{relative_path}:{ln}:{rule.id}"
            if dk in seen: continue
            seen.add(dk)
            raw = lines_list[ln-1] if ln <= len(lines_list) else ""
            cs = max(0, ln - context_window - 1)
            ce = min(len(lines_list), ln + context_window)
            findings.append(CryptoFinding(
                id=CryptoFinding.generate_id(relative_path, ln, f"EXT-{rule.id}"),
                file=relative_path, language=language or "unknown",
                line_number=ln, line_content=sanitize_line(raw.strip()),
                column_start=None, column_end=None,
                algorithm=rule.family.value, family=rule.family,
                risk=rule.risk, confidence=round(rule.confidence, 3),
                confidence_level=confidence_to_level(rule.confidence),
                key_size=None, hndl_relevant=False, pattern_note=rule.note,
                migration={"action": rule.remediation or "Review and remediate", "cwe": rule.cwe},
                compliance_violations=[], context_lines=[sanitize_line(l) for l in lines_list[cs:ce]],
                cwe_id=rule.cwe, cvss_estimate=rule.risk.numeric,
                remediation_effort="medium", tags=list(rule.tags),
            ))
    return findings
