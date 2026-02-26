"""
Quantum Protocol v4.0 — A08: Software & Data Integrity (Extended)
Unsafe deserialization, SRI, CI/CD integrity,
unsigned artifacts, dependency confusion, ML model safety.
"""
from __future__ import annotations
import re, logging
from typing import Optional
from quantum_protocol.models.enums import AlgoFamily, RiskLevel, ScanMode
from quantum_protocol.models.findings import CryptoFinding
from quantum_protocol.rules.owasp_rules import VulnRule, _compile
from quantum_protocol.utils.analysis import confidence_to_level, sanitize_line

logger = logging.getLogger("quantum_protocol.integrity_scanner")

_EXTENDED_RULES: list[VulnRule] = [
    VulnRule("INT-001", "TypeNameHandling\\s*=\\s*TypeNameHandling\\.(?:All|Auto|Objects)", AlgoFamily.VULN_UNSAFE_DESER, RiskLevel.CRITICAL, 0.92, ".NET JSON TypeNameHandling enables arbitrary type instantiation", "CWE-502", ('csharp',), ('integrity', 'deser')),
    VulnRule("INT-002", "(?:XMLDecoder|XStream)\\s*\\(\\s*\\)\\.(?:readObject|fromXML)\\s*\\(", AlgoFamily.VULN_UNSAFE_DESER, RiskLevel.CRITICAL, 0.88, "Java XML deserialization \u2014 code execution", "CWE-502", ('java',), ('integrity', 'deser')),
    VulnRule("INT-003", "shelve\\.open\\s*\\(|dill\\.loads?\\s*\\(|cloudpickle\\.loads?\\s*\\(", AlgoFamily.VULN_UNSAFE_DESER, RiskLevel.CRITICAL, 0.88, "Python unsafe deserialization (shelve/dill/cloudpickle)", "CWE-502", ('python',), ('integrity', 'deser')),
    VulnRule("INT-004", "torch\\.load\\s*\\((?!.*weights_only\\s*=\\s*True)", AlgoFamily.VULN_UNSAFE_DESER, RiskLevel.HIGH, 0.8, "PyTorch torch.load without weights_only \u2014 pickle exec", "CWE-502", ('python',), ('integrity', 'deser', 'ml')),
    VulnRule("INT-005", "np\\.load\\s*\\(.*?allow_pickle\\s*=\\s*True", AlgoFamily.VULN_UNSAFE_DESER, RiskLevel.HIGH, 0.82, "NumPy load with allow_pickle", "CWE-502", ('python',), ('integrity', 'deser')),
    VulnRule("INT-006", "<script\\s+src\\s*=\\s*['\\\"]https?://(?:cdn|unpkg|jsdelivr|cdnjs)[^'\\\"]+['\\\"](?![^>]*integrity)", AlgoFamily.VULN_MISSING_SRI, RiskLevel.MEDIUM, 0.82, "External script without SRI hash", "CWE-829", ('html',), ('integrity', 'sri')),
    VulnRule("INT-007", "<link\\s+[^>]*href\\s*=\\s*['\\\"]https?://(?:cdn|unpkg|jsdelivr|cdnjs)[^'\\\"]+['\\\"](?![^>]*integrity)", AlgoFamily.VULN_MISSING_SRI, RiskLevel.MEDIUM, 0.78, "External stylesheet without SRI", "CWE-829", ('html',), ('integrity', 'sri')),
    VulnRule("INT-008", "pip\\s+install\\s+(?:--index-url|--extra-index-url)\\s+https?://(?!pypi\\.org)", AlgoFamily.VULN_UNVERIFIED_CICD, RiskLevel.HIGH, 0.82, "pip install from non-PyPI index \u2014 dependency confusion", "CWE-494", ('config', 'shell'), ('integrity', 'supply-chain')),
    VulnRule("INT-009", "Kryo\\s*\\(\\s*\\)(?!.*setRegistrationRequired\\s*\\(\\s*true)", AlgoFamily.VULN_UNSAFE_DESER, RiskLevel.HIGH, 0.82, "Java Kryo without registration requirement", "CWE-502", ('java',), ('integrity', 'deser')),
    VulnRule("INT-010", "JsonConvert\\.DeserializeObject.*?(?:req|request|input|body)", AlgoFamily.VULN_UNSAFE_DESER, RiskLevel.HIGH, 0.78, ".NET JSON deserialization from user input", "CWE-502", ('csharp',), ('integrity', 'deser')),
    VulnRule("INT-011", "(?:gpg|pgp|sigstore|cosign)\\s+verify", AlgoFamily.VULN_UNSIGNED_UPDATE, RiskLevel.INFO, 0.5, "Signature verification present \u2014 good practice", "CWE-494", ('config', 'shell'), ('integrity', 'sign')),
]

COMPILED_EXTENDED = _compile(_EXTENDED_RULES)

def scan_integrity_scanner(content, relative_path, language, scan_mode, context_window=3):
    """Run extended integrity_scanner analysis."""
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
