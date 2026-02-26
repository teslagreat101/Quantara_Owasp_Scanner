"""
Quantum Protocol v4.0 — Cloud & IaC Security Scanner
Advanced detection for AWS, GCP, Azure, Terraform, Docker, Kubernetes,
CloudFormation, Helm, and Ansible misconfigurations.
"""
from __future__ import annotations
import re, logging
from typing import Optional
from quantum_protocol.models.enums import AlgoFamily, RiskLevel, ScanMode
from quantum_protocol.models.findings import CryptoFinding
from quantum_protocol.rules.owasp_rules import VulnRule, _compile
from quantum_protocol.utils.analysis import confidence_to_level, sanitize_line

logger = logging.getLogger("quantum_protocol.cloud")

_CLOUD_EXT_RULES: list[VulnRule] = [
    # ── AWS Extended ───────────────────────────────────────────
    VulnRule("CLD-001", r'aws_iam_user_policy.*?Action.*?\*', AlgoFamily.VULN_OVERPRIVILEGED_IAM, RiskLevel.CRITICAL, 0.90, "IAM user policy with wildcard Action", "CWE-250", ("terraform",), ("cloud","aws","iam")),
    VulnRule("CLD-002", r'aws_iam_role_policy.*?Resource.*?\*', AlgoFamily.VULN_OVERPRIVILEGED_IAM, RiskLevel.HIGH, 0.85, "IAM role with wildcard Resource", "CWE-250", ("terraform",), ("cloud","aws","iam")),
    VulnRule("CLD-003", r'aws_db_instance.*?storage_encrypted\s*=\s*false', AlgoFamily.VULN_MISSING_ENCRYPTION, RiskLevel.HIGH, 0.88, "RDS storage encryption disabled", "CWE-311", ("terraform",), ("cloud","aws","rds")),
    VulnRule("CLD-004", r'aws_ebs_volume(?!.*encrypted\s*=\s*true)', AlgoFamily.VULN_MISSING_ENCRYPTION, RiskLevel.MEDIUM, 0.72, "EBS volume without encryption", "CWE-311", ("terraform",), ("cloud","aws","ebs")),
    VulnRule("CLD-005", r'aws_cloudtrail.*?enable_logging\s*=\s*false', AlgoFamily.VULN_MISSING_AUDIT_LOG, RiskLevel.CRITICAL, 0.92, "CloudTrail logging disabled", "CWE-778", ("terraform",), ("cloud","aws","audit")),
    VulnRule("CLD-006", r'aws_cloudfront_distribution(?!.*viewer_protocol_policy\s*=\s*"redirect-to-https")', AlgoFamily.VULN_MISSING_ENCRYPTION, RiskLevel.MEDIUM, 0.72, "CloudFront without HTTPS redirect", "CWE-319", ("terraform",), ("cloud","aws","cf")),
    VulnRule("CLD-007", r'aws_lambda_permission.*?principal\s*=\s*["\']?\*', AlgoFamily.VULN_PERMISSIVE_POLICY, RiskLevel.HIGH, 0.85, "Lambda function publicly invocable", "CWE-284", ("terraform",), ("cloud","aws","lambda")),
    VulnRule("CLD-008", r'aws_sqs_queue_policy.*?Principal.*?\*', AlgoFamily.VULN_PERMISSIVE_POLICY, RiskLevel.HIGH, 0.85, "SQS queue publicly accessible", "CWE-284", ("terraform",), ("cloud","aws","sqs")),
    VulnRule("CLD-009", r'aws_sns_topic_policy.*?Principal.*?\*', AlgoFamily.VULN_PERMISSIVE_POLICY, RiskLevel.HIGH, 0.85, "SNS topic publicly accessible", "CWE-284", ("terraform",), ("cloud","aws","sns")),
    VulnRule("CLD-010", r'aws_elasticsearch_domain(?!.*encrypt_at_rest)', AlgoFamily.VULN_MISSING_ENCRYPTION, RiskLevel.HIGH, 0.78, "Elasticsearch without encryption at rest", "CWE-311", ("terraform",), ("cloud","aws","es")),

    # ── GCP ────────────────────────────────────────────────────
    VulnRule("CLD-020", r'google_storage_bucket_iam.*?allUsers|allAuthenticatedUsers', AlgoFamily.VULN_PUBLIC_S3, RiskLevel.CRITICAL, 0.92, "GCS bucket publicly accessible", "CWE-732", ("terraform",), ("cloud","gcp","storage")),
    VulnRule("CLD-021", r'google_compute_firewall.*?source_ranges.*?0\.0\.0\.0/0', AlgoFamily.VULN_OPEN_SECURITY_GROUP, RiskLevel.HIGH, 0.85, "GCP firewall open to all IPs", "CWE-284", ("terraform",), ("cloud","gcp","firewall")),
    VulnRule("CLD-022", r'google_sql_database_instance(?!.*require_ssl)', AlgoFamily.VULN_MISSING_ENCRYPTION, RiskLevel.HIGH, 0.78, "Cloud SQL without SSL requirement", "CWE-319", ("terraform",), ("cloud","gcp","sql")),

    # ── Azure ──────────────────────────────────────────────────
    VulnRule("CLD-030", r'azurerm_storage_account(?!.*enable_https_traffic_only\s*=\s*true)', AlgoFamily.VULN_MISSING_ENCRYPTION, RiskLevel.HIGH, 0.78, "Azure Storage without HTTPS-only", "CWE-319", ("terraform",), ("cloud","azure","storage")),
    VulnRule("CLD-031", r'azurerm_network_security_rule.*?source_address_prefix\s*=\s*["\']?\*', AlgoFamily.VULN_OPEN_SECURITY_GROUP, RiskLevel.HIGH, 0.85, "Azure NSG rule open to all", "CWE-284", ("terraform",), ("cloud","azure","nsg")),

    # ── Docker Extended ────────────────────────────────────────
    VulnRule("CLD-040", r'FROM\s+\S+:latest', AlgoFamily.VULN_UNPINNED_DEP, RiskLevel.MEDIUM, 0.75, "Docker FROM with :latest tag — pin to specific version", "CWE-1357", ("dockerfile",), ("cloud","docker","supply-chain")),
    VulnRule("CLD-041", r'RUN\s+.*?apt-get\s+install(?!.*--no-install-recommends)', AlgoFamily.VULN_PERMISSIVE_POLICY, RiskLevel.LOW, 0.60, "apt-get install without --no-install-recommends", "CWE-1188", ("dockerfile",), ("cloud","docker")),
    VulnRule("CLD-042", r'EXPOSE\s+(?:22|23|3389|5900|5432|3306|27017|6379|9200)\b', AlgoFamily.VULN_EXPOSED_ADMIN, RiskLevel.MEDIUM, 0.75, "Docker EXPOSE on sensitive port", "CWE-200", ("dockerfile",), ("cloud","docker","network")),
    VulnRule("CLD-043", r'ENV\s+\w*(?:PASSWORD|SECRET|KEY|TOKEN|CREDENTIAL)\w*\s*=', AlgoFamily.VULN_DOCKER_SECRETS, RiskLevel.HIGH, 0.85, "Secret in Docker ENV — visible in image inspect", "CWE-798", ("dockerfile",), ("cloud","docker","secret")),
    VulnRule("CLD-044", r'VOLUME\s+/(?:etc|var/run/docker\.sock|root)', AlgoFamily.VULN_PRIVILEGED_CONTAINER, RiskLevel.HIGH, 0.82, "Docker VOLUME mounting sensitive host path", "CWE-250", ("dockerfile",), ("cloud","docker")),

    # ── Kubernetes Extended ────────────────────────────────────
    VulnRule("CLD-050", r'readOnlyRootFilesystem:\s*false', AlgoFamily.VULN_K8S_MISCONFIG, RiskLevel.MEDIUM, 0.75, "K8s writable root filesystem", "CWE-732", ("config",), ("cloud","k8s")),
    VulnRule("CLD-051", r'runAsNonRoot:\s*false', AlgoFamily.VULN_CONTAINER_ROOT, RiskLevel.HIGH, 0.82, "K8s pod not required to run as non-root", "CWE-250", ("config",), ("cloud","k8s")),
    VulnRule("CLD-052", r'automountServiceAccountToken:\s*true', AlgoFamily.VULN_K8S_MISCONFIG, RiskLevel.MEDIUM, 0.72, "K8s auto-mount SA token — disable if not needed", "CWE-284", ("config",), ("cloud","k8s")),
    VulnRule("CLD-053", r'hostPath:\s*\n\s*path:\s*/', AlgoFamily.VULN_PRIVILEGED_CONTAINER, RiskLevel.HIGH, 0.85, "K8s hostPath mount — container can access host filesystem", "CWE-250", ("config",), ("cloud","k8s")),
    VulnRule("CLD-054", r'capabilities:\s*\n\s*add:\s*\n\s*-\s*(?:ALL|SYS_ADMIN|NET_ADMIN)', AlgoFamily.VULN_PRIVILEGED_CONTAINER, RiskLevel.CRITICAL, 0.90, "K8s container with dangerous capabilities", "CWE-250", ("config",), ("cloud","k8s")),

    # ── Helm/Ansible ───────────────────────────────────────────
    VulnRule("CLD-060", r'(?:ansible_ssh_pass|ansible_become_pass)\s*[=:]\s*["\'][^"\']+["\']', AlgoFamily.VULN_HARDCODED_CREDS, RiskLevel.CRITICAL, 0.90, "Ansible password in plaintext", "CWE-798", ("config",), ("cloud","ansible","secret")),
    VulnRule("CLD-061", r'no_log:\s*false', AlgoFamily.VULN_SENSITIVE_LOG, RiskLevel.MEDIUM, 0.72, "Ansible task logging enabled for sensitive operation", "CWE-532", ("config",), ("cloud","ansible","logging")),
]

COMPILED_CLOUD_EXT = _compile(_CLOUD_EXT_RULES)

def scan_cloud(content, relative_path, language, scan_mode, context_window=3):
    """Deep cloud/IaC security scanning."""
    if language not in ("terraform", "dockerfile", "config", "shell", None):
        # Also scan YAML/JSON for K8s/CloudFormation
        if not any(relative_path.endswith(ext) for ext in ('.tf', '.yaml', '.yml', '.json', '.dockerfile', 'Dockerfile', 'docker-compose', '.hcl', '.toml')):
            return []
    findings, seen, lines = [], set(), content.split("\n")
    for compiled_re, rule in COMPILED_CLOUD_EXT:
        if rule.languages and language and language not in rule.languages:
            continue
        for match in compiled_re.finditer(content):
            ln = content[:match.start()].count("\n") + 1
            dk = f"{relative_path}:{ln}:{rule.id}"
            if dk in seen: continue
            seen.add(dk)
            raw = lines[ln-1] if ln <= len(lines) else ""
            cs, ce = max(0, ln-context_window-1), min(len(lines), ln+context_window)
            findings.append(CryptoFinding(
                id=CryptoFinding.generate_id(relative_path, ln, f"CLD-{rule.id}"),
                file=relative_path, language=language or "config",
                line_number=ln, line_content=sanitize_line(raw.strip()),
                column_start=None, column_end=None,
                algorithm=rule.family.value, family=rule.family,
                risk=rule.risk, confidence=round(rule.confidence, 3),
                confidence_level=confidence_to_level(rule.confidence),
                key_size=None, hndl_relevant=False, pattern_note=rule.note,
                migration={"action": "Fix cloud misconfiguration per CIS benchmark", "cwe": rule.cwe},
                compliance_violations=[], context_lines=[sanitize_line(l) for l in lines[cs:ce]],
                cwe_id=rule.cwe, cvss_estimate=rule.risk.numeric,
                remediation_effort="medium", tags=list(rule.tags),
            ))
    return findings
