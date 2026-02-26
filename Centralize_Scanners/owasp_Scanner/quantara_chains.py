"""
Quantara Attack Chain Correlation Engine
=========================================

Phase 8 of the Quantara enterprise scanner pipeline.

Correlates individual findings into multi-step attack chains (attack paths).
Individual vulnerabilities may be MEDIUM severity, but when chained they
can form a CRITICAL attack path resulting in full compromise.

Architecture:
  AttackChainNode — a finding participating in a chain
  AttackChain — ordered sequence of nodes forming an attack path
  ChainRule — pattern rule that links two finding types
  AttackChainCorrelator — main engine that builds chains from findings
  ChainReporter — generates human-readable attack narratives

Pre-defined chain templates:
  Chain A: Secret/Env Exposure → Credential Leak → Authenticated API → Data Exfil
  Chain B: SSRF → Cloud Metadata → IAM Role Pivot → S3/Storage Exfil
  Chain C: LFI → Source Code Disclosure → Hardcoded Creds → DB SQL Injection
  Chain D: Open Redirect → OAuth2 Hijacking → Account Takeover
  Chain E: XSS → Session Hijack → CSRF → Admin Action
  Chain F: XXE → SSRF → Internal Service → Lateral Movement
  Chain G: Misconfigured CORS → API Abuse → Data Theft
  Chain H: Default Credentials → Admin Access → System Compromise
  Chain I: Prototype Pollution → RCE (Node.js / JavaScript apps)
  Chain J: GraphQL Introspection → Schema Leak → API Abuse

The engine also performs dynamic chain discovery based on
finding attribute correlations (same file, same URL prefix, same endpoint).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

logger = logging.getLogger("owasp_scanner.quantara_chains")

# ─────────────────────────────────────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AttackChainNode:
    """A single finding node in an attack chain."""
    finding_id: str
    title: str
    severity: str
    category: str                  # finding category / vuln type
    url: str = ""
    file: str = ""
    description: str = ""
    cwe: str = ""
    owasp: str = ""
    confidence: float = 0.75
    step_label: str = ""           # Human-readable step label (e.g. "Step 1: Initial Access")
    role: str = ""                 # Role in the chain: "entry", "pivot", "impact"


@dataclass
class AttackChain:
    """
    A multi-step attack chain correlating several findings into a complete attack path.
    """
    chain_id: str
    template_id: str               # which built-in chain template matched
    title: str                     # e.g. "SSRF → Cloud Metadata → S3 Exfiltration"
    description: str               # narrative summary
    nodes: list[AttackChainNode] = field(default_factory=list)
    combined_severity: str = "HIGH"  # escalated from individual severities
    cvss_estimate: float = 0.0
    exploitability: str = ""       # "trivial", "moderate", "sophisticated"
    business_impact: str = ""      # business-language impact
    attack_narrative: str = ""     # step-by-step "An attacker could..." story
    remediation_priority: list[str] = field(default_factory=list)  # ordered remediation steps
    mitre_tactics: list[str] = field(default_factory=list)         # MITRE ATT&CK tactics
    owasp_coverage: list[str] = field(default_factory=list)
    confidence: float = 0.75

    def to_dict(self) -> dict:
        return {
            "chain_id": self.chain_id,
            "template_id": self.template_id,
            "title": self.title,
            "description": self.description,
            "combined_severity": self.combined_severity,
            "cvss_estimate": self.cvss_estimate,
            "exploitability": self.exploitability,
            "business_impact": self.business_impact,
            "attack_narrative": self.attack_narrative,
            "node_count": len(self.nodes),
            "nodes": [
                {
                    "step": i + 1,
                    "finding_id": n.finding_id,
                    "title": n.title,
                    "severity": n.severity,
                    "category": n.category,
                    "url": n.url,
                    "step_label": n.step_label,
                    "role": n.role,
                }
                for i, n in enumerate(self.nodes)
            ],
            "remediation_priority": self.remediation_priority,
            "mitre_tactics": self.mitre_tactics,
            "owasp_coverage": self.owasp_coverage,
            "confidence": self.confidence,
        }


@dataclass
class ChainRule:
    """
    A rule that defines a link between two finding types in a chain.

    from_categories: categories that can occupy the "source" role
    to_categories: categories that can occupy the "destination" role
    relationship: human-readable description of the link
    requires_same_host: True if both findings must share the same host
    """
    from_categories: list[str]
    to_categories: list[str]
    relationship: str
    requires_same_host: bool = True
    weight: float = 1.0            # higher weight = stronger chain link


# ─────────────────────────────────────────────────────────────────────────────
# Built-in Chain Templates
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ChainTemplate:
    """A predefined multi-step attack chain template."""
    template_id: str
    title: str
    description: str
    steps: list[dict]              # list of {categories: [...], role: str, step_label: str}
    combined_severity: str
    cvss_estimate: float
    exploitability: str
    business_impact: str
    attack_narrative_template: str
    remediation_priority: list[str]
    mitre_tactics: list[str]
    owasp_coverage: list[str]
    min_matches: int = 2           # minimum steps that must match to form chain


CHAIN_TEMPLATES: list[ChainTemplate] = [
    ChainTemplate(
        template_id="chain-a-secret-to-exfil",
        title="Secret Exposure → Credential Leak → Authenticated API Access → Data Exfiltration",
        description=(
            "Hardcoded secrets or exposed configuration files allow attackers to harvest credentials, "
            "authenticate to backend APIs, and exfiltrate sensitive data."
        ),
        steps=[
            {"categories": ["sensitive-data", "secret", "hardcoded-key", "env-exposure", "backup-files", "source-disclosure"], "role": "entry", "step_label": "Step 1: Secret/Config Exposure"},
            {"categories": ["hardcoded-credentials", "secret", "api-key", "token"], "role": "pivot", "step_label": "Step 2: Credential Extraction"},
            {"categories": ["auth", "authentication", "api-security", "access-control"], "role": "pivot", "step_label": "Step 3: Authenticated API Access"},
            {"categories": ["injection", "sqli", "nosqli", "data-exposure"], "role": "impact", "step_label": "Step 4: Data Exfiltration"},
        ],
        combined_severity="CRITICAL",
        cvss_estimate=9.1,
        exploitability="moderate",
        business_impact="Complete database compromise and sensitive data exfiltration possible.",
        attack_narrative_template=(
            "1. Attacker discovers exposed {step0_title} ({step0_url})\n"
            "2. Credentials/API keys extracted from exposed file\n"
            "3. Attacker authenticates to the backend API using stolen credentials\n"
            "4. Authenticated access enables direct database queries and data exfiltration"
        ),
        remediation_priority=[
            "Immediately rotate all exposed credentials and API keys",
            "Remove secrets from source code and configuration files",
            "Implement secrets management (HashiCorp Vault, AWS Secrets Manager)",
            "Add pre-commit hooks to prevent secret commits",
        ],
        mitre_tactics=["TA0006-Credential Access", "TA0009-Collection", "TA0010-Exfiltration"],
        owasp_coverage=["A02:2021", "A07:2021", "A09:2021"],
        min_matches=2,
    ),

    ChainTemplate(
        template_id="chain-b-ssrf-to-cloud",
        title="SSRF → Cloud Metadata → IAM Role Pivot → Cloud Storage Exfiltration",
        description=(
            "Server-Side Request Forgery used to reach the cloud instance metadata service "
            "(AWS IMDSv1, GCP metadata, Azure IMDS), exfiltrate IAM credentials, "
            "and access cloud storage buckets."
        ),
        steps=[
            {"categories": ["ssrf", "open-redirect"], "role": "entry", "step_label": "Step 1: SSRF / Open Redirect"},
            {"categories": ["ssrf", "cloud-metadata", "cloud"], "role": "pivot", "step_label": "Step 2: Cloud Metadata Access"},
            {"categories": ["cloud", "aws", "gcp", "azure", "iam"], "role": "pivot", "step_label": "Step 3: IAM Credential Extraction"},
            {"categories": ["cloud", "s3", "storage", "data-exposure"], "role": "impact", "step_label": "Step 4: Cloud Storage Exfiltration"},
        ],
        combined_severity="CRITICAL",
        cvss_estimate=9.8,
        exploitability="trivial",
        business_impact="Full cloud account compromise. Attacker can access all S3 buckets, databases, and internal services.",
        attack_narrative_template=(
            "1. Attacker exploits SSRF at {step0_url}\n"
            "2. SSRF request reaches http://169.254.169.254/latest/meta-data/iam/security-credentials/\n"
            "3. IAM role credentials (AccessKeyId, SecretAccessKey, Token) extracted\n"
            "4. Attacker uses credentials to list and download all S3 buckets"
        ),
        remediation_priority=[
            "Enforce IMDSv2 on all EC2 instances (requires session tokens)",
            "Implement SSRF prevention: URL allowlisting, block internal IP ranges",
            "Apply least-privilege IAM policies",
            "Enable CloudTrail and alert on unusual metadata API access",
        ],
        mitre_tactics=["TA0006-Credential Access", "TA0009-Collection", "TA0008-Lateral Movement"],
        owasp_coverage=["A10:2021", "A05:2021"],
        min_matches=2,
    ),

    ChainTemplate(
        template_id="chain-c-lfi-to-sqli",
        title="LFI → Source Code Disclosure → Hardcoded DB Credentials → SQL Injection",
        description=(
            "Local File Inclusion used to read application source code containing hardcoded "
            "database credentials, enabling SQL injection or direct database access."
        ),
        steps=[
            {"categories": ["lfi", "path-traversal", "file-inclusion"], "role": "entry", "step_label": "Step 1: LFI / Path Traversal"},
            {"categories": ["source-disclosure", "backup-files", "sensitive-data"], "role": "pivot", "step_label": "Step 2: Source Code / Config Disclosure"},
            {"categories": ["hardcoded-credentials", "secret", "database-credentials"], "role": "pivot", "step_label": "Step 3: Database Credential Extraction"},
            {"categories": ["injection", "sqli", "database"], "role": "impact", "step_label": "Step 4: SQL Injection / DB Compromise"},
        ],
        combined_severity="CRITICAL",
        cvss_estimate=9.0,
        exploitability="moderate",
        business_impact="Full database compromise and potential RCE via SQL injection.",
        attack_narrative_template=(
            "1. Attacker exploits LFI at {step0_url} to read /etc/passwd and app config files\n"
            "2. Database connection string with credentials found in config file\n"
            "3. Direct database connection established using stolen credentials\n"
            "4. All database tables exfiltrated; potential for stored XSS / RCE via INTO OUTFILE"
        ),
        remediation_priority=[
            "Fix LFI vulnerability: validate file paths, use allowlists",
            "Remove hardcoded credentials from source code",
            "Implement parameterized queries to prevent SQL injection",
            "Use environment variables for sensitive configuration",
        ],
        mitre_tactics=["TA0007-Discovery", "TA0006-Credential Access", "TA0009-Collection"],
        owasp_coverage=["A03:2021", "A05:2021", "A02:2021"],
        min_matches=2,
    ),

    ChainTemplate(
        template_id="chain-d-redirect-to-takeover",
        title="Open Redirect → OAuth2 Hijacking → Account Takeover",
        description=(
            "An open redirect vulnerability used to hijack OAuth2 authorization codes "
            "by manipulating the redirect_uri parameter, leading to account takeover."
        ),
        steps=[
            {"categories": ["open-redirect", "redirect"], "role": "entry", "step_label": "Step 1: Open Redirect"},
            {"categories": ["auth", "oauth", "authentication"], "role": "pivot", "step_label": "Step 2: OAuth2 Authorization Code Interception"},
            {"categories": ["auth", "session", "token-hijack"], "role": "impact", "step_label": "Step 3: Account Takeover"},
        ],
        combined_severity="CRITICAL",
        cvss_estimate=8.8,
        exploitability="sophisticated",
        business_impact="Complete account takeover for any user who clicks a malicious link.",
        attack_narrative_template=(
            "1. Attacker discovers open redirect at {step0_url}\n"
            "2. Crafts OAuth2 authorization URL with redirect_uri pointing to attacker's server via open redirect\n"
            "3. Victim clicks link, OAuth code delivered to attacker's server\n"
            "4. Attacker exchanges code for access token, gaining full account access"
        ),
        remediation_priority=[
            "Fix open redirect: implement strict redirect URL allowlisting",
            "Validate redirect_uri against pre-registered URIs in OAuth2 flow",
            "Implement PKCE (Proof Key for Code Exchange) for OAuth2",
            "Add state parameter CSRF protection to OAuth2 flow",
        ],
        mitre_tactics=["TA0001-Initial Access", "TA0006-Credential Access"],
        owasp_coverage=["A07:2021", "A01:2021"],
        min_matches=2,
    ),

    ChainTemplate(
        template_id="chain-e-xss-to-admin",
        title="XSS → Session Hijack → CSRF → Admin Action",
        description=(
            "Cross-site scripting used to steal session cookies, impersonate the victim, "
            "and perform CSRF-protected admin actions."
        ),
        steps=[
            {"categories": ["xss", "reflected-xss", "stored-xss"], "role": "entry", "step_label": "Step 1: Cross-Site Scripting (XSS)"},
            {"categories": ["session", "cookie", "auth"], "role": "pivot", "step_label": "Step 2: Session Cookie Theft"},
            {"categories": ["csrf", "access-control", "admin"], "role": "impact", "step_label": "Step 3: CSRF / Admin Action"},
        ],
        combined_severity="HIGH",
        cvss_estimate=8.0,
        exploitability="moderate",
        business_impact="Attacker can perform any action on behalf of the victim, including admin operations.",
        attack_narrative_template=(
            "1. Attacker injects XSS payload at {step0_url}\n"
            "2. Victim's browser executes payload, exfiltrating session cookie to attacker\n"
            "3. Attacker replays session cookie to impersonate victim\n"
            "4. CSRF-protected admin action performed (user deletion, privilege escalation, etc.)"
        ),
        remediation_priority=[
            "Fix XSS: implement Content Security Policy (CSP), encode all output",
            "Set HttpOnly flag on all session cookies",
            "Implement CSRF tokens on all state-changing actions",
            "Implement SameSite=Strict on session cookies",
        ],
        mitre_tactics=["TA0001-Initial Access", "TA0006-Credential Access", "TA0040-Impact"],
        owasp_coverage=["A03:2021", "A07:2021", "A01:2021"],
        min_matches=2,
    ),

    ChainTemplate(
        template_id="chain-f-xxe-to-lateral",
        title="XXE → Internal SSRF → Internal Service Discovery → Lateral Movement",
        description=(
            "XML External Entity injection used to reach internal services "
            "not directly accessible from the internet."
        ),
        steps=[
            {"categories": ["xxe", "xml"], "role": "entry", "step_label": "Step 1: XXE Injection"},
            {"categories": ["ssrf", "internal-network", "cloud"], "role": "pivot", "step_label": "Step 2: SSRF to Internal Network"},
            {"categories": ["cloud", "service-discovery", "internal"], "role": "impact", "step_label": "Step 3: Internal Service Compromise"},
        ],
        combined_severity="CRITICAL",
        cvss_estimate=9.2,
        exploitability="sophisticated",
        business_impact="Full internal network access. All internal APIs, databases, and services exposed.",
        attack_narrative_template=(
            "1. Attacker injects XXE payload into XML endpoint at {step0_url}\n"
            "2. Server resolves external entity, making requests to internal IP ranges\n"
            "3. Internal services (Redis, Elasticsearch, internal APIs) discovered and accessed\n"
            "4. Lateral movement through internal network to high-value targets"
        ),
        remediation_priority=[
            "Disable external entity processing: set FEATURE_SECURE_PROCESSING on XML parsers",
            "Implement network segmentation to limit internal service exposure",
            "Block outbound requests from application servers to internal IP ranges",
            "Use XML schema validation to reject malformed XML",
        ],
        mitre_tactics=["TA0008-Lateral Movement", "TA0007-Discovery"],
        owasp_coverage=["A05:2021", "A10:2021"],
        min_matches=2,
    ),

    ChainTemplate(
        template_id="chain-g-cors-to-api-abuse",
        title="Misconfigured CORS → Cross-Origin API Abuse → Data Theft",
        description=(
            "Wildcard or overly permissive CORS policy allows malicious sites to "
            "make authenticated cross-origin requests to the API, stealing user data."
        ),
        steps=[
            {"categories": ["cors", "misconfig", "misconfiguration"], "role": "entry", "step_label": "Step 1: CORS Misconfiguration"},
            {"categories": ["api-security", "authentication", "auth"], "role": "pivot", "step_label": "Step 2: Authenticated Cross-Origin Request"},
            {"categories": ["data-exposure", "sensitive-data", "injection"], "role": "impact", "step_label": "Step 3: Data Theft"},
        ],
        combined_severity="HIGH",
        cvss_estimate=7.5,
        exploitability="moderate",
        business_impact="Any user visiting a malicious site can have their data stolen without their knowledge.",
        attack_narrative_template=(
            "1. Attacker discovers CORS misconfiguration at {step0_url} (allows arbitrary origins)\n"
            "2. Malicious site makes cross-origin requests on behalf of authenticated user\n"
            "3. Authenticated API responses returned to attacker-controlled origin\n"
            "4. User's sensitive data (PII, tokens, secrets) exfiltrated"
        ),
        remediation_priority=[
            "Implement strict CORS allowlist — never use '*' with credentials",
            "Validate Origin header against server-side allowlist",
            "Set SameSite cookie attribute to prevent cross-site requests",
            "Implement additional CSRF protection on all mutating endpoints",
        ],
        mitre_tactics=["TA0009-Collection", "TA0010-Exfiltration"],
        owasp_coverage=["A05:2021", "A01:2021"],
        min_matches=2,
    ),

    ChainTemplate(
        template_id="chain-h-default-creds",
        title="Default Credentials → Admin Access → Full System Compromise",
        description=(
            "Default or weak credentials on administrative interfaces allow "
            "direct admin access, leading to full system compromise."
        ),
        steps=[
            {"categories": ["default-credentials", "weak-password", "authentication"], "role": "entry", "step_label": "Step 1: Default Credential Discovery"},
            {"categories": ["admin", "admin-panel", "access-control"], "role": "pivot", "step_label": "Step 2: Admin Interface Access"},
            {"categories": ["rce", "command-injection", "file-upload", "injection"], "role": "impact", "step_label": "Step 3: Remote Code Execution / Full Compromise"},
        ],
        combined_severity="CRITICAL",
        cvss_estimate=9.5,
        exploitability="trivial",
        business_impact="Complete system compromise. Attacker has full administrative control.",
        attack_narrative_template=(
            "1. Attacker accesses admin panel at {step0_url} with default credentials (admin:admin)\n"
            "2. Full administrative interface access granted\n"
            "3. Attacker uploads a web shell or modifies system configuration\n"
            "4. Remote code execution achieved on the server"
        ),
        remediation_priority=[
            "Change all default credentials immediately",
            "Implement strong password policy and MFA for admin interfaces",
            "Restrict admin interface access to known IP ranges",
            "Enable admin action audit logging",
        ],
        mitre_tactics=["TA0001-Initial Access", "TA0004-Privilege Escalation", "TA0040-Impact"],
        owasp_coverage=["A07:2021", "A01:2021"],
        min_matches=2,
    ),

    ChainTemplate(
        template_id="chain-i-graphql-abuse",
        title="GraphQL Introspection → Schema Discovery → API Data Abuse",
        description=(
            "Enabled GraphQL introspection exposes the full API schema, "
            "enabling attackers to discover and abuse sensitive queries and mutations."
        ),
        steps=[
            {"categories": ["graphql", "introspection", "api-security"], "role": "entry", "step_label": "Step 1: GraphQL Introspection Enabled"},
            {"categories": ["graphql", "api-security", "access-control"], "role": "pivot", "step_label": "Step 2: Schema and Query Discovery"},
            {"categories": ["injection", "data-exposure", "access-control", "sensitive-data"], "role": "impact", "step_label": "Step 3: Data Exfiltration via Crafted Queries"},
        ],
        combined_severity="HIGH",
        cvss_estimate=7.8,
        exploitability="moderate",
        business_impact="Attacker has full knowledge of data model and can craft queries to exfiltrate sensitive data.",
        attack_narrative_template=(
            "1. Attacker runs GraphQL introspection query at {step0_url}\n"
            "2. Full schema extracted: all types, fields, queries, mutations\n"
            "3. Attacker identifies sensitive fields (PII, tokens, internal data)\n"
            "4. Crafted GraphQL queries bypass access controls and exfiltrate data"
        ),
        remediation_priority=[
            "Disable GraphQL introspection in production",
            "Implement query depth and complexity limits",
            "Apply field-level authorization to all sensitive GraphQL fields",
            "Rate-limit GraphQL queries per user",
        ],
        mitre_tactics=["TA0007-Discovery", "TA0009-Collection"],
        owasp_coverage=["A01:2021", "A05:2021"],
        min_matches=2,
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# Attack Chain Correlator
# ─────────────────────────────────────────────────────────────────────────────

class AttackChainCorrelator:
    """
    Correlates a list of vulnerability findings into multi-step attack chains.

    Matching strategy:
      1. Template matching: check if findings satisfy chain template steps
      2. Dynamic correlation: find findings linked by URL/host/file proximity

    Usage:
        findings = [...list of finding dicts from scanner...]
        correlator = AttackChainCorrelator()
        chains = correlator.correlate(findings)
        for chain in chains:
            print(chain.title, chain.combined_severity)
    """

    def __init__(self, templates: Optional[list[ChainTemplate]] = None):
        self.templates = templates or CHAIN_TEMPLATES
        self._chain_counter = 0

    def correlate(self, findings: list[dict]) -> list[AttackChain]:
        """
        Run chain correlation on a list of finding dicts.
        Returns list of AttackChain objects.
        """
        chains = []

        # Convert findings to nodes
        nodes = [self._finding_to_node(f) for f in findings if f]

        # Template-based matching
        for template in self.templates:
            matched_chains = self._match_template(template, nodes)
            chains.extend(matched_chains)

        # Dynamic proximity correlation
        dynamic_chains = self._dynamic_correlation(nodes, existing_chains=chains)
        chains.extend(dynamic_chains)

        # Deduplicate and sort by severity
        chains = self._deduplicate_chains(chains)
        chains.sort(key=lambda c: _severity_rank(c.combined_severity), reverse=True)

        logger.info(f"[chains] Correlation complete: {len(chains)} attack chains identified from {len(findings)} findings")
        return chains

    def _finding_to_node(self, finding: dict) -> AttackChainNode:
        """Convert a finding dict to an AttackChainNode."""
        # Normalize category
        category = (
            finding.get("category") or
            finding.get("injection_type") or
            finding.get("finding_type") or
            finding.get("subcategory") or
            ""
        ).lower().replace(" ", "-")

        # Also include title words as category hints
        title = finding.get("title", "").lower()
        extra_cats = []
        if "sql" in title or "sqli" in title:
            extra_cats.append("sqli")
        if "xss" in title or "cross-site scripting" in title:
            extra_cats.append("xss")
        if "ssrf" in title:
            extra_cats.append("ssrf")
        if "lfi" in title or "path traversal" in title:
            extra_cats.append("lfi")
        if "admin" in title or "administration" in title:
            extra_cats.append("admin")
        if "cors" in title:
            extra_cats.append("cors")
        if "redirect" in title:
            extra_cats.append("open-redirect")
        if "secret" in title or "credential" in title or "api key" in title or "password" in title:
            extra_cats.append("secret")
        if "graphql" in title:
            extra_cats.append("graphql")
        if "xxe" in title or "entity" in title:
            extra_cats.append("xxe")
        if "default" in title:
            extra_cats.append("default-credentials")
        if "backup" in title:
            extra_cats.append("backup-files")
        if "source" in title or "disclosure" in title:
            extra_cats.append("source-disclosure")
        if "cloud" in title or "metadata" in title:
            extra_cats.append("cloud")
        if "hardcoded" in title:
            extra_cats.append("hardcoded-credentials")

        # Tags as additional categories
        tags = [t.lower() for t in (finding.get("tags") or [])]
        all_categories = [category] + extra_cats + tags

        # Stash all categories as a comma-joined string for matching
        full_category = ",".join(set(c for c in all_categories if c))

        return AttackChainNode(
            finding_id=finding.get("id", ""),
            title=finding.get("title", "Unknown"),
            severity=finding.get("severity", "info").upper(),
            category=full_category,
            url=finding.get("file", finding.get("url", "")),
            file=finding.get("file", ""),
            description=finding.get("description", ""),
            cwe=finding.get("cwe", ""),
            owasp=finding.get("owasp", ""),
            confidence=finding.get("confidence", 0.75),
        )

    def _node_matches_step(self, node: AttackChainNode, step: dict) -> bool:
        """Check if a node's categories match a chain step."""
        step_categories = step.get("categories", [])
        node_cats = set(node.category.split(","))
        # Match if any step category appears in node categories
        for sc in step_categories:
            sc_lower = sc.lower()
            if any(sc_lower in nc for nc in node_cats):
                return True
            if sc_lower in node.category.lower():
                return True
        return False

    def _match_template(
        self, template: ChainTemplate, nodes: list[AttackChainNode]
    ) -> list[AttackChain]:
        """Try to match a chain template against the finding nodes."""
        chains = []

        # For each step in the template, find matching nodes
        step_matches: list[list[AttackChainNode]] = []
        for step in template.steps:
            matching = [n for n in nodes if self._node_matches_step(n, step)]
            step_matches.append(matching)

        # Count how many steps have at least one matching node
        matched_steps = sum(1 for m in step_matches if m)

        if matched_steps < template.min_matches:
            return chains

        # Build chain from best matching nodes per step
        chain_nodes = []
        used_ids = set()
        for i, step in enumerate(template.steps):
            matching = step_matches[i]
            # Pick the highest-severity unused match
            available = [n for n in matching if n.finding_id not in used_ids]
            if not available:
                continue
            best = max(available, key=lambda n: _severity_rank(n.severity))
            labeled = AttackChainNode(
                finding_id=best.finding_id,
                title=best.title,
                severity=best.severity,
                category=best.category,
                url=best.url,
                file=best.file,
                description=best.description,
                cwe=best.cwe,
                owasp=best.owasp,
                confidence=best.confidence,
                step_label=step.get("step_label", f"Step {i+1}"),
                role=step.get("role", "pivot"),
            )
            chain_nodes.append(labeled)
            used_ids.add(best.finding_id)

        if len(chain_nodes) < template.min_matches:
            return chains

        # Build narrative
        narrative = self._build_narrative(template, chain_nodes)

        self._chain_counter += 1
        chain = AttackChain(
            chain_id=f"QC-{self._chain_counter:04d}",
            template_id=template.template_id,
            title=template.title,
            description=template.description,
            nodes=chain_nodes,
            combined_severity=template.combined_severity,
            cvss_estimate=template.cvss_estimate,
            exploitability=template.exploitability,
            business_impact=template.business_impact,
            attack_narrative=narrative,
            remediation_priority=template.remediation_priority,
            mitre_tactics=template.mitre_tactics,
            owasp_coverage=template.owasp_coverage,
            confidence=_chain_confidence(chain_nodes),
        )
        chains.append(chain)
        logger.info(f"[chains] Template match: {template.template_id} → {len(chain_nodes)} steps")
        return chains

    def _build_narrative(self, template: ChainTemplate, nodes: list[AttackChainNode]) -> str:
        """Build a step-by-step attack narrative from template + matched nodes."""
        narrative_parts = [f"ATTACK CHAIN: {template.title}\n"]
        narrative_parts.append(f"Business Impact: {template.business_impact}\n")
        narrative_parts.append(f"Exploitability: {template.exploitability.capitalize()}\n")
        narrative_parts.append(f"CVSS Estimate: {template.cvss_estimate}\n\n")
        narrative_parts.append("ATTACK STEPS:\n")
        for i, node in enumerate(nodes):
            narrative_parts.append(
                f"  {node.step_label}\n"
                f"    Finding: {node.title}\n"
                f"    Location: {node.url or node.file or 'unknown'}\n"
                f"    Severity: {node.severity}\n"
            )
        narrative_parts.append("\nMITRE ATT&CK TACTICS:\n")
        for tactic in template.mitre_tactics:
            narrative_parts.append(f"  - {tactic}\n")
        return "".join(narrative_parts)

    def _dynamic_correlation(
        self, nodes: list[AttackChainNode], existing_chains: list[AttackChain]
    ) -> list[AttackChain]:
        """
        Dynamic chain discovery: find HIGH+ findings on the same host/path
        that form a logical chain not covered by templates.
        """
        chains = []
        high_nodes = [n for n in nodes if _severity_rank(n.severity) >= 2]

        if len(high_nodes) < 2:
            return chains

        # Group by host
        host_groups: dict[str, list[AttackChainNode]] = {}
        for node in high_nodes:
            host = _extract_host(node.url or node.file)
            if host:
                host_groups.setdefault(host, []).append(node)

        for host, group in host_groups.items():
            if len(group) < 2:
                continue

            # Check if these nodes are already in an existing chain
            existing_ids = {n.finding_id for chain in existing_chains for n in chain.nodes}
            new_group = [n for n in group if n.finding_id not in existing_ids]

            if len(new_group) < 2:
                continue

            # Create a dynamic chain for co-located HIGH+ findings
            self._chain_counter += 1
            chain = AttackChain(
                chain_id=f"QC-DYN-{self._chain_counter:04d}",
                template_id="dynamic-correlation",
                title=f"Co-located High-Severity Findings: {host}",
                description=(
                    f"{len(new_group)} high-severity vulnerabilities found on the same host ({host}). "
                    f"An attacker could chain these vulnerabilities to achieve greater impact."
                ),
                nodes=[
                    AttackChainNode(
                        **{k: v for k, v in n.__dict__.items()},
                        step_label=f"Finding {i+1}: {n.title}",
                        role="pivot" if i < len(new_group) - 1 else "impact",
                    )
                    for i, n in enumerate(new_group[:5])  # cap at 5 nodes
                ],
                combined_severity=_max_severity([n.severity for n in new_group]),
                cvss_estimate=0.0,
                exploitability="moderate",
                business_impact=f"Multiple high-severity vulnerabilities on {host} may be chained for amplified impact.",
                attack_narrative=(
                    f"Dynamic correlation: {len(new_group)} findings on {host} "
                    f"may be exploited in sequence for greater impact."
                ),
                remediation_priority=list({n.title for n in new_group})[:5],
                mitre_tactics=[],
                owasp_coverage=list({n.owasp for n in new_group if n.owasp})[:5],
                confidence=_chain_confidence(new_group),
            )
            chains.append(chain)

        return chains

    def _deduplicate_chains(self, chains: list[AttackChain]) -> list[AttackChain]:
        """Remove duplicate chains (same template_id + same node IDs)."""
        seen = set()
        unique = []
        for chain in chains:
            key = (chain.template_id, frozenset(n.finding_id for n in chain.nodes))
            if key not in seen:
                seen.add(key)
                unique.append(chain)
        return unique


# ─────────────────────────────────────────────────────────────────────────────
# Chain Reporter
# ─────────────────────────────────────────────────────────────────────────────

class ChainReporter:
    """Generates structured reports from attack chains."""

    def summary(self, chains: list[AttackChain]) -> dict:
        """Generate a summary dict of all chains."""
        return {
            "total_chains": len(chains),
            "critical_chains": sum(1 for c in chains if c.combined_severity == "CRITICAL"),
            "high_chains": sum(1 for c in chains if c.combined_severity == "HIGH"),
            "chains": [c.to_dict() for c in chains],
        }

    def text_report(self, chains: list[AttackChain]) -> str:
        """Generate a plain-text attack chain report."""
        if not chains:
            return "No attack chains identified.\n"

        lines = [
            f"QUANTARA ATTACK CHAIN REPORT",
            f"{'='*60}",
            f"Total Chains: {len(chains)}",
            f"Critical: {sum(1 for c in chains if c.combined_severity == 'CRITICAL')}",
            f"High: {sum(1 for c in chains if c.combined_severity == 'HIGH')}",
            f"{'='*60}\n",
        ]

        for i, chain in enumerate(chains, 1):
            lines.append(f"CHAIN {i}: {chain.title}")
            lines.append(f"  ID: {chain.chain_id}")
            lines.append(f"  Severity: {chain.combined_severity} | CVSS: {chain.cvss_estimate}")
            lines.append(f"  Exploitability: {chain.exploitability}")
            lines.append(f"  Business Impact: {chain.business_impact}")
            lines.append(f"  Steps ({len(chain.nodes)}):")
            for node in chain.nodes:
                lines.append(f"    ├─ [{node.severity}] {node.step_label}: {node.title}")
                if node.url:
                    lines.append(f"    │    URL: {node.url}")
            lines.append(f"  Remediation Priority:")
            for j, rem in enumerate(chain.remediation_priority, 1):
                lines.append(f"    {j}. {rem}")
            lines.append("")

        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _severity_rank(severity: str) -> int:
    return _SEVERITY_RANK.get(severity.upper(), 0)


def _max_severity(severities: list[str]) -> str:
    if not severities:
        return "INFO"
    return max(severities, key=_severity_rank)


def _chain_confidence(nodes: list[AttackChainNode]) -> float:
    if not nodes:
        return 0.0
    return min(1.0, sum(n.confidence for n in nodes) / len(nodes) * 0.9)


def _extract_host(url_or_file: str) -> str:
    """Extract hostname from URL or file path."""
    if not url_or_file:
        return ""
    if url_or_file.startswith("http"):
        from urllib.parse import urlparse
        return urlparse(url_or_file).netloc or ""
    # For file paths, use directory
    from pathlib import Path
    return str(Path(url_or_file).parent)


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def correlate_findings(findings: list[dict]) -> list[AttackChain]:
    """
    Convenience function: correlate findings into attack chains.
    Called by the scan orchestrator post-scan.

    findings: list of finding dicts (from normalize_finding().to_dict())
    Returns: list of AttackChain objects
    """
    correlator = AttackChainCorrelator()
    return correlator.correlate(findings)


def chains_to_summary(chains: list[AttackChain]) -> dict:
    """Convert chains list to summary dict for API/frontend consumption."""
    reporter = ChainReporter()
    return reporter.summary(chains)


def chains_to_text(chains: list[AttackChain]) -> str:
    """Generate plain-text chain report."""
    reporter = ChainReporter()
    return reporter.text_report(chains)
