"""
Quantum Protocol v4.0 — Cloud & Infrastructure Security Scanner

Detects:
  - AWS misconfigurations (S3 public access, IAM wildcards, open security groups)
  - Terraform/IaC issues (unencrypted resources, public instances, overly-broad policies)
  - Kubernetes/Docker (running as root, privileged mode, host networking, missing security context)
  - Dockerfile security (secrets in ARGs, missing USER, COPY leaks)
  - GCP/Azure misconfigurations
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from pathlib import Path

@dataclass
class CloudFinding:
    id: str
    file: str
    line_number: int
    severity: str
    title: str
    description: str
    matched_content: str
    category: str
    subcategory: str  # aws | gcp | azure | terraform | kubernetes | docker
    cwe: str
    remediation: str
    confidence: float
    tags: list[str] = field(default_factory=list)

@dataclass
class CloudPattern:
    id: str
    pattern: str
    severity: str
    title: str
    description: str
    cwe: str
    remediation: str
    confidence: float
    subcategory: str
    tags: tuple[str, ...] = ()

def _build_rules() -> list[CloudPattern]:
    rules: list[CloudPattern] = []
    def _add(id_, pat, sev, title, desc, cwe, rem, conf, sub, tags=()):
        rules.append(CloudPattern(id_, pat, sev, title, desc, cwe, rem, conf, sub, tags))

    # ── AWS S3 ────────────────────────────────────────────────────
    _add("CL-001", r""""Principal"\s*:\s*"\*".*?(?:s3|S3|bucket)""",
         "Critical", "S3 Bucket Policy — Public Access (Principal: *)",
         "S3 bucket policy allows access from any principal. All data is publicly accessible.",
         "CWE-732", "Remove Principal: *. Use specific IAM identities. Enable S3 Block Public Access.",
         0.90, "aws", ("s3", "public-access"))

    _add("CL-002", r"""(?:block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false""",
         "Critical", "S3 Public Access Block Disabled",
         "S3 public access block explicitly disabled. Buckets may be inadvertently made public.",
         "CWE-732", "Enable all four S3 public access block settings: block_public_acls, block_public_policy, ignore_public_acls, restrict_public_buckets.",
         0.90, "terraform", ("s3", "public-block"))

    # ── AWS IAM ───────────────────────────────────────────────────
    _add("CL-010", r""""Effect"\s*:\s*"Allow"[^}]*"Action"\s*:\s*"\*"[^}]*"Resource"\s*:\s*"\*\"""",
         "Critical", "IAM Policy — Full Admin Access (*:*)",
         "IAM policy grants Allow on all Actions for all Resources. This is full administrator access.",
         "CWE-250", "Follow least-privilege. Scope Action and Resource to specific services and ARNs.",
         0.95, "aws", ("iam", "admin"))

    _add("CL-011", r"""(?:iam_policy|aws_iam)\s*(?:=|{)[^}]*(?:Action\s*=\s*\[?\s*"\*"|actions?\s*=\s*\[?\s*"\*")""",
         "Critical", "Terraform IAM Wildcard Action",
         "Terraform IAM policy with Action: * grants access to all AWS services.",
         "CWE-250", "Specify exact actions needed: [\"s3:GetObject\", \"s3:PutObject\"]",
         0.90, "terraform", ("iam", "wildcard"))

    # ── AWS Security Groups ───────────────────────────────────────
    _add("CL-020", r"""(?:cidr_blocks|CidrIp)\s*(?:=|:)\s*\[?\s*["']0\.0\.0\.0/0["']""",
         "High", "Security Group — Open to Internet (0.0.0.0/0)",
         "Ingress rule allows traffic from all IPs. Sensitive ports should not be world-accessible.",
         "CWE-284", "Restrict CIDR blocks to specific IP ranges. Use VPN for admin access.",
         0.80, "aws", ("security-group", "open"))

    _add("CL-021", r"""(?:from_port|FromPort)\s*(?:=|:)\s*(?:22|3306|5432|27017|6379|9200|2379)\b[^}]*?0\.0\.0\.0/0""",
         "Critical", "Sensitive Port Open to Internet",
         "SSH (22), DB (3306/5432/27017/6379), or ES (9200) port open to 0.0.0.0/0.",
         "CWE-284", "Never expose database or admin ports to the internet. Use bastion host or VPN.",
         0.85, "aws", ("security-group", "sensitive-port"))

    # ── AWS RDS / Databases ───────────────────────────────────────
    _add("CL-025", r"""publicly_accessible\s*=\s*true""",
         "Critical", "RDS Instance Publicly Accessible",
         "Database instance is publicly accessible from the internet.",
         "CWE-284", "Set publicly_accessible=false. Use private subnets and VPC peering.",
         0.90, "terraform", ("rds", "public"))

    _add("CL-026", r"""(?:storage_encrypted|encryption_at_rest)\s*=\s*false""",
         "High", "Database Encryption at Rest Disabled",
         "Database or storage resource does not encrypt data at rest.",
         "CWE-311", "Enable storage_encrypted=true. Use KMS customer-managed keys.",
         0.85, "terraform", ("encryption", "at-rest"))

    # ── Terraform General ─────────────────────────────────────────
    _add("CL-030", r"""associate_public_ip_address\s*=\s*true""",
         "High", "EC2 Instance with Public IP",
         "EC2 instance configured with public IP address. Increases attack surface.",
         "CWE-284", "Use private subnets with NAT gateway. Remove public IP unless required.",
         0.70, "terraform", ("ec2", "public-ip"))

    _add("CL-031", r"""(?:kms_key_id|kms_master_key_id)\s*=\s*["']["']""",
         "High", "Missing KMS Key for Encryption",
         "KMS key field is empty. Resource may use default AWS-managed encryption or none.",
         "CWE-311", "Specify a customer-managed KMS key for encryption.",
         0.70, "terraform", ("kms", "missing"))

    # ── Kubernetes ────────────────────────────────────────────────
    _add("CL-040", r"""runAsUser\s*:\s*0\b""",
         "High", "Kubernetes Container Running as Root (UID 0)",
         "Container configured to run as root. Compromised container = root on host if breakout occurs.",
         "CWE-250", "Set runAsUser to non-root UID (1000+). Set runAsNonRoot: true.",
         0.85, "kubernetes", ("k8s", "root"))

    _add("CL-041", r"""privileged\s*:\s*true""",
         "Critical", "Kubernetes Privileged Container",
         "Container runs in privileged mode with full host kernel access. Trivial container escape.",
         "CWE-250", "Never use privileged mode. Use specific Linux capabilities instead.",
         0.95, "kubernetes", ("k8s", "privileged"))

    _add("CL-042", r"""hostNetwork\s*:\s*true""",
         "High", "Kubernetes Host Network Enabled",
         "Pod shares the host's network namespace. Can access all host network services.",
         "CWE-250", "Avoid hostNetwork unless absolutely necessary. Use NetworkPolicies.",
         0.85, "kubernetes", ("k8s", "host-network"))

    _add("CL-043", r"""hostPID\s*:\s*true""",
         "High", "Kubernetes Host PID Namespace",
         "Pod can see and interact with all host processes.",
         "CWE-250", "Remove hostPID: true. Isolate containers properly.",
         0.85, "kubernetes", ("k8s", "host-pid"))

    _add("CL-044", r"""(?:readOnlyRootFilesystem)\s*:\s*false""",
         "Medium", "Kubernetes Writable Root Filesystem",
         "Container has writable filesystem. Attackers can modify binaries if compromised.",
         "CWE-732", "Set readOnlyRootFilesystem: true. Use emptyDir for writable paths.",
         0.70, "kubernetes", ("k8s", "filesystem"))

    _add("CL-045", r"""(?:name|key)\s*:\s*(?:DB_PASSWORD|API_KEY|SECRET_KEY|AWS_SECRET)\s*\n\s*value\s*:""",
         "Critical", "K8s Secret in Environment Variable (Plain YAML)",
         "Sensitive value in plain YAML spec instead of Kubernetes Secret or Vault reference.",
         "CWE-312", "Use Kubernetes Secrets, Sealed Secrets, or external Vault. Never put secrets in plain YAML.",
         0.85, "kubernetes", ("k8s", "secrets"))

    # ── Docker ────────────────────────────────────────────────────
    _add("CL-050", r"""^FROM\s+\S+\s*(?:$|\n(?!.*^USER\s).*$)""",
         "High", "Dockerfile Missing USER Directive",
         "Dockerfile has no USER directive. Container will run as root by default.",
         "CWE-250", "Add USER directive: RUN adduser --system app && USER app",
         0.60, "docker", ("docker", "user"))

    _add("CL-051", r"""^ARG\s+(?:.*?(?:PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL|API_KEY))\s*=""",
         "Critical", "Docker Secrets in Build ARG",
         "Secrets passed via ARG persist in image layers. Anyone with image access can extract them.",
         "CWE-312", "Use --mount=type=secret for build-time secrets. Never pass secrets as ARG.",
         0.90, "docker", ("docker", "arg-secret"))

    _add("CL-052", r"""^COPY\s+\.\s+\.""",
         "High", "Dockerfile COPY . . Without .dockerignore",
         "Copying entire context may include .env, .git, credentials, and other sensitive files.",
         "CWE-200", "Use .dockerignore to exclude .env, .git, node_modules, secrets. Copy only needed files.",
         0.70, "docker", ("docker", "copy"))

    _add("CL-053", r"""FROM\s+\S+:latest\b""",
         "Medium", "Docker Image Using 'latest' Tag",
         "Using :latest tag leads to unpredictable builds. Pin to specific versions.",
         "CWE-829", "Pin image versions: FROM node:20-alpine instead of FROM node:latest",
         0.65, "docker", ("docker", "latest"))

    # ── GCP ───────────────────────────────────────────────────────
    _add("CL-060", r"""allUsers|allAuthenticatedUsers""",
         "Critical", "GCP Resource Public Access (allUsers/allAuthenticatedUsers)",
         "GCP resource accessible to allUsers or allAuthenticatedUsers. Data is publicly exposed.",
         "CWE-732", "Remove allUsers/allAuthenticatedUsers bindings. Use specific IAM members.",
         0.85, "gcp", ("gcp", "public"))

    # ── Azure ─────────────────────────────────────────────────────
    _add("CL-070", r"""(?:network_access|public_network_access)\s*[:=]\s*["']?(?:Enabled|enabled|true)""",
         "High", "Azure Resource Public Network Access Enabled",
         "Azure resource has public network access enabled. Should use private endpoints.",
         "CWE-284", "Set public_network_access=Disabled. Use Private Endpoints for access.",
         0.75, "azure", ("azure", "public-access"))

    return rules

ALL_CLOUD_RULES = _build_rules()
COMPILED_CLOUD_RULES = [(re.compile(r.pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL), r) for r in ALL_CLOUD_RULES]
SKIP_DIRS = {"node_modules", ".git", ".next", "dist", "build", "__pycache__", ".venv", "venv", "vendor", ".cache"}
SCAN_EXTENSIONS = {".py", ".js", ".ts", ".tf", ".yaml", ".yml", ".json", ".toml", ".conf", ".dockerfile", ".hcl", ".tfvars"}
SCAN_FILENAMES = {"Dockerfile", "docker-compose.yml", "docker-compose.yaml", "Vagrantfile", "kubernetes.yaml", "deployment.yaml", "pod.yaml"}

def scan_cloud_file(content: str, filepath: str, base_path: str = "") -> list[CloudFinding]:
    findings: list[CloudFinding] = []
    relative = filepath.replace(base_path, "").lstrip("/\\") if base_path else filepath
    seen: set[str] = set()
    for compiled_re, rule in COMPILED_CLOUD_RULES:
        for match in compiled_re.finditer(content):
            line_num = content.count("\n", 0, match.start()) + 1
            key = f"{rule.id}:{line_num}"
            if key in seen: continue
            seen.add(key)
            findings.append(CloudFinding(
                id=f"CL-{relative}:{line_num}:{rule.id}", file=relative, line_number=line_num,
                severity=rule.severity, title=rule.title, description=rule.description,
                matched_content=match.group(0).strip()[:200], category="Cloud/IaC Security",
                subcategory=rule.subcategory, cwe=rule.cwe, remediation=rule.remediation,
                confidence=rule.confidence, tags=list(rule.tags),
            ))
    return findings

def scan_cloud_directory(root: str, max_files: int = 50_000) -> list[CloudFinding]:
    all_findings: list[CloudFinding] = []
    root_path = Path(root)
    scanned = 0
    for fpath in root_path.rglob("*"):
        if scanned >= max_files: break
        if fpath.is_dir(): continue
        if any(s in fpath.parts for s in SKIP_DIRS): continue
        if fpath.suffix.lower() not in SCAN_EXTENSIONS and fpath.name not in SCAN_FILENAMES: continue
        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
            if len(content) > 5_000_000: continue
            all_findings.extend(scan_cloud_file(content, str(fpath), str(root_path)))
            scanned += 1
        except (OSError, PermissionError): continue
    return all_findings
