"""
Quantum Protocol v3.5 — Enumerations, Constants, and Compliance Mappings

Covers:
  - NIST PQC (FIPS 203/204/205)
  - CNSA 2.0 timeline
  - ETSI QSC / PCI-DSS 4.0 / FIPS 140-3
  - Secrets & credential exposure categories
"""

from __future__ import annotations
from enum import Enum
from typing import Optional


# ────────────────────────────────────────────────────────────────────────────
# Risk & Severity
# ────────────────────────────────────────────────────────────────────────────

class RiskLevel(str, Enum):
    CRITICAL = "Critical"
    HIGH     = "High"
    MEDIUM   = "Medium"
    LOW      = "Low"
    INFO     = "Info"

    @property
    def numeric(self) -> float:
        return {"Critical": 9.5, "High": 7.5, "Medium": 5.0,
                "Low": 2.5, "Info": 0.5}[self.value]

    @property
    def sarif_level(self) -> str:
        return {"Critical": "error", "High": "error", "Medium": "warning",
                "Low": "note", "Info": "none"}[self.value]


class ConfidenceLevel(str, Enum):
    CONFIRMED  = "Confirmed"
    HIGH       = "High"
    MEDIUM     = "Medium"
    LOW        = "Low"
    TENTATIVE  = "Tentative"


# ────────────────────────────────────────────────────────────────────────────
# Algorithm Families  (crypto + secrets + credentials)
# ────────────────────────────────────────────────────────────────────────────

class AlgoFamily(str, Enum):
    # ── Asymmetric — quantum-broken ──────────────────────────────────
    RSA        = "RSA"
    RSA_OAEP   = "RSA-OAEP"
    ECC        = "ECC"
    ECDSA      = "ECDSA"
    ECDH       = "ECDH"
    DSA        = "DSA"
    DH         = "DH"
    ELGAMAL    = "ElGamal"
    X25519     = "X25519"
    ED25519    = "Ed25519"
    ED448      = "Ed448"
    X448       = "X448"

    # ── Symmetric ────────────────────────────────────────────────────
    AES_128    = "AES-128"
    AES_ECB    = "AES-ECB"
    DES        = "DES"
    TRIPLE_DES = "3DES"
    RC4        = "RC4"
    RC2        = "RC2"
    BLOWFISH   = "Blowfish"
    IDEA       = "IDEA"

    # ── Hashes ───────────────────────────────────────────────────────
    MD4        = "MD4"
    MD5        = "MD5"
    SHA1       = "SHA-1"
    RIPEMD160  = "RIPEMD-160"
    HMAC_MD5   = "HMAC-MD5"
    HMAC_SHA1  = "HMAC-SHA1"

    # ── Modes / misc crypto ──────────────────────────────────────────
    CBC_NO_HMAC = "CBC-without-HMAC"
    HARDCODED_KEY  = "Hardcoded-Key"
    HARDCODED_CERT = "Hardcoded-Certificate"
    WEAK_RANDOM    = "Weak-Random"
    CERT_ISSUE     = "Certificate-Issue"
    PROTOCOL       = "Protocol-Issue"
    AGILITY        = "Crypto-Agility"

    # ── Post-quantum (positive detection) ────────────────────────────
    ML_KEM     = "ML-KEM"
    ML_DSA     = "ML-DSA"
    SLH_DSA    = "SLH-DSA"
    XMSS       = "XMSS"

    # ══════════════════════════════════════════════════════════════════
    # ═══  SECRETS & CREDENTIALS ENGINE FAMILIES  ═════════════════════
    # ══════════════════════════════════════════════════════════════════

    # ── Cloud Providers ──────────────────────────────────────────────
    SECRET_AWS           = "AWS-Credential"
    SECRET_GCP           = "GCP-Credential"
    SECRET_AZURE         = "Azure-Credential"
    SECRET_DIGITALOCEAN  = "DigitalOcean-Credential"
    SECRET_ALIBABA       = "Alibaba-Cloud-Credential"
    SECRET_IBM            = "IBM-Cloud-Credential"
    SECRET_ORACLE         = "Oracle-Cloud-Credential"
    SECRET_HEROKU         = "Heroku-Credential"
    SECRET_CLOUDFLARE     = "Cloudflare-Credential"

    # ── Source Control & CI/CD ───────────────────────────────────────
    SECRET_GITHUB        = "GitHub-Token"
    SECRET_GITLAB        = "GitLab-Token"
    SECRET_BITBUCKET     = "Bitbucket-Credential"
    SECRET_CIRCLECI      = "CircleCI-Token"
    SECRET_TRAVIS        = "TravisCI-Token"
    SECRET_JENKINS       = "Jenkins-Credential"
    SECRET_NPM           = "NPM-Token"
    SECRET_PYPI          = "PyPI-Token"
    SECRET_DOCKER         = "Docker-Credential"
    SECRET_TERRAFORM      = "Terraform-Token"

    # ── Payment / Finance ────────────────────────────────────────────
    SECRET_STRIPE        = "Stripe-Key"
    SECRET_SQUARE        = "Square-Credential"
    SECRET_PAYPAL        = "PayPal-Credential"
    SECRET_BRAINTREE     = "Braintree-Credential"
    SECRET_PLAID         = "Plaid-Credential"
    SECRET_SHOPIFY       = "Shopify-Credential"

    # ── Communication / SaaS ─────────────────────────────────────────
    SECRET_SLACK         = "Slack-Token"
    SECRET_TWILIO        = "Twilio-Credential"
    SECRET_SENDGRID      = "SendGrid-Key"
    SECRET_MAILGUN       = "Mailgun-Key"
    SECRET_MAILCHIMP     = "Mailchimp-Key"
    SECRET_TELEGRAM      = "Telegram-Bot-Token"
    SECRET_DISCORD       = "Discord-Token"
    SECRET_FIREBASE      = "Firebase-Credential"

    # ── Monitoring / Analytics ───────────────────────────────────────
    SECRET_DATADOG       = "Datadog-Key"
    SECRET_NEWRELIC      = "NewRelic-Key"
    SECRET_SENTRY        = "Sentry-DSN"
    SECRET_PAGERDUTY     = "PagerDuty-Key"
    SECRET_SPLUNK        = "Splunk-Token"
    SECRET_GRAFANA       = "Grafana-Token"
    SECRET_ELASTIC       = "Elastic-Key"

    # ── Database & Cache Credentials ─────────────────────────────────
    SECRET_DB_CONNSTR    = "Database-Connection-String"
    SECRET_POSTGRES      = "PostgreSQL-Credential"
    SECRET_MYSQL         = "MySQL-Credential"
    SECRET_MONGODB       = "MongoDB-Credential"
    SECRET_REDIS         = "Redis-Credential"
    SECRET_MSSQL         = "MSSQL-Credential"
    SECRET_ELASTICSEARCH = "Elasticsearch-Credential"
    SECRET_CASSANDRA     = "Cassandra-Credential"

    # ── Auth / Tokens ────────────────────────────────────────────────
    SECRET_JWT           = "JWT-Token"
    SECRET_OAUTH         = "OAuth-Token"
    SECRET_BEARER        = "Bearer-Token"
    SECRET_SESSION       = "Session-Secret"
    SECRET_COOKIE        = "Cookie-Secret"
    SECRET_SAML          = "SAML-Credential"
    SECRET_LDAP          = "LDAP-Credential"

    # ── Infrastructure / SSH / TLS ───────────────────────────────────
    SECRET_SSH_KEY       = "SSH-Private-Key"
    SECRET_PGP_KEY       = "PGP-Private-Key"
    SECRET_SSL_KEY       = "SSL/TLS-Private-Key"
    SECRET_PKCS_FILE     = "PKCS-File"

    # ── API Keys (generic / multi-provider) ──────────────────────────
    SECRET_GENERIC_API   = "Generic-API-Key"
    SECRET_GENERIC_SECRET = "Generic-Secret"
    SECRET_GENERIC_PASSWORD = "Generic-Password"
    SECRET_GENERIC_TOKEN = "Generic-Token"
    SECRET_PRIVATE_KEY_VAR = "Private-Key-Variable"
    SECRET_ENTROPY       = "High-Entropy-String"

    # ── Messaging & Storage ──────────────────────────────────────────
    SECRET_RABBITMQ      = "RabbitMQ-Credential"
    SECRET_KAFKA         = "Kafka-Credential"
    SECRET_S3            = "S3-Credential"

    # ── Other SaaS ───────────────────────────────────────────────────
    SECRET_OPENAI        = "OpenAI-Key"
    SECRET_ANTHROPIC     = "Anthropic-Key"
    SECRET_MAPBOX        = "Mapbox-Token"
    SECRET_GOOGLE_MAPS   = "Google-Maps-Key"
    SECRET_ALGOLIA       = "Algolia-Key"
    SECRET_OKTA          = "Okta-Token"
    SECRET_AUTH0         = "Auth0-Credential"

    @property
    def is_quantum_broken(self) -> bool:
        return self in _QUANTUM_BROKEN_SET

    @property
    def is_classically_broken(self) -> bool:
        return self in _CLASSICALLY_BROKEN_SET

    @property
    def is_pqc_safe(self) -> bool:
        return self in _PQC_SAFE_SET

    @property
    def is_secret(self) -> bool:
        return self.value.startswith(("AWS-", "GCP-", "Azure-", "DigitalOcean-",
            "Alibaba-", "IBM-", "Oracle-", "Heroku-", "Cloudflare-",
            "GitHub-", "GitLab-", "Bitbucket-", "CircleCI-", "TravisCI-",
            "Jenkins-", "NPM-", "PyPI-", "Docker-", "Terraform-",
            "Stripe-", "Square-", "PayPal-", "Braintree-", "Plaid-", "Shopify-",
            "Slack-", "Twilio-", "SendGrid-", "Mailgun-", "Mailchimp-",
            "Telegram-", "Discord-", "Firebase-",
            "Datadog-", "NewRelic-", "Sentry-", "PagerDuty-", "Splunk-",
            "Grafana-", "Elastic-",
            "Database-", "PostgreSQL-", "MySQL-", "MongoDB-", "Redis-",
            "MSSQL-", "Elasticsearch-", "Cassandra-",
            "JWT-", "OAuth-", "Bearer-", "Session-", "Cookie-", "SAML-", "LDAP-",
            "SSH-Private", "PGP-Private", "SSL/TLS-", "PKCS-",
            "Generic-", "Private-Key-", "High-Entropy",
            "RabbitMQ-", "Kafka-", "S3-",
            "OpenAI-", "Anthropic-", "Mapbox-", "Google-Maps-", "Algolia-",
            "Okta-", "Auth0-",
        ))

    @property
    def is_symmetric(self) -> bool:
        return self in _SYMMETRIC_SET


_QUANTUM_BROKEN_SET = {
    AlgoFamily.RSA, AlgoFamily.RSA_OAEP, AlgoFamily.ECC, AlgoFamily.ECDSA,
    AlgoFamily.ECDH, AlgoFamily.DSA, AlgoFamily.DH, AlgoFamily.ELGAMAL,
    AlgoFamily.X25519, AlgoFamily.ED25519, AlgoFamily.ED448, AlgoFamily.X448,
}

_CLASSICALLY_BROKEN_SET = {
    AlgoFamily.MD4, AlgoFamily.MD5, AlgoFamily.SHA1, AlgoFamily.DES,
    AlgoFamily.RC4, AlgoFamily.RC2, AlgoFamily.BLOWFISH, AlgoFamily.IDEA,
    AlgoFamily.RIPEMD160, AlgoFamily.HMAC_MD5, AlgoFamily.HMAC_SHA1,
    AlgoFamily.AES_ECB, AlgoFamily.TRIPLE_DES, AlgoFamily.WEAK_RANDOM,
}

_PQC_SAFE_SET = {
    AlgoFamily.ML_KEM, AlgoFamily.ML_DSA, AlgoFamily.SLH_DSA, AlgoFamily.XMSS,
}

_SYMMETRIC_SET = {
    AlgoFamily.AES_128, AlgoFamily.AES_ECB, AlgoFamily.DES, AlgoFamily.TRIPLE_DES,
    AlgoFamily.RC4, AlgoFamily.RC2, AlgoFamily.BLOWFISH, AlgoFamily.IDEA,
}


# ────────────────────────────────────────────────────────────────────────────
# Compliance Frameworks
# ────────────────────────────────────────────────────────────────────────────

class ComplianceFramework(str, Enum):
    NIST_PQC       = "NIST-PQC"
    CNSA_2_0       = "CNSA-2.0"
    FIPS_140_3     = "FIPS-140-3"
    PCI_DSS_4      = "PCI-DSS-4.0"
    ETSI_QSC       = "ETSI-QSC"
    HIPAA          = "HIPAA"
    SOC2           = "SOC-2"
    NIST_800_131A  = "NIST-800-131A"
    OWASP_TOP10    = "OWASP-Top-10"
    CIS_BENCHMARK  = "CIS-Benchmark"
    GDPR           = "GDPR"


class ScanMode(str, Enum):
    FULL       = "full"
    QUICK      = "quick"
    QUANTUM    = "quantum"
    SECRETS    = "secrets"       # secrets-only mode
    COMPLIANCE = "compliance"
    DIFF       = "diff"
    # v4.0 OWASP modes
    OWASP      = "owasp"        # All OWASP Top 10 analyzers
    FRONTEND   = "frontend"     # Frontend JS analysis only
    RECON      = "recon"        # Bug bounty recon (endpoints, tech fingerprint)
    CLOUD      = "cloud"        # Cloud/IaC misconfigurations
    API        = "api"          # API security patterns


class OutputFormat(str, Enum):
    JSON    = "json"
    SARIF   = "sarif"
    CSV     = "csv"
    HTML    = "html"
    SUMMARY = "summary"


# ────────────────────────────────────────────────────────────────────────────
# PQC Replacement Map
# ────────────────────────────────────────────────────────────────────────────

PQC_REPLACEMENTS: dict[str, dict] = {
    AlgoFamily.RSA: {
        "kem": "ML-KEM-768 / ML-KEM-1024 (FIPS 203)",
        "sign": "ML-DSA-65 / ML-DSA-87 (FIPS 204)",
        "hash_sign": "SLH-DSA-SHA2-128s (FIPS 205)",
        "hybrid_kem": "X25519+ML-KEM-768 (hybrid, RFC 9180 HPKE)",
        "library": "liboqs >= 0.11 | cryptography >= 44.0 | wolfSSL 5.7+",
        "notes": "RSA is fully broken by Shor's algorithm regardless of key size.",
    },
    AlgoFamily.RSA_OAEP: {
        "kem": "ML-KEM-768 (FIPS 203)",
        "notes": "RSA-OAEP padding is better but RSA itself is quantum-broken.",
    },
    AlgoFamily.ECC: {
        "kem": "ML-KEM-768 (FIPS 203)",
        "sign": "ML-DSA-65 (FIPS 204) or SLH-DSA-SHA2-128s (FIPS 205)",
        "hybrid_kem": "X25519+ML-KEM-768",
        "library": "liboqs >= 0.11 | BoringSSL PQ | OpenSSL 3.5+",
        "notes": "All ECC curves are vulnerable to Shor's algorithm.",
    },
    AlgoFamily.ECDSA: {
        "sign": "ML-DSA-65 (FIPS 204)",
        "notes": "ECDSA on any curve is quantum-broken.",
    },
    AlgoFamily.ECDH: {
        "kem": "ML-KEM-768 (FIPS 203)",
        "hybrid_kem": "X25519+ML-KEM-768 (already in Chrome 131+)",
        "notes": "ECDH key exchange is quantum-broken.",
    },
    AlgoFamily.DSA: {
        "sign": "ML-DSA-65 (FIPS 204)",
        "notes": "DSA is deprecated by NIST AND quantum-broken.",
    },
    AlgoFamily.DH: {
        "kem": "ML-KEM-768 / ML-KEM-1024 (FIPS 203)",
        "notes": "DH is broken by Shor. Use ML-KEM hybrid for TLS/IPsec.",
    },
    AlgoFamily.X25519: {
        "kem": "ML-KEM-768 (FIPS 203)",
        "hybrid_kem": "X25519+ML-KEM-768",
        "notes": "X25519 is quantum-broken.",
    },
    AlgoFamily.ED25519: {
        "sign": "ML-DSA-65 (FIPS 204)",
        "notes": "Ed25519 is quantum-broken despite being modern.",
    },
    AlgoFamily.ED448: {"sign": "ML-DSA-87 (FIPS 204)", "notes": "Ed448 is quantum-broken."},
    AlgoFamily.X448:  {"kem": "ML-KEM-1024 (FIPS 203)", "notes": "X448 is quantum-broken."},
    AlgoFamily.MD5: {
        "replacement": "SHA-256 minimum; SHA3-256 for new designs",
        "notes": "MD5 is collision-broken.",
    },
    AlgoFamily.SHA1: {
        "replacement": "SHA-256 or SHA3-256",
        "notes": "SHA-1 is collision-broken (SHAttered).",
    },
    AlgoFamily.DES: {"replacement": "AES-256-GCM", "notes": "DES is classically broken."},
    AlgoFamily.TRIPLE_DES: {"replacement": "AES-256-GCM", "notes": "3DES deprecated by NIST."},
    AlgoFamily.RC4: {"replacement": "ChaCha20-Poly1305 or AES-256-GCM", "notes": "RC4 is broken."},
    AlgoFamily.AES_ECB: {"replacement": "AES-256-GCM (AEAD)", "notes": "ECB leaks patterns."},
    AlgoFamily.AES_128: {"replacement": "AES-256-GCM", "notes": "Only 64-bit quantum security."},
    AlgoFamily.HARDCODED_KEY: {
        "replacement": "AWS KMS / HashiCorp Vault / Azure Key Vault / GCP KMS",
        "notes": "Hardcoded keys are exposed in source control and binaries.",
    },
    AlgoFamily.WEAK_RANDOM: {
        "replacement": "os.urandom() / secrets (Python), crypto.randomBytes (Node), SecureRandom (Java)",
        "notes": "Non-cryptographic RNGs must never be used for keys/tokens.",
    },
}

# Secrets remediation map
SECRETS_REMEDIATION: dict[str, dict] = {
    # Cloud
    "AWS": {"action": "Rotate via AWS IAM console → deactivate old key → use IAM roles/instance profiles instead", "vault": "AWS Secrets Manager or SSM Parameter Store"},
    "GCP": {"action": "Revoke in GCP Console → IAM → Service Accounts. Use Workload Identity.", "vault": "GCP Secret Manager"},
    "Azure": {"action": "Rotate in Azure Portal → App Registration → Certificates & Secrets.", "vault": "Azure Key Vault"},
    # Payment
    "Stripe": {"action": "Roll key at dashboard.stripe.com/apikeys immediately.", "vault": "Environment variable or Vault"},
    "PayPal": {"action": "Generate new credentials in PayPal Developer portal.", "vault": "Secrets manager"},
    # Source Control
    "GitHub": {"action": "Revoke at github.com/settings/tokens. Token may already be auto-revoked.", "vault": "GitHub Secrets (Actions) or Vault"},
    "GitLab": {"action": "Revoke at gitlab.com/-/user_settings/personal_access_tokens.", "vault": "GitLab CI/CD Variables (masked)"},
    # Database
    "Database": {"action": "Rotate credentials immediately. Check access logs for unauthorised use.", "vault": "HashiCorp Vault dynamic secrets or cloud-native secret manager"},
    # Generic
    "Generic": {"action": "Identify the service, rotate the credential, audit usage logs.", "vault": "Any secrets manager (Vault, AWS SM, Doppler, 1Password CLI)"},
}


# ────────────────────────────────────────────────────────────────────────────
# Language / File Extension Map
# ────────────────────────────────────────────────────────────────────────────

LANGUAGE_MAP: dict[str, list[str]] = {
    "python":       [".py", ".pyw", ".pyi"],
    "javascript":   [".js", ".mjs", ".cjs", ".jsx"],
    "typescript":   [".ts", ".tsx", ".mts", ".cts"],
    "java":         [".java"],
    "kotlin":       [".kt", ".kts"],
    "go":           [".go"],
    "cpp":          [".cpp", ".cc", ".cxx", ".c", ".h", ".hpp", ".hxx"],
    "rust":         [".rs"],
    "ruby":         [".rb", ".rake", ".gemspec"],
    "php":          [".php", ".phtml"],
    "swift":        [".swift"],
    "csharp":       [".cs"],
    "scala":        [".scala", ".sc"],
    "dart":         [".dart"],
    "elixir":       [".ex", ".exs"],
    "perl":         [".pl", ".pm"],
    "groovy":       [".groovy", ".gvy", ".gradle"],
    "config":       [".yaml", ".yml", ".toml", ".ini", ".env", ".conf", ".cfg",
                     ".json", ".xml", ".properties", ".hcl", ".tf"],
    "cert":         [".pem", ".crt", ".cer", ".der", ".p12", ".pfx", ".p7b"],
    "dockerfile":   ["dockerfile", ".dockerfile", "containerfile"],
    "shell":        [".sh", ".bash", ".zsh", ".fish"],
    "terraform":    [".tf", ".tfvars"],
    "protobuf":     [".proto"],
    "env":          [".env", ".env.local", ".env.dev", ".env.staging",
                     ".env.production", ".env.test"],
}

SKIP_DIRS: set[str] = {
    ".git", ".svn", ".hg", "node_modules", "__pycache__", ".pytest_cache",
    "venv", ".venv", "env", ".tox", ".nox",
    "dist", "build", "target", "out", "bin", "obj",
    ".gradle", ".idea", ".vscode",
    "vendor", "third_party", "3rdparty", "external",
    ".terraform", ".serverless",
    "coverage", ".nyc_output", "htmlcov",
}

MAX_FILE_SIZE_BYTES: int = 10 * 1024 * 1024

# ────────────────────────────────────────────────────────────────────────────
# Compliance Mapping
# ────────────────────────────────────────────────────────────────────────────

COMPLIANCE_VIOLATIONS: dict[AlgoFamily, list[ComplianceFramework]] = {
    AlgoFamily.RSA:        [ComplianceFramework.CNSA_2_0, ComplianceFramework.NIST_PQC],
    AlgoFamily.ECC:        [ComplianceFramework.CNSA_2_0, ComplianceFramework.NIST_PQC],
    AlgoFamily.ECDSA:      [ComplianceFramework.CNSA_2_0, ComplianceFramework.NIST_PQC],
    AlgoFamily.ECDH:       [ComplianceFramework.CNSA_2_0, ComplianceFramework.NIST_PQC],
    AlgoFamily.DSA:        [ComplianceFramework.CNSA_2_0, ComplianceFramework.NIST_PQC, ComplianceFramework.NIST_800_131A],
    AlgoFamily.DH:         [ComplianceFramework.CNSA_2_0, ComplianceFramework.NIST_PQC],
    AlgoFamily.MD5:        [ComplianceFramework.FIPS_140_3, ComplianceFramework.PCI_DSS_4, ComplianceFramework.NIST_800_131A],
    AlgoFamily.SHA1:       [ComplianceFramework.FIPS_140_3, ComplianceFramework.NIST_800_131A],
    AlgoFamily.DES:        [ComplianceFramework.FIPS_140_3, ComplianceFramework.PCI_DSS_4, ComplianceFramework.NIST_800_131A],
    AlgoFamily.TRIPLE_DES: [ComplianceFramework.FIPS_140_3, ComplianceFramework.PCI_DSS_4],
    AlgoFamily.RC4:        [ComplianceFramework.PCI_DSS_4, ComplianceFramework.FIPS_140_3],
    AlgoFamily.AES_ECB:    [ComplianceFramework.FIPS_140_3],
    AlgoFamily.HARDCODED_KEY: [ComplianceFramework.PCI_DSS_4, ComplianceFramework.SOC2, ComplianceFramework.HIPAA],
    AlgoFamily.WEAK_RANDOM:[ComplianceFramework.FIPS_140_3, ComplianceFramework.PCI_DSS_4],
    # Secrets-specific compliance
    AlgoFamily.SECRET_AWS:  [ComplianceFramework.PCI_DSS_4, ComplianceFramework.SOC2, ComplianceFramework.HIPAA, ComplianceFramework.OWASP_TOP10, ComplianceFramework.CIS_BENCHMARK],
    AlgoFamily.SECRET_GCP:  [ComplianceFramework.PCI_DSS_4, ComplianceFramework.SOC2, ComplianceFramework.OWASP_TOP10],
    AlgoFamily.SECRET_AZURE:[ComplianceFramework.PCI_DSS_4, ComplianceFramework.SOC2, ComplianceFramework.OWASP_TOP10],
    AlgoFamily.SECRET_STRIPE:[ComplianceFramework.PCI_DSS_4, ComplianceFramework.SOC2, ComplianceFramework.OWASP_TOP10],
    AlgoFamily.SECRET_DB_CONNSTR: [ComplianceFramework.PCI_DSS_4, ComplianceFramework.HIPAA, ComplianceFramework.SOC2, ComplianceFramework.OWASP_TOP10, ComplianceFramework.GDPR],
    AlgoFamily.SECRET_POSTGRES:   [ComplianceFramework.PCI_DSS_4, ComplianceFramework.HIPAA, ComplianceFramework.OWASP_TOP10, ComplianceFramework.GDPR],
    AlgoFamily.SECRET_MYSQL:      [ComplianceFramework.PCI_DSS_4, ComplianceFramework.HIPAA, ComplianceFramework.OWASP_TOP10, ComplianceFramework.GDPR],
    AlgoFamily.SECRET_MONGODB:    [ComplianceFramework.PCI_DSS_4, ComplianceFramework.HIPAA, ComplianceFramework.OWASP_TOP10, ComplianceFramework.GDPR],
    AlgoFamily.SECRET_REDIS:      [ComplianceFramework.OWASP_TOP10],
    AlgoFamily.SECRET_JWT:        [ComplianceFramework.OWASP_TOP10, ComplianceFramework.SOC2],
    AlgoFamily.SECRET_SSH_KEY:    [ComplianceFramework.PCI_DSS_4, ComplianceFramework.SOC2, ComplianceFramework.CIS_BENCHMARK],
    AlgoFamily.SECRET_GENERIC_PASSWORD: [ComplianceFramework.OWASP_TOP10, ComplianceFramework.PCI_DSS_4],
    AlgoFamily.SECRET_GENERIC_API:      [ComplianceFramework.OWASP_TOP10, ComplianceFramework.SOC2],
    AlgoFamily.SECRET_GENERIC_SECRET:   [ComplianceFramework.OWASP_TOP10, ComplianceFramework.SOC2],
}
