"""
Quantum Protocol v4.0 — Enumerations, Constants, and Compliance Mappings
Full OWASP Top 10:2025, secrets, crypto, cloud/IaC, API, frontend, recon.
"""
from __future__ import annotations
from enum import Enum
from typing import Optional


class RiskLevel(str, Enum):
    CRITICAL = "Critical"
    HIGH     = "High"
    MEDIUM   = "Medium"
    LOW      = "Low"
    INFO     = "Info"

    @property
    def numeric(self) -> float:
        return {"Critical": 9.5, "High": 7.5, "Medium": 5.0, "Low": 2.5, "Info": 0.5}[self.value]

    @property
    def sarif_level(self) -> str:
        return {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note", "Info": "none"}[self.value]


class ConfidenceLevel(str, Enum):
    CONFIRMED = "Confirmed"; HIGH = "High"; MEDIUM = "Medium"; LOW = "Low"; TENTATIVE = "Tentative"


class OwaspCategory(str, Enum):
    A01_BROKEN_ACCESS      = "A01:2025-Broken Access Control"
    A02_SECURITY_MISCONFIG = "A02:2025-Security Misconfiguration"
    A03_SUPPLY_CHAIN       = "A03:2025-Software Supply Chain Failures"
    A04_CRYPTO_FAILURES    = "A04:2025-Cryptographic Failures"
    A05_INJECTION          = "A05:2025-Injection"
    A06_INSECURE_DESIGN    = "A06:2025-Insecure Design"
    A07_AUTH_FAILURES      = "A07:2025-Identification and Authentication Failures"
    A08_INTEGRITY_FAILURES = "A08:2025-Software and Data Integrity Failures"
    A09_LOGGING_FAILURES   = "A09:2025-Security Logging and Alerting Failures"
    A10_EXCEPTION_HANDLING = "A10:2025-Mishandling of Exceptional Conditions"


class VulnCategory(str, Enum):
    CRYPTO = "Cryptographic"; SECRET = "Secret/Credential"; INJECTION = "Injection"
    ACCESS_CONTROL = "Access Control"; MISCONFIG = "Security Misconfiguration"
    AUTH = "Authentication"; SUPPLY_CHAIN = "Supply Chain"; INTEGRITY = "Data Integrity"
    LOGGING = "Logging/Monitoring"; EXCEPTION = "Exception Handling"
    INSECURE_DESIGN = "Insecure Design"; API_SECURITY = "API Security"
    CLOUD = "Cloud/Infrastructure"; DATA_EXPOSURE = "Sensitive Data Exposure"
    FRONTEND = "Frontend/Client-Side"; RECON = "Reconnaissance Intel"


class AlgoFamily(str, Enum):
    # Asymmetric
    RSA = "RSA"; RSA_OAEP = "RSA-OAEP"; ECC = "ECC"; ECDSA = "ECDSA"
    ECDH = "ECDH"; DSA = "DSA"; DH = "DH"; ELGAMAL = "ElGamal"
    X25519 = "X25519"; ED25519 = "Ed25519"; ED448 = "Ed448"; X448 = "X448"
    # Symmetric
    AES_128 = "AES-128"; AES_ECB = "AES-ECB"; DES = "DES"; TRIPLE_DES = "3DES"
    RC4 = "RC4"; RC2 = "RC2"; BLOWFISH = "Blowfish"; IDEA = "IDEA"
    # Hashes
    MD4 = "MD4"; MD5 = "MD5"; SHA1 = "SHA-1"; RIPEMD160 = "RIPEMD-160"
    HMAC_MD5 = "HMAC-MD5"; HMAC_SHA1 = "HMAC-SHA1"
    # Modes
    CBC_NO_HMAC = "CBC-without-HMAC"; HARDCODED_KEY = "Hardcoded-Key"
    HARDCODED_CERT = "Hardcoded-Certificate"; WEAK_RANDOM = "Weak-Random"
    CERT_ISSUE = "Certificate-Issue"; PROTOCOL = "Protocol-Issue"; AGILITY = "Crypto-Agility"
    # PQC
    ML_KEM = "ML-KEM"; ML_DSA = "ML-DSA"; SLH_DSA = "SLH-DSA"; XMSS = "XMSS"
    # PQSI — PQC detection signals
    PQC_KYBER = "PQC-Kyber-Detected"; PQC_DILITHIUM = "PQC-Dilithium-Detected"
    PQC_FALCON = "PQC-Falcon-Detected"; PQC_SPHINCS = "PQC-SPHINCS+-Detected"
    PQC_BIKE = "PQC-BIKE-Detected"; PQC_MCELIECE = "PQC-McEliece-Detected"
    PQC_HYBRID = "PQC-Hybrid-Deployed"
    # PQSI — HNDL activity
    HNDL_HARVEST = "HNDL-Harvest-Activity"; HNDL_STORAGE = "HNDL-Storage-Activity"
    # PQSI — Quantum recon
    QUANTUM_RECON = "Quantum-Recon-Activity"; CRYPTO_ENUMERATION = "Crypto-Enumeration-Engine"
    # PQSI — Adoption signals
    PQC_ADOPTION = "PQC-Adoption-Signal"; CRYPTO_AGILITY_SIGNAL = "Crypto-Agility-Signal"
    # Secrets
    SECRET_AWS = "AWS-Credential"; SECRET_GCP = "GCP-Credential"; SECRET_AZURE = "Azure-Credential"
    SECRET_DIGITALOCEAN = "DigitalOcean-Credential"; SECRET_ALIBABA = "Alibaba-Cloud-Credential"
    SECRET_IBM = "IBM-Cloud-Credential"; SECRET_ORACLE = "Oracle-Cloud-Credential"
    SECRET_HEROKU = "Heroku-Credential"; SECRET_CLOUDFLARE = "Cloudflare-Credential"
    SECRET_GITHUB = "GitHub-Token"; SECRET_GITLAB = "GitLab-Token"
    SECRET_BITBUCKET = "Bitbucket-Credential"; SECRET_CIRCLECI = "CircleCI-Token"
    SECRET_TRAVIS = "TravisCI-Token"; SECRET_JENKINS = "Jenkins-Credential"
    SECRET_NPM = "NPM-Token"; SECRET_PYPI = "PyPI-Token"
    SECRET_DOCKER = "Docker-Credential"; SECRET_TERRAFORM = "Terraform-Token"
    SECRET_STRIPE = "Stripe-Key"; SECRET_SQUARE = "Square-Credential"
    SECRET_PAYPAL = "PayPal-Credential"; SECRET_BRAINTREE = "Braintree-Credential"
    SECRET_PLAID = "Plaid-Credential"; SECRET_SHOPIFY = "Shopify-Credential"
    SECRET_SLACK = "Slack-Token"; SECRET_TWILIO = "Twilio-Credential"
    SECRET_SENDGRID = "SendGrid-Key"; SECRET_MAILGUN = "Mailgun-Key"
    SECRET_MAILCHIMP = "Mailchimp-Key"; SECRET_TELEGRAM = "Telegram-Bot-Token"
    SECRET_DISCORD = "Discord-Token"; SECRET_FIREBASE = "Firebase-Credential"
    SECRET_DATADOG = "Datadog-Key"; SECRET_NEWRELIC = "NewRelic-Key"
    SECRET_SENTRY = "Sentry-DSN"; SECRET_PAGERDUTY = "PagerDuty-Key"
    SECRET_SPLUNK = "Splunk-Token"; SECRET_GRAFANA = "Grafana-Token"; SECRET_ELASTIC = "Elastic-Key"
    SECRET_DB_CONNSTR = "Database-Connection-String"; SECRET_POSTGRES = "PostgreSQL-Credential"
    SECRET_MYSQL = "MySQL-Credential"; SECRET_MONGODB = "MongoDB-Credential"
    SECRET_REDIS = "Redis-Credential"; SECRET_MSSQL = "MSSQL-Credential"
    SECRET_ELASTICSEARCH = "Elasticsearch-Credential"; SECRET_CASSANDRA = "Cassandra-Credential"
    SECRET_JWT = "JWT-Token"; SECRET_OAUTH = "OAuth-Token"; SECRET_BEARER = "Bearer-Token"
    SECRET_SESSION = "Session-Secret"; SECRET_COOKIE = "Cookie-Secret"
    SECRET_SAML = "SAML-Credential"; SECRET_LDAP = "LDAP-Credential"
    SECRET_SSH_KEY = "SSH-Private-Key"; SECRET_PGP_KEY = "PGP-Private-Key"
    SECRET_SSL_KEY = "SSL/TLS-Private-Key"; SECRET_PKCS_FILE = "PKCS-File"
    SECRET_GENERIC_API = "Generic-API-Key"; SECRET_GENERIC_SECRET = "Generic-Secret"
    SECRET_GENERIC_PASSWORD = "Generic-Password"; SECRET_GENERIC_TOKEN = "Generic-Token"
    SECRET_PRIVATE_KEY_VAR = "Private-Key-Variable"; SECRET_ENTROPY = "High-Entropy-String"
    SECRET_RABBITMQ = "RabbitMQ-Credential"; SECRET_KAFKA = "Kafka-Credential"; SECRET_S3 = "S3-Credential"
    SECRET_OPENAI = "OpenAI-Key"; SECRET_ANTHROPIC = "Anthropic-Key"; SECRET_MAPBOX = "Mapbox-Token"
    SECRET_GOOGLE_MAPS = "Google-Maps-Key"; SECRET_ALGOLIA = "Algolia-Key"
    SECRET_OKTA = "Okta-Token"; SECRET_AUTH0 = "Auth0-Credential"
    # OWASP A01: Broken Access Control
    VULN_IDOR = "IDOR-Vulnerability"; VULN_PATH_TRAVERSAL = "Path-Traversal"
    VULN_CORS_MISCONFIG = "CORS-Misconfiguration"; VULN_SSRF = "SSRF-Vulnerability"
    VULN_PRIVILEGE_ESCALATION = "Privilege-Escalation"
    VULN_MISSING_AUTH_MIDDLEWARE = "Missing-Auth-Middleware"
    VULN_OPEN_REDIRECT = "Open-Redirect"; VULN_FILE_UPLOAD = "Unrestricted-File-Upload"
    # A02: Security Misconfiguration
    VULN_DEBUG_ENABLED = "Debug-Mode-Enabled"; VULN_DEFAULT_CREDS = "Default-Credentials"
    VULN_MISSING_HEADERS = "Missing-Security-Headers"; VULN_EXPOSED_ADMIN = "Exposed-Admin-Endpoint"
    VULN_DIRECTORY_LISTING = "Directory-Listing-Enabled"; VULN_VERBOSE_ERRORS = "Verbose-Error-Messages"
    VULN_EXPOSED_DOCS = "Exposed-API-Documentation"; VULN_PERMISSIVE_POLICY = "Overly-Permissive-Policy"
    # A03: Supply Chain
    VULN_UNPINNED_DEP = "Unpinned-Dependency"; VULN_KNOWN_VULN_DEP = "Known-Vulnerable-Dependency"
    VULN_MISSING_LOCKFILE = "Missing-Lockfile"; VULN_TYPOSQUAT = "Potential-Typosquat"
    VULN_POSTINSTALL_SCRIPT = "Suspicious-PostInstall-Script"; VULN_BUILD_LEAK = "Build-System-Credential-Leak"
    # A05: Injection
    VULN_SQL_INJECTION = "SQL-Injection"; VULN_XSS = "Cross-Site-Scripting"
    VULN_COMMAND_INJECTION = "Command-Injection"; VULN_TEMPLATE_INJECTION = "Template-Injection"
    VULN_NOSQL_INJECTION = "NoSQL-Injection"; VULN_LDAP_INJECTION = "LDAP-Injection"
    VULN_XPATH_INJECTION = "XPath-Injection"; VULN_XXE = "XML-External-Entity"
    VULN_DOM_XSS = "DOM-Based-XSS"; VULN_HEADER_INJECTION = "Header-Injection"; VULN_CRLF_INJECTION = "CRLF-Injection"
    # A06: Insecure Design
    VULN_MISSING_RATE_LIMIT = "Missing-Rate-Limiting"; VULN_CSRF = "CSRF-Vulnerability"
    VULN_MASS_ASSIGNMENT = "Mass-Assignment"; VULN_BUSINESS_LOGIC = "Business-Logic-Flaw"
    VULN_MISSING_CAPTCHA = "Missing-CAPTCHA"
    # A07: Auth Failures
    VULN_WEAK_PASSWORD_POLICY = "Weak-Password-Policy"; VULN_WEAK_HASH_PASSWORD = "Weak-Password-Hashing"
    VULN_JWT_MISCONFIG = "JWT-Misconfiguration"; VULN_SESSION_FIXATION = "Session-Fixation"
    VULN_MISSING_MFA = "Missing-MFA"; VULN_INSECURE_COOKIE = "Insecure-Cookie-Config"
    VULN_HARDCODED_CREDS = "Hardcoded-Credentials"
    # A08: Integrity
    VULN_UNSAFE_DESER = "Unsafe-Deserialization"; VULN_MISSING_SRI = "Missing-Subresource-Integrity"
    VULN_UNVERIFIED_CICD = "Unverified-CICD-Pipeline"; VULN_UNSIGNED_UPDATE = "Unsigned-Update"
    # A09: Logging
    VULN_MISSING_AUDIT_LOG = "Missing-Audit-Logging"; VULN_PII_IN_LOGS = "PII-in-Logs"
    VULN_SENSITIVE_LOG = "Sensitive-Data-in-Logs"
    # A10: Exception
    VULN_FAIL_OPEN = "Fail-Open-Logic"; VULN_SWALLOWED_ERROR = "Swallowed-Exception"
    VULN_RESOURCE_LEAK = "Resource-Leak"; VULN_NULL_DEREF = "Null-Dereference-Risk"
    VULN_UNHANDLED_PROMISE = "Unhandled-Promise-Rejection"
    # Cloud / IaC
    VULN_PUBLIC_S3 = "Public-S3-Bucket"; VULN_OVERPRIVILEGED_IAM = "Over-Privileged-IAM"
    VULN_OPEN_SECURITY_GROUP = "Open-Security-Group"; VULN_CONTAINER_ROOT = "Container-Running-As-Root"
    VULN_PRIVILEGED_CONTAINER = "Privileged-Container"; VULN_MISSING_ENCRYPTION = "Missing-Encryption-At-Rest"
    VULN_DOCKER_SECRETS = "Docker-Secrets-Exposure"; VULN_K8S_MISCONFIG = "Kubernetes-Misconfiguration"
    # API Security
    VULN_EXCESSIVE_DATA = "Excessive-Data-Exposure"; VULN_BOLA = "Broken-Object-Level-Auth"
    VULN_NO_PAGINATION = "No-Pagination"; VULN_GRAPHQL_INTROSPECTION = "GraphQL-Introspection-Enabled"
    VULN_GRAPHQL_DEPTH = "GraphQL-No-Depth-Limit"
    # Data Exposure
    VULN_PII_IN_CODE = "PII-in-Source-Code"; VULN_CLEARTEXT_STORAGE = "Cleartext-Sensitive-Storage"
    VULN_SENSITIVE_COMMENT = "Sensitive-Data-in-Comments"; VULN_INTERNAL_IP = "Internal-IP-Exposure"
    VULN_INTERNAL_URL = "Internal-URL-Exposure"
    # Frontend / JS
    VULN_JS_SECRET = "Frontend-Secret-Exposure"; VULN_SOURCE_MAP = "Source-Map-In-Production"
    VULN_EVAL_USAGE = "Eval-Usage"; VULN_POSTMESSAGE = "PostMessage-No-Origin-Check"
    VULN_LOCALSTORAGE_SENSITIVE = "Sensitive-Data-in-LocalStorage"
    VULN_ENV_INLINE = "Environment-Variable-Inlined"; VULN_DEBUG_CONSOLE = "Debug-Console-In-Production"
    # Recon
    RECON_ENDPOINT = "Discovered-Endpoint"; RECON_ADMIN_ROUTE = "Admin-Route-Discovered"
    RECON_INTERNAL_SERVICE = "Internal-Service-Reference"; RECON_TECH_FINGERPRINT = "Technology-Fingerprint"
    RECON_TODO_FIXME = "Security-Relevant-TODO"

    @property
    def is_quantum_broken(self) -> bool:
        return self in _QB

    @property
    def is_classically_broken(self) -> bool:
        return self in _CB

    @property
    def is_pqc_safe(self) -> bool:
        return self in _PQ

    @property
    def is_secret(self) -> bool:
        return self.value.startswith(("AWS-","GCP-","Azure-","DigitalOcean-","Alibaba-","IBM-","Oracle-","Heroku-","Cloudflare-","GitHub-","GitLab-","Bitbucket-","CircleCI-","TravisCI-","Jenkins-","NPM-","PyPI-","Docker-","Terraform-","Stripe-","Square-","PayPal-","Braintree-","Plaid-","Shopify-","Slack-","Twilio-","SendGrid-","Mailgun-","Mailchimp-","Telegram-","Discord-","Firebase-","Datadog-","NewRelic-","Sentry-","PagerDuty-","Splunk-","Grafana-","Elastic-","Database-","PostgreSQL-","MySQL-","MongoDB-","Redis-","MSSQL-","Elasticsearch-","Cassandra-","JWT-","OAuth-","Bearer-","Session-","Cookie-","SAML-","LDAP-","SSH-Private","PGP-Private","SSL/TLS-","PKCS-","Generic-","Private-Key-","High-Entropy","RabbitMQ-","Kafka-","S3-","OpenAI-","Anthropic-","Mapbox-","Google-Maps-","Algolia-","Okta-","Auth0-"))

    @property
    def is_vuln(self) -> bool:
        return self.name.startswith("VULN_")

    @property
    def is_recon(self) -> bool:
        return self.name.startswith("RECON_")

    @property
    def is_symmetric(self) -> bool:
        return self in _SY

    @property
    def vuln_category(self) -> VulnCategory:
        if self.is_secret: return VulnCategory.SECRET
        if self.is_quantum_broken or self.is_classically_broken or self.is_pqc_safe: return VulnCategory.CRYPTO
        if self.is_recon: return VulnCategory.RECON
        return _VC.get(self, VulnCategory.CRYPTO)


_QB = {AlgoFamily.RSA, AlgoFamily.RSA_OAEP, AlgoFamily.ECC, AlgoFamily.ECDSA, AlgoFamily.ECDH, AlgoFamily.DSA, AlgoFamily.DH, AlgoFamily.ELGAMAL, AlgoFamily.X25519, AlgoFamily.ED25519, AlgoFamily.ED448, AlgoFamily.X448}
_CB = {AlgoFamily.MD4, AlgoFamily.MD5, AlgoFamily.SHA1, AlgoFamily.DES, AlgoFamily.RC4, AlgoFamily.RC2, AlgoFamily.BLOWFISH, AlgoFamily.IDEA, AlgoFamily.RIPEMD160, AlgoFamily.HMAC_MD5, AlgoFamily.HMAC_SHA1, AlgoFamily.AES_ECB, AlgoFamily.TRIPLE_DES, AlgoFamily.WEAK_RANDOM}
_PQ = {AlgoFamily.ML_KEM, AlgoFamily.ML_DSA, AlgoFamily.SLH_DSA, AlgoFamily.XMSS, AlgoFamily.PQC_KYBER, AlgoFamily.PQC_DILITHIUM, AlgoFamily.PQC_FALCON, AlgoFamily.PQC_SPHINCS, AlgoFamily.PQC_BIKE, AlgoFamily.PQC_MCELIECE, AlgoFamily.PQC_HYBRID}
_SY = {AlgoFamily.AES_128, AlgoFamily.AES_ECB, AlgoFamily.DES, AlgoFamily.TRIPLE_DES, AlgoFamily.RC4, AlgoFamily.RC2, AlgoFamily.BLOWFISH, AlgoFamily.IDEA}
_VC: dict[AlgoFamily, VulnCategory] = {
    AlgoFamily.HNDL_HARVEST: VulnCategory.CRYPTO, AlgoFamily.HNDL_STORAGE: VulnCategory.CRYPTO,
    AlgoFamily.QUANTUM_RECON: VulnCategory.RECON, AlgoFamily.CRYPTO_ENUMERATION: VulnCategory.RECON,
    AlgoFamily.PQC_ADOPTION: VulnCategory.CRYPTO, AlgoFamily.CRYPTO_AGILITY_SIGNAL: VulnCategory.CRYPTO,
}
for _f, _c in [(AlgoFamily.VULN_IDOR,VulnCategory.ACCESS_CONTROL),(AlgoFamily.VULN_PATH_TRAVERSAL,VulnCategory.ACCESS_CONTROL),(AlgoFamily.VULN_CORS_MISCONFIG,VulnCategory.ACCESS_CONTROL),(AlgoFamily.VULN_SSRF,VulnCategory.ACCESS_CONTROL),(AlgoFamily.VULN_PRIVILEGE_ESCALATION,VulnCategory.ACCESS_CONTROL),(AlgoFamily.VULN_MISSING_AUTH_MIDDLEWARE,VulnCategory.ACCESS_CONTROL),(AlgoFamily.VULN_OPEN_REDIRECT,VulnCategory.ACCESS_CONTROL),(AlgoFamily.VULN_FILE_UPLOAD,VulnCategory.ACCESS_CONTROL),(AlgoFamily.VULN_DEBUG_ENABLED,VulnCategory.MISCONFIG),(AlgoFamily.VULN_DEFAULT_CREDS,VulnCategory.MISCONFIG),(AlgoFamily.VULN_MISSING_HEADERS,VulnCategory.MISCONFIG),(AlgoFamily.VULN_EXPOSED_ADMIN,VulnCategory.MISCONFIG),(AlgoFamily.VULN_DIRECTORY_LISTING,VulnCategory.MISCONFIG),(AlgoFamily.VULN_VERBOSE_ERRORS,VulnCategory.MISCONFIG),(AlgoFamily.VULN_EXPOSED_DOCS,VulnCategory.MISCONFIG),(AlgoFamily.VULN_PERMISSIVE_POLICY,VulnCategory.MISCONFIG),(AlgoFamily.VULN_UNPINNED_DEP,VulnCategory.SUPPLY_CHAIN),(AlgoFamily.VULN_KNOWN_VULN_DEP,VulnCategory.SUPPLY_CHAIN),(AlgoFamily.VULN_MISSING_LOCKFILE,VulnCategory.SUPPLY_CHAIN),(AlgoFamily.VULN_TYPOSQUAT,VulnCategory.SUPPLY_CHAIN),(AlgoFamily.VULN_POSTINSTALL_SCRIPT,VulnCategory.SUPPLY_CHAIN),(AlgoFamily.VULN_BUILD_LEAK,VulnCategory.SUPPLY_CHAIN),(AlgoFamily.VULN_SQL_INJECTION,VulnCategory.INJECTION),(AlgoFamily.VULN_XSS,VulnCategory.INJECTION),(AlgoFamily.VULN_COMMAND_INJECTION,VulnCategory.INJECTION),(AlgoFamily.VULN_TEMPLATE_INJECTION,VulnCategory.INJECTION),(AlgoFamily.VULN_NOSQL_INJECTION,VulnCategory.INJECTION),(AlgoFamily.VULN_LDAP_INJECTION,VulnCategory.INJECTION),(AlgoFamily.VULN_XPATH_INJECTION,VulnCategory.INJECTION),(AlgoFamily.VULN_XXE,VulnCategory.INJECTION),(AlgoFamily.VULN_DOM_XSS,VulnCategory.INJECTION),(AlgoFamily.VULN_HEADER_INJECTION,VulnCategory.INJECTION),(AlgoFamily.VULN_CRLF_INJECTION,VulnCategory.INJECTION),(AlgoFamily.VULN_MISSING_RATE_LIMIT,VulnCategory.INSECURE_DESIGN),(AlgoFamily.VULN_CSRF,VulnCategory.INSECURE_DESIGN),(AlgoFamily.VULN_MASS_ASSIGNMENT,VulnCategory.INSECURE_DESIGN),(AlgoFamily.VULN_BUSINESS_LOGIC,VulnCategory.INSECURE_DESIGN),(AlgoFamily.VULN_MISSING_CAPTCHA,VulnCategory.INSECURE_DESIGN),(AlgoFamily.VULN_WEAK_PASSWORD_POLICY,VulnCategory.AUTH),(AlgoFamily.VULN_WEAK_HASH_PASSWORD,VulnCategory.AUTH),(AlgoFamily.VULN_JWT_MISCONFIG,VulnCategory.AUTH),(AlgoFamily.VULN_SESSION_FIXATION,VulnCategory.AUTH),(AlgoFamily.VULN_MISSING_MFA,VulnCategory.AUTH),(AlgoFamily.VULN_INSECURE_COOKIE,VulnCategory.AUTH),(AlgoFamily.VULN_HARDCODED_CREDS,VulnCategory.AUTH),(AlgoFamily.VULN_UNSAFE_DESER,VulnCategory.INTEGRITY),(AlgoFamily.VULN_MISSING_SRI,VulnCategory.INTEGRITY),(AlgoFamily.VULN_UNVERIFIED_CICD,VulnCategory.INTEGRITY),(AlgoFamily.VULN_UNSIGNED_UPDATE,VulnCategory.INTEGRITY),(AlgoFamily.VULN_MISSING_AUDIT_LOG,VulnCategory.LOGGING),(AlgoFamily.VULN_PII_IN_LOGS,VulnCategory.LOGGING),(AlgoFamily.VULN_SENSITIVE_LOG,VulnCategory.LOGGING),(AlgoFamily.VULN_FAIL_OPEN,VulnCategory.EXCEPTION),(AlgoFamily.VULN_SWALLOWED_ERROR,VulnCategory.EXCEPTION),(AlgoFamily.VULN_RESOURCE_LEAK,VulnCategory.EXCEPTION),(AlgoFamily.VULN_NULL_DEREF,VulnCategory.EXCEPTION),(AlgoFamily.VULN_UNHANDLED_PROMISE,VulnCategory.EXCEPTION),(AlgoFamily.VULN_PUBLIC_S3,VulnCategory.CLOUD),(AlgoFamily.VULN_OVERPRIVILEGED_IAM,VulnCategory.CLOUD),(AlgoFamily.VULN_OPEN_SECURITY_GROUP,VulnCategory.CLOUD),(AlgoFamily.VULN_CONTAINER_ROOT,VulnCategory.CLOUD),(AlgoFamily.VULN_PRIVILEGED_CONTAINER,VulnCategory.CLOUD),(AlgoFamily.VULN_MISSING_ENCRYPTION,VulnCategory.CLOUD),(AlgoFamily.VULN_DOCKER_SECRETS,VulnCategory.CLOUD),(AlgoFamily.VULN_K8S_MISCONFIG,VulnCategory.CLOUD),(AlgoFamily.VULN_EXCESSIVE_DATA,VulnCategory.API_SECURITY),(AlgoFamily.VULN_BOLA,VulnCategory.API_SECURITY),(AlgoFamily.VULN_NO_PAGINATION,VulnCategory.API_SECURITY),(AlgoFamily.VULN_GRAPHQL_INTROSPECTION,VulnCategory.API_SECURITY),(AlgoFamily.VULN_GRAPHQL_DEPTH,VulnCategory.API_SECURITY),(AlgoFamily.VULN_PII_IN_CODE,VulnCategory.DATA_EXPOSURE),(AlgoFamily.VULN_CLEARTEXT_STORAGE,VulnCategory.DATA_EXPOSURE),(AlgoFamily.VULN_SENSITIVE_COMMENT,VulnCategory.DATA_EXPOSURE),(AlgoFamily.VULN_INTERNAL_IP,VulnCategory.DATA_EXPOSURE),(AlgoFamily.VULN_INTERNAL_URL,VulnCategory.DATA_EXPOSURE),(AlgoFamily.VULN_JS_SECRET,VulnCategory.FRONTEND),(AlgoFamily.VULN_SOURCE_MAP,VulnCategory.FRONTEND),(AlgoFamily.VULN_EVAL_USAGE,VulnCategory.FRONTEND),(AlgoFamily.VULN_POSTMESSAGE,VulnCategory.FRONTEND),(AlgoFamily.VULN_LOCALSTORAGE_SENSITIVE,VulnCategory.FRONTEND),(AlgoFamily.VULN_ENV_INLINE,VulnCategory.FRONTEND),(AlgoFamily.VULN_DEBUG_CONSOLE,VulnCategory.FRONTEND)]:
    _VC[_f] = _c


class ComplianceFramework(str, Enum):
    NIST_PQC = "NIST-PQC"; CNSA_2_0 = "CNSA-2.0"; FIPS_140_3 = "FIPS-140-3"
    PCI_DSS_4 = "PCI-DSS-4.0"; ETSI_QSC = "ETSI-QSC"; HIPAA = "HIPAA"
    SOC2 = "SOC-2"; NIST_800_131A = "NIST-800-131A"; OWASP_TOP10 = "OWASP-Top-10"
    CIS_BENCHMARK = "CIS-Benchmark"; GDPR = "GDPR"; NIST_800_53 = "NIST-800-53"
    ISO_27001 = "ISO-27001"; SANS_TOP25 = "SANS-Top-25"; OWASP_API_TOP10 = "OWASP-API-Top-10"


class ScanMode(str, Enum):
    FULL = "full"; QUICK = "quick"; QUANTUM = "quantum"; SECRETS = "secrets"
    COMPLIANCE = "compliance"; DIFF = "diff"; OWASP = "owasp"; FRONTEND = "frontend"
    RECON = "recon"; CLOUD = "cloud"; API = "api"; INJECTION = "injection"


class OutputFormat(str, Enum):
    JSON = "json"; SARIF = "sarif"; CSV = "csv"; HTML = "html"; SUMMARY = "summary"


PQC_REPLACEMENTS: dict[str, dict] = {
    AlgoFamily.RSA: {"kem": "ML-KEM-768 / ML-KEM-1024 (FIPS 203)", "sign": "ML-DSA-65 / ML-DSA-87 (FIPS 204)", "notes": "RSA is fully broken by Shor's algorithm regardless of key size."},
    AlgoFamily.RSA_OAEP: {"kem": "ML-KEM-768 (FIPS 203)", "notes": "RSA-OAEP padding is better but RSA itself is quantum-broken."},
    AlgoFamily.ECC: {"kem": "ML-KEM-768 (FIPS 203)", "sign": "ML-DSA-65 (FIPS 204)", "notes": "All ECC curves are vulnerable to Shor's algorithm."},
    AlgoFamily.ECDSA: {"sign": "ML-DSA-65 (FIPS 204)", "notes": "ECDSA on any curve is quantum-broken."},
    AlgoFamily.ECDH: {"kem": "ML-KEM-768 (FIPS 203)", "notes": "ECDH key exchange is quantum-broken."},
    AlgoFamily.DSA: {"sign": "ML-DSA-65 (FIPS 204)", "notes": "DSA is deprecated by NIST AND quantum-broken."},
    AlgoFamily.DH: {"kem": "ML-KEM-768 (FIPS 203)", "notes": "DH is broken by Shor."},
    AlgoFamily.X25519: {"kem": "ML-KEM-768 (FIPS 203)", "notes": "X25519 is quantum-broken."},
    AlgoFamily.ED25519: {"sign": "ML-DSA-65 (FIPS 204)", "notes": "Ed25519 is quantum-broken."},
    AlgoFamily.ED448: {"sign": "ML-DSA-87 (FIPS 204)", "notes": "Ed448 is quantum-broken."},
    AlgoFamily.X448: {"kem": "ML-KEM-1024 (FIPS 203)", "notes": "X448 is quantum-broken."},
    AlgoFamily.MD5: {"replacement": "SHA-256 or SHA3-256", "notes": "MD5 is collision-broken."},
    AlgoFamily.SHA1: {"replacement": "SHA-256 or SHA3-256", "notes": "SHA-1 is collision-broken (SHAttered)."},
    AlgoFamily.DES: {"replacement": "AES-256-GCM", "notes": "DES is classically broken."},
    AlgoFamily.TRIPLE_DES: {"replacement": "AES-256-GCM", "notes": "3DES deprecated by NIST."},
    AlgoFamily.RC4: {"replacement": "ChaCha20-Poly1305 or AES-256-GCM", "notes": "RC4 is broken."},
    AlgoFamily.AES_ECB: {"replacement": "AES-256-GCM (AEAD)", "notes": "ECB leaks patterns."},
    AlgoFamily.AES_128: {"replacement": "AES-256-GCM", "notes": "Only 64-bit quantum security."},
    AlgoFamily.HARDCODED_KEY: {"replacement": "AWS KMS / HashiCorp Vault / Azure Key Vault / GCP KMS", "notes": "Hardcoded keys are exposed in source control and binaries."},
    AlgoFamily.WEAK_RANDOM: {"replacement": "os.urandom() / secrets.token_bytes()", "notes": "Non-cryptographic RNGs must never be used for keys/tokens."},
}

SECRETS_REMEDIATION: dict[str, dict] = {
    "AWS": {"action": "Rotate via AWS IAM console", "vault": "AWS Secrets Manager"},
    "GCP": {"action": "Revoke in GCP Console", "vault": "GCP Secret Manager"},
    "Azure": {"action": "Rotate in Azure Portal", "vault": "Azure Key Vault"},
    "Stripe": {"action": "Roll key at dashboard.stripe.com/apikeys", "vault": "Vault"},
    "GitHub": {"action": "Revoke at github.com/settings/tokens", "vault": "GitHub Secrets"},
    "GitLab": {"action": "Revoke at gitlab.com settings", "vault": "GitLab CI/CD Variables"},
    "Database": {"action": "Rotate credentials immediately", "vault": "HashiCorp Vault"},
    "Generic": {"action": "Identify service, rotate credential", "vault": "Any secrets manager"},
}

LANGUAGE_MAP: dict[str, list[str]] = {
    "python": [".py",".pyw",".pyi"], "javascript": [".js",".mjs",".cjs",".jsx"],
    "typescript": [".ts",".tsx",".mts",".cts"], "java": [".java"],
    "kotlin": [".kt",".kts"], "go": [".go"],
    "cpp": [".cpp",".cc",".cxx",".c",".h",".hpp",".hxx"],
    "rust": [".rs"], "ruby": [".rb",".rake",".gemspec"],
    "php": [".php",".phtml"], "swift": [".swift"], "csharp": [".cs"],
    "scala": [".scala",".sc"], "dart": [".dart"], "elixir": [".ex",".exs"],
    "perl": [".pl",".pm"], "groovy": [".groovy",".gvy",".gradle"],
    "vue": [".vue"], "svelte": [".svelte"], "html": [".html",".htm",".xhtml"],
    "config": [".yaml",".yml",".toml",".ini",".env",".conf",".cfg",".json",".xml",".properties",".hcl",".tf"],
    "cert": [".pem",".crt",".cer",".der",".p12",".pfx",".p7b"],
    "dockerfile": ["dockerfile",".dockerfile","containerfile"],
    "shell": [".sh",".bash",".zsh",".fish"],
    "terraform": [".tf",".tfvars"], "graphql": [".graphql",".gql"],
    "env": [".env",".env.local",".env.dev",".env.staging",".env.production",".env.test"],
}

SKIP_DIRS: set[str] = {".git",".svn",".hg","node_modules","__pycache__",".pytest_cache","venv",".venv","env",".tox",".nox","dist","build","target","out","bin","obj",".gradle",".idea",".vscode","vendor","third_party","3rdparty","external",".terraform",".serverless","coverage",".nyc_output","htmlcov"}
MAX_FILE_SIZE_BYTES: int = 10 * 1024 * 1024

COMPLIANCE_VIOLATIONS: dict[AlgoFamily, list[ComplianceFramework]] = {
    AlgoFamily.RSA: [ComplianceFramework.CNSA_2_0, ComplianceFramework.NIST_PQC],
    AlgoFamily.ECC: [ComplianceFramework.CNSA_2_0, ComplianceFramework.NIST_PQC],
    AlgoFamily.ECDSA: [ComplianceFramework.CNSA_2_0, ComplianceFramework.NIST_PQC],
    AlgoFamily.ECDH: [ComplianceFramework.CNSA_2_0, ComplianceFramework.NIST_PQC],
    AlgoFamily.DSA: [ComplianceFramework.CNSA_2_0, ComplianceFramework.NIST_PQC, ComplianceFramework.NIST_800_131A],
    AlgoFamily.DH: [ComplianceFramework.CNSA_2_0, ComplianceFramework.NIST_PQC],
    AlgoFamily.MD5: [ComplianceFramework.FIPS_140_3, ComplianceFramework.PCI_DSS_4, ComplianceFramework.NIST_800_131A],
    AlgoFamily.SHA1: [ComplianceFramework.FIPS_140_3, ComplianceFramework.NIST_800_131A],
    AlgoFamily.DES: [ComplianceFramework.FIPS_140_3, ComplianceFramework.PCI_DSS_4, ComplianceFramework.NIST_800_131A],
    AlgoFamily.TRIPLE_DES: [ComplianceFramework.FIPS_140_3, ComplianceFramework.PCI_DSS_4],
    AlgoFamily.RC4: [ComplianceFramework.PCI_DSS_4, ComplianceFramework.FIPS_140_3],
    AlgoFamily.AES_ECB: [ComplianceFramework.FIPS_140_3],
    AlgoFamily.HARDCODED_KEY: [ComplianceFramework.PCI_DSS_4, ComplianceFramework.SOC2, ComplianceFramework.HIPAA],
    AlgoFamily.WEAK_RANDOM: [ComplianceFramework.FIPS_140_3, ComplianceFramework.PCI_DSS_4],
    AlgoFamily.SECRET_AWS: [ComplianceFramework.PCI_DSS_4, ComplianceFramework.SOC2, ComplianceFramework.HIPAA, ComplianceFramework.OWASP_TOP10, ComplianceFramework.CIS_BENCHMARK],
    AlgoFamily.SECRET_GCP: [ComplianceFramework.PCI_DSS_4, ComplianceFramework.SOC2, ComplianceFramework.OWASP_TOP10],
    AlgoFamily.SECRET_AZURE: [ComplianceFramework.PCI_DSS_4, ComplianceFramework.SOC2, ComplianceFramework.OWASP_TOP10],
    AlgoFamily.SECRET_STRIPE: [ComplianceFramework.PCI_DSS_4, ComplianceFramework.SOC2, ComplianceFramework.OWASP_TOP10],
    AlgoFamily.SECRET_DB_CONNSTR: [ComplianceFramework.PCI_DSS_4, ComplianceFramework.HIPAA, ComplianceFramework.SOC2, ComplianceFramework.OWASP_TOP10, ComplianceFramework.GDPR],
    AlgoFamily.SECRET_POSTGRES: [ComplianceFramework.PCI_DSS_4, ComplianceFramework.HIPAA, ComplianceFramework.OWASP_TOP10, ComplianceFramework.GDPR],
    AlgoFamily.SECRET_MYSQL: [ComplianceFramework.PCI_DSS_4, ComplianceFramework.HIPAA, ComplianceFramework.OWASP_TOP10, ComplianceFramework.GDPR],
    AlgoFamily.SECRET_MONGODB: [ComplianceFramework.PCI_DSS_4, ComplianceFramework.HIPAA, ComplianceFramework.OWASP_TOP10, ComplianceFramework.GDPR],
    AlgoFamily.SECRET_REDIS: [ComplianceFramework.OWASP_TOP10],
    AlgoFamily.SECRET_JWT: [ComplianceFramework.OWASP_TOP10, ComplianceFramework.SOC2],
    AlgoFamily.SECRET_SSH_KEY: [ComplianceFramework.PCI_DSS_4, ComplianceFramework.SOC2, ComplianceFramework.CIS_BENCHMARK],
    AlgoFamily.SECRET_GENERIC_PASSWORD: [ComplianceFramework.OWASP_TOP10, ComplianceFramework.PCI_DSS_4],
    AlgoFamily.SECRET_GENERIC_API: [ComplianceFramework.OWASP_TOP10, ComplianceFramework.SOC2],
    AlgoFamily.SECRET_GENERIC_SECRET: [ComplianceFramework.OWASP_TOP10, ComplianceFramework.SOC2],
    AlgoFamily.VULN_SQL_INJECTION: [ComplianceFramework.OWASP_TOP10, ComplianceFramework.PCI_DSS_4, ComplianceFramework.SANS_TOP25, ComplianceFramework.HIPAA],
    AlgoFamily.VULN_XSS: [ComplianceFramework.OWASP_TOP10, ComplianceFramework.PCI_DSS_4, ComplianceFramework.SANS_TOP25],
    AlgoFamily.VULN_COMMAND_INJECTION: [ComplianceFramework.OWASP_TOP10, ComplianceFramework.PCI_DSS_4, ComplianceFramework.SANS_TOP25],
    AlgoFamily.VULN_SSRF: [ComplianceFramework.OWASP_TOP10, ComplianceFramework.PCI_DSS_4, ComplianceFramework.SANS_TOP25],
    AlgoFamily.VULN_PATH_TRAVERSAL: [ComplianceFramework.OWASP_TOP10, ComplianceFramework.PCI_DSS_4, ComplianceFramework.SANS_TOP25],
    AlgoFamily.VULN_IDOR: [ComplianceFramework.OWASP_TOP10, ComplianceFramework.PCI_DSS_4, ComplianceFramework.SOC2],
    AlgoFamily.VULN_CORS_MISCONFIG: [ComplianceFramework.OWASP_TOP10, ComplianceFramework.PCI_DSS_4],
    AlgoFamily.VULN_DEBUG_ENABLED: [ComplianceFramework.OWASP_TOP10, ComplianceFramework.PCI_DSS_4, ComplianceFramework.SOC2, ComplianceFramework.CIS_BENCHMARK],
    AlgoFamily.VULN_DEFAULT_CREDS: [ComplianceFramework.OWASP_TOP10, ComplianceFramework.PCI_DSS_4, ComplianceFramework.CIS_BENCHMARK, ComplianceFramework.NIST_800_53],
    AlgoFamily.VULN_UNSAFE_DESER: [ComplianceFramework.OWASP_TOP10, ComplianceFramework.PCI_DSS_4, ComplianceFramework.SANS_TOP25],
    AlgoFamily.VULN_JWT_MISCONFIG: [ComplianceFramework.OWASP_TOP10, ComplianceFramework.SOC2],
    AlgoFamily.VULN_CSRF: [ComplianceFramework.OWASP_TOP10, ComplianceFramework.PCI_DSS_4],
    AlgoFamily.VULN_MASS_ASSIGNMENT: [ComplianceFramework.OWASP_TOP10, ComplianceFramework.OWASP_API_TOP10],
    AlgoFamily.VULN_PUBLIC_S3: [ComplianceFramework.CIS_BENCHMARK, ComplianceFramework.SOC2, ComplianceFramework.PCI_DSS_4, ComplianceFramework.HIPAA],
    AlgoFamily.VULN_OVERPRIVILEGED_IAM: [ComplianceFramework.CIS_BENCHMARK, ComplianceFramework.SOC2, ComplianceFramework.NIST_800_53],
    AlgoFamily.VULN_OPEN_SECURITY_GROUP: [ComplianceFramework.CIS_BENCHMARK, ComplianceFramework.PCI_DSS_4],
    AlgoFamily.VULN_CONTAINER_ROOT: [ComplianceFramework.CIS_BENCHMARK, ComplianceFramework.SOC2],
    AlgoFamily.VULN_PII_IN_LOGS: [ComplianceFramework.OWASP_TOP10, ComplianceFramework.GDPR, ComplianceFramework.HIPAA],
    AlgoFamily.VULN_PII_IN_CODE: [ComplianceFramework.GDPR, ComplianceFramework.HIPAA, ComplianceFramework.PCI_DSS_4],
    AlgoFamily.VULN_MISSING_ENCRYPTION: [ComplianceFramework.PCI_DSS_4, ComplianceFramework.HIPAA, ComplianceFramework.GDPR],
    AlgoFamily.VULN_MISSING_AUDIT_LOG: [ComplianceFramework.OWASP_TOP10, ComplianceFramework.SOC2, ComplianceFramework.PCI_DSS_4, ComplianceFramework.HIPAA],
    AlgoFamily.VULN_FAIL_OPEN: [ComplianceFramework.OWASP_TOP10, ComplianceFramework.PCI_DSS_4],
    AlgoFamily.VULN_XXE: [ComplianceFramework.OWASP_TOP10, ComplianceFramework.PCI_DSS_4],
    AlgoFamily.VULN_KNOWN_VULN_DEP: [ComplianceFramework.OWASP_TOP10, ComplianceFramework.PCI_DSS_4, ComplianceFramework.SOC2],
    AlgoFamily.VULN_JS_SECRET: [ComplianceFramework.OWASP_TOP10, ComplianceFramework.PCI_DSS_4],
    AlgoFamily.VULN_HARDCODED_CREDS: [ComplianceFramework.OWASP_TOP10, ComplianceFramework.PCI_DSS_4, ComplianceFramework.SOC2],
    AlgoFamily.VULN_INSECURE_COOKIE: [ComplianceFramework.OWASP_TOP10, ComplianceFramework.PCI_DSS_4],
    AlgoFamily.VULN_WEAK_PASSWORD_POLICY: [ComplianceFramework.OWASP_TOP10, ComplianceFramework.PCI_DSS_4, ComplianceFramework.NIST_800_53],
    AlgoFamily.VULN_CLEARTEXT_STORAGE: [ComplianceFramework.PCI_DSS_4, ComplianceFramework.HIPAA, ComplianceFramework.GDPR],
    AlgoFamily.VULN_MISSING_SRI: [ComplianceFramework.OWASP_TOP10],
    AlgoFamily.VULN_UNVERIFIED_CICD: [ComplianceFramework.OWASP_TOP10, ComplianceFramework.SOC2, ComplianceFramework.NIST_800_53],
    AlgoFamily.VULN_GRAPHQL_INTROSPECTION: [ComplianceFramework.OWASP_API_TOP10],
    AlgoFamily.VULN_MISSING_RATE_LIMIT: [ComplianceFramework.OWASP_TOP10, ComplianceFramework.OWASP_API_TOP10],
    AlgoFamily.VULN_EXCESSIVE_DATA: [ComplianceFramework.OWASP_API_TOP10, ComplianceFramework.GDPR],
    # PQSI compliance
    AlgoFamily.HNDL_HARVEST: [ComplianceFramework.NIST_PQC, ComplianceFramework.CNSA_2_0, ComplianceFramework.ETSI_QSC],
    AlgoFamily.HNDL_STORAGE: [ComplianceFramework.NIST_PQC, ComplianceFramework.CNSA_2_0, ComplianceFramework.ETSI_QSC],
    AlgoFamily.QUANTUM_RECON: [ComplianceFramework.NIST_PQC, ComplianceFramework.CNSA_2_0],
    AlgoFamily.CRYPTO_ENUMERATION: [ComplianceFramework.NIST_PQC, ComplianceFramework.CNSA_2_0],
}
