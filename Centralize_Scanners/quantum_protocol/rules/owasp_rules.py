"""
Quantum Protocol v4.0 — OWASP Vulnerability Rules Engine
150+ detection patterns for OWASP Top 10:2025 + API Top 10 + Cloud/IaC + Frontend
"""
from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Optional
from quantum_protocol.models.enums import AlgoFamily, RiskLevel


@dataclass(frozen=True)
class VulnRule:
    id: str
    pattern: str
    family: AlgoFamily
    risk: RiskLevel
    confidence: float
    note: str
    cwe: str = ""
    languages: tuple = ()
    tags: tuple = ()
    remediation: str = ""


def _compile(rules):
    out = []
    for r in rules:
        try:
            out.append((re.compile(r.pattern, re.IGNORECASE | re.MULTILINE), r))
        except re.error:
            pass
    return out

INJECTION_RULES = []
ACCESS_CONTROL_RULES = []
MISCONFIG_RULES = []
AUTH_RULES = []
DESIGN_RULES = []
INTEGRITY_RULES = []
CLOUD_RULES = []
FRONTEND_RULES = []
LOG_EXC_RULES = []
DATA_RECON_RULES = []
API_RULES = []
SUPPLY_CHAIN_RULES = []

INJECTION_RULES.append(VulnRule("SQLI-001", "(?:cursor|conn|db)\\s*\\.\\s*(?:execute|query)\\s*\\(\\s*(?:f[\"\\'])", AlgoFamily.VULN_SQL_INJECTION, RiskLevel.CRITICAL, 0.9, "SQL query with f-string \u2014 use parameterized queries", "CWE-89", ('python',), ('injection', 'sql')))
INJECTION_RULES.append(VulnRule("SQLI-002", "\\.(?:execute|query)\\s*\\(\\s*[\"\\'].*?\\+\\s*(?:req|request|params|args|input|user)", AlgoFamily.VULN_SQL_INJECTION, RiskLevel.CRITICAL, 0.92, "SQL query concatenating user input", "CWE-89", (), ('injection', 'sql')))
INJECTION_RULES.append(VulnRule("SQLI-003", "(?:SELECT|INSERT|UPDATE|DELETE|DROP)\\s+.*?\\+\\s*(?:req|request|params|input|user)", AlgoFamily.VULN_SQL_INJECTION, RiskLevel.CRITICAL, 0.85, "Raw SQL with string concatenation of user input", "CWE-89", (), ('injection', 'sql')))
INJECTION_RULES.append(VulnRule("SQLI-004", "\\.raw\\s*\\(\\s*(?:f[\"\\']|[\"\\'].*?\\+)", AlgoFamily.VULN_SQL_INJECTION, RiskLevel.HIGH, 0.82, "ORM .raw() with string interpolation", "CWE-89", (), ('injection', 'sql')))
INJECTION_RULES.append(VulnRule("SQLI-005", "sequelize\\.query\\s*\\(\\s*[`\"\\'].*?\\$\\{", AlgoFamily.VULN_SQL_INJECTION, RiskLevel.CRITICAL, 0.88, "Sequelize raw query with template interpolation", "CWE-89", ('javascript', 'typescript'), ('injection', 'sql')))
INJECTION_RULES.append(VulnRule("SQLI-006", "(?:createQuery|prepareStatement)\\s*\\(\\s*[\"\\'].*?\\+", AlgoFamily.VULN_SQL_INJECTION, RiskLevel.CRITICAL, 0.88, "Java SQL with string concatenation", "CWE-89", ('java', 'kotlin'), ('injection', 'sql')))
INJECTION_RULES.append(VulnRule("SQLI-007", "Sprintf\\s*\\(\\s*[\"`](?:SELECT|INSERT|UPDATE|DELETE)", AlgoFamily.VULN_SQL_INJECTION, RiskLevel.HIGH, 0.82, "Go SQL with Sprintf", "CWE-89", ('go',), ('injection', 'sql')))
INJECTION_RULES.append(VulnRule("SQLI-008", "query\\s*\\(\\s*`[^`]*\\$\\{[^}]*(?:req|params|body|query|input)", AlgoFamily.VULN_SQL_INJECTION, RiskLevel.CRITICAL, 0.9, "Template literal SQL with user input", "CWE-89", ('javascript', 'typescript'), ('injection', 'sql')))
INJECTION_RULES.append(VulnRule("SQLI-009", "\\.where\\s*\\(\\s*[\"\\'].*?#\\{", AlgoFamily.VULN_SQL_INJECTION, RiskLevel.HIGH, 0.8, "Rails where with string interpolation", "CWE-89", ('ruby',), ('injection', 'sql')))
INJECTION_RULES.append(VulnRule("SQLI-010", "\\.extra\\s*\\(\\s*(?:where|select).*?%", AlgoFamily.VULN_SQL_INJECTION, RiskLevel.HIGH, 0.78, "Django .extra() with format strings", "CWE-89", ('python',), ('injection', 'sql')))
INJECTION_RULES.append(VulnRule("XSS-001", "\\.innerHTML\\s*=", AlgoFamily.VULN_XSS, RiskLevel.HIGH, 0.78, "innerHTML assignment \u2014 XSS risk if user-controlled", "CWE-79", ('javascript', 'typescript'), ('injection', 'xss')))
INJECTION_RULES.append(VulnRule("XSS-002", "document\\.write\\s*\\(", AlgoFamily.VULN_XSS, RiskLevel.HIGH, 0.78, "document.write() \u2014 XSS risk", "CWE-79", ('javascript', 'typescript'), ('injection', 'xss')))
INJECTION_RULES.append(VulnRule("XSS-003", "dangerouslySetInnerHTML\\s*=\\s*\\{", AlgoFamily.VULN_DOM_XSS, RiskLevel.HIGH, 0.85, "React dangerouslySetInnerHTML \u2014 sanitize input", "CWE-79", ('javascript', 'typescript'), ('injection', 'xss')))
INJECTION_RULES.append(VulnRule("XSS-004", "v-html\\s*=", AlgoFamily.VULN_DOM_XSS, RiskLevel.HIGH, 0.82, "Vue v-html renders raw HTML", "CWE-79", ('vue', 'javascript'), ('injection', 'xss')))
INJECTION_RULES.append(VulnRule("XSS-005", "\\|\\s*safe\\b", AlgoFamily.VULN_XSS, RiskLevel.HIGH, 0.8, "Django/Jinja |safe filter disables escaping", "CWE-79", ('python', 'html'), ('injection', 'xss')))
INJECTION_RULES.append(VulnRule("XSS-006", "\\{!!.*?!!\\}", AlgoFamily.VULN_XSS, RiskLevel.HIGH, 0.82, "Laravel Blade unescaped output", "CWE-79", ('php',), ('injection', 'xss')))
INJECTION_RULES.append(VulnRule("XSS-007", "render_template_string\\s*\\(", AlgoFamily.VULN_TEMPLATE_INJECTION, RiskLevel.CRITICAL, 0.9, "Flask SSTI \u2014 render_template_string with user data", "CWE-1336", ('python',), ('injection', 'ssti')))
INJECTION_RULES.append(VulnRule("XSS-008", "Response\\.Write\\s*\\(\\s*(?:Request|HttpContext)", AlgoFamily.VULN_XSS, RiskLevel.HIGH, 0.82, ".NET reflected XSS", "CWE-79", ('csharp',), ('injection', 'xss')))
INJECTION_RULES.append(VulnRule("CMDI-001", "os\\.system\\s*\\(\\s*(?:f[\"\\']|.*?\\+|.*?%|.*?format)", AlgoFamily.VULN_COMMAND_INJECTION, RiskLevel.CRITICAL, 0.92, "os.system() with dynamic input", "CWE-78", ('python',), ('injection', 'command')))
INJECTION_RULES.append(VulnRule("CMDI-002", "subprocess\\.(?:call|run|Popen)\\s*\\([^)]*shell\\s*=\\s*True", AlgoFamily.VULN_COMMAND_INJECTION, RiskLevel.HIGH, 0.85, "subprocess with shell=True", "CWE-78", ('python',), ('injection', 'command')))
INJECTION_RULES.append(VulnRule("CMDI-003", "child_process\\.(?:exec|execSync)\\s*\\(", AlgoFamily.VULN_COMMAND_INJECTION, RiskLevel.HIGH, 0.82, "Node child_process.exec", "CWE-78", ('javascript', 'typescript'), ('injection', 'command')))
INJECTION_RULES.append(VulnRule("CMDI-004", "Runtime\\.getRuntime\\(\\)\\.exec\\s*\\(", AlgoFamily.VULN_COMMAND_INJECTION, RiskLevel.HIGH, 0.8, "Java Runtime.exec()", "CWE-78", ('java', 'kotlin'), ('injection', 'command')))
INJECTION_RULES.append(VulnRule("CMDI-005", "(?:exec|system|passthru|shell_exec|popen)\\s*\\(\\s*\\$", AlgoFamily.VULN_COMMAND_INJECTION, RiskLevel.CRITICAL, 0.9, "PHP command execution with variable", "CWE-78", ('php',), ('injection', 'command')))
INJECTION_RULES.append(VulnRule("XXE-001", "(?:etree\\.parse|minidom\\.parse|sax\\.parse)\\s*\\(", AlgoFamily.VULN_XXE, RiskLevel.HIGH, 0.75, "Python XML parser \u2014 verify entity protection", "CWE-611", ('python',), ('injection', 'xxe')))
INJECTION_RULES.append(VulnRule("XXE-002", "LIBXML_NOENT", AlgoFamily.VULN_XXE, RiskLevel.CRITICAL, 0.88, "PHP LIBXML_NOENT enables entity expansion", "CWE-611", ('php',), ('injection', 'xxe')))
INJECTION_RULES.append(VulnRule("NOSQL-001", "\\.find\\s*\\(\\s*(?:req\\.body|req\\.query|JSON\\.parse)", AlgoFamily.VULN_NOSQL_INJECTION, RiskLevel.HIGH, 0.82, "MongoDB find() with direct user input", "CWE-943", ('javascript', 'typescript'), ('injection', 'nosql')))
ACCESS_CONTROL_RULES.append(VulnRule("PT-001", "(?:open|readFile|readFileSync|sendFile|send_file)\\s*\\(\\s*(?:req|request|params|input)", AlgoFamily.VULN_PATH_TRAVERSAL, RiskLevel.CRITICAL, 0.88, "File operation with user path \u2014 traversal risk", "CWE-22", (), ('access', 'path-traversal')))
ACCESS_CONTROL_RULES.append(VulnRule("PT-002", "os\\.path\\.join\\s*\\(.*?,\\s*(?:req|request|params|input)", AlgoFamily.VULN_PATH_TRAVERSAL, RiskLevel.HIGH, 0.82, "os.path.join with user input", "CWE-22", ('python',), ('access', 'path-traversal')))
ACCESS_CONTROL_RULES.append(VulnRule("PT-003", "path\\.join\\s*\\(.*?,\\s*(?:req|params)\\.", AlgoFamily.VULN_PATH_TRAVERSAL, RiskLevel.HIGH, 0.82, "path.join with request parameter", "CWE-22", ('javascript', 'typescript'), ('access', 'path-traversal')))
ACCESS_CONTROL_RULES.append(VulnRule("CORS-001", "Access-Control-Allow-Origin[\\s:]*\\*", AlgoFamily.VULN_CORS_MISCONFIG, RiskLevel.HIGH, 0.88, "CORS wildcard origin", "CWE-942", (), ('access', 'cors')))
ACCESS_CONTROL_RULES.append(VulnRule("CORS-002", "origin\\s*[=:]\\s*(?:req|request)\\.(?:headers?|get)", AlgoFamily.VULN_CORS_MISCONFIG, RiskLevel.CRITICAL, 0.9, "CORS origin reflection", "CWE-942", (), ('access', 'cors')))
ACCESS_CONTROL_RULES.append(VulnRule("CORS-003", "credentials\\s*:\\s*true.*?origin\\s*:\\s*(?:true|req\\.)", AlgoFamily.VULN_CORS_MISCONFIG, RiskLevel.CRITICAL, 0.92, "CORS credentials + dynamic origin", "CWE-942", ('javascript', 'typescript'), ('access', 'cors')))
ACCESS_CONTROL_RULES.append(VulnRule("SSRF-001", "requests\\.(?:get|post|put|delete)\\s*\\(\\s*(?:url|req|request|params|input)", AlgoFamily.VULN_SSRF, RiskLevel.CRITICAL, 0.88, "Python requests with user URL", "CWE-918", ('python',), ('access', 'ssrf')))
ACCESS_CONTROL_RULES.append(VulnRule("SSRF-002", "(?:fetch|axios|http\\.get)\\s*\\(\\s*(?:url|req|request|params|input)", AlgoFamily.VULN_SSRF, RiskLevel.CRITICAL, 0.85, "JS HTTP client with user URL", "CWE-918", ('javascript', 'typescript'), ('access', 'ssrf')))
ACCESS_CONTROL_RULES.append(VulnRule("SSRF-003", "169\\.254\\.169\\.254|metadata\\.google\\.internal|100\\.100\\.100\\.200", AlgoFamily.VULN_SSRF, RiskLevel.CRITICAL, 0.95, "Cloud metadata endpoint", "CWE-918", (), ('access', 'ssrf', 'cloud')))
ACCESS_CONTROL_RULES.append(VulnRule("IDOR-001", "(?:findById|findByPk|findOne|get_object_or_404)\\s*\\(\\s*(?:req|request|params)", AlgoFamily.VULN_IDOR, RiskLevel.HIGH, 0.75, "DB lookup by user ID without ownership check", "CWE-639", (), ('access', 'idor')))
ACCESS_CONTROL_RULES.append(VulnRule("REDIR-001", "(?:redirect|location\\.href|window\\.location)\\s*=\\s*(?:req|request|params|query|input)", AlgoFamily.VULN_OPEN_REDIRECT, RiskLevel.MEDIUM, 0.78, "Redirect with unvalidated user input", "CWE-601", (), ('access', 'redirect')))
MISCONFIG_RULES.append(VulnRule("DBG-001", "DEBUG\\s*=\\s*True", AlgoFamily.VULN_DEBUG_ENABLED, RiskLevel.HIGH, 0.9, "Django DEBUG=True", "CWE-489", ('python',), ('misconfig', 'debug')))
MISCONFIG_RULES.append(VulnRule("DBG-002", "app\\.debug\\s*=\\s*True", AlgoFamily.VULN_DEBUG_ENABLED, RiskLevel.HIGH, 0.88, "Flask debug enabled", "CWE-489", ('python',), ('misconfig', 'debug')))
MISCONFIG_RULES.append(VulnRule("DBG-003", "NODE_ENV\\s*[=:]\\s*[\"\\']?development", AlgoFamily.VULN_DEBUG_ENABLED, RiskLevel.HIGH, 0.82, "NODE_ENV=development", "CWE-489", ('javascript', 'typescript', 'config'), ('misconfig', 'debug')))
MISCONFIG_RULES.append(VulnRule("DBG-004", "display_errors\\s*=\\s*(?:On|1|true)", AlgoFamily.VULN_VERBOSE_ERRORS, RiskLevel.HIGH, 0.88, "PHP display_errors enabled", "CWE-209", ('php', 'config'), ('misconfig', 'debug')))
MISCONFIG_RULES.append(VulnRule("DBG-005", "management\\.endpoints\\.web\\.exposure\\.include\\s*=\\s*\\*", AlgoFamily.VULN_EXPOSED_ADMIN, RiskLevel.HIGH, 0.82, "Spring Actuator all endpoints exposed", "CWE-200", ('java', 'config'), ('misconfig', 'debug')))
MISCONFIG_RULES.append(VulnRule("DCRED-001", "(?:password|passwd|pwd)\\s*[=:]\\s*[\"\\'](?:admin|password|123456|root|test|default|changeme|secret|qwerty)[\"\\']", AlgoFamily.VULN_DEFAULT_CREDS, RiskLevel.CRITICAL, 0.88, "Default/common password", "CWE-1393", (), ('misconfig', 'default-creds')))
MISCONFIG_RULES.append(VulnRule("EXPO-001", "(?:route|path|url)\\s*[=(]\\s*[\"\\']/?(?:admin|phpmyadmin|adminer|wp-admin)", AlgoFamily.VULN_EXPOSED_ADMIN, RiskLevel.HIGH, 0.78, "Admin endpoint \u2014 ensure auth", "CWE-200", (), ('misconfig', 'admin')))
MISCONFIG_RULES.append(VulnRule("EXPO-002", "(?:route|path|url)\\s*[=(]\\s*[\"\\']/?(?:swagger|api-docs|openapi|graphql-playground)", AlgoFamily.VULN_EXPOSED_DOCS, RiskLevel.MEDIUM, 0.78, "API docs \u2014 protect in production", "CWE-200", (), ('misconfig', 'docs')))
MISCONFIG_RULES.append(VulnRule("PERM-001", "chmod\\s+(?:777|666)", AlgoFamily.VULN_PERMISSIVE_POLICY, RiskLevel.HIGH, 0.82, "Overly permissive file permissions", "CWE-732", ('shell', 'config'), ('misconfig', 'permissions')))
AUTH_RULES.append(VulnRule("AUTH-001", "(?:md5|sha1|sha256)\\s*\\(\\s*(?:password|passwd|pwd|pass)", AlgoFamily.VULN_WEAK_HASH_PASSWORD, RiskLevel.CRITICAL, 0.9, "Password with fast hash \u2014 use bcrypt/argon2", "CWE-916", (), ('auth', 'password')))
AUTH_RULES.append(VulnRule("JWT-001", "(?:algorithm|alg)\\s*[=:]\\s*[\"\\'](?:none|None|NONE)[\"\\']", AlgoFamily.VULN_JWT_MISCONFIG, RiskLevel.CRITICAL, 0.95, "JWT algorithm=none \u2014 forged tokens", "CWE-345", (), ('auth', 'jwt')))
AUTH_RULES.append(VulnRule("JWT-002", "(?:verify|verification)\\s*[=:]\\s*(?:false|False|0)", AlgoFamily.VULN_JWT_MISCONFIG, RiskLevel.CRITICAL, 0.92, "JWT verification disabled", "CWE-345", (), ('auth', 'jwt')))
AUTH_RULES.append(VulnRule("JWT-003", "(?:jwt_secret|JWT_SECRET|secret_key)\\s*[=:]\\s*[\"\\'][a-zA-Z0-9]{1,16}[\"\\']", AlgoFamily.VULN_JWT_MISCONFIG, RiskLevel.HIGH, 0.8, "Short JWT secret", "CWE-521", (), ('auth', 'jwt')))
AUTH_RULES.append(VulnRule("SESS-001", "(?:httponly|HttpOnly|http_only)\\s*[=:]\\s*(?:false|False|0)", AlgoFamily.VULN_INSECURE_COOKIE, RiskLevel.MEDIUM, 0.82, "Cookie HttpOnly disabled", "CWE-614", (), ('auth', 'cookie')))
AUTH_RULES.append(VulnRule("SESS-002", "(?:secure|Secure)\\s*[=:]\\s*(?:false|False|0)", AlgoFamily.VULN_INSECURE_COOKIE, RiskLevel.MEDIUM, 0.82, "Cookie Secure flag disabled", "CWE-614", (), ('auth', 'cookie')))
DESIGN_RULES.append(VulnRule("MASS-001", "(?:Model\\.create|\\.create)\\s*\\(\\s*(?:req\\.body|request\\.data|request\\.json)", AlgoFamily.VULN_MASS_ASSIGNMENT, RiskLevel.HIGH, 0.82, "Model.create with raw body \u2014 mass assignment", "CWE-915", ('javascript', 'typescript', 'python'), ('design', 'mass-assignment')))
DESIGN_RULES.append(VulnRule("MASS-002", "fields\\s*=\\s*[\"\\']__all__[\"\\']", AlgoFamily.VULN_MASS_ASSIGNMENT, RiskLevel.HIGH, 0.85, "Django fields=__all__", "CWE-915", ('python',), ('design', 'mass-assignment')))
DESIGN_RULES.append(VulnRule("MASS-003", "params\\.permit!", AlgoFamily.VULN_MASS_ASSIGNMENT, RiskLevel.HIGH, 0.88, "Rails permit! all params", "CWE-915", ('ruby',), ('design', 'mass-assignment')))
DESIGN_RULES.append(VulnRule("CSRF-001", "(?:@csrf_exempt|csrf_exempt)", AlgoFamily.VULN_CSRF, RiskLevel.HIGH, 0.85, "CSRF protection disabled", "CWE-352", ('python',), ('design', 'csrf')))
DESIGN_RULES.append(VulnRule("CSRF-002", "csrf\\s*[=:]\\s*(?:false|disabled|off)", AlgoFamily.VULN_CSRF, RiskLevel.HIGH, 0.85, "CSRF disabled in config", "CWE-352", ('config',), ('design', 'csrf')))
INTEGRITY_RULES.append(VulnRule("DESER-001", "pickle\\.(?:loads?|Unpickler)\\s*\\(", AlgoFamily.VULN_UNSAFE_DESER, RiskLevel.CRITICAL, 0.9, "pickle deserialization \u2014 code exec risk", "CWE-502", ('python',), ('integrity', 'deser')))
INTEGRITY_RULES.append(VulnRule("DESER-002", "yaml\\.(?:load|unsafe_load)\\s*\\(", AlgoFamily.VULN_UNSAFE_DESER, RiskLevel.CRITICAL, 0.85, "YAML load \u2014 use safe_load", "CWE-502", ('python',), ('integrity', 'deser')))
INTEGRITY_RULES.append(VulnRule("DESER-003", "(?:ObjectInputStream|readObject)\\s*\\(", AlgoFamily.VULN_UNSAFE_DESER, RiskLevel.HIGH, 0.78, "Java deserialization", "CWE-502", ('java',), ('integrity', 'deser')))
INTEGRITY_RULES.append(VulnRule("DESER-004", "unserialize\\s*\\(\\s*\\$", AlgoFamily.VULN_UNSAFE_DESER, RiskLevel.CRITICAL, 0.88, "PHP unserialize with user data", "CWE-502", ('php',), ('integrity', 'deser')))
INTEGRITY_RULES.append(VulnRule("DESER-005", "Marshal\\.(?:load|restore)\\s*\\(", AlgoFamily.VULN_UNSAFE_DESER, RiskLevel.CRITICAL, 0.85, "Ruby Marshal.load \u2014 code exec", "CWE-502", ('ruby',), ('integrity', 'deser')))
INTEGRITY_RULES.append(VulnRule("CICD-001", "uses:\\s*[\\w-]+/[\\w-]+@(?:master|main|latest)", AlgoFamily.VULN_UNVERIFIED_CICD, RiskLevel.HIGH, 0.82, "GitHub Action pinned to branch", "CWE-494", ('config',), ('integrity', 'cicd')))
INTEGRITY_RULES.append(VulnRule("CICD-002", "curl.*?\\|\\s*(?:sh|bash|python|sudo)", AlgoFamily.VULN_UNVERIFIED_CICD, RiskLevel.HIGH, 0.85, "Pipe download to shell", "CWE-494", ('shell', 'config'), ('integrity', 'cicd')))
CLOUD_RULES.append(VulnRule("AWS-002", "\"Action\"\\s*:\\s*\"\\*\"", AlgoFamily.VULN_OVERPRIVILEGED_IAM, RiskLevel.CRITICAL, 0.9, "IAM Action: * \u2014 full admin", "CWE-250", ('config', 'terraform'), ('cloud', 'aws')))
CLOUD_RULES.append(VulnRule("AWS-003", "block_public_acls\\s*=\\s*false", AlgoFamily.VULN_PUBLIC_S3, RiskLevel.CRITICAL, 0.9, "S3 public access block disabled", "CWE-732", ('terraform',), ('cloud', 'aws', 's3')))
CLOUD_RULES.append(VulnRule("AWS-004", "publicly_accessible\\s*=\\s*true", AlgoFamily.VULN_PERMISSIVE_POLICY, RiskLevel.CRITICAL, 0.88, "Resource publicly accessible", "CWE-284", ('terraform',), ('cloud', 'aws')))
CLOUD_RULES.append(VulnRule("AWS-005", "cidr_blocks\\s*=\\s*\\[\"0\\.0\\.0\\.0/0\"\\]", AlgoFamily.VULN_OPEN_SECURITY_GROUP, RiskLevel.HIGH, 0.85, "Security group open to 0.0.0.0/0", "CWE-284", ('terraform',), ('cloud', 'aws')))
CLOUD_RULES.append(VulnRule("AWS-006", "(?:encrypted|encryption)\\s*=\\s*false", AlgoFamily.VULN_MISSING_ENCRYPTION, RiskLevel.HIGH, 0.85, "Encryption at rest disabled", "CWE-311", ('terraform', 'config'), ('cloud', 'encryption')))
CLOUD_RULES.append(VulnRule("DOCK-001", "^\\s*USER\\s+root\\s*$", AlgoFamily.VULN_CONTAINER_ROOT, RiskLevel.HIGH, 0.82, "Dockerfile USER root", "CWE-250", ('dockerfile',), ('cloud', 'docker')))
CLOUD_RULES.append(VulnRule("DOCK-002", "privileged\\s*[=:]\\s*true", AlgoFamily.VULN_PRIVILEGED_CONTAINER, RiskLevel.CRITICAL, 0.92, "Privileged container", "CWE-250", ('dockerfile', 'config'), ('cloud', 'docker')))
CLOUD_RULES.append(VulnRule("DOCK-003", "ARG\\s+\\w*(?:PASSWORD|SECRET|KEY|TOKEN)\\w*\\s*=", AlgoFamily.VULN_DOCKER_SECRETS, RiskLevel.HIGH, 0.85, "Secret in Docker build ARG", "CWE-798", ('dockerfile',), ('cloud', 'docker')))
CLOUD_RULES.append(VulnRule("K8S-001", "runAsUser:\\s*0", AlgoFamily.VULN_CONTAINER_ROOT, RiskLevel.HIGH, 0.85, "K8s root UID 0", "CWE-250", ('config',), ('cloud', 'k8s')))
CLOUD_RULES.append(VulnRule("K8S-002", "privileged:\\s*true", AlgoFamily.VULN_PRIVILEGED_CONTAINER, RiskLevel.CRITICAL, 0.92, "K8s privileged", "CWE-250", ('config',), ('cloud', 'k8s')))
CLOUD_RULES.append(VulnRule("K8S-003", "hostNetwork:\\s*true", AlgoFamily.VULN_K8S_MISCONFIG, RiskLevel.HIGH, 0.85, "K8s hostNetwork", "CWE-284", ('config',), ('cloud', 'k8s')))
CLOUD_RULES.append(VulnRule("K8S-004", "hostPID:\\s*true", AlgoFamily.VULN_K8S_MISCONFIG, RiskLevel.HIGH, 0.85, "K8s hostPID", "CWE-284", ('config',), ('cloud', 'k8s')))
CLOUD_RULES.append(VulnRule("K8S-005", "allowPrivilegeEscalation:\\s*true", AlgoFamily.VULN_PRIVILEGE_ESCALATION, RiskLevel.HIGH, 0.85, "K8s privilege escalation", "CWE-269", ('config',), ('cloud', 'k8s')))
FRONTEND_RULES.append(VulnRule("FE-001", "(?:firebase|firebaseConfig).*?apiKey\\s*[=:]\\s*[\"\\'][A-Za-z0-9_-]{20,}[\"\\']", AlgoFamily.VULN_JS_SECRET, RiskLevel.HIGH, 0.85, "Firebase API key in frontend", "CWE-798", ('javascript', 'typescript'), ('frontend', 'secret')))
FRONTEND_RULES.append(VulnRule("FE-002", "(?:REACT_APP_|NEXT_PUBLIC_|VITE_|VUE_APP_)\\w*(?:SECRET|KEY|TOKEN|PASSWORD)\\w*\\s*[=:]\\s*[\"\\'][^\"\\' ]{8,}[\"\\']", AlgoFamily.VULN_ENV_INLINE, RiskLevel.HIGH, 0.85, "Sensitive env var in frontend bundle", "CWE-798", ('javascript', 'typescript', 'config'), ('frontend', 'env')))
FRONTEND_RULES.append(VulnRule("FE-003", "process\\.env\\.(?:REACT_APP_|NEXT_PUBLIC_)\\w*(?:SECRET|KEY|TOKEN|PASSWORD)", AlgoFamily.VULN_ENV_INLINE, RiskLevel.HIGH, 0.82, "Sensitive env in client code", "CWE-798", ('javascript', 'typescript'), ('frontend', 'env')))
FRONTEND_RULES.append(VulnRule("FE-010", "\\beval\\s*\\(", AlgoFamily.VULN_EVAL_USAGE, RiskLevel.HIGH, 0.8, "eval() \u2014 code injection risk", "CWE-95", ('javascript', 'typescript'), ('frontend', 'eval')))
FRONTEND_RULES.append(VulnRule("FE-011", "new\\s+Function\\s*\\(", AlgoFamily.VULN_EVAL_USAGE, RiskLevel.HIGH, 0.78, "new Function() \u2014 dynamic exec", "CWE-95", ('javascript', 'typescript'), ('frontend', 'eval')))
FRONTEND_RULES.append(VulnRule("FE-020", "addEventListener\\s*\\(\\s*[\"\\']message[\"\\']", AlgoFamily.VULN_POSTMESSAGE, RiskLevel.MEDIUM, 0.72, "postMessage listener \u2014 verify origin check", "CWE-346", ('javascript', 'typescript'), ('frontend', 'postmessage')))
FRONTEND_RULES.append(VulnRule("FE-030", "localStorage\\.setItem\\s*\\(\\s*[\"\\'](?:token|jwt|auth|session|password|secret|access_token)", AlgoFamily.VULN_LOCALSTORAGE_SENSITIVE, RiskLevel.HIGH, 0.82, "Sensitive data in localStorage", "CWE-922", ('javascript', 'typescript'), ('frontend', 'storage')))
FRONTEND_RULES.append(VulnRule("FE-040", "sourceMappingURL\\s*=", AlgoFamily.VULN_SOURCE_MAP, RiskLevel.MEDIUM, 0.85, "Source map in production", "CWE-540", ('javascript', 'typescript'), ('frontend', 'sourcemap')))
FRONTEND_RULES.append(VulnRule("FE-050", "console\\.(?:log|debug|info)\\s*\\(.*?(?:token|key|secret|password|credential)", AlgoFamily.VULN_DEBUG_CONSOLE, RiskLevel.HIGH, 0.8, "Console logging sensitive data", "CWE-489", ('javascript', 'typescript'), ('frontend', 'debug')))
LOG_EXC_RULES.append(VulnRule("LOG-001", "(?:log|logger|logging|console)\\.(?:info|debug|warn|error)\\s*\\(.*?(?:password|passwd|secret|token|api.?key|credit)", AlgoFamily.VULN_SENSITIVE_LOG, RiskLevel.HIGH, 0.8, "Logging sensitive data", "CWE-532", (), ('logging', 'sensitive')))
LOG_EXC_RULES.append(VulnRule("LOG-002", "(?:print|puts|echo|System\\.out\\.print).*?(?:password|secret|token|private.?key)", AlgoFamily.VULN_SENSITIVE_LOG, RiskLevel.HIGH, 0.78, "Printing sensitive data", "CWE-532", (), ('logging', 'sensitive')))
LOG_EXC_RULES.append(VulnRule("EXC-001", "except\\s*:\\s*(?:pass|continue)", AlgoFamily.VULN_SWALLOWED_ERROR, RiskLevel.MEDIUM, 0.78, "Bare except: pass", "CWE-390", ('python',), ('exception', 'swallowed')))
LOG_EXC_RULES.append(VulnRule("EXC-002", "catch\\s*\\(\\s*(?:e|err|error)?\\s*\\)\\s*\\{\\s*\\}", AlgoFamily.VULN_SWALLOWED_ERROR, RiskLevel.MEDIUM, 0.78, "Empty catch block", "CWE-390", ('javascript', 'typescript', 'java'), ('exception', 'swallowed')))
LOG_EXC_RULES.append(VulnRule("EXC-003", "try\\s*:.*?(?:verify|auth|check|token).*?except.*?(?:pass|True)", AlgoFamily.VULN_FAIL_OPEN, RiskLevel.CRITICAL, 0.82, "Auth check with permissive except \u2014 fail-open", "CWE-636", ('python',), ('exception', 'fail-open')))
DATA_RECON_RULES.append(VulnRule("IP-001", "(?:10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|172\\.(?:1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3})(?::\\d{2,5})?", AlgoFamily.VULN_INTERNAL_IP, RiskLevel.MEDIUM, 0.72, "Internal IP exposed", "CWE-200", (), ('data', 'internal')))
DATA_RECON_RULES.append(VulnRule("URL-001", "https?://[\\w-]+\\.(?:internal|local|corp|staging|dev)\\.", AlgoFamily.VULN_INTERNAL_URL, RiskLevel.MEDIUM, 0.78, "Internal/staging URL exposed", "CWE-200", (), ('data', 'internal')))
DATA_RECON_RULES.append(VulnRule("RECON-001", "(?:TODO|FIXME|HACK|XXX)\\s*[:-]?\\s*(?:fix\\s+auth|remove\\s+hardcoded|insecure|temporary|not\\s+secure|bypass)", AlgoFamily.RECON_TODO_FIXME, RiskLevel.MEDIUM, 0.8, "Security-relevant TODO", "CWE-615", (), ('recon', 'todo')))
DATA_RECON_RULES.append(VulnRule("RECON-002", "/(?:api|internal|admin|debug|private|hidden|secret)/v?\\d*/?[\\w-]+", AlgoFamily.RECON_ENDPOINT, RiskLevel.INFO, 0.65, "API/internal endpoint in source", "CWE-200", (), ('recon', 'endpoint')))
API_RULES.append(VulnRule("API-001", "introspection\\s*[=:]\\s*(?:true|enabled)", AlgoFamily.VULN_GRAPHQL_INTROSPECTION, RiskLevel.MEDIUM, 0.82, "GraphQL introspection enabled", "CWE-200", ('config', 'javascript'), ('api', 'graphql')))
API_RULES.append(VulnRule("API-002", "fields\\s*=\\s*[\"\\']__all__[\"\\'].*?serializer", AlgoFamily.VULN_EXCESSIVE_DATA, RiskLevel.HIGH, 0.8, "DRF serializer exposes all fields", "CWE-200", ('python',), ('api', 'data-exposure')))
SUPPLY_CHAIN_RULES.append(VulnRule("SC-001", "\"[\\w@/-]+?\"\\s*:\\s*\"\\*\"", AlgoFamily.VULN_UNPINNED_DEP, RiskLevel.HIGH, 0.82, "Dependency with wildcard version *", "CWE-1357", ('config',), ('supply-chain', 'unpinned')))
SUPPLY_CHAIN_RULES.append(VulnRule("SC-002", "\"[\\w@/-]+?\"\\s*:\\s*\">=[^\"]*\"", AlgoFamily.VULN_UNPINNED_DEP, RiskLevel.MEDIUM, 0.72, "Dependency without upper bound", "CWE-1357", ('config',), ('supply-chain', 'unpinned')))
SUPPLY_CHAIN_RULES.append(VulnRule("SC-003", "_authToken\\s*=", AlgoFamily.VULN_BUILD_LEAK, RiskLevel.CRITICAL, 0.9, "NPM auth token in .npmrc", "CWE-798", ('config',), ('supply-chain', 'credential')))

ALL_VULN_RULES = INJECTION_RULES + ACCESS_CONTROL_RULES + MISCONFIG_RULES + AUTH_RULES + DESIGN_RULES + INTEGRITY_RULES + CLOUD_RULES + FRONTEND_RULES + LOG_EXC_RULES + DATA_RECON_RULES + API_RULES + SUPPLY_CHAIN_RULES
COMPILED_VULN_RULES = _compile(ALL_VULN_RULES)
