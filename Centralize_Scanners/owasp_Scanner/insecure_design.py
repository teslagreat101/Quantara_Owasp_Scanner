"""
Quantum Protocol v4.0 — A06: Insecure Design Scanner

Detects:
  - Missing rate limiting on auth/login endpoints
  - Missing CSRF protection (csrf_exempt, no CSRF tokens)
  - Mass assignment / over-posting (Model.create(req.body), fields='__all__', params.permit!)
  - Missing CAPTCHA on registration/password-reset
  - Business logic issues (price manipulation, quantity bypass)
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from pathlib import Path

@dataclass
class DesignFinding:
    id: str
    file: str
    line_number: int
    severity: str
    title: str
    description: str
    matched_content: str
    category: str
    subcategory: str  # rate-limit | csrf | mass-assignment | captcha | business-logic
    cwe: str
    remediation: str
    confidence: float
    tags: list[str] = field(default_factory=list)

@dataclass
class DesignPattern:
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

def _build_rules() -> list[DesignPattern]:
    rules: list[DesignPattern] = []
    def _add(id_, pat, sev, title, desc, cwe, rem, conf, sub, tags=()):
        rules.append(DesignPattern(id_, pat, sev, title, desc, cwe, rem, conf, sub, tags))

    # ── Missing Rate Limiting ─────────────────────────────────────
    _add("ID-001", r"""(?:@app\.(?:route|post)|router\.(?:post|put))\s*\(\s*["'].*?(?:login|signin|sign-in|authenticate|auth|register|signup|sign-up|forgot|reset)""",
         "High", "Auth Endpoint — Verify Rate Limiting",
         "Authentication endpoint detected. Verify rate limiting is applied to prevent brute force attacks.",
         "CWE-307", "Add rate limiting: express-rate-limit (5 req/min), Django ratelimit, Spring @RateLimiter.",
         0.55, "rate-limit", ("rate-limit", "auth"))

    _add("ID-002", r"""(?:express-rate-limit|RateLimiter|ratelimit|throttle|Throttle)""",
         "Info", "Rate Limiting Implementation Found",
         "Rate limiting library/decorator detected. Verify it covers all sensitive endpoints.",
         "CWE-307", "Ensure rate limiting covers: login, registration, password reset, API endpoints.",
         0.30, "rate-limit", ("rate-limit",))

    # ── CSRF Protection ───────────────────────────────────────────
    _add("ID-010", r"""@csrf_exempt""",
         "High", "Django @csrf_exempt — CSRF Protection Disabled",
         "CSRF protection explicitly exempted on this view. State-changing operations are vulnerable.",
         "CWE-352", "Remove @csrf_exempt. Use CSRF tokens or token-based auth (JWT) instead.",
         0.85, "csrf", ("csrf", "django"))

    _add("ID-011", r"""(?:CSRF_ENABLED|WTF_CSRF_ENABLED|csrf)\s*(?:=|:)\s*(?:False|false|0|disabled)""",
         "Critical", "CSRF Protection Globally Disabled",
         "CSRF protection disabled application-wide. All state-changing operations are vulnerable.",
         "CWE-352", "Enable CSRF protection. Use csrf_token in all forms. Set SameSite cookie flag.",
         0.90, "csrf", ("csrf", "disabled"))

    _add("ID-012", r"""SameSite\s*(?:=|:)\s*["']?None""",
         "High", "SameSite=None on Cookies — CSRF Risk",
         "SameSite=None allows cross-site cookie transmission, enabling CSRF attacks.",
         "CWE-352", "Set SameSite=Strict or Lax for session cookies.",
         0.75, "csrf", ("csrf", "samesite"))

    # ── Mass Assignment ───────────────────────────────────────────
    _add("ID-020", r"""\.create\s*\(\s*(?:req\.body|request\.(?:data|json|POST)|params\b)""",
         "Critical", "Mass Assignment — Direct Request to Model.create()",
         "All request fields passed to model create(). Attacker can set admin=true, role='admin'.",
         "CWE-915", "Use allowlist: Model.create({name: req.body.name, email: req.body.email}).",
         0.80, "mass-assignment", ("mass-assignment",))

    _add("ID-021", r"""fields\s*=\s*["']__all__["']""",
         "High", "Django ModelForm fields='__all__' — Over-Posting Risk",
         "All model fields included in form. Users can modify fields they shouldn't have access to.",
         "CWE-915", "Explicitly list fields: fields = ['name', 'email']. Exclude sensitive fields.",
         0.85, "mass-assignment", ("django", "form"))

    _add("ID-022", r"""params\.permit\s*!""",
         "Critical", "Rails permit! — All Parameters Allowed",
         "params.permit! bypasses strong parameters. All user-submitted fields are mass-assignable.",
         "CWE-915", "Use specific permits: params.require(:user).permit(:name, :email).",
         0.90, "mass-assignment", ("rails", "permit"))

    _add("ID-023", r"""@(?:JsonIgnore|Transient)\b""",
         "Info", "Sensitive Field Annotation Found",
         "@JsonIgnore/@Transient detected. Verify all sensitive fields are annotated.",
         "CWE-915", "Apply @JsonIgnore to all sensitive fields: password, salt, internalId, etc.",
         0.35, "mass-assignment", ("java", "annotation"))

    # ── Missing CAPTCHA ───────────────────────────────────────────
    _add("ID-030", r"""(?:register|signup|sign_up|forgot_password|reset_password)\s*(?:\(|=)(?!.*?(?:captcha|recaptcha|hcaptcha|turnstile))""",
         "Medium", "Registration/Password Reset Without CAPTCHA",
         "Auth form without CAPTCHA. Automated attacks can spam accounts or abuse password reset.",
         "CWE-799", "Add CAPTCHA (reCAPTCHA, hCaptcha, Cloudflare Turnstile) to registration and reset forms.",
         0.50, "captcha", ("captcha", "registration"))

    # ── Business Logic ────────────────────────────────────────────
    _add("ID-040", r"""(?:price|amount|total|cost|quantity)\s*=\s*(?:req|request|params|input)""",
         "High", "User-Controlled Price/Amount — Business Logic Risk",
         "Price or quantity derived directly from user input. Attacker can set price=0.01.",
         "CWE-840", "Calculate prices server-side from product catalog. Never trust client-supplied amounts.",
         0.65, "business-logic", ("price", "manipulation"))

    _add("ID-041", r"""(?:coupon|discount|promo)\s*(?:=|:)\s*(?:req|request|params)""",
         "Medium", "User-Supplied Coupon/Discount Without Validation",
         "Discount code applied from user input without apparent server-side validation.",
         "CWE-840", "Validate coupons server-side. Check expiry, usage limits, and eligibility.",
         0.55, "business-logic", ("coupon", "discount"))

    return rules

ALL_DESIGN_RULES = _build_rules()
COMPILED_DESIGN_RULES = [(re.compile(r.pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL), r) for r in ALL_DESIGN_RULES]
SKIP_DIRS = {"node_modules", ".git", ".next", "dist", "build", "__pycache__", ".venv", "venv", "vendor", ".cache"}
SCAN_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php", ".cs", ".html", ".vue", ".svelte"}

def scan_design_file(content: str, filepath: str, base_path: str = "") -> list[DesignFinding]:
    findings: list[DesignFinding] = []
    relative = filepath.replace(base_path, "").lstrip("/\\") if base_path else filepath
    seen: set[str] = set()
    for compiled_re, rule in COMPILED_DESIGN_RULES:
        for match in compiled_re.finditer(content):
            line_num = content.count("\n", 0, match.start()) + 1
            key = f"{rule.id}:{line_num}"
            if key in seen: continue
            seen.add(key)
            findings.append(DesignFinding(
                id=f"ID-{relative}:{line_num}:{rule.id}", file=relative, line_number=line_num,
                severity=rule.severity, title=rule.title, description=rule.description,
                matched_content=match.group(0).strip()[:200], category="A06:2025-Insecure Design",
                subcategory=rule.subcategory, cwe=rule.cwe, remediation=rule.remediation,
                confidence=rule.confidence, tags=list(rule.tags),
            ))
    return findings

def scan_design_directory(root: str, max_files: int = 50_000) -> list[DesignFinding]:
    all_findings: list[DesignFinding] = []
    root_path = Path(root)
    scanned = 0
    for fpath in root_path.rglob("*"):
        if scanned >= max_files: break
        if fpath.is_dir(): continue
        if any(s in fpath.parts for s in SKIP_DIRS): continue
        if fpath.suffix.lower() not in SCAN_EXTENSIONS: continue
        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
            if len(content) > 5_000_000: continue
            all_findings.extend(scan_design_file(content, str(fpath), str(root_path)))
            scanned += 1
        except (OSError, PermissionError): continue
    return all_findings
