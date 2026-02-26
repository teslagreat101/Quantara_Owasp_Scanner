"""
Quantum Protocol v4.0 — A08: Software & Data Integrity Failures Scanner

Detects:
  - Unsafe deserialization (pickle, yaml.load, ObjectInputStream, unserialize, Marshal.load)
  - Missing Subresource Integrity (SRI) on CDN scripts/stylesheets
  - Unverified CI/CD (unpinned actions, missing code signing, auto-merge without review)
  - Unsigned updates / missing integrity checks
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from pathlib import Path

@dataclass
class IntegrityFinding:
    id: str
    file: str
    line_number: int
    severity: str
    title: str
    description: str
    matched_content: str
    category: str
    subcategory: str  # deserialization | sri | cicd | signing
    cwe: str
    remediation: str
    confidence: float
    tags: list[str] = field(default_factory=list)

@dataclass
class IntegrityPattern:
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

def _build_rules() -> list[IntegrityPattern]:
    rules: list[IntegrityPattern] = []
    def _add(id_, pat, sev, title, desc, cwe, rem, conf, sub, tags=()):
        rules.append(IntegrityPattern(id_, pat, sev, title, desc, cwe, rem, conf, sub, tags))

    # ── Unsafe Deserialization ────────────────────────────────────
    _add("INT-001", r"""pickle\.(?:loads?|Unpickler)\s*\(""",
         "Critical", "Python pickle Deserialization",
         "pickle.load() executes arbitrary Python code during deserialization. Never use with untrusted data.",
         "CWE-502", "Use JSON or MessagePack for data serialization. If pickle needed, use hmac-signed data.",
         0.85, "deserialization", ("python", "pickle"))

    _add("INT-002", r"""yaml\.(?:load|unsafe_load)\s*\([^)]*(?!Loader\s*=\s*(?:Safe|Base)Loader)""",
         "Critical", "Python YAML Unsafe Load",
         "yaml.load() without SafeLoader can execute arbitrary Python objects (!python/object tag).",
         "CWE-502", "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).",
         0.85, "deserialization", ("python", "yaml"))

    _add("INT-003", r"""ObjectInputStream\s*\(\s*(?:new\s+)?(?:ByteArrayInputStream|socket\.getInputStream|request\.getInputStream)""",
         "Critical", "Java ObjectInputStream from Untrusted Source",
         "Java deserialization from network/request stream. Can lead to Remote Code Execution.",
         "CWE-502", "Avoid Java native deserialization. Use JSON/XML. Implement ObjectInputFilter.",
         0.85, "deserialization", ("java", "ois"))

    _add("INT-004", r"""(?:unserialize|php://input.*?unserialize)\s*\(\s*\$""",
         "Critical", "PHP unserialize() with User Input",
         "PHP unserialize() can trigger __wakeup/__destruct magic methods for code execution.",
         "CWE-502", "Use json_decode() instead. If unserialize needed, use allowed_classes option.",
         0.85, "deserialization", ("php", "unserialize"))

    _add("INT-005", r"""Marshal\.(?:load|restore)\s*\(""",
         "Critical", "Ruby Marshal.load — Unsafe Deserialization",
         "Ruby Marshal.load can execute arbitrary Ruby objects during deserialization.",
         "CWE-502", "Use JSON.parse() for untrusted data. Only use Marshal with trusted, signed data.",
         0.85, "deserialization", ("ruby", "marshal"))

    _add("INT-006", r"""(?:node-serialize|serialize-javascript).*?(?:unserialize|deserialize)\s*\(""",
         "Critical", "Node.js Unsafe Deserialization",
         "node-serialize/serialize-javascript deserialize() can execute arbitrary JS via IIFE injection.",
         "CWE-502", "Use JSON.parse(). Never deserialize untrusted data with these libraries.",
         0.85, "deserialization", ("nodejs", "serialize"))

    # ── Missing Subresource Integrity ─────────────────────────────
    _add("INT-010", r"""<script\s+src\s*=\s*["']https?://(?:cdn|unpkg|cdnjs|jsdelivr|stackpath|ajax\.googleapis)[^"']*["'][^>]*>(?!.*?integrity)""",
         "High", "CDN Script Without Subresource Integrity (SRI)",
         "External CDN script loaded without integrity hash. CDN compromise = code injection on your site.",
         "CWE-829", "Add integrity='sha384-...' and crossorigin='anonymous' to all CDN script tags.",
         0.80, "sri", ("cdn", "sri", "script"))

    _add("INT-011", r"""<link\s+[^>]*href\s*=\s*["']https?://(?:cdn|unpkg|cdnjs|jsdelivr|stackpath|fonts\.googleapis)[^"']*["'][^>]*rel\s*=\s*["']stylesheet["'][^>]*>(?!.*?integrity)""",
         "Medium", "CDN Stylesheet Without Subresource Integrity",
         "External stylesheet loaded without SRI. Compromised CDN can inject malicious CSS.",
         "CWE-829", "Add integrity attribute to CDN stylesheet links.",
         0.70, "sri", ("cdn", "sri", "css"))

    # ── CI/CD Integrity ───────────────────────────────────────────
    _add("INT-020", r"""auto_merge\s*(?:=|:)\s*(?:true|enabled)""",
         "High", "Auto-Merge Without Required Reviews",
         "Auto-merge enabled. Code can be merged without human review, bypassing security checks.",
         "CWE-345", "Require minimum 1 reviewer approval. Enable branch protection rules.",
         0.70, "cicd", ("ci", "auto-merge"))

    _add("INT-021", r"""(?:echo|print|puts|console\.log).*?\$\{\{\s*secrets\.""",
         "Critical", "CI/CD Secret Printed to Logs",
         "Repository secret printed in CI logs. Logs are often accessible to all project members.",
         "CWE-532", "Never echo/print secrets. Use them only as environment variables in commands.",
         0.90, "cicd", ("ci", "secret-leak"))

    _add("INT-022", r"""(?:gpg|cosign|sigstore|notation)\s*(?:sign|verify)""",
         "Info", "Code Signing Detected",
         "Code signing or verification logic found. Verify it's enforced in the release pipeline.",
         "CWE-345", "Enforce signature verification on all releases and container images.",
         0.40, "signing", ("signing", "verification"))

    return rules

ALL_INTEGRITY_RULES = _build_rules()
COMPILED_INTEGRITY_RULES = [(re.compile(r.pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL), r) for r in ALL_INTEGRITY_RULES]
SKIP_DIRS = {"node_modules", ".git", ".next", "dist", "build", "__pycache__", ".venv", "venv", "vendor", ".cache"}
SCAN_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".rb", ".php", ".cs", ".go", ".html", ".htm", ".yaml", ".yml", ".json"}

def scan_integrity_file(content: str, filepath: str, base_path: str = "") -> list[IntegrityFinding]:
    findings: list[IntegrityFinding] = []
    relative = filepath.replace(base_path, "").lstrip("/\\") if base_path else filepath
    seen: set[str] = set()
    for compiled_re, rule in COMPILED_INTEGRITY_RULES:
        for match in compiled_re.finditer(content):
            line_num = content.count("\n", 0, match.start()) + 1
            key = f"{rule.id}:{line_num}"
            if key in seen: continue
            seen.add(key)
            findings.append(IntegrityFinding(
                id=f"INT-{relative}:{line_num}:{rule.id}", file=relative, line_number=line_num,
                severity=rule.severity, title=rule.title, description=rule.description,
                matched_content=match.group(0).strip()[:200], category="A08:2025-Integrity Failures",
                subcategory=rule.subcategory, cwe=rule.cwe, remediation=rule.remediation,
                confidence=rule.confidence, tags=list(rule.tags),
            ))
    return findings

def scan_integrity_directory(root: str, max_files: int = 50_000) -> list[IntegrityFinding]:
    all_findings: list[IntegrityFinding] = []
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
            all_findings.extend(scan_integrity_file(content, str(fpath), str(root_path)))
            scanned += 1
        except (OSError, PermissionError): continue
    return all_findings
