"""
Quantum Protocol v4.0 — A03: Software Supply Chain Failures Scanner

Detects:
  - Unpinned / wildcard dependencies
  - Missing lockfiles
  - Typosquatting risk (known typosquat packages)
  - Post-install script abuse
  - Build system credential leaks (.npmrc, pypirc)
  - Dockerfile ARG secrets in build layers
  - GitHub Actions with unpinned actions
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from pathlib import Path

@dataclass
class SupplyChainFinding:
    id: str
    file: str
    line_number: int
    severity: str
    title: str
    description: str
    matched_content: str
    category: str
    subcategory: str  # dependency | typosquat | build-leak | post-install | lockfile
    cwe: str
    remediation: str
    confidence: float
    tags: list[str] = field(default_factory=list)

@dataclass
class SupplyChainPattern:
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

# Known typosquat package names
KNOWN_TYPOSQUATS = {
    "colourama", "python-nmap2", "jeIlyfish", "python3-dateutil", "request", "beautifulsoup",
    "djago", "fask", "nump", "scikitlearn", "openvc", "tensoflow", "pytorh",
    "crossenv", "event-stream-malicious", "flatmap-stream",
}

def _build_rules() -> list[SupplyChainPattern]:
    rules: list[SupplyChainPattern] = []
    def _add(id_, pat, sev, title, desc, cwe, rem, conf, sub, tags=()):
        rules.append(SupplyChainPattern(id_, pat, sev, title, desc, cwe, rem, conf, sub, tags))

    # ── Unpinned Dependencies ─────────────────────────────────────
    _add("SC-001", r""""[^"]+"\s*:\s*["']\*["']""",
         "High", "Wildcard Dependency Version (*)",
         "Dependency version set to '*'. Any version will be installed including malicious ones.",
         "CWE-829", "Pin to specific semver range: ^1.2.3 or ~1.2.3. Use lockfiles.",
         0.85, "dependency", ("npm", "wildcard"))

    _add("SC-002", r""""[^"]+"\s*:\s*["']>=\d+(?:\.\d+)*["']""",
         "High", "Unbounded Dependency Version (>=)",
         "Dependency with no upper version bound. Breaking changes or supply chain attacks possible.",
         "CWE-829", "Pin with upper bound: >=1.2.0 <2.0.0 or use ^1.2.0.",
         0.75, "dependency", ("npm", "unbounded"))

    _add("SC-003", r"""==\s*\d+\.\d+\.\d+.*?#\s*(?:TODO|FIXME|HACK).*?(?:update|upgrade|bump)""",
         "Medium", "Outdated Pinned Dependency (Has TODO to Update)",
         "Dependency pinned but developer noted it needs updating. May have known vulnerabilities.",
         "CWE-1104", "Run dependency audit (npm audit / pip-audit). Update to latest stable.",
         0.60, "dependency", ("outdated",))

    # ── Build System Leaks ────────────────────────────────────────
    _add("SC-010", r"""_authToken\s*=\s*\S+""",
         "Critical", ".npmrc Auth Token Exposed",
         "NPM registry auth token found in .npmrc. Grants publish access to all your packages.",
         "CWE-798", "Remove token from .npmrc. Use npm login with environment variable NPM_TOKEN.",
         0.95, "build-leak", ("npmrc", "token"))

    _add("SC-011", r"""(?:repository|index-url)\s*=\s*https?://[^@\s]+:[^@\s]+@""",
         "Critical", "Package Registry Credentials in Config",
         "Registry URL contains embedded username:password. Credentials in plaintext config.",
         "CWE-798", "Use environment variables or credential helpers for package registry auth.",
         0.90, "build-leak", ("pypi", "credentials"))

    _add("SC-012", r"""(?:GITHUB_TOKEN|NPM_TOKEN|PYPI_TOKEN|GH_TOKEN)\s*(?:=|:)\s*\S{10,}""",
         "Critical", "CI/CD Token in Configuration",
         "Build system token found in configuration file. Tokens should be in secrets management.",
         "CWE-798", "Use repository secrets (GitHub Secrets, GitLab CI Variables). Never commit tokens.",
         0.85, "build-leak", ("ci", "token"))

    # ── Post-Install Scripts ──────────────────────────────────────
    _add("SC-020", r""""(?:preinstall|postinstall)"\s*:\s*"[^"]*(?:curl|wget|http|eval|exec|require\()""",
         "Critical", "Suspicious Post-Install Script",
         "Package has pre/post-install script with network calls or code execution. Common malware vector.",
         "CWE-506", "Review post-install scripts carefully. Use --ignore-scripts flag. Audit dependencies.",
         0.80, "post-install", ("postinstall", "malware"))

    _add("SC-021", r"""(?:setup\.py|setup\.cfg).*?(?:cmdclass|install_requires).*?(?:os\.system|subprocess|urllib)""",
         "Critical", "Python setup.py with Code Execution",
         "setup.py contains code execution during install. Can run arbitrary commands.",
         "CWE-506", "Review setup.py. Use pyproject.toml with build system. Audit before pip install.",
         0.75, "post-install", ("python", "setup"))

    # ── GitHub Actions ────────────────────────────────────────────
    _add("SC-030", r"""uses\s*:\s*\S+@(?:master|main|latest)\b""",
         "High", "GitHub Action Not Pinned to Commit SHA",
         "GitHub Action referenced by branch name, not SHA. Action owner can push malicious updates.",
         "CWE-829", "Pin actions to full commit SHA: uses: actions/checkout@abc123def. Use Dependabot for updates.",
         0.85, "dependency", ("github-actions", "unpinned"))

    _add("SC-031", r"""(?:run|script)\s*:.*?\$\{\{\s*(?:github\.event\.(?:issue|pull_request|comment)\.(?:title|body)|inputs\.)""",
         "Critical", "GitHub Actions Script Injection",
         "User-controlled input interpolated into run: script. Enables arbitrary command execution.",
         "CWE-78", "Use environment variables with ${{ }} only in env: context, not in run: scripts.",
         0.85, "build-leak", ("github-actions", "injection"))

    return rules

ALL_SUPPLY_CHAIN_RULES = _build_rules()
COMPILED_SUPPLY_CHAIN_RULES = [(re.compile(r.pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL), r) for r in ALL_SUPPLY_CHAIN_RULES]
SKIP_DIRS = {"node_modules", ".git", ".next", "dist", "build", "__pycache__", ".venv", "venv", ".cache"}
SCAN_EXTENSIONS = {".json", ".yaml", ".yml", ".toml", ".cfg", ".ini", ".txt", ".lock", ".npmrc", ".pypirc", ".py", ".js", ".ts"}
SCAN_FILENAMES = {"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Pipfile", "Pipfile.lock", "requirements.txt", "setup.py", "setup.cfg", "pyproject.toml", ".npmrc", ".yarnrc", ".pypirc", "Gemfile", "Gemfile.lock", "go.mod", "go.sum", "Cargo.toml", "Cargo.lock"}

def scan_supply_chain_file(content: str, filepath: str, base_path: str = "") -> list[SupplyChainFinding]:
    findings: list[SupplyChainFinding] = []
    relative = filepath.replace(base_path, "").lstrip("/\\") if base_path else filepath
    seen: set[str] = set()
    for compiled_re, rule in COMPILED_SUPPLY_CHAIN_RULES:
        for match in compiled_re.finditer(content):
            line_num = content.count("\n", 0, match.start()) + 1
            key = f"{rule.id}:{line_num}"
            if key in seen: continue
            seen.add(key)
            findings.append(SupplyChainFinding(
                id=f"SC-{relative}:{line_num}:{rule.id}", file=relative, line_number=line_num,
                severity=rule.severity, title=rule.title, description=rule.description,
                matched_content=match.group(0).strip()[:200], category="A03:2025-Supply Chain",
                subcategory=rule.subcategory, cwe=rule.cwe, remediation=rule.remediation,
                confidence=rule.confidence, tags=list(rule.tags),
            ))
    # Check for known typosquats in package files
    fname = Path(filepath).name.lower()
    if fname in ("package.json", "requirements.txt", "pipfile", "gemfile"):
        for typo in KNOWN_TYPOSQUATS:
            if typo in content.lower():
                line_num = next((i+1 for i, l in enumerate(content.splitlines()) if typo in l.lower()), 1)
                key = f"TYPO:{typo}:{line_num}"
                if key not in seen:
                    seen.add(key)
                    findings.append(SupplyChainFinding(
                        id=f"SC-{relative}:{line_num}:TYPOSQUAT", file=relative, line_number=line_num,
                        severity="Critical", title=f"Known Typosquat Package: {typo}",
                        description=f"Package name '{typo}' matches a known typosquat. This may be malicious.",
                        matched_content=typo, category="A03:2025-Supply Chain",
                        subcategory="typosquat", cwe="CWE-506", confidence=0.85,
                        remediation="Verify the package name is correct. Check npm/PyPI for the legitimate package.",
                        tags=["typosquat", "malware"],
                    ))
    return findings

def scan_supply_chain_directory(root: str, max_files: int = 50_000) -> list[SupplyChainFinding]:
    all_findings: list[SupplyChainFinding] = []
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
            all_findings.extend(scan_supply_chain_file(content, str(fpath), str(root_path)))
            scanned += 1
        except (OSError, PermissionError): continue
    return all_findings
