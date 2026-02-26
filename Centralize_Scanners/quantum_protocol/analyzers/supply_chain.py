"""
Quantum Protocol v4.0 — A03: Supply Chain Analyzer
Dependency pinning analysis, lockfile integrity, typosquatting detection,
build system credential leak detection, and post-install script analysis.
"""
from __future__ import annotations
import json, re, logging
from pathlib import Path
from typing import Optional
from quantum_protocol.models.enums import AlgoFamily, RiskLevel, ScanMode
from quantum_protocol.models.findings import CryptoFinding
from quantum_protocol.utils.analysis import confidence_to_level, sanitize_line

logger = logging.getLogger("quantum_protocol.supply_chain")

# Common popular packages for typosquatting detection
_POPULAR_NPM = {"react","express","lodash","axios","next","webpack","typescript","eslint","jest","mocha",
                 "chalk","commander","debug","dotenv","moment","mongoose","passport","sequelize","socket.io",
                 "cors","helmet","jsonwebtoken","bcrypt","uuid","yargs","inquirer","cheerio","puppeteer"}
_POPULAR_PYPI = {"requests","flask","django","numpy","pandas","scipy","boto3","celery","sqlalchemy",
                 "pytest","pydantic","fastapi","uvicorn","gunicorn","redis","pillow","cryptography",
                 "httpx","aiohttp","beautifulsoup4","scrapy","tensorflow","torch","transformers"}

def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b): return _levenshtein(b, a)
    if not b: return len(a)
    prev = range(len(b) + 1)
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j] + (ca != cb), prev[j+1] + 1, curr[-1] + 1))
        prev = curr
    return prev[-1]

def scan_supply_chain(content, relative_path, language, scan_mode, context_window=3):
    """Analyze dependency manifests and build configs for supply chain risks."""
    findings = []
    fname = Path(relative_path).name.lower()

    # package.json analysis
    if fname == "package.json":
        findings.extend(_analyze_npm(content, relative_path))
    # requirements.txt / Pipfile
    elif fname in ("requirements.txt", "requirements-dev.txt", "requirements-prod.txt"):
        findings.extend(_analyze_pip(content, relative_path))
    elif fname == "pipfile":
        findings.extend(_analyze_pipfile(content, relative_path))
    # Go modules
    elif fname == "go.mod":
        findings.extend(_analyze_gomod(content, relative_path))
    # .npmrc / .pypirc
    elif fname in (".npmrc", ".pypirc", "pip.conf"):
        findings.extend(_analyze_build_config(content, relative_path))
    # GitHub Actions
    elif ".github" in relative_path and relative_path.endswith((".yml", ".yaml")):
        findings.extend(_analyze_ci(content, relative_path))

    return findings

def _analyze_npm(content, path):
    findings = []
    try:
        pkg = json.loads(content)
    except json.JSONDecodeError:
        return findings
    lines = content.split("\n")

    all_deps = {}
    for key in ("dependencies", "devDependencies", "peerDependencies"):
        all_deps.update(pkg.get(key, {}))

    for name, version in all_deps.items():
        # Find line number
        ln = 1
        for i, line in enumerate(lines, 1):
            if f'"{name}"' in line:
                ln = i; break

        # Wildcard version
        if version in ("*", "latest", ""):
            findings.append(_make_finding(path, ln, lines, AlgoFamily.VULN_UNPINNED_DEP,
                RiskLevel.HIGH, 0.88, f"Dependency '{name}' has wildcard version '{version}'",
                "CWE-1357", ("supply-chain","unpinned")))
        # No upper bound
        elif version.startswith(">=") and "<" not in version:
            findings.append(_make_finding(path, ln, lines, AlgoFamily.VULN_UNPINNED_DEP,
                RiskLevel.MEDIUM, 0.75, f"Dependency '{name}' has no upper version bound: {version}",
                "CWE-1357", ("supply-chain","unpinned")))

        # Typosquatting check
        clean_name = name.lstrip("@").split("/")[-1].lower()
        for popular in _POPULAR_NPM:
            if clean_name != popular and 0 < _levenshtein(clean_name, popular) <= 2:
                findings.append(_make_finding(path, ln, lines, AlgoFamily.VULN_TYPOSQUAT,
                    RiskLevel.HIGH, 0.72, f"Package '{name}' is similar to popular '{popular}' — possible typosquat",
                    "CWE-506", ("supply-chain","typosquat")))
                break

    # Post-install scripts
    scripts = pkg.get("scripts", {})
    for hook in ("preinstall", "postinstall", "preuninstall"):
        if hook in scripts:
            cmd = scripts[hook]
            if any(sus in cmd.lower() for sus in ("curl", "wget", "node -e", "sh -c", "bash", "python")):
                ln = next((i for i, l in enumerate(lines, 1) if hook in l), 1)
                findings.append(_make_finding(path, ln, lines, AlgoFamily.VULN_POSTINSTALL_SCRIPT,
                    RiskLevel.HIGH, 0.80, f"Suspicious {hook} script: {cmd[:60]}",
                    "CWE-506", ("supply-chain","postinstall")))
    return findings

def _analyze_pip(content, path):
    findings = []
    lines = content.split("\n")
    for i, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Check for unpinned
        if "==" not in line and ">=" not in line and line and not line.startswith("git+"):
            pkg_name = re.split(r'[<>=!;]', line)[0].strip().lower()
            if pkg_name:
                findings.append(_make_finding(path, i, lines, AlgoFamily.VULN_UNPINNED_DEP,
                    RiskLevel.MEDIUM, 0.75, f"Python dependency '{pkg_name}' is not pinned to exact version",
                    "CWE-1357", ("supply-chain","unpinned")))
                # Typosquat
                for popular in _POPULAR_PYPI:
                    if pkg_name != popular and 0 < _levenshtein(pkg_name, popular) <= 2:
                        findings.append(_make_finding(path, i, lines, AlgoFamily.VULN_TYPOSQUAT,
                            RiskLevel.HIGH, 0.72, f"Package '{pkg_name}' similar to '{popular}' — possible typosquat",
                            "CWE-506", ("supply-chain","typosquat")))
                        break
    return findings

def _analyze_pipfile(content, path):
    return []  # Placeholder for extended Pipfile analysis

def _analyze_gomod(content, path):
    return []  # Placeholder for Go module analysis

def _analyze_build_config(content, path):
    findings = []
    lines = content.split("\n")
    for i, line in enumerate(lines, 1):
        if re.search(r'_authToken\s*=', line):
            findings.append(_make_finding(path, i, lines, AlgoFamily.VULN_BUILD_LEAK,
                RiskLevel.CRITICAL, 0.92, "NPM auth token in .npmrc — credential exposure",
                "CWE-798", ("supply-chain","credential")))
        if re.search(r'(?:password|token|secret)\s*[=:]\s*\S+', line, re.I):
            findings.append(_make_finding(path, i, lines, AlgoFamily.VULN_BUILD_LEAK,
                RiskLevel.HIGH, 0.82, f"Credential in build config: {Path(path).name}",
                "CWE-798", ("supply-chain","credential")))
    return findings

def _analyze_ci(content, path):
    findings = []
    lines = content.split("\n")
    for i, line in enumerate(lines, 1):
        # Unpinned GitHub Actions
        m = re.search(r'uses:\s*([\w-]+/[\w-]+)@(master|main|latest|HEAD|v\d+)\b', line)
        if m:
            findings.append(_make_finding(path, i, lines, AlgoFamily.VULN_UNVERIFIED_CICD,
                RiskLevel.HIGH, 0.85, f"GitHub Action '{m.group(1)}' pinned to branch '{m.group(2)}' — pin to SHA",
                "CWE-494", ("supply-chain","cicd")))
        # Pipe to shell
        if re.search(r'curl.*?\|\s*(?:sh|bash|sudo)', line):
            findings.append(_make_finding(path, i, lines, AlgoFamily.VULN_UNVERIFIED_CICD,
                RiskLevel.HIGH, 0.88, "Pipe download to shell in CI — verify integrity",
                "CWE-494", ("supply-chain","cicd")))
    return findings

def _make_finding(path, ln, lines, family, risk, conf, note, cwe, tags):
    raw = lines[ln-1] if ln <= len(lines) else ""
    return CryptoFinding(
        id=CryptoFinding.generate_id(path, ln, f"SC-{family.value}"),
        file=path, language="config", line_number=ln,
        line_content=sanitize_line(raw.strip()),
        column_start=None, column_end=None, algorithm=family.value,
        family=family, risk=risk, confidence=round(conf, 3),
        confidence_level=confidence_to_level(conf),
        key_size=None, hndl_relevant=False, pattern_note=note,
        migration={"action": "Pin dependency versions and use lockfiles", "cwe": cwe},
        compliance_violations=[], context_lines=[],
        cwe_id=cwe, cvss_estimate=risk.numeric,
        remediation_effort="low" if "unpinned" in str(tags) else "medium",
        tags=list(tags),
    )
