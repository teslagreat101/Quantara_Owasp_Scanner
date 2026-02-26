"""
Quantum Protocol v3.5 — Core Scanner Engine

The central orchestrator that:
  1. Walks directory trees with intelligent filtering
  2. Dispatches to regex pattern matcher + semantic analyzers
  3. *** SECRETS & CREDENTIALS DETECTION (120+ provider patterns) ***
  4. *** ENTROPY-BASED SECRET DISCOVERY (Shannon + Chi-squared) ***
  5. *** CONTEXT-AWARE FALSE POSITIVE FILTERING ***
  6. *** ATTACK SURFACE MAPPING ***
  7. Aggregates findings with deduplication
  8. Computes risk scores, agility metrics, secrets exposure scores
  9. Generates compliance mappings (OWASP Top 10, PCI-DSS 4.0, GDPR)
  10. Supports incremental / diff-based scanning
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
import tempfile
import time
import zipfile
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import urlparse

try:
    import git
    GIT_AVAILABLE = True
except ImportError:
    GIT_AVAILABLE = False

from quantum_protocol.models.enums import (
    AlgoFamily, ComplianceFramework, ConfidenceLevel, PQC_REPLACEMENTS,
    RiskLevel, ScanMode, COMPLIANCE_VIOLATIONS, SKIP_DIRS,
    MAX_FILE_SIZE_BYTES, SECRETS_REMEDIATION,
)
from quantum_protocol.models.findings import (
    CryptoFinding, CWE_MAP, FileReport, ScanSummary,
    estimate_remediation_effort,
)
from quantum_protocol.rules.patterns import COMPILED_RULES, PatternRule
from quantum_protocol.analyzers.semantic import (
    ast_scan_python, scan_certificate, scan_dependency_manifest,
)
from quantum_protocol.analyzers.secrets_engine import (
    COMPILED_SECRET_RULES, SecretRule, VALIDATORS,
    is_likely_false_positive_path, redact_secret,
    shannon_entropy, entropy_confidence_boost, is_high_entropy,
)
from quantum_protocol.utils.analysis import (
    confidence_to_level, detect_language, extract_key_size,
    key_size_risk, sanitize_line,
)

logger = logging.getLogger("quantum_protocol.scanner")

MANIFEST_FILES = {
    "requirements.txt", "pipfile", "pyproject.toml", "setup.py", "setup.cfg",
    "package.json", "package-lock.json", "yarn.lock",
    "go.mod", "go.sum",
    "cargo.toml", "cargo.lock",
    "pom.xml", "build.gradle", "build.gradle.kts",
    "gemfile", "gemfile.lock",
    "composer.json", "composer.lock",
}

# Attack surface category map — tags secret findings for ASM
ATTACK_SURFACE_MAP: dict[str, str] = {
    "cloud":       "Cloud Infrastructure",
    "aws":         "Cloud Infrastructure (AWS)",
    "gcp":         "Cloud Infrastructure (GCP)",
    "azure":       "Cloud Infrastructure (Azure)",
    "payment":     "Payment Processing",
    "stripe":      "Payment Processing (Stripe)",
    "database":    "Database & Data Stores",
    "postgres":    "Database (PostgreSQL)",
    "mysql":       "Database (MySQL)",
    "mongodb":     "Database (MongoDB)",
    "redis":       "Cache/Session Store (Redis)",
    "cicd":        "CI/CD Pipeline",
    "github":      "Source Control (GitHub)",
    "gitlab":      "Source Control (GitLab)",
    "docker":      "Container Registry",
    "npm":         "Package Registry (NPM)",
    "pypi":        "Package Registry (PyPI)",
    "saas":        "SaaS Integration",
    "slack":       "Communication (Slack)",
    "auth":        "Authentication & Identity",
    "jwt":         "Authentication (JWT)",
    "oauth":       "Authentication (OAuth)",
    "infra":       "Infrastructure & SSH",
    "ssh":         "Infrastructure (SSH)",
    "tls":         "Infrastructure (TLS/SSL)",
    "monitoring":  "Monitoring & Observability",
    "ai":          "AI/ML Services",
    "generic":     "General Credentials",
}


def _resolve_attack_surface(tags: tuple[str, ...]) -> str:
    """Determine attack surface category from secret rule tags."""
    for tag in tags:
        if tag in ATTACK_SURFACE_MAP:
            return ATTACK_SURFACE_MAP[tag]
    return "General Credentials"


def _resolve_secret_type(family: AlgoFamily) -> str:
    """Determine human-readable secret type from family."""
    val = family.value
    if "Key" in val or "Token" in val: return "API Key / Token"
    if "Credential" in val: return "Credential"
    if "Password" in val: return "Password"
    if "Connection-String" in val or "PostgreSQL" in val or "MySQL" in val or "MongoDB" in val:
        return "Database Credential"
    if "Private-Key" in val or "SSH" in val or "PGP" in val or "SSL" in val:
        return "Private Key"
    if "DSN" in val: return "Service Endpoint"
    if "JWT" in val: return "Authentication Token"
    if "Session" in val or "Cookie" in val: return "Session Secret"
    if "Entropy" in val: return "Suspected Secret (entropy)"
    return "Secret"


# ────────────────────────────────────────────────────────────────────────────
# Single File Scanner — All Layers
# ────────────────────────────────────────────────────────────────────────────

def scan_file(
    path: Path,
    base_path: Path,
    scan_mode: ScanMode = ScanMode.FULL,
    context_window: int = 5,
) -> list[CryptoFinding]:
    """
    Scan a single file through all analysis layers.

    Layers:
      1. Certificate deep scan (for .pem/.crt/.cer files)
      2. Dependency manifest scan
      3. Python AST semantic analysis
      4. Crypto regex pattern matching (200+ rules)
      5. *** SECRETS & CREDENTIALS SCAN (120+ provider patterns) ***
      6. *** HIGH-ENTROPY STRING DETECTION ***
    """
    findings: list[CryptoFinding] = []
    relative = str(path.relative_to(base_path))
    language = detect_language(path)

    if language is None:
        return findings

    try:
        file_size = path.stat().st_size
    except OSError:
        return findings

    if file_size > MAX_FILE_SIZE_BYTES or file_size == 0:
        return findings

    try:
        raw = path.read_bytes()
    except OSError:
        return findings

    # ── Layer 1: Certificate deep scan ───────────────────────────────
    if language == "cert":
        for cm in scan_certificate(raw, relative):
            family = cm.get("family_hint") or AlgoFamily.CERT_ISSUE
            migration = PQC_REPLACEMENTS.get(family, {"notes": "Review certificate algorithm."})
            cwe = CWE_MAP.get(family)
            compliance = [fw.value for fw in COMPLIANCE_VIOLATIONS.get(family, [])]
            findings.append(CryptoFinding(
                id=CryptoFinding.generate_id(relative, cm.get("line", 1), str(family)),
                file=relative, language=language,
                line_number=cm.get("line", 1),
                line_content=str(cm.get("note", ""))[:200],
                column_start=None, column_end=None,
                algorithm=family.value if isinstance(family, AlgoFamily) else str(family),
                family=family if isinstance(family, AlgoFamily) else AlgoFamily.CERT_ISSUE,
                risk=cm.get("risk", RiskLevel.CRITICAL),
                confidence=0.98,
                confidence_level=ConfidenceLevel.CONFIRMED,
                key_size=cm.get("key_size"),
                hndl_relevant=True,
                pattern_note=str(cm.get("note", "")),
                migration=migration,
                compliance_violations=compliance,
                context_lines=[],
                cwe_id=cwe[0] if cwe else None,
                remediation_effort=estimate_remediation_effort(family),
            ))
        return findings

    # Decode text content
    try:
        content = raw.decode("utf-8", errors="ignore")
    except Exception:
        return findings

    lines = content.splitlines()
    seen: set[str] = set()

    # Determine if this file is in a test/example path (for false-positive reduction)
    is_fp_path = is_likely_false_positive_path(relative)

    # ── Layer 2: Dependency manifest scan ────────────────────────────
    if path.name.lower() in MANIFEST_FILES:
        for dm in scan_dependency_manifest(content, path.name):
            family = dm.get("family_hint") or AlgoFamily.PROTOCOL
            findings.append(CryptoFinding(
                id=CryptoFinding.generate_id(relative, dm.get("line", 1), "dep"),
                file=relative, language="config",
                line_number=dm.get("line", 1),
                line_content=sanitize_line(
                    lines[dm.get("line", 1) - 1].strip() if dm.get("line", 1) <= len(lines) else ""
                ),
                column_start=None, column_end=None,
                algorithm="Dependency",
                family=family if isinstance(family, AlgoFamily) else AlgoFamily.PROTOCOL,
                risk=dm.get("risk", RiskLevel.MEDIUM),
                confidence=0.70,
                confidence_level=ConfidenceLevel.MEDIUM,
                key_size=None, hndl_relevant=False,
                pattern_note=dm.get("note", ""),
                migration=PQC_REPLACEMENTS.get(family, {}),
                compliance_violations=[],
                context_lines=[],
                remediation_effort="medium",
                tags=["dependency"],
            ))

    # ── Layer 3: Python AST semantic analysis ────────────────────────
    ast_meta: dict[int, dict] = {}
    if language == "python" and scan_mode != ScanMode.SECRETS:
        for m in ast_scan_python(content, relative):
            ast_meta[m["line"]] = m

    # ── Layer 4: Crypto regex pattern matching ───────────────────────
    if scan_mode != ScanMode.SECRETS:  # skip crypto patterns in secrets-only mode
        for compiled_re, rule in COMPILED_RULES:
            if rule.language_hint and rule.language_hint != language:
                continue
            if scan_mode == ScanMode.QUICK and rule.confidence < 0.80:
                continue
            if scan_mode == ScanMode.QUANTUM and not rule.family.is_quantum_broken:
                continue

            for match in compiled_re.finditer(content):
                line_no = content[:match.start()].count("\n") + 1
                col_start = match.start() - content.rfind("\n", 0, match.start()) - 1
                col_end = col_start + len(match.group())

                dedup_key = f"{relative}:{line_no}:{rule.family.value}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                ctx_start = max(0, line_no - context_window - 1)
                ctx_end = min(len(lines), line_no + context_window)
                ctx_lines = lines[ctx_start:ctx_end]
                raw_line = lines[line_no - 1] if line_no <= len(lines) else ""

                ctx_text = "\n".join(ctx_lines)
                ks = extract_key_size(raw_line, ctx_text) if rule.extract_key_size else None

                # Risk determination
                if rule.family == AlgoFamily.AGILITY:
                    risk = RiskLevel.INFO
                elif rule.family.is_pqc_safe:
                    risk = RiskLevel.INFO
                elif rule.family == AlgoFamily.PROTOCOL:
                    risk = RiskLevel.HIGH
                elif rule.family in (AlgoFamily.HARDCODED_KEY, AlgoFamily.HARDCODED_CERT):
                    risk = RiskLevel.CRITICAL
                elif rule.family == AlgoFamily.WEAK_RANDOM:
                    risk = RiskLevel.HIGH
                else:
                    risk, _ = key_size_risk(rule.family, ks)

                confidence = rule.confidence
                if line_no in ast_meta:
                    confidence = min(1.0, confidence + ast_meta[line_no].get("confidence_boost", 0.05))

                migration = PQC_REPLACEMENTS.get(rule.family, {
                    "notes": "Consult NIST SP 800-227 for migration guidance.",
                })
                cwe = CWE_MAP.get(rule.family)
                cwe_id = rule.cwe or (cwe[0] if cwe else None)
                compliance = [fw.value for fw in COMPLIANCE_VIOLATIONS.get(rule.family, [])]

                findings.append(CryptoFinding(
                    id=CryptoFinding.generate_id(relative, line_no, rule.family.value),
                    file=relative, language=language or "unknown",
                    line_number=line_no,
                    line_content=sanitize_line(raw_line.strip()),
                    column_start=col_start, column_end=col_end,
                    algorithm=rule.family.value, family=rule.family,
                    risk=risk,
                    confidence=round(confidence, 3),
                    confidence_level=confidence_to_level(confidence),
                    key_size=ks, hndl_relevant=rule.hndl_relevant,
                    pattern_note=rule.note,
                    migration=migration,
                    compliance_violations=compliance,
                    context_lines=[sanitize_line(l) for l in ctx_lines],
                    cwe_id=cwe_id,
                    cvss_estimate=_estimate_cvss(rule.family, risk, ks),
                    remediation_effort=estimate_remediation_effort(rule.family),
                    tags=list(rule.tags),
                ))

    # ══════════════════════════════════════════════════════════════════
    # ═══  Layer 5: SECRETS & CREDENTIALS DETECTION ENGINE  ═══════════
    # ══════════════════════════════════════════════════════════════════
    #
    # This layer runs the 120+ provider-specific patterns from
    # secrets_engine.py, with entropy analysis, context-aware FP
    # reduction, validation functions, and attack surface mapping.
    #
    if scan_mode in (ScanMode.FULL, ScanMode.SECRETS, ScanMode.COMPLIANCE):
        _scan_secrets(
            content=content,
            lines=lines,
            relative=relative,
            language=language or "unknown",
            is_fp_path=is_fp_path,
            seen=seen,
            findings=findings,
            context_window=context_window,
            scan_mode=scan_mode,
        )

    return findings


def _scan_secrets(
    content: str,
    lines: list[str],
    relative: str,
    language: str,
    is_fp_path: bool,
    seen: set[str],
    findings: list[CryptoFinding],
    context_window: int,
    scan_mode: ScanMode,
) -> None:
    """
    Layer 5: Secrets & Credentials Detection

    Process:
    1. Run each compiled secret rule against the file content
    2. Extract the matched secret value (named group or full match)
    3. Run validation functions (placeholder rejection, entropy checks, format checks)
    4. Apply false-positive path confidence discount
    5. Apply entropy-based confidence boosting
    6. Map to attack surface category
    7. Build remediation guidance from SECRETS_REMEDIATION
    8. Create CryptoFinding with is_secret=True, provider, attack surface
    """
    for compiled_re, rule in COMPILED_SECRET_RULES:
        for match in compiled_re.finditer(content):
            line_no = content[:match.start()].count("\n") + 1
            col_start = match.start() - content.rfind("\n", 0, match.start()) - 1
            col_end = col_start + len(match.group())
            raw_line = lines[line_no - 1] if line_no <= len(lines) else ""

            # Deduplication
            dedup_key = f"{relative}:{line_no}:{rule.family.value}:{rule.id}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            # Extract the secret value for validation
            try:
                secret_value = match.group("secret")
            except IndexError:
                secret_value = match.group(0)

            if not secret_value or len(secret_value) < 4:
                continue

            # ── Validation pass ──────────────────────────────────────
            if rule.validator:
                validator_fn = VALIDATORS.get(rule.validator)
                if validator_fn:
                    # For "not_placeholder" and "min_entropy", pass the secret value
                    # For "not_test_context", pass the full line
                    if rule.validator == "not_test_context":
                        if not validator_fn(raw_line):
                            continue
                    elif rule.validator == "aws_key_format":
                        if not validator_fn(secret_value):
                            continue
                    else:
                        if not validator_fn(secret_value):
                            continue

            # ── Confidence calibration ───────────────────────────────
            confidence = rule.confidence

            # Entropy boost: high-entropy secrets get confidence bump
            ent_boost = entropy_confidence_boost(secret_value)
            confidence = min(1.0, confidence + ent_boost)

            # False-positive path discount
            if is_fp_path:
                confidence *= 0.5  # halve confidence for test/example files

            # Low-confidence cut-off
            if confidence < 0.30:
                continue

            # ── Context extraction ───────────────────────────────────
            ctx_start = max(0, line_no - context_window - 1)
            ctx_end = min(len(lines), line_no + context_window)
            ctx_lines = lines[ctx_start:ctx_end]

            # ── Redaction: NEVER store the actual secret ─────────────
            redacted_line = _redact_line(raw_line, secret_value)
            redacted_ctx = [_redact_line(l, secret_value) for l in ctx_lines]

            # ── Attack surface & secret type mapping ─────────────────
            attack_surface = _resolve_attack_surface(rule.tags)
            secret_type = _resolve_secret_type(rule.family)

            # ── Remediation guidance ─────────────────────────────────
            remediation = _build_secret_remediation(rule)

            # ── Compliance violations ────────────────────────────────
            compliance = [fw.value for fw in COMPLIANCE_VIOLATIONS.get(rule.family, [])]

            # ── CWE mapping ──────────────────────────────────────────
            cwe = CWE_MAP.get(rule.family)
            cwe_id = rule.cwe or (cwe[0] if cwe else "CWE-798")

            # ── CVSS for secrets ─────────────────────────────────────
            cvss = _estimate_secret_cvss(rule)

            findings.append(CryptoFinding(
                id=CryptoFinding.generate_id(relative, line_no, f"SEC-{rule.family.value}"),
                file=relative,
                language=language,
                line_number=line_no,
                line_content=redacted_line.strip(),
                column_start=col_start,
                column_end=col_end,
                algorithm=rule.family.value,
                family=rule.family,
                risk=rule.risk,
                confidence=round(confidence, 3),
                confidence_level=confidence_to_level(confidence),
                key_size=None,
                hndl_relevant=True,  # all secrets are HNDL-relevant
                pattern_note=rule.note,
                migration=remediation,
                compliance_violations=compliance,
                context_lines=redacted_ctx,
                cwe_id=cwe_id,
                cvss_estimate=cvss,
                remediation_effort="low",  # secrets = rotate immediately
                secret_provider=rule.provider,
                secret_type=secret_type,
                attack_surface=attack_surface,
                is_secret=True,
                tags=list(rule.tags) + ["secret", "credential"],
            ))


def _redact_line(line: str, secret_value: str) -> str:
    """Replace the actual secret value in a line with a redacted version."""
    if not secret_value or len(secret_value) < 6:
        return sanitize_line(line)
    redacted = redact_secret(secret_value)
    return sanitize_line(line.replace(secret_value, redacted))


def _build_secret_remediation(rule: SecretRule) -> dict:
    """Build remediation guidance dict for a secret finding."""
    provider = rule.provider

    # Try provider-specific guidance first
    for key, guidance in SECRETS_REMEDIATION.items():
        if key.lower() in provider.lower():
            return {
                "action": guidance["action"],
                "vault": guidance.get("vault", "Use a secrets manager"),
                "notes": (
                    f"IMMEDIATE ACTION REQUIRED: {rule.note}. "
                    f"1) Revoke/rotate the credential immediately. "
                    f"2) Audit access logs for unauthorised usage. "
                    f"3) Move to {guidance.get('vault', 'a secrets manager')}. "
                    f"4) Add to .gitignore / pre-commit hooks to prevent recurrence."
                ),
            }

    # Generic fallback
    return SECRETS_REMEDIATION.get("Generic", {
        "action": "Rotate the credential immediately.",
        "vault": "Any secrets manager",
        "notes": "Exposed credentials must be rotated and moved to a secrets manager.",
    })


def _estimate_secret_cvss(rule: SecretRule) -> float:
    """Estimate CVSS for exposed secrets based on scope and access level."""
    base = rule.risk.numeric
    # Cloud admin credentials = highest impact
    if rule.provider in ("AWS", "GCP", "Azure"):
        return min(10.0, max(base, 9.5))
    # Payment keys = financial impact
    if "payment" in rule.tags or rule.provider in ("Stripe", "PayPal", "Square"):
        return min(10.0, max(base, 9.0))
    # Database credentials = data breach risk
    if "database" in rule.tags:
        return min(10.0, max(base, 9.0))
    # Source control tokens = supply chain risk
    if rule.provider in ("GitHub", "GitLab", "NPM", "PyPI"):
        return min(10.0, max(base, 8.5))
    # Private keys = infrastructure compromise
    if "infra" in rule.tags or "ssh" in rule.tags:
        return min(10.0, max(base, 9.5))
    return min(10.0, round(base, 1))


def _estimate_cvss(family: AlgoFamily, risk: RiskLevel, key_size: Optional[int]) -> float:
    """Estimate CVSS 3.1 for crypto vulnerabilities."""
    base = risk.numeric
    if family.is_quantum_broken:
        base = max(base, 7.5)
    if family.is_classically_broken:
        base = max(base, 8.0)
    if family in (AlgoFamily.HARDCODED_KEY, AlgoFamily.HARDCODED_CERT):
        base = 9.8
    if family.is_secret:
        base = max(base, 9.0)
    return min(10.0, round(base, 1))


# ────────────────────────────────────────────────────────────────────────────
# Directory Walker
# ────────────────────────────────────────────────────────────────────────────

def scan_directory(
    root: Path,
    scan_mode: ScanMode = ScanMode.FULL,
    progress_cb: Optional[Callable[[str, int, int], None]] = None,
    max_files: int = 50_000,
) -> tuple[list[CryptoFinding], list[str], int, int, set[str]]:
    """Walk a directory tree and scan each eligible file."""
    all_findings: list[CryptoFinding] = []
    errors: list[str] = []
    files_scanned = 0
    files_skipped = 0
    languages: set[str] = set()

    eligible: list[Path] = []
    for p in root.rglob("*"):
        if len(eligible) >= max_files:
            logger.warning("Hit max file limit (%d).", max_files)
            break
        if not p.is_file():
            continue
        if any(skip in p.parts for skip in SKIP_DIRS):
            continue
        if detect_language(p) is not None:
            eligible.append(p)

    total = len(eligible)
    logger.info("Found %d eligible files to scan.", total)

    for idx, fpath in enumerate(eligible):
        if progress_cb:
            try:
                progress_cb(str(fpath.relative_to(root)), idx + 1, total)
            except Exception:
                pass
        try:
            file_findings = scan_file(fpath, root, scan_mode)
            all_findings.extend(file_findings)
            lang = detect_language(fpath)
            if lang:
                languages.add(lang)
            files_scanned += 1
        except Exception as exc:
            errors.append(f"{fpath.relative_to(root)}: {exc}")
            files_skipped += 1

    return all_findings, errors, files_scanned, files_skipped, languages


# ────────────────────────────────────────────────────────────────────────────
# Score Calculators
# ────────────────────────────────────────────────────────────────────────────

def compute_quantum_risk_score(findings: list[CryptoFinding]) -> float:
    if not findings:
        return 0.0
    weights = {RiskLevel.CRITICAL: 10.0, RiskLevel.HIGH: 6.0, RiskLevel.MEDIUM: 3.0,
               RiskLevel.LOW: 1.0, RiskLevel.INFO: 0.0}
    total = sum(
        weights.get(f.risk, 0) * f.confidence
        for f in findings
        if (f.family.is_quantum_broken or f.family.is_classically_broken) and not f.is_secret
    )
    return min(100.0, round(total, 1))


def compute_agility_score(findings: list[CryptoFinding]) -> float:
    agility_signals = sum(1 for f in findings if f.family == AlgoFamily.AGILITY)
    pqc_signals = sum(1 for f in findings if f.family.is_pqc_safe)
    vuln_families = len(set(
        f.family for f in findings
        if (f.family.is_quantum_broken or f.family.is_classically_broken) and not f.is_secret
    ))
    score = 50.0 + agility_signals * 10.0 + pqc_signals * 15.0 - vuln_families * 5.0
    return max(0.0, min(100.0, round(score, 1)))


def compute_secrets_exposure_score(findings: list[CryptoFinding]) -> float:
    """
    Compute secrets exposure score (0–100). Higher = worse.

    Weights:
    - Critical secrets (cloud admin, payment, DB): 15 points each
    - High secrets (tokens, SaaS): 8 points each
    - Medium/Low: 3/1 points each
    """
    if not findings:
        return 0.0
    secret_findings = [f for f in findings if f.is_secret]
    if not secret_findings:
        return 0.0
    weights = {RiskLevel.CRITICAL: 15.0, RiskLevel.HIGH: 8.0,
               RiskLevel.MEDIUM: 3.0, RiskLevel.LOW: 1.0, RiskLevel.INFO: 0.0}
    total = sum(weights.get(f.risk, 0) * f.confidence for f in secret_findings)
    return min(100.0, round(total, 1))


def compute_overall_security_score(
    quantum_risk: float,
    secrets_exposure: float,
    agility: float,
) -> float:
    """
    Combined security score (0–100). Higher = BETTER.
    Inverts the risk scores and combines with agility.
    """
    crypto_health = max(0, 100 - quantum_risk)
    secrets_health = max(0, 100 - secrets_exposure)
    # Weighted: crypto 40%, secrets 40%, agility 20%
    score = crypto_health * 0.40 + secrets_health * 0.40 + agility * 0.20
    return max(0.0, min(100.0, round(score, 1)))


def build_file_reports(findings: list[CryptoFinding]) -> list[FileReport]:
    by_file: dict[str, list[CryptoFinding]] = {}
    for f in findings:
        by_file.setdefault(f.file, []).append(f)
    reports = []
    for filepath, ffindings in sorted(by_file.items()):
        critical = sum(1 for f in ffindings if f.risk == RiskLevel.CRITICAL)
        high = sum(1 for f in ffindings if f.risk == RiskLevel.HIGH)
        secrets = sum(1 for f in ffindings if f.is_secret)
        risk_score = sum(f.risk.numeric * f.confidence for f in ffindings)
        has_pqc = any(f.family.is_pqc_safe for f in ffindings)
        reports.append(FileReport(
            path=filepath,
            language=ffindings[0].language if ffindings else "unknown",
            findings_count=len(ffindings),
            critical_count=critical,
            high_count=high,
            secrets_count=secrets,
            risk_score=round(risk_score, 1),
            findings=ffindings,
            has_pqc_adoption=has_pqc,
        ))
    return sorted(reports, key=lambda r: r.risk_score, reverse=True)


def build_compliance_summary(findings: list[CryptoFinding]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for f in findings:
        for fw_name in f.compliance_violations:
            summary[fw_name] = summary.get(fw_name, 0) + 1
    return {k: v for k, v in sorted(summary.items(), key=lambda x: -x[1]) if v > 0}


def build_secrets_by_provider(findings: list[CryptoFinding]) -> dict[str, int]:
    """Count secret findings by provider."""
    counts: dict[str, int] = {}
    for f in findings:
        if f.is_secret and f.secret_provider:
            counts[f.secret_provider] = counts.get(f.secret_provider, 0) + 1
    return dict(sorted(counts.items(), key=lambda x: -x[1]))


def build_attack_surface_summary(findings: list[CryptoFinding]) -> dict[str, int]:
    """Count findings by attack surface category."""
    counts: dict[str, int] = {}
    for f in findings:
        if f.is_secret and f.attack_surface:
            counts[f.attack_surface] = counts.get(f.attack_surface, 0) + 1
    return dict(sorted(counts.items(), key=lambda x: -x[1]))


# ────────────────────────────────────────────────────────────────────────────
# Summary Builder
# ────────────────────────────────────────────────────────────────────────────

def build_summary(
    scan_id: str, source: str, source_type: str, scan_mode: ScanMode,
    started_at: str, findings: list[CryptoFinding], errors: list[str],
    files_scanned: int, files_skipped: int, languages: set[str],
    duration: float, metadata: Optional[dict] = None,
) -> ScanSummary:
    qr = compute_quantum_risk_score(findings)
    ag = compute_agility_score(findings)
    se = compute_secrets_exposure_score(findings)
    overall = compute_overall_security_score(qr, se, ag)

    secret_findings = [f for f in findings if f.is_secret]

    return ScanSummary(
        scan_id=scan_id,
        scanner_version="3.5.0",
        source=source,
        source_type=source_type,
        scan_mode=scan_mode.value,
        started_at=started_at,
        completed_at=datetime.now(timezone.utc).isoformat(),
        duration_seconds=round(duration, 2),
        files_scanned=files_scanned,
        files_skipped=files_skipped,
        total_findings=len(findings),
        critical_count=sum(1 for f in findings if f.risk == RiskLevel.CRITICAL),
        high_count=sum(1 for f in findings if f.risk == RiskLevel.HIGH),
        medium_count=sum(1 for f in findings if f.risk == RiskLevel.MEDIUM),
        low_count=sum(1 for f in findings if f.risk == RiskLevel.LOW),
        info_count=sum(1 for f in findings if f.risk == RiskLevel.INFO),
        hndl_count=sum(1 for f in findings if f.hndl_relevant),
        pqc_ready_count=sum(1 for f in findings if f.family.is_pqc_safe),
        secrets_count=len(secret_findings),
        secrets_critical=sum(1 for f in secret_findings if f.risk == RiskLevel.CRITICAL),
        secrets_by_provider=build_secrets_by_provider(findings),
        attack_surface_summary=build_attack_surface_summary(findings),
        quantum_risk_score=qr,
        crypto_agility_score=ag,
        secrets_exposure_score=se,
        overall_security_score=overall,
        languages_detected=sorted(languages),
        compliance_summary=build_compliance_summary(findings),
        findings=findings,
        file_reports=build_file_reports(findings),
        errors=errors,
        metadata=metadata or {},
    )


# ────────────────────────────────────────────────────────────────────────────
# Public API — Entry Points
# ────────────────────────────────────────────────────────────────────────────

def scan_local_directory(path: str, scan_mode: ScanMode = ScanMode.FULL,
                         progress_cb: Optional[Callable] = None) -> ScanSummary:
    started_at = datetime.now(timezone.utc).isoformat()
    start_time = time.monotonic()
    scan_id = hashlib.sha256(f"{path}:{started_at}".encode()).hexdigest()[:16]
    root = Path(path).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Path does not exist: {path}")
    findings, errors, scanned, skipped, langs = scan_directory(root, scan_mode, progress_cb)
    duration = time.monotonic() - start_time
    return build_summary(scan_id, str(root), "directory", scan_mode, started_at,
                         findings, errors, scanned, skipped, langs, duration)


def scan_repository(repo_url: str, github_token: Optional[str] = None,
                    branch: str = "main", scan_mode: ScanMode = ScanMode.FULL,
                    progress_cb: Optional[Callable] = None) -> ScanSummary:
    if not GIT_AVAILABLE:
        raise RuntimeError("GitPython not installed. Run: pip install gitpython")
    started_at = datetime.now(timezone.utc).isoformat()
    start_time = time.monotonic()
    scan_id = hashlib.sha256(f"{repo_url}:{started_at}".encode()).hexdigest()[:16]
    auth_url = repo_url
    if github_token:
        parsed = urlparse(repo_url)
        auth_url = parsed._replace(netloc=f"{github_token}@{parsed.netloc}").geturl()
    with tempfile.TemporaryDirectory() as tmp:
        logger.info("Cloning %s (branch: %s)...", repo_url, branch)
        try:
            git.Repo.clone_from(auth_url, tmp, branch=branch, depth=1, single_branch=True)
        except git.GitCommandError as e:
            raise RuntimeError(f"Clone failed: {e}") from e
        findings, errors, scanned, skipped, langs = scan_directory(Path(tmp), scan_mode, progress_cb)
    duration = time.monotonic() - start_time
    return build_summary(scan_id, repo_url, "repository", scan_mode, started_at,
                         findings, errors, scanned, skipped, langs, duration,
                         metadata={"branch": branch})


def scan_uploaded_archive(archive_path: str, scan_mode: ScanMode = ScanMode.FULL,
                          progress_cb: Optional[Callable] = None) -> ScanSummary:
    started_at = datetime.now(timezone.utc).isoformat()
    start_time = time.monotonic()
    scan_id = hashlib.sha256(f"{archive_path}:{started_at}".encode()).hexdigest()[:16]
    ap = Path(archive_path)
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        if zipfile.is_zipfile(ap):
            with zipfile.ZipFile(ap, "r") as z: z.extractall(tmp_path)
        elif tarfile.is_tarfile(ap):
            with tarfile.open(ap, "r:*") as t: t.extractall(tmp_path, filter="data")
        else:
            raise ValueError(f"Unsupported archive: {ap.suffix}")
        findings, errors, scanned, skipped, langs = scan_directory(tmp_path, scan_mode, progress_cb)
    duration = time.monotonic() - start_time
    return build_summary(scan_id, archive_path, "archive", scan_mode, started_at,
                         findings, errors, scanned, skipped, langs, duration)


# Async wrappers
async def scan_local_directory_async(path, scan_mode=ScanMode.FULL, progress_cb=None):
    return await asyncio.get_running_loop().run_in_executor(
        None, lambda: scan_local_directory(path, scan_mode, progress_cb))

async def scan_repository_async(url, token=None, branch="main", scan_mode=ScanMode.FULL, cb=None):
    return await asyncio.get_running_loop().run_in_executor(
        None, lambda: scan_repository(url, token, branch, scan_mode, cb))

async def scan_uploaded_archive_async(path, scan_mode=ScanMode.FULL, cb=None):
    return await asyncio.get_running_loop().run_in_executor(
        None, lambda: scan_uploaded_archive(path, scan_mode, cb))
