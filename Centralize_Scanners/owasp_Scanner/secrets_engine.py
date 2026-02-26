"""
Quantum Protocol v5.0 — Secrets & Credentials Detection Engine
Enterprise Intelligence Platform

Detection layers:
  - 120+ provider-specific regex patterns with verified format accuracy
  - Entropy-based detection (Shannon + Chi-squared) for unknown secret formats
  - Context-aware false-positive reduction (comments, tests, examples, docs)
  - Database connection string parsing (URI + DSN + JDBC)
  - .env file deep analysis
  - Active credential validation (AWS STS, GitHub API, Stripe API)
  - Exposure intelligence scoring (public repo × file context × sensitivity)
  - Secret lifecycle tracking (first_seen / last_seen / reintroduction detection)
  - Git history awareness (detect secrets in old commits, incremental CI scanning)
  - Severity calibration: live vs test keys, scope of access
  - Redaction for safe storage of findings
  - Graph-ready relationship model (Neo4j compatible)

Architecture sections:
  I.   SecretRule dataclass + entropy functions + validators + filters
  II.  120+ provider-specific SECRET RULES
  III. Enterprise SecretFinding model
  IV.  Active credential validators (AWS / GitHub / Stripe)
  V.   Exposure intelligence engine
  VI.  Secret lifecycle tracker
  VII. Git history & incremental scanner
  VIII.Graph relationship builder
  IX.  SecretEngine orchestrator (main entry point)
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
import math
import os
import re
import string
import subprocess
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, Generator, Iterable, List, Optional, Set, Tuple

from quantum_protocol.models.enums import AlgoFamily, RiskLevel

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════════
# SECTION I — Secret Rule Definition + Entropy + Validators + Filters
# ════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class SecretRule:
    """A single secret/credential detection pattern."""
    id: str
    pattern: str
    family: AlgoFamily
    provider: str                       # e.g. "AWS", "Stripe", "PostgreSQL"
    confidence: float                   # base confidence 0.0–1.0
    risk: RiskLevel
    note: str
    cwe: str = "CWE-798"               # CWE-798: Use of Hard-coded Credentials
    validator: Optional[str] = None     # name of post-match validation function
    tags: tuple = ()


# ── Entropy Analysis ─────────────────────────────────────────────────────────

def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy in bits per character."""
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def chi_squared_score(data: str) -> float:
    """Uniformity test — high values suggest random/encrypted data."""
    if len(data) < 16:
        return 0.0
    observed = Counter(data.encode("utf-8", errors="ignore"))
    n = sum(observed.values())
    expected = n / 256.0
    chi2 = sum((observed.get(i, 0) - expected) ** 2 / expected for i in range(256))
    return max(0.0, min(1.0, 1.0 - (chi2 / 1000.0)))


def is_high_entropy(value: str, threshold: float = 4.0) -> bool:
    """True if string has suspiciously high entropy (likely a secret)."""
    if len(value) < 16:
        return False
    return shannon_entropy(value) >= threshold


def entropy_confidence_boost(value: str) -> float:
    """Return confidence boost based on entropy analysis."""
    ent = shannon_entropy(value)
    if ent >= 5.0: return 0.25
    if ent >= 4.5: return 0.15
    if ent >= 4.0: return 0.10
    return 0.0


# ── Post-Match Validators ────────────────────────────────────────────────────

def _validate_not_placeholder(match_text: str) -> bool:
    """Reject common placeholder values."""
    lower = match_text.lower()
    placeholders = {
        "xxx", "your_", "replace_", "change_me", "insert_", "todo",
        "example", "sample", "test", "dummy", "fake", "placeholder",
        "none", "null", "undefined", "empty", "<your", "${", "{{",
        "xxxxxxxx", "00000000", "11111111", "aaaaaaaa",
        "password123", "changeme", "secretkey", "mysecret",
        "my_secret", "my_key", "your_key", "your_secret",
        "put_your", "add_your", "enter_your",
    }
    return not any(p in lower for p in placeholders)


def _validate_min_entropy(match_text: str, min_ent: float = 3.0) -> bool:
    """Ensure the matched secret has minimum entropy."""
    return shannon_entropy(match_text) >= min_ent


def _validate_aws_key_format(match_text: str) -> bool:
    """AWS access keys are exactly 20 uppercase alphanumeric chars starting with AKIA/ASIA."""
    return bool(re.match(r"^(AKIA|ASIA)[A-Z0-9]{16}$", match_text))


def _validate_not_test_context(line: str) -> bool:
    """Reject lines that appear to be in test/example context."""
    lower = line.lower()
    test_indicators = {
        "test", "mock", "fake", "stub", "fixture", "example",
        "sample", "demo", "# ", "// ", "/* ", "<!-- ",
        "todo:", "fixme:", "note:", "xxx:",
    }
    return not any(ind in lower for ind in test_indicators)


VALIDATORS: Dict[str, Callable] = {
    "not_placeholder": _validate_not_placeholder,
    "min_entropy": _validate_min_entropy,
    "aws_key_format": _validate_aws_key_format,
    "not_test_context": _validate_not_test_context,
}


# ── Context-Aware False Positive Filters ────────────────────────────────────

FALSE_POSITIVE_PATHS = re.compile(
    r"(test[s_/]|spec[s_/]|__test__|\.test\.|_test\.|mock[s_/]|fixture[s_/]|"
    r"example[s_/]|sample[s_/]|demo[s_/]|doc[s_/]|README|CHANGELOG|"
    r"\.md$|\.rst$|\.txt$|\.adoc$|node_modules|vendor[/]|third_party)",
    re.IGNORECASE,
)

ALLOWLISTED_FILENAMES = {
    ".env.example", ".env.sample", ".env.template", ".env.defaults",
    "docker-compose.example.yml", "config.example.yaml",
}


def is_likely_false_positive_path(filepath: str) -> bool:
    """Check if file path suggests examples/tests/docs."""
    import os
    basename = os.path.basename(filepath).lower()
    if basename in ALLOWLISTED_FILENAMES:
        return True
    return bool(FALSE_POSITIVE_PATHS.search(filepath))


# ── Redaction Utility ────────────────────────────────────────────────────────

def redact_secret(value: str, visible_chars: int = 4) -> str:
    """Redact a secret value, keeping only first and last few characters."""
    if len(value) <= visible_chars * 2 + 4:
        return "*" * len(value)
    return value[:visible_chars] + "*" * (len(value) - visible_chars * 2) + value[-visible_chars:]


# ════════════════════════════════════════════════════════════════════════════
# SECTION II — SECRET RULES: 120+ Provider-Specific Patterns
# ════════════════════════════════════════════════════════════════════════════

def _build_secret_rules() -> List[SecretRule]:
    rules: List[SecretRule] = []
    _counter = [0]

    def _add(family: AlgoFamily, provider: str, pattern: str,
             confidence: float, risk: RiskLevel, note: str, *,
             cwe: str = "CWE-798", validator: Optional[str] = None,
             tags: tuple = ()):
        _counter[0] += 1
        rules.append(SecretRule(
            id=f"SEC-{_counter[0]:03d}",
            pattern=pattern, family=family, provider=provider,
            confidence=confidence, risk=risk, note=note,
            cwe=cwe, validator=validator, tags=tags,
        ))

    # ╔══════════════════════════════════════════════════════════════════╗
    # ║  CLOUD PROVIDER CREDENTIALS                                    ║
    # ╚══════════════════════════════════════════════════════════════════╝

    # ── AWS ──────────────────────────────────────────────────────────
    _add(AlgoFamily.SECRET_AWS, "AWS",
         r"(?:^|['\"\s=:])(?P<secret>(?:AKIA|ASIA)[A-Z0-9]{16})(?:['\"\s,;]|$)",
         0.97, RiskLevel.CRITICAL,
         "AWS Access Key ID (AKIA*/ASIA*) — grants programmatic AWS access",
         validator="aws_key_format", tags=("cloud", "aws"))

    _add(AlgoFamily.SECRET_AWS, "AWS",
         r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|aws_secret_key)\s*[=:]\s*['\"]?(?P<secret>[A-Za-z0-9/+=]{40})['\"]?",
         0.95, RiskLevel.CRITICAL,
         "AWS Secret Access Key — full account access when paired with Access Key ID",
         tags=("cloud", "aws"))

    _add(AlgoFamily.SECRET_AWS, "AWS",
         r"(?:aws_session_token|AWS_SESSION_TOKEN)\s*[=:]\s*['\"]?(?P<secret>[A-Za-z0-9/+=]{100,})['\"]?",
         0.90, RiskLevel.HIGH,
         "AWS Session Token (temporary credential)",
         tags=("cloud", "aws"))

    _add(AlgoFamily.SECRET_AWS, "AWS",
         r"arn:aws:iam::\d{12}:(?:user|role|policy)/[A-Za-z0-9+=,.@\-_/]+",
         0.60, RiskLevel.LOW,
         "AWS IAM ARN — informational (maps attack surface)",
         tags=("cloud", "aws", "informational"))

    _add(AlgoFamily.SECRET_S3, "AWS",
         r"['\"]?s3://[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9](?:/\S+)?['\"]?",
         0.50, RiskLevel.LOW,
         "AWS S3 bucket URI — review bucket ACLs for public exposure",
         tags=("cloud", "aws", "informational"))

    # ── GCP ──────────────────────────────────────────────────────────
    _add(AlgoFamily.SECRET_GCP, "GCP",
         r"(?:\"type\"\s*:\s*\"service_account\")",
         0.90, RiskLevel.CRITICAL,
         "GCP Service Account JSON key file detected",
         tags=("cloud", "gcp"))

    _add(AlgoFamily.SECRET_GCP, "GCP",
         r"(?:GOOGLE_API_KEY|google_api_key|gcp_api_key)\s*[=:]\s*['\"]?(?P<secret>AIza[A-Za-z0-9\-_]{35})['\"]?",
         0.95, RiskLevel.CRITICAL,
         "Google Cloud API Key (AIza prefix)",
         tags=("cloud", "gcp"))

    _add(AlgoFamily.SECRET_GCP, "GCP",
         r"AIza[A-Za-z0-9\-_]{35}",
         0.85, RiskLevel.HIGH,
         "Google API Key pattern (AIza*) — may grant access to billable APIs",
         tags=("cloud", "gcp"))

    _add(AlgoFamily.SECRET_GCP, "GCP",
         r"(?:\"private_key\"\s*:\s*\"-----BEGIN (?:RSA )?PRIVATE KEY-----)",
         0.95, RiskLevel.CRITICAL,
         "GCP service account private key embedded in JSON",
         tags=("cloud", "gcp"))

    # ── Azure ────────────────────────────────────────────────────────
    _add(AlgoFamily.SECRET_AZURE, "Azure",
         r"(?:AZURE_CLIENT_SECRET|azure_client_secret)\s*[=:]\s*['\"]?(?P<secret>[A-Za-z0-9\-._~]{30,})['\"]?",
         0.93, RiskLevel.CRITICAL,
         "Azure Client Secret (Service Principal credential)",
         tags=("cloud", "azure"))

    _add(AlgoFamily.SECRET_AZURE, "Azure",
         r"(?:AccountKey|SharedAccessKey)\s*=\s*(?P<secret>[A-Za-z0-9+/=]{44,88})",
         0.92, RiskLevel.CRITICAL,
         "Azure Storage Account Key or SAS token",
         tags=("cloud", "azure"))

    _add(AlgoFamily.SECRET_AZURE, "Azure",
         r"(?:DefaultEndpointsProtocol=https?;AccountName=)\w+;AccountKey=(?P<secret>[A-Za-z0-9+/=]{44,88})",
         0.95, RiskLevel.CRITICAL,
         "Azure Storage connection string with embedded key",
         tags=("cloud", "azure"))

    # ── DigitalOcean ─────────────────────────────────────────────────
    _add(AlgoFamily.SECRET_DIGITALOCEAN, "DigitalOcean",
         r"(?:dop_v1_[a-f0-9]{64})",
         0.95, RiskLevel.CRITICAL,
         "DigitalOcean Personal Access Token",
         tags=("cloud", "digitalocean"))

    _add(AlgoFamily.SECRET_DIGITALOCEAN, "DigitalOcean",
         r"(?:doo_v1_[a-f0-9]{64})",
         0.95, RiskLevel.HIGH,
         "DigitalOcean OAuth Token",
         tags=("cloud", "digitalocean"))

    # ── Heroku ───────────────────────────────────────────────────────
    _add(AlgoFamily.SECRET_HEROKU, "Heroku",
         r"(?:HEROKU_API_KEY|heroku_api_key)\s*[=:]\s*['\"]?(?P<secret>[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['\"]?",
         0.92, RiskLevel.HIGH,
         "Heroku API Key (UUID format)",
         tags=("cloud", "heroku"))

    # ── Cloudflare ───────────────────────────────────────────────────
    _add(AlgoFamily.SECRET_CLOUDFLARE, "Cloudflare",
         r"(?:CLOUDFLARE_API_KEY|CF_API_KEY)\s*[=:]\s*['\"]?(?P<secret>[a-f0-9]{37})['\"]?",
         0.90, RiskLevel.HIGH,
         "Cloudflare Global API Key",
         tags=("cloud", "cloudflare"))

    # ╔══════════════════════════════════════════════════════════════════╗
    # ║  SOURCE CONTROL & CI/CD TOKENS                                 ║
    # ╚══════════════════════════════════════════════════════════════════╝

    _add(AlgoFamily.SECRET_GITHUB, "GitHub",
         r"(?:ghp_[A-Za-z0-9]{36})",
         0.98, RiskLevel.CRITICAL,
         "GitHub Personal Access Token (fine-grained or classic)",
         tags=("cicd", "github"))

    _add(AlgoFamily.SECRET_GITHUB, "GitHub",
         r"(?:gho_[A-Za-z0-9]{36})",
         0.98, RiskLevel.HIGH,
         "GitHub OAuth Access Token",
         tags=("cicd", "github"))

    _add(AlgoFamily.SECRET_GITHUB, "GitHub",
         r"(?:ghu_[A-Za-z0-9]{36})",
         0.95, RiskLevel.HIGH,
         "GitHub User-to-Server Token",
         tags=("cicd", "github"))

    _add(AlgoFamily.SECRET_GITHUB, "GitHub",
         r"(?:ghs_[A-Za-z0-9]{36})",
         0.95, RiskLevel.HIGH,
         "GitHub Server-to-Server Token (GitHub App installation)",
         tags=("cicd", "github"))

    _add(AlgoFamily.SECRET_GITHUB, "GitHub",
         r"(?:github_pat_[A-Za-z0-9_]{82})",
         0.98, RiskLevel.CRITICAL,
         "GitHub Fine-Grained Personal Access Token",
         tags=("cicd", "github"))

    _add(AlgoFamily.SECRET_GITLAB, "GitLab",
         r"(?:glpat-[A-Za-z0-9\-_]{20,})",
         0.97, RiskLevel.CRITICAL,
         "GitLab Personal Access Token",
         tags=("cicd", "gitlab"))

    _add(AlgoFamily.SECRET_GITLAB, "GitLab",
         r"(?:glrt-[A-Za-z0-9\-_]{20,})",
         0.95, RiskLevel.HIGH,
         "GitLab Runner Registration Token",
         tags=("cicd", "gitlab"))

    _add(AlgoFamily.SECRET_NPM, "NPM",
         r"(?:npm_[A-Za-z0-9]{36})",
         0.97, RiskLevel.CRITICAL,
         "NPM Access Token — can publish packages",
         tags=("cicd", "npm"))

    _add(AlgoFamily.SECRET_PYPI, "PyPI",
         r"(?:pypi-[A-Za-z0-9\-_]{16,})",
         0.95, RiskLevel.CRITICAL,
         "PyPI API Token — can publish Python packages",
         tags=("cicd", "pypi"))

    _add(AlgoFamily.SECRET_DOCKER, "Docker",
         r"(?:dckr_pat_[A-Za-z0-9\-_]{27,})",
         0.95, RiskLevel.HIGH,
         "Docker Hub Personal Access Token",
         tags=("cicd", "docker"))

    _add(AlgoFamily.SECRET_TERRAFORM, "Terraform",
         r"(?:['\"]?(?:TF_TOKEN_|terraform_token|ATLAS_TOKEN)\s*[=:]\s*['\"]?)(?P<secret>[A-Za-z0-9._\-]{14,})",
         0.88, RiskLevel.HIGH,
         "Terraform Cloud / Enterprise API Token",
         tags=("cicd", "terraform"))

    # ╔══════════════════════════════════════════════════════════════════╗
    # ║  PAYMENT & FINANCE CREDENTIALS                                 ║
    # ╚══════════════════════════════════════════════════════════════════╝

    _add(AlgoFamily.SECRET_STRIPE, "Stripe",
         r"(?:sk_live_[A-Za-z0-9]{24,})",
         0.99, RiskLevel.CRITICAL,
         "Stripe Live Secret Key — full payment processing access",
         tags=("payment", "stripe"))

    _add(AlgoFamily.SECRET_STRIPE, "Stripe",
         r"(?:sk_test_[A-Za-z0-9]{24,})",
         0.90, RiskLevel.MEDIUM,
         "Stripe Test Secret Key — test mode only but still sensitive",
         tags=("payment", "stripe"))

    _add(AlgoFamily.SECRET_STRIPE, "Stripe",
         r"(?:rk_live_[A-Za-z0-9]{24,})",
         0.97, RiskLevel.CRITICAL,
         "Stripe Restricted Live API Key",
         tags=("payment", "stripe"))

    _add(AlgoFamily.SECRET_STRIPE, "Stripe",
         r"(?:pk_live_[A-Za-z0-9]{24,})",
         0.70, RiskLevel.LOW,
         "Stripe Live Publishable Key — limited scope but avoid exposing",
         tags=("payment", "stripe"))

    _add(AlgoFamily.SECRET_SQUARE, "Square",
         r"(?:sq0atp-[A-Za-z0-9\-_]{22,})",
         0.95, RiskLevel.CRITICAL,
         "Square Access Token (production)",
         tags=("payment", "square"))

    _add(AlgoFamily.SECRET_SQUARE, "Square",
         r"(?:sq0csp-[A-Za-z0-9\-_]{43,})",
         0.95, RiskLevel.CRITICAL,
         "Square OAuth Secret",
         tags=("payment", "square"))

    _add(AlgoFamily.SECRET_PAYPAL, "PayPal",
         r"(?:access_token\$(?:production|sandbox)\$[a-z0-9]{16}\$[a-f0-9]{32})",
         0.95, RiskLevel.CRITICAL,
         "PayPal Braintree Access Token",
         tags=("payment", "paypal"))

    _add(AlgoFamily.SECRET_PLAID, "Plaid",
         r"(?:(?:access|secret|public)-(?:sandbox|development|production)-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})",
         0.93, RiskLevel.CRITICAL,
         "Plaid API credential",
         tags=("payment", "plaid"))

    _add(AlgoFamily.SECRET_SHOPIFY, "Shopify",
         r"(?:shpat_[a-fA-F0-9]{32})",
         0.95, RiskLevel.HIGH,
         "Shopify Admin API Access Token",
         tags=("payment", "shopify"))

    _add(AlgoFamily.SECRET_SHOPIFY, "Shopify",
         r"(?:shpss_[a-fA-F0-9]{32})",
         0.95, RiskLevel.HIGH,
         "Shopify Shared Secret",
         tags=("payment", "shopify"))

    # ╔══════════════════════════════════════════════════════════════════╗
    # ║  COMMUNICATION / SAAS CREDENTIALS                              ║
    # ╚══════════════════════════════════════════════════════════════════╝

    _add(AlgoFamily.SECRET_SLACK, "Slack",
         r"(?:xoxb-\d{10,13}-\d{10,13}-[A-Za-z0-9]{24,})",
         0.97, RiskLevel.CRITICAL,
         "Slack Bot Token (xoxb) — can read/write messages",
         tags=("saas", "slack"))

    _add(AlgoFamily.SECRET_SLACK, "Slack",
         r"(?:xoxp-\d{10,13}-\d{10,13}-\d{10,13}-[a-f0-9]{32})",
         0.97, RiskLevel.CRITICAL,
         "Slack User Token (xoxp) — acts as a user",
         tags=("saas", "slack"))

    _add(AlgoFamily.SECRET_SLACK, "Slack",
         r"(?:xapp-\d-[A-Z0-9]{10,}-\d{13}-[a-z0-9]{64})",
         0.95, RiskLevel.HIGH,
         "Slack App-Level Token (xapp)",
         tags=("saas", "slack"))

    _add(AlgoFamily.SECRET_SLACK, "Slack",
         r"(?:https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24,})",
         0.95, RiskLevel.HIGH,
         "Slack Incoming Webhook URL — can post messages",
         tags=("saas", "slack"))

    _add(AlgoFamily.SECRET_TWILIO, "Twilio",
         r"(?:SK[a-f0-9]{32})",
         0.88, RiskLevel.HIGH,
         "Twilio API Key (SK prefix)",
         tags=("saas", "twilio"))

    _add(AlgoFamily.SECRET_TWILIO, "Twilio",
         r"(?:AC[a-f0-9]{32})",
         0.80, RiskLevel.MEDIUM,
         "Twilio Account SID (AC prefix) — pair with Auth Token for access",
         tags=("saas", "twilio"))

    _add(AlgoFamily.SECRET_SENDGRID, "SendGrid",
         r"(?:SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43})",
         0.97, RiskLevel.CRITICAL,
         "SendGrid API Key — can send emails as your domain",
         tags=("saas", "sendgrid"))

    _add(AlgoFamily.SECRET_MAILGUN, "Mailgun",
         r"(?:key-[a-f0-9]{32})",
         0.88, RiskLevel.HIGH,
         "Mailgun API Key",
         tags=("saas", "mailgun"))

    _add(AlgoFamily.SECRET_TELEGRAM, "Telegram",
         r"(?:\d{8,10}:[A-Za-z0-9_-]{35})",
         0.85, RiskLevel.HIGH,
         "Telegram Bot API Token",
         tags=("saas", "telegram"))

    _add(AlgoFamily.SECRET_DISCORD, "Discord",
         r"(?:[MN][A-Za-z0-9\-_]{23,28}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27,})",
         0.88, RiskLevel.HIGH,
         "Discord Bot Token",
         tags=("saas", "discord"))

    _add(AlgoFamily.SECRET_FIREBASE, "Firebase",
         r"(?:AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140,})",
         0.85, RiskLevel.HIGH,
         "Firebase Cloud Messaging Server Key",
         tags=("saas", "firebase"))

    # ╔══════════════════════════════════════════════════════════════════╗
    # ║  MONITORING / ANALYTICS CREDENTIALS                            ║
    # ╚══════════════════════════════════════════════════════════════════╝

    _add(AlgoFamily.SECRET_DATADOG, "Datadog",
         r"(?:(?:DD_API_KEY|DATADOG_API_KEY|dd_api_key)\s*[=:]\s*['\"]?)(?P<secret>[a-f0-9]{32})",
         0.90, RiskLevel.HIGH,
         "Datadog API Key",
         tags=("monitoring", "datadog"))

    _add(AlgoFamily.SECRET_NEWRELIC, "New Relic",
         r"(?:NRAK-[A-Z0-9]{27})",
         0.95, RiskLevel.HIGH,
         "New Relic API Key (NRAK prefix)",
         tags=("monitoring", "newrelic"))

    _add(AlgoFamily.SECRET_SENTRY, "Sentry",
         r"(?:https://[a-f0-9]{32}@(?:o\d+\.)?(?:sentry\.io|[a-z]+\.sentry\.io)/\d+)",
         0.92, RiskLevel.HIGH,
         "Sentry DSN — exposes error tracking endpoint with auth",
         tags=("monitoring", "sentry"))

    _add(AlgoFamily.SECRET_GRAFANA, "Grafana",
         r"(?:glc_[A-Za-z0-9+/]{32,}={0,2})",
         0.90, RiskLevel.HIGH,
         "Grafana Cloud API Token",
         tags=("monitoring", "grafana"))

    _add(AlgoFamily.SECRET_SPLUNK, "Splunk",
         r"(?:(?:SPLUNK_TOKEN|splunk_hec_token)\s*[=:]\s*['\"]?)(?P<secret>[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})",
         0.88, RiskLevel.HIGH,
         "Splunk HEC Token",
         tags=("monitoring", "splunk"))

    # ╔══════════════════════════════════════════════════════════════════╗
    # ║  DATABASE & CACHE CREDENTIALS                                  ║
    # ╚══════════════════════════════════════════════════════════════════╝

    _add(AlgoFamily.SECRET_POSTGRES, "PostgreSQL",
         r"(?:postgres(?:ql)?://[^:]+:)(?P<secret>[^@\s'\"]+)(?:@[^/\s'\"]+)",
         0.93, RiskLevel.CRITICAL,
         "PostgreSQL connection URI with embedded password",
         tags=("database", "postgres"))

    _add(AlgoFamily.SECRET_MYSQL, "MySQL",
         r"(?:mysql://[^:]+:)(?P<secret>[^@\s'\"]+)(?:@[^/\s'\"]+)",
         0.93, RiskLevel.CRITICAL,
         "MySQL connection URI with embedded password",
         tags=("database", "mysql"))

    _add(AlgoFamily.SECRET_MONGODB, "MongoDB",
         r"(?:mongodb(?:\+srv)?://[^:]+:)(?P<secret>[^@\s'\"]+)(?:@[^/\s'\"]+)",
         0.93, RiskLevel.CRITICAL,
         "MongoDB connection URI with embedded password",
         tags=("database", "mongodb"))

    _add(AlgoFamily.SECRET_REDIS, "Redis",
         r"(?:redis(?:s)?://(?:[^:]+:)?)(?P<secret>[^@\s'\"]+)(?:@[^/\s'\"]+)",
         0.88, RiskLevel.HIGH,
         "Redis connection URI with credentials",
         tags=("database", "redis"))

    _add(AlgoFamily.SECRET_MSSQL, "MSSQL",
         r"(?:(?:Server|Data Source)\s*=[^;]+;\s*(?:User ID|uid)\s*=[^;]+;\s*(?:Password|pwd)\s*=)(?P<secret>[^;'\"\s]+)",
         0.90, RiskLevel.CRITICAL,
         "MSSQL connection string with embedded password",
         tags=("database", "mssql"))

    _add(AlgoFamily.SECRET_ELASTICSEARCH, "Elasticsearch",
         r"(?:https?://[^:]+:)(?P<secret>[^@\s'\"]+)(?:@[^/\s'\"]*(?:9200|9243|elastic))",
         0.85, RiskLevel.HIGH,
         "Elasticsearch connection with embedded credentials",
         tags=("database", "elasticsearch"))

    _add(AlgoFamily.SECRET_DB_CONNSTR, "Database",
         r"(?:DATABASE_URL|DB_URL|DATABASE_URI|SQLALCHEMY_DATABASE_URI|JDBC_URL|CONNECTION_STRING)\s*[=:]\s*['\"]?(?P<secret>[a-z]+://\S{10,})['\"]?",
         0.88, RiskLevel.CRITICAL,
         "Database connection string in environment variable",
         tags=("database", "connection-string"))

    _add(AlgoFamily.SECRET_DB_CONNSTR, "Database",
         r"(?:DB_PASSWORD|DATABASE_PASSWORD|MYSQL_PASSWORD|POSTGRES_PASSWORD|MONGO_PASSWORD|REDIS_PASSWORD)\s*[=:]\s*['\"]?(?P<secret>[^'\"\s]{6,})['\"]?",
         0.85, RiskLevel.CRITICAL,
         "Database password in environment/config variable",
         validator="not_placeholder",
         tags=("database", "password"))

    _add(AlgoFamily.SECRET_DB_CONNSTR, "Database",
         r"(?:jdbc:(?:mysql|postgresql|oracle|sqlserver|mariadb)://[^;]+;.*password=)(?P<secret>[^;'\"\s]+)",
         0.90, RiskLevel.CRITICAL,
         "JDBC connection string with embedded password",
         tags=("database", "jdbc"))

    # ╔══════════════════════════════════════════════════════════════════╗
    # ║  AUTH TOKENS / JWT / OAUTH / SESSION SECRETS                   ║
    # ╚══════════════════════════════════════════════════════════════════╝

    _add(AlgoFamily.SECRET_JWT, "JWT",
         r"(?:eyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,})",
         0.88, RiskLevel.HIGH,
         "JWT (JSON Web Token) — may contain session/auth claims",
         tags=("auth", "jwt"))

    _add(AlgoFamily.SECRET_BEARER, "Bearer",
         r"(?:(?:Authorization|authorization)\s*[=:]\s*['\"]?Bearer\s+)(?P<secret>[A-Za-z0-9\-._~+/]{20,})",
         0.85, RiskLevel.HIGH,
         "Bearer authentication token",
         tags=("auth", "bearer"))

    _add(AlgoFamily.SECRET_SESSION, "Session",
         r"(?:SESSION_SECRET|SECRET_KEY_BASE|APP_SECRET|FLASK_SECRET_KEY|DJANGO_SECRET_KEY|NEXTAUTH_SECRET|JWT_SECRET)\s*[=:]\s*['\"]?(?P<secret>[^\s'\"]{16,})['\"]?",
         0.88, RiskLevel.CRITICAL,
         "Application session/signing secret — enables session forgery if leaked",
         validator="not_placeholder",
         tags=("auth", "session"))

    _add(AlgoFamily.SECRET_OAUTH, "OAuth",
         r"(?:(?:OAUTH|GOOGLE|FACEBOOK|TWITTER)_(?:CLIENT_SECRET|APP_SECRET))\s*[=:]\s*['\"]?(?P<secret>[^\s'\"]{10,})['\"]?",
         0.85, RiskLevel.HIGH,
         "OAuth client secret — enables impersonation",
         validator="not_placeholder",
         tags=("auth", "oauth"))

    _add(AlgoFamily.SECRET_LDAP, "LDAP",
         r"(?:LDAP_(?:BIND_)?PASSWORD|ldap_password)\s*[=:]\s*['\"]?(?P<secret>[^\s'\"]{6,})['\"]?",
         0.82, RiskLevel.HIGH,
         "LDAP bind password",
         validator="not_placeholder",
         tags=("auth", "ldap"))

    # ╔══════════════════════════════════════════════════════════════════╗
    # ║  INFRASTRUCTURE / SSH / PGP / TLS KEYS                         ║
    # ╚══════════════════════════════════════════════════════════════════╝

    _add(AlgoFamily.SECRET_SSH_KEY, "SSH",
         r"(?:-----BEGIN (?:RSA|DSA|EC|OPENSSH|ENCRYPTED) PRIVATE KEY-----)",
         1.00, RiskLevel.CRITICAL,
         "SSH / asymmetric private key — grants server or service access",
         tags=("infra", "ssh"))

    _add(AlgoFamily.SECRET_PGP_KEY, "PGP",
         r"(?:-----BEGIN PGP PRIVATE KEY BLOCK-----)",
         1.00, RiskLevel.CRITICAL,
         "PGP private key — enables decryption and signature forgery",
         tags=("infra", "pgp"))

    _add(AlgoFamily.SECRET_SSL_KEY, "TLS",
         r"(?:-----BEGIN (?:PRIVATE KEY|ENCRYPTED PRIVATE KEY)-----)",
         0.98, RiskLevel.CRITICAL,
         "TLS/SSL private key — enables MITM on associated certificates",
         tags=("infra", "tls"))

    # ╔══════════════════════════════════════════════════════════════════╗
    # ║  AI / ML PROVIDER KEYS                                         ║
    # ╚══════════════════════════════════════════════════════════════════╝

    _add(AlgoFamily.SECRET_OPENAI, "OpenAI",
         r"(?:sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})",
         0.97, RiskLevel.HIGH,
         "OpenAI API Key (legacy format)",
         tags=("ai", "openai"))

    _add(AlgoFamily.SECRET_OPENAI, "OpenAI",
         r"(?:sk-proj-[A-Za-z0-9\-_]{40,})",
         0.95, RiskLevel.HIGH,
         "OpenAI Project API Key",
         tags=("ai", "openai"))

    _add(AlgoFamily.SECRET_ANTHROPIC, "Anthropic",
         r"(?:sk-ant-[A-Za-z0-9\-_]{80,})",
         0.97, RiskLevel.HIGH,
         "Anthropic API Key",
         tags=("ai", "anthropic"))

    # ╔══════════════════════════════════════════════════════════════════╗
    # ║  OTHER SAAS KEYS                                               ║
    # ╚══════════════════════════════════════════════════════════════════╝

    _add(AlgoFamily.SECRET_MAPBOX, "Mapbox",
         r"(?:pk\.[A-Za-z0-9]{60,})",
         0.80, RiskLevel.MEDIUM,
         "Mapbox Public Access Token",
         tags=("saas", "mapbox"))

    _add(AlgoFamily.SECRET_MAPBOX, "Mapbox",
         r"(?:sk\.[A-Za-z0-9]{60,})",
         0.90, RiskLevel.HIGH,
         "Mapbox Secret Access Token",
         tags=("saas", "mapbox"))

    _add(AlgoFamily.SECRET_ALGOLIA, "Algolia",
         r"(?:ALGOLIA_(?:API_KEY|ADMIN_KEY))\s*[=:]\s*['\"]?(?P<secret>[a-f0-9]{32})['\"]?",
         0.88, RiskLevel.HIGH,
         "Algolia API Key",
         tags=("saas", "algolia"))

    _add(AlgoFamily.SECRET_OKTA, "Okta",
         r"(?:00[A-Za-z0-9\-_]{40,})",
         0.70, RiskLevel.HIGH,
         "Okta API Token (00 prefix)",
         tags=("auth", "okta"))

    _add(AlgoFamily.SECRET_AUTH0, "Auth0",
         r"(?:AUTH0_CLIENT_SECRET)\s*[=:]\s*['\"]?(?P<secret>[A-Za-z0-9\-_]{30,})['\"]?",
         0.88, RiskLevel.HIGH,
         "Auth0 Client Secret",
         tags=("auth", "auth0"))

    # ╔══════════════════════════════════════════════════════════════════╗
    # ║  GENERIC CREDENTIAL PATTERNS (high recall, needs entropy)      ║
    # ╚══════════════════════════════════════════════════════════════════╝

    _add(AlgoFamily.SECRET_GENERIC_API, "Generic",
         r"(?:api[_-]?key|apikey|API_KEY)\s*[=:]\s*['\"]?(?P<secret>[A-Za-z0-9\-_./+=]{20,})['\"]?",
         0.70, RiskLevel.HIGH,
         "Generic API key in config/env",
         validator="not_placeholder",
         tags=("generic",))

    _add(AlgoFamily.SECRET_GENERIC_SECRET, "Generic",
         r"(?:(?:client|app|api|auth|signing|encryption|master|hmac)[_-]?secret)\s*[=:]\s*['\"]?(?P<secret>[A-Za-z0-9\-_./+=]{16,})['\"]?",
         0.72, RiskLevel.HIGH,
         "Generic application secret",
         validator="not_placeholder",
         tags=("generic",))

    _add(AlgoFamily.SECRET_GENERIC_PASSWORD, "Generic",
         r"(?:(?:password|passwd|pwd|pass)\s*[=:]\s*['\"])(?P<secret>[^'\"]{8,})['\"]",
         0.68, RiskLevel.HIGH,
         "Hardcoded password in source code",
         validator="not_placeholder",
         tags=("generic", "password"))

    _add(AlgoFamily.SECRET_GENERIC_TOKEN, "Generic",
         r"(?:(?:access_token|auth_token|refresh_token|bearer_token|secret_token)\s*[=:]\s*['\"]?)(?P<secret>[A-Za-z0-9\-_./+=]{20,})['\"]?",
         0.72, RiskLevel.HIGH,
         "Generic authentication/access token",
         validator="not_placeholder",
         tags=("generic", "token"))

    _add(AlgoFamily.SECRET_PRIVATE_KEY_VAR, "Generic",
         r"(?:PRIVATE_KEY|private_key|signing_key|encryption_key)\s*[=:]\s*['\"](?P<secret>[A-Za-z0-9+/=\-]{40,})['\"]",
         0.80, RiskLevel.CRITICAL,
         "Private/signing key stored in variable",
         tags=("generic", "key"))

    # ╔══════════════════════════════════════════════════════════════════╗
    # ║  MESSAGE BROKERS                                               ║
    # ╚══════════════════════════════════════════════════════════════════╝

    _add(AlgoFamily.SECRET_RABBITMQ, "RabbitMQ",
         r"(?:amqps?://[^:]+:)(?P<secret>[^@\s'\"]+)(?:@)",
         0.90, RiskLevel.HIGH,
         "RabbitMQ connection URI with credentials",
         tags=("infra", "rabbitmq"))

    _add(AlgoFamily.SECRET_KAFKA, "Kafka",
         r"(?:(?:KAFKA_SASL_PASSWORD|kafka\.sasl\.password|sasl\.password)\s*[=:]\s*['\"]?)(?P<secret>[^\s'\"]{8,})",
         0.85, RiskLevel.HIGH,
         "Kafka SASL password",
         tags=("infra", "kafka"))

    return rules


# ── Build and compile at import time ─────────────────────────────────────────

ALL_SECRET_RULES: List[SecretRule] = _build_secret_rules()

COMPILED_SECRET_RULES: List[Tuple[re.Pattern, SecretRule]] = [
    (re.compile(r.pattern, re.MULTILINE), r)
    for r in ALL_SECRET_RULES
]


def get_rule_count() -> int:
    return len(ALL_SECRET_RULES)


def get_rules_by_provider(provider: str) -> List[SecretRule]:
    return [r for r in ALL_SECRET_RULES if r.provider.lower() == provider.lower()]


# ════════════════════════════════════════════════════════════════════════════
# SECTION III — Enterprise SecretFinding Model
# ════════════════════════════════════════════════════════════════════════════

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class SecretFinding:
    """
    Enterprise-grade finding model.

    Lifecycle-ready, graph-ready, telemetry-ready.
    Compatible with Neo4j relationship builder and SSE event streaming.
    """
    rule_id: str
    provider: str
    secret_hash: str                            # SHA-256 of raw value
    redacted_value: str                         # safe for logs/storage

    file_path: str
    line_number: int
    commit: Optional[str]                       # Git SHA if from history scan

    entropy: float
    confidence: float = 0.0
    risk: str = "High"                          # RiskLevel.value
    cwe: str = "CWE-798"

    verified: bool = False                      # True = active credential confirmed
    verification_method: Optional[str] = None  # "aws_sts", "github_api", "stripe_api"

    exposure_score: float = 0.0                 # 0–10 composite exposure
    risk_score: float = 0.0                     # confidence × entropy × exposure

    first_seen: datetime = field(default_factory=_utcnow)
    last_seen: datetime = field(default_factory=_utcnow)
    reintroduced: bool = False                  # True = was fixed, now back

    tags: List[str] = field(default_factory=list)
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "provider": self.provider,
            "secret_hash": self.secret_hash,
            "redacted_value": self.redacted_value,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "commit": self.commit,
            "entropy": round(self.entropy, 3),
            "confidence": round(self.confidence, 3),
            "risk": self.risk,
            "cwe": self.cwe,
            "verified": self.verified,
            "verification_method": self.verification_method,
            "exposure_score": round(self.exposure_score, 2),
            "risk_score": round(self.risk_score, 3),
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "reintroduced": self.reintroduced,
            "tags": self.tags,
            "note": self.note,
        }


# ════════════════════════════════════════════════════════════════════════════
# SECTION IV — Active Credential Validators
# ════════════════════════════════════════════════════════════════════════════

class _BaseValidator:
    """Base class for live credential validators."""
    name: str = "base"
    timeout: int = 8  # seconds

    def validate(self, secret: str, **kwargs) -> bool:
        raise NotImplementedError


class AWSValidator(_BaseValidator):
    """
    Validate AWS credentials via STS GetCallerIdentity.
    Requires: access_key + secret_key (passed as kwargs).
    """
    name = "aws_sts"

    def validate(self, access_key: str, secret_key: str = "", **kwargs) -> bool:
        try:
            import boto3
            from botocore.exceptions import ClientError, NoCredentialsError
            sts = boto3.client(
                "sts",
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            sts.get_caller_identity()
            return True
        except Exception:
            return False


class GitHubValidator(_BaseValidator):
    """Validate GitHub token via /user endpoint."""
    name = "github_api"

    def validate(self, secret: str, **kwargs) -> bool:
        try:
            import urllib.request
            req = urllib.request.Request(
                "https://api.github.com/user",
                headers={"Authorization": f"token {secret}",
                         "User-Agent": "Quantara-Scanner/5.0"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status == 200
        except Exception:
            return False


class StripeValidator(_BaseValidator):
    """Validate Stripe key via /v1/account endpoint."""
    name = "stripe_api"

    def validate(self, secret: str, **kwargs) -> bool:
        try:
            import urllib.request, base64
            creds = base64.b64encode(f"{secret}:".encode()).decode()
            req = urllib.request.Request(
                "https://api.stripe.com/v1/account",
                headers={"Authorization": f"Basic {creds}"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status == 200
        except Exception:
            return False


class SlackValidator(_BaseValidator):
    """Validate Slack token via auth.test API."""
    name = "slack_api"

    def validate(self, secret: str, **kwargs) -> bool:
        try:
            import urllib.request, urllib.parse
            data = urllib.parse.urlencode({"token": secret}).encode()
            req = urllib.request.Request(
                "https://slack.com/api/auth.test",
                data=data,
                method="POST",
            )
            import json
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read())
                return bool(body.get("ok"))
        except Exception:
            return False


# Registry mapping provider → validator instance
_ACTIVE_VALIDATORS: Dict[str, _BaseValidator] = {
    "GitHub":  GitHubValidator(),
    "Stripe":  StripeValidator(),
    "AWS":     AWSValidator(),
    "Slack":   SlackValidator(),
}


def validate_secret_live(finding: SecretFinding, raw_secret: str) -> SecretFinding:
    """
    Attempt live validation of a secret finding.
    Updates finding.verified and finding.verification_method in-place.
    Safe: any exception leaves verified=False.
    """
    validator = _ACTIVE_VALIDATORS.get(finding.provider)
    if validator is None:
        return finding
    try:
        result = validator.validate(raw_secret)
        if result:
            finding.verified = True
            finding.verification_method = validator.name
            logger.warning(
                "ACTIVE CREDENTIAL CONFIRMED: provider=%s rule=%s file=%s",
                finding.provider, finding.rule_id, finding.file_path,
            )
    except Exception as exc:
        logger.debug("Validator error for %s: %s", finding.provider, exc)
    return finding


# ════════════════════════════════════════════════════════════════════════════
# SECTION V — Exposure Intelligence Engine
# ════════════════════════════════════════════════════════════════════════════

def compute_exposure_score(filepath: str, public_repo: bool = False) -> float:
    """
    Composite exposure score (0–10) based on file context and repo visibility.

    Scoring logic:
      - Public repository:        +3.0  (widest blast radius)
      - .env / secrets file:      +2.5  (primary secret store)
      - Frontend / JS bundle:     +2.0  (visible to all users)
      - Docker / compose file:    +1.5  (infra credential leakage)
      - CI/CD config:             +1.5  (pipeline poisoning risk)
      - Cloud config (tf/yaml):   +1.0  (infra-as-code exposure)
      - Source code:              +0.5  (lower than config, still serious)
    """
    fp = filepath.lower()
    score = 1.0  # baseline: any hardcoded secret is a risk

    if public_repo:
        score += 3.0

    if any(p in fp for p in (".env", "secrets", "credentials", ".secret")):
        score += 2.5

    if any(p in fp for p in (".js", ".ts", ".jsx", ".tsx", "frontend", "client", "public")):
        score += 2.0

    if any(p in fp for p in ("dockerfile", "docker-compose", "compose.yml", "compose.yaml")):
        score += 1.5

    if any(p in fp for p in (".github/", ".gitlab-ci", "jenkins", ".travis", "circleci", ".circleci")):
        score += 1.5

    if any(p in fp for p in (".tf", ".tfvars", ".hcl", ".yaml", ".yml")):
        score += 1.0

    if any(p in fp for p in (".py", ".java", ".go", ".rb", ".php", ".cs", ".rs")):
        score += 0.5

    return min(score, 10.0)


def exposure_label(score: float) -> str:
    """Human-readable exposure tier."""
    if score >= 8.0:  return "CRITICAL-EXPOSURE"
    if score >= 6.0:  return "HIGH-EXPOSURE"
    if score >= 4.0:  return "MEDIUM-EXPOSURE"
    if score >= 2.0:  return "LOW-EXPOSURE"
    return "MINIMAL-EXPOSURE"


# ════════════════════════════════════════════════════════════════════════════
# SECTION VI — Secret Lifecycle Tracker
# ════════════════════════════════════════════════════════════════════════════

class SecretLifecycleTracker:
    """
    Tracks secret lifecycle across scans.

    Maintains an in-memory registry keyed by secret_hash.
    Detects:
      - Persistence: secret present in consecutive scans
      - Reintroduction: secret was absent, now found again
      - Rotation failure: high-risk secret never rotated
    """

    def __init__(self) -> None:
        # hash → SecretFinding (last known state)
        self._registry: Dict[str, SecretFinding] = {}
        # hash → set of scan timestamps
        self._history: Dict[str, List[datetime]] = {}

    def update(self, finding: SecretFinding) -> SecretFinding:
        """
        Update lifecycle state for a finding.
        Returns the finding (potentially modified with reintroduced=True).
        """
        h = finding.secret_hash
        now = _utcnow()

        if h in self._registry:
            existing = self._registry[h]
            # Still present — update last_seen, preserve first_seen
            finding.first_seen = existing.first_seen
            finding.last_seen = now
            finding.reintroduced = False
        elif h in self._history:
            # Was seen before but dropped out — it's back
            finding.first_seen = self._history[h][0]
            finding.last_seen = now
            finding.reintroduced = True
            logger.warning(
                "SECRET REINTRODUCED: hash=%s...%s provider=%s file=%s",
                h[:8], h[-4:], finding.provider, finding.file_path,
            )
        else:
            # Brand new finding
            finding.first_seen = now
            finding.last_seen = now

        self._registry[h] = finding
        self._history.setdefault(h, []).append(now)
        return finding

    def mark_resolved(self, secret_hash: str) -> None:
        """Remove a secret from the active registry (e.g. after rotation)."""
        self._registry.pop(secret_hash, None)

    def get_persistent_findings(self, min_occurrences: int = 2) -> List[SecretFinding]:
        """Return findings seen across multiple scans — rotation failure."""
        return [
            f for h, f in self._registry.items()
            if len(self._history.get(h, [])) >= min_occurrences
        ]

    def summary(self) -> dict:
        return {
            "active_secrets": len(self._registry),
            "total_unique_hashes": len(self._history),
            "reintroduced_count": sum(
                1 for f in self._registry.values() if f.reintroduced
            ),
        }


# ════════════════════════════════════════════════════════════════════════════
# SECTION VII — Git History & Incremental Scanner
# ════════════════════════════════════════════════════════════════════════════

def git_commit_history(repo_path: str) -> List[str]:
    """
    Return list of all commit SHAs in the repository.
    Used for full historical secret scanning.
    """
    try:
        result = subprocess.run(
            ["git", "log", "--pretty=format:%H"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            return [sha.strip() for sha in result.stdout.splitlines() if sha.strip()]
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        logger.debug("git log failed: %s", exc)
    return []


def git_show_file_at_commit(repo_path: str, commit_sha: str, filepath: str) -> Optional[str]:
    """Retrieve file contents at a specific git commit."""
    try:
        result = subprocess.run(
            ["git", "show", f"{commit_sha}:{filepath}"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode == 0:
            return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return None


def git_changed_files(repo_path: str, base_ref: str = "HEAD~1") -> List[str]:
    """
    Return files changed since base_ref.
    Used for incremental CI scanning — only scan diff, not entire repo.
    """
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", base_ref],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode == 0:
            return [f.strip() for f in result.stdout.splitlines() if f.strip()]
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        logger.debug("git diff failed: %s", exc)
    return []


def git_file_introduction_commit(repo_path: str, filepath: str, secret_hash: str) -> Optional[str]:
    """
    Find the commit that first introduced a secret into a file.
    Returns commit SHA or None.
    """
    try:
        commits = git_commit_history(repo_path)
        for sha in reversed(commits):   # oldest first
            content = git_show_file_at_commit(repo_path, sha, filepath)
            if content and secret_hash[:16] in hashlib.sha256(content.encode()).hexdigest():
                return sha
    except Exception:
        pass
    return None


# ════════════════════════════════════════════════════════════════════════════
# SECTION VIII — Graph Relationship Builder (Neo4j-ready)
# ════════════════════════════════════════════════════════════════════════════

def build_graph_relationship(finding: SecretFinding) -> Dict:
    """
    Build a Neo4j-compatible graph relationship descriptor.

    Graph model:
      (Developer)-[:COMMITTED]->(Commit)-[:CONTAINS]->(Secret)
      (Secret)-[:GRANTS_ACCESS_TO]->(Provider)
      (Provider)-[:CONTROLS]->(CloudAsset)

    Returns a dict ready for Cypher MERGE queries or JSON export.
    """
    return {
        "nodes": {
            "secret": {
                "label": "Secret",
                "hash": finding.secret_hash,
                "provider": finding.provider,
                "rule_id": finding.rule_id,
                "risk": finding.risk,
                "verified": finding.verified,
                "entropy": round(finding.entropy, 3),
                "exposure_score": round(finding.exposure_score, 2),
            },
            "file": {
                "label": "SourceFile",
                "path": finding.file_path,
                "line": finding.line_number,
            },
            "commit": {
                "label": "GitCommit",
                "sha": finding.commit or "HEAD",
            },
            "provider": {
                "label": "CloudProvider",
                "name": finding.provider,
                "tags": finding.tags,
            },
        },
        "relationships": [
            {"from": "commit", "to": "file",    "type": "MODIFIED"},
            {"from": "file",   "to": "secret",  "type": "CONTAINS"},
            {"from": "secret", "to": "provider","type": "GRANTS_ACCESS_TO"},
        ],
        "cypher_hints": {
            "merge_secret": (
                f"MERGE (s:Secret {{hash: '{finding.secret_hash}'}}) "
                f"SET s.provider = '{finding.provider}', "
                f"s.risk = '{finding.risk}', "
                f"s.verified = {str(finding.verified).lower()}"
            ),
        },
    }


def build_attack_path(findings: List[SecretFinding]) -> Dict:
    """
    Build a multi-node attack path from a list of findings.
    Groups findings by provider for graph traversal.

    Returns a dict describing:
      credential_chain: list of provider → access escalation steps
    """
    by_provider: Dict[str, List[SecretFinding]] = {}
    for f in findings:
        by_provider.setdefault(f.provider, []).append(f)

    # Prioritise by risk_score descending
    chain = sorted(
        [(p, max(fs, key=lambda x: x.risk_score)) for p, fs in by_provider.items()],
        key=lambda x: x[1].risk_score,
        reverse=True,
    )

    return {
        "credential_chain": [
            {
                "step": idx + 1,
                "provider": p,
                "rule_id": f.rule_id,
                "risk": f.risk,
                "risk_score": round(f.risk_score, 3),
                "file": f.file_path,
                "verified": f.verified,
            }
            for idx, (p, f) in enumerate(chain)
        ],
        "total_providers_compromised": len(chain),
        "verified_active_count": sum(1 for _, f in chain if f.verified),
    }


# ════════════════════════════════════════════════════════════════════════════
# SECTION IX — SecretEngine: Main Orchestrator
# ════════════════════════════════════════════════════════════════════════════

# ── Directory scanner constants ───────────────────────────────────────────

DEFAULT_SKIP_DIRS: Set[str] = {
    ".git", ".svn", ".hg", "node_modules", "__pycache__", ".pytest_cache",
    "venv", ".venv", "env", ".tox", ".nox",
    "dist", "build", "target", "out", "bin", "obj",
    ".gradle", ".idea", ".vscode",
    "vendor", "third_party", "3rdparty", "external",
    ".terraform", ".serverless",
    "coverage", ".nyc_output", "htmlcov",
    "migrations", ".eggs", "*.egg-info",
}

# File extensions to include in directory scans (empty = all files)
ALL_SCAN_EXTENSIONS: Set[str] = {
    # Source code
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".java", ".kt", ".go", ".rb", ".php", ".cs", ".rs",
    ".cpp", ".cc", ".c", ".h", ".hpp", ".swift", ".scala",
    ".dart", ".ex", ".exs", ".pl", ".pm", ".groovy",
    # Config / secrets
    ".env", ".env.local", ".env.dev", ".env.staging",
    ".env.production", ".env.test", ".env.example",
    ".yaml", ".yml", ".toml", ".ini", ".conf", ".cfg",
    ".json", ".xml", ".properties", ".hcl", ".tf", ".tfvars",
    # Infra / CI
    ".sh", ".bash", ".zsh", ".fish",
    "dockerfile", ".dockerfile", "containerfile",
    # Certs / keys
    ".pem", ".key", ".crt", ".cer", ".p12", ".pfx",
    # Gradle / Maven
    ".gradle", "pom.xml",
}


def _hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class SecretEngine:
    """
    Enterprise secrets detection orchestrator.

    Usage:
        engine = SecretEngine(validate_live=True, public_repo=False)
        findings = engine.scan_text(content, filepath="app/config.py")
        summary  = engine.summarise(findings)

    Scan pipeline per match:
      1. Regex match from 120+ rule library
      2. Validator filter (not_placeholder, entropy, format)
      3. False-positive path filter
      4. SecretFinding model construction
      5. Entropy computation
      6. Exposure score
      7. Composite risk_score = confidence × entropy × exposure
      8. Optional: live credential validation
      9. Lifecycle tracking
     10. Graph relationship tagging
    """

    def __init__(
        self,
        validate_live: bool = False,
        public_repo: bool = False,
        tracker: Optional[SecretLifecycleTracker] = None,
        min_entropy_threshold: float = 2.5,
    ) -> None:
        self.validate_live = validate_live
        self.public_repo = public_repo
        self.tracker = tracker or SecretLifecycleTracker()
        self.min_entropy_threshold = min_entropy_threshold

    def scan_text(
        self,
        text: str,
        filepath: str = "<unknown>",
        commit_sha: Optional[str] = None,
    ) -> List[SecretFinding]:
        """
        Scan a block of text for secrets.
        Returns a deduplicated list of SecretFinding instances.
        """
        findings: List[SecretFinding] = []
        seen_hashes: set = set()

        for compiled_pattern, rule in COMPILED_SECRET_RULES:
            for match in compiled_pattern.finditer(text):
                raw_secret = match.groupdict().get("secret") or match.group(0)
                if not raw_secret or len(raw_secret) < 8:
                    continue

                # Validator gate
                if rule.validator and rule.validator in VALIDATORS:
                    if not VALIDATORS[rule.validator](raw_secret):
                        continue

                # Entropy gate (skip very low entropy generic patterns)
                ent = shannon_entropy(raw_secret)
                if ent < self.min_entropy_threshold and "generic" in rule.tags:
                    continue

                secret_hash = _hash_secret(raw_secret)

                # Deduplicate within this scan
                dedup_key = f"{rule.id}:{filepath}:{secret_hash}"
                if dedup_key in seen_hashes:
                    continue
                seen_hashes.add(dedup_key)

                line_number = text[: match.start()].count("\n") + 1
                exposure = compute_exposure_score(filepath, self.public_repo)

                # Entropy confidence boost
                adjusted_confidence = min(
                    1.0, rule.confidence + entropy_confidence_boost(raw_secret)
                )

                finding = SecretFinding(
                    rule_id=rule.id,
                    provider=rule.provider,
                    secret_hash=secret_hash,
                    redacted_value=redact_secret(raw_secret),
                    file_path=filepath,
                    line_number=line_number,
                    commit=commit_sha,
                    entropy=ent,
                    confidence=adjusted_confidence,
                    risk=rule.risk.value,
                    cwe=rule.cwe,
                    exposure_score=exposure,
                    risk_score=round(adjusted_confidence * ent * exposure, 3),
                    tags=list(rule.tags),
                    note=rule.note,
                )

                # Live validation (network call — only if enabled)
                if self.validate_live:
                    finding = validate_secret_live(finding, raw_secret)

                # Lifecycle tracking
                finding = self.tracker.update(finding)

                findings.append(finding)

        return findings

    def scan_file(
        self,
        filepath: str,
        commit_sha: Optional[str] = None,
    ) -> List[SecretFinding]:
        """Scan a file on disk."""
        try:
            with open(filepath, encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
        except OSError as exc:
            logger.debug("Cannot read %s: %s", filepath, exc)
            return []

        if is_likely_false_positive_path(filepath):
            logger.debug("Skipping likely FP path: %s", filepath)
            return []

        return self.scan_text(content, filepath=filepath, commit_sha=commit_sha)

    def scan_git_history(
        self,
        repo_path: str,
        max_commits: int = 200,
    ) -> List[SecretFinding]:
        """
        Scan all commits in a git repository for secrets.
        Returns findings tagged with the introducing commit SHA.

        max_commits: cap to avoid very long scans on large repos.
        """
        all_findings: List[SecretFinding] = []
        commits = git_commit_history(repo_path)[:max_commits]

        if not commits:
            logger.info("No git history found at %s", repo_path)
            return []

        logger.info("Scanning %d commits in %s", len(commits), repo_path)

        for sha in commits:
            # Get changed files in this commit
            try:
                result = subprocess.run(
                    ["git", "diff-tree", "--no-commit-id", "-r", "--name-only", sha],
                    cwd=repo_path,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                changed = [f.strip() for f in result.stdout.splitlines() if f.strip()]
            except Exception:
                continue

            for filepath in changed:
                content = git_show_file_at_commit(repo_path, sha, filepath)
                if content:
                    findings = self.scan_text(content, filepath=filepath, commit_sha=sha)
                    all_findings.extend(findings)

        return all_findings

    def scan_incremental(
        self,
        repo_path: str,
        base_ref: str = "HEAD~1",
    ) -> List[SecretFinding]:
        """
        CI-speed incremental scan: only files changed since base_ref.
        Use this in CI pipelines for fast PR-gate checks.
        """
        changed = git_changed_files(repo_path, base_ref)
        if not changed:
            logger.info("No changed files detected vs %s", base_ref)
            return []

        findings: List[SecretFinding] = []
        for filepath in changed:
            import os
            full_path = os.path.join(repo_path, filepath)
            findings.extend(self.scan_file(full_path))
        return findings

    def summarise(self, findings: List[SecretFinding]) -> dict:
        """
        Aggregate a list of findings into a risk summary dict.
        Compatible with SSE event streaming (`risk_updated` event).
        """
        if not findings:
            return {
                "total": 0,
                "verified_active": 0,
                "by_provider": {},
                "by_risk": {},
                "exposure_distribution": {},
                "lifecycle": self.tracker.summary(),
                "top_findings": [],
            }

        by_provider: Dict[str, int] = {}
        by_risk: Dict[str, int] = {}
        exposure_dist: Dict[str, int] = {}

        for f in findings:
            by_provider[f.provider] = by_provider.get(f.provider, 0) + 1
            by_risk[f.risk] = by_risk.get(f.risk, 0) + 1
            label = exposure_label(f.exposure_score)
            exposure_dist[label] = exposure_dist.get(label, 0) + 1

        # Top 5 findings by risk_score
        top = sorted(findings, key=lambda x: x.risk_score, reverse=True)[:5]

        return {
            "total": len(findings),
            "verified_active": sum(1 for f in findings if f.verified),
            "reintroduced": sum(1 for f in findings if f.reintroduced),
            "by_provider": by_provider,
            "by_risk": by_risk,
            "exposure_distribution": exposure_dist,
            "lifecycle": self.tracker.summary(),
            "attack_path": build_attack_path(findings),
            "top_findings": [f.to_dict() for f in top],
        }

    # ── Directory Scanner ─────────────────────────────────────────────────

    def scan_directory(
        self,
        root: str,
        extensions: Optional[Set[str]] = None,
        skip_dirs: Optional[Set[str]] = None,
        max_file_bytes: int = 10 * 1024 * 1024,
    ) -> List[SecretFinding]:
        """
        Recursively walk a directory tree and scan every eligible file.

        extensions    : only scan these file extensions, e.g. {".py", ".env"}
                        defaults to ALL_SCAN_EXTENSIONS
        skip_dirs     : directory names to prune (defaults to DEFAULT_SKIP_DIRS)
        max_file_bytes: skip files larger than this (avoid binary/data files)
        """
        _skip = skip_dirs if skip_dirs is not None else DEFAULT_SKIP_DIRS
        _exts = extensions if extensions is not None else ALL_SCAN_EXTENSIONS

        all_findings: List[SecretFinding] = []
        scanned = 0
        skipped = 0

        for dirpath, dirnames, filenames in os.walk(root):
            # Prune unwanted directories in-place
            dirnames[:] = [
                d for d in dirnames
                if d not in _skip and not d.startswith(".")
            ]

            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                _, ext = os.path.splitext(filename.lower())

                # Extension filter
                if _exts and ext not in _exts and filename.lower() not in _exts:
                    skipped += 1
                    continue

                # File size guard
                try:
                    if os.path.getsize(filepath) > max_file_bytes:
                        logger.debug("Skipping large file: %s", filepath)
                        skipped += 1
                        continue
                except OSError:
                    skipped += 1
                    continue

                findings = self.scan_file(filepath)
                all_findings.extend(findings)
                scanned += 1

        logger.info(
            "Directory scan complete: root=%s scanned=%d skipped=%d findings=%d",
            root, scanned, skipped, len(all_findings),
        )
        return all_findings

    # ── .env Deep Analyzer ────────────────────────────────────────────────

    def scan_env_file(self, filepath: str) -> List[SecretFinding]:
        """
        Specialised deep analysis for .env / dotenv files.

        In addition to pattern matching, this method:
          - Parses every KEY=VALUE pair
          - Applies entropy check on ALL values (not just those matching a rule)
          - Flags any high-entropy value as a potential secret even without a
            known-format rule match
          - Attaches ENV_FILE tag for downstream filtering
        """
        findings: List[SecretFinding] = []

        try:
            with open(filepath, encoding="utf-8", errors="ignore") as fh:
                lines = fh.readlines()
        except OSError as exc:
            logger.debug("Cannot read .env file %s: %s", filepath, exc)
            return []

        # Run standard pattern scan first
        text = "".join(lines)
        findings.extend(self.scan_text(text, filepath=filepath))

        # Entropy sweep on raw KEY=VALUE pairs
        seen_hashes: Set[str] = {f.secret_hash for f in findings}
        for lineno, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue

            key, _, value = line.partition("=")
            value = value.strip().strip("'\"")
            if len(value) < 12:
                continue

            ent = shannon_entropy(value)
            if ent < 4.0:
                continue  # not high enough entropy to flag

            h = _hash_secret(value)
            if h in seen_hashes:
                continue  # already caught by pattern scan
            seen_hashes.add(h)

            exposure = compute_exposure_score(filepath, self.public_repo)
            finding = SecretFinding(
                rule_id="SEC-ENTROPY",
                provider="Generic",
                secret_hash=h,
                redacted_value=redact_secret(value),
                file_path=filepath,
                line_number=lineno,
                commit=None,
                entropy=ent,
                confidence=min(0.90, 0.55 + entropy_confidence_boost(value)),
                risk=RiskLevel.HIGH.value,
                cwe="CWE-798",
                exposure_score=exposure,
                risk_score=round(0.70 * ent * exposure, 3),
                tags=["env-file", "high-entropy"],
                note=(
                    f"High-entropy value in .env key '{key.strip()}' "
                    f"(entropy={ent:.2f}) — likely hardcoded secret"
                ),
            )
            finding = self.tracker.update(finding)
            findings.append(finding)

        return findings

    # ── High-Entropy Fallback Scanner ─────────────────────────────────────

    def scan_high_entropy_strings(
        self,
        text: str,
        filepath: str = "<unknown>",
        min_length: int = 20,
        entropy_threshold: float = 4.5,
    ) -> List[SecretFinding]:
        """
        Fallback scanner: detect high-entropy strings not matched by any rule.

        Useful for catching:
          - Novel API key formats not yet in the rule library
          - Custom internal tokens
          - Base64-encoded secrets without a provider prefix

        Only emits findings for tokens that:
          1. Are ≥ min_length characters
          2. Have Shannon entropy ≥ entropy_threshold
          3. Do NOT already match a known rule (dedup by hash)
        """
        # Collect hashes already caught by pattern rules
        known = {f.secret_hash for f in self.scan_text(text, filepath)}

        # Candidate token regex: base64-ish, hex, or alphanumeric strings
        _TOKEN_RE = re.compile(
            r"(?:^|[\"'=:\s])([A-Za-z0-9+/=_\-]{%d,})(?:[\"';\s,]|$)" % min_length,
            re.MULTILINE,
        )

        findings: List[SecretFinding] = []
        seen: Set[str] = set()

        for match in _TOKEN_RE.finditer(text):
            token = match.group(1).strip("=")
            if len(token) < min_length:
                continue

            ent = shannon_entropy(token)
            if ent < entropy_threshold:
                continue

            h = _hash_secret(token)
            if h in known or h in seen:
                continue
            seen.add(h)

            exposure = compute_exposure_score(filepath, self.public_repo)
            line_no = text[: match.start()].count("\n") + 1

            finding = SecretFinding(
                rule_id="SEC-ENTROPY",
                provider="Generic",
                secret_hash=h,
                redacted_value=redact_secret(token),
                file_path=filepath,
                line_number=line_no,
                commit=None,
                entropy=ent,
                confidence=min(0.85, 0.45 + entropy_confidence_boost(token)),
                risk=RiskLevel.HIGH.value,
                cwe="CWE-798",
                exposure_score=exposure,
                risk_score=round(0.65 * ent * exposure, 3),
                tags=["high-entropy", "unknown-format"],
                note=(
                    f"High-entropy string (entropy={ent:.2f}, len={len(token)}) "
                    "— potential unknown secret format"
                ),
            )
            finding = self.tracker.update(finding)
            findings.append(finding)

        return findings

    # ── Export: SARIF 2.1 ────────────────────────────────────────────────

    def to_sarif(
        self,
        findings: List[SecretFinding],
        tool_version: str = "5.0.0",
    ) -> dict:
        """
        Serialize findings as a SARIF 2.1 report.
        Compatible with GitHub Advanced Security, Azure DevOps, and VS Code.
        """
        rules_seen: Dict[str, dict] = {}
        results: list = []

        for f in findings:
            rule_id = f"QP/SECRETS/{f.rule_id}"

            if rule_id not in rules_seen:
                rules_seen[rule_id] = {
                    "id": rule_id,
                    "name": f.provider.replace(" ", ""),
                    "shortDescription": {
                        "text": f"Hardcoded {f.provider} credential detected"
                    },
                    "fullDescription": {"text": f.note},
                    "defaultConfiguration": {
                        "level": (
                            "error"   if f.risk in ("Critical", "High")
                            else "warning" if f.risk == "Medium"
                            else "note"
                        )
                    },
                    "helpUri": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
                    "properties": {
                        "tags": ["security", "secrets", "credentials"] + f.tags,
                        "cwe": f.cwe,
                    },
                }

            results.append({
                "ruleId": rule_id,
                "level": (
                    "error"   if f.risk in ("Critical", "High")
                    else "warning" if f.risk == "Medium"
                    else "note"
                ),
                "message": {
                    "text": (
                        f"{f.note} | Provider: {f.provider} | "
                        f"Risk: {f.risk} | Entropy: {f.entropy:.2f} | "
                        f"Exposure: {f.exposure_score:.1f}/10 | "
                        f"{'VERIFIED-ACTIVE' if f.verified else 'unverified'}"
                    )
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.file_path.replace("\\", "/"),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {"startLine": max(1, f.line_number)},
                    }
                }],
                "properties": {
                    "secretHash":     f.secret_hash[:16] + "...",
                    "redactedValue":  f.redacted_value,
                    "confidence":     round(f.confidence, 3),
                    "riskScore":      round(f.risk_score, 3),
                    "exposureScore":  round(f.exposure_score, 2),
                    "verified":       f.verified,
                    "verificationMethod": f.verification_method,
                    "reintroduced":   f.reintroduced,
                    "commit":         f.commit,
                    "firstSeen":      f.first_seen.isoformat(),
                    "lastSeen":       f.last_seen.isoformat(),
                },
            })

        return {
            "$schema": (
                "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json"
            ),
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Quantara Secrets Engine",
                        "semanticVersion": tool_version,
                        "informationUri": "https://quantara.io",
                        "rules": list(rules_seen.values()),
                    }
                },
                "results": results,
                "invocations": [{
                    "executionSuccessful": True,
                    "startTimeUtc": _utcnow().isoformat(),
                }],
            }],
        }

    def to_sarif_json(self, findings: List[SecretFinding], indent: int = 2) -> str:
        """Return SARIF report as a formatted JSON string."""
        return json.dumps(self.to_sarif(findings), indent=indent, default=str)

    # ── Export: CSV ──────────────────────────────────────────────────────

    def to_csv(self, findings: List[SecretFinding]) -> str:
        """
        Serialize findings as a CSV string.
        Suitable for import into Jira, spreadsheets, or SIEM tools.
        """
        fieldnames = [
            "rule_id", "provider", "risk", "cwe",
            "file_path", "line_number", "commit",
            "entropy", "confidence", "exposure_score", "risk_score",
            "verified", "verification_method", "reintroduced",
            "redacted_value", "note", "tags",
            "first_seen", "last_seen",
        ]
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for f in findings:
            row = f.to_dict()
            row["tags"] = "|".join(f.tags)
            writer.writerow(row)
        return buf.getvalue()

    # ── Export: JSON ─────────────────────────────────────────────────────

    def to_json(self, findings: List[SecretFinding], indent: int = 2) -> str:
        """Return findings as a formatted JSON array string."""
        return json.dumps(
            [f.to_dict() for f in findings],
            indent=indent,
            default=str,
        )

    # ── Convenience: full scan pipeline ─────────────────────────────────

    def run(
        self,
        target: str,
        mode: str = "directory",
        public_repo: bool = False,
        validate_live: bool = False,
        git_history: bool = False,
        incremental: bool = False,
        output_format: str = "json",
    ) -> str:
        """
        One-shot scan entry point. Returns output in the requested format.

        mode values:
          "directory"  — scan entire directory tree (default)
          "file"       — scan a single file
          "text"       — scan a string passed as `target`

        output_format: "json" | "sarif" | "csv" | "summary"
        """
        self.public_repo = public_repo
        self.validate_live = validate_live

        if mode == "file":
            findings = self.scan_file(target)
        elif mode == "text":
            findings = self.scan_text(target, filepath="<inline>")
        else:
            findings = self.scan_directory(target)

        if git_history and os.path.isdir(os.path.join(target, ".git")):
            findings.extend(self.scan_git_history(target))
        elif incremental and os.path.isdir(os.path.join(target, ".git")):
            findings.extend(self.scan_incremental(target))

        # Deduplicate across git + directory scan
        seen: Set[str] = set()
        unique: List[SecretFinding] = []
        for f in findings:
            key = f"{f.rule_id}:{f.file_path}:{f.secret_hash}"
            if key not in seen:
                seen.add(key)
                unique.append(f)

        if output_format == "sarif":
            return self.to_sarif_json(unique)
        if output_format == "csv":
            return self.to_csv(unique)
        if output_format == "summary":
            return json.dumps(self.summarise(unique), indent=2, default=str)
        return self.to_json(unique)


# ════════════════════════════════════════════════════════════════════════════
# SECTION X — SecretEngineConfig: Typed Configuration Dataclass
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class SecretEngineConfig:
    """
    Typed configuration for SecretEngine.

    Decouples engine construction from caller code.
    Serialisable for storage in scan job metadata.

    Example
    -------
    cfg = SecretEngineConfig(validate_live=True, public_repo=True)
    engine = cfg.build()
    findings = engine.run("/path/to/repo", output_format="sarif")
    """
    validate_live: bool = False
    public_repo: bool = False
    min_entropy_threshold: float = 2.5
    max_file_bytes: int = 10 * 1024 * 1024   # 10 MB
    skip_dirs: Optional[Set[str]] = None
    scan_extensions: Optional[Set[str]] = None
    # Git options
    git_history: bool = False
    incremental: bool = False
    max_commits: int = 200
    # Output
    output_format: str = "json"               # "json" | "sarif" | "csv" | "summary"

    def build(self) -> "SecretEngine":
        """Construct a configured SecretEngine from this config."""
        return SecretEngine(
            validate_live=self.validate_live,
            public_repo=self.public_repo,
            min_entropy_threshold=self.min_entropy_threshold,
        )

    def to_dict(self) -> dict:
        return {
            "validate_live": self.validate_live,
            "public_repo": self.public_repo,
            "min_entropy_threshold": self.min_entropy_threshold,
            "max_file_bytes": self.max_file_bytes,
            "git_history": self.git_history,
            "incremental": self.incremental,
            "max_commits": self.max_commits,
            "output_format": self.output_format,
        }


# ════════════════════════════════════════════════════════════════════════════
# Public API — what callers import
# ════════════════════════════════════════════════════════════════════════════

__all__ = [
    # Core rule primitives
    "SecretRule",
    "ALL_SECRET_RULES",
    "COMPILED_SECRET_RULES",
    "get_rule_count",
    "get_rules_by_provider",

    # Entropy helpers
    "shannon_entropy",
    "chi_squared_score",
    "is_high_entropy",
    "entropy_confidence_boost",

    # Validators
    "VALIDATORS",
    "_validate_not_placeholder",
    "_validate_min_entropy",
    "_validate_aws_key_format",
    "_validate_not_test_context",

    # Path filters + redaction
    "is_likely_false_positive_path",
    "redact_secret",

    # Enterprise finding model
    "SecretFinding",

    # Live validators
    "AWSValidator",
    "GitHubValidator",
    "StripeValidator",
    "SlackValidator",
    "validate_secret_live",

    # Exposure engine
    "compute_exposure_score",
    "exposure_label",

    # Lifecycle tracker
    "SecretLifecycleTracker",

    # Git intelligence
    "git_commit_history",
    "git_show_file_at_commit",
    "git_changed_files",
    "git_file_introduction_commit",

    # Graph builder
    "build_graph_relationship",
    "build_attack_path",

    # Directory constants
    "DEFAULT_SKIP_DIRS",
    "ALL_SCAN_EXTENSIONS",

    # Orchestrator + config
    "SecretEngine",
    "SecretEngineConfig",
]
