"""
Finding Deduplication Engine
============================
Prevents duplicate vulnerability explosions during large scans (e.g. GitHub repos).

Key functions:
  - normalize_endpoint_path()   : /api/user/1, /api/user/2 → /api/user/{id}
  - compute_finding_fingerprint(): SHA-256 fingerprint for real-time dedup
  - is_duplicate()               : O(1) set lookup — call in scan hot loop
  - compute_evidence_hash()      : content-based hash for DB evidence_hash column
"""

import re
import hashlib
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Path normalisation patterns (applied in order — most specific first)
# ──────────────────────────────────────────────────────────────────────────────

_UUID_SEGMENT = re.compile(
    r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=/|$)",
    re.IGNORECASE,
)
_HEX_SEGMENT = re.compile(r"/[0-9a-f]{16,}(?=/|$)", re.IGNORECASE)
_NUMERIC_SEGMENT = re.compile(r"/\d+(?=/|$)")

# Common dynamic query params whose values should be stripped
_QS_DYNAMIC = re.compile(r"([\?&](?:id|user_id|page|offset|limit|cursor)=)[^&]*", re.IGNORECASE)


def normalize_endpoint_path(path: str) -> str:
    """
    Normalize a URL path so that parametric variants are treated as the same endpoint.

    Examples:
        /api/users/123         → /api/users/{id}
        /api/users/abc-def-123 → /api/users/{id}   (UUID)
        /api/posts/1/comments/2 → /api/posts/{id}/comments/{id}
        /api/items?id=42       → /api/items?id={val}

    Returns the original path unchanged if it is falsy.
    """
    if not path:
        return path or ""
    # Separate path from query string
    if "?" in path:
        base, qs = path.split("?", 1)
    else:
        base, qs = path, ""

    # Apply substitutions — order matters
    base = _UUID_SEGMENT.sub("/{id}", base)
    base = _HEX_SEGMENT.sub("/{id}", base)
    base = _NUMERIC_SEGMENT.sub("/{id}", base)

    if qs:
        qs = _QS_DYNAMIC.sub(r"\1{val}", qs)
        return f"{base}?{qs}"
    return base


def compute_finding_fingerprint(normalized: dict) -> str:
    """
    Compute a SHA-256 fingerprint for a normalized finding dict.

    The fingerprint encodes:
      vuln_type | normalized_endpoint | line_number | severity | module

    Path normalization is applied so that /api/user/1 and /api/user/2 share
    the same fingerprint when they have the same vulnerability type.

    Returns: 64-character hex digest string.
    """
    vuln_type = (normalized.get("title") or "").strip().lower()

    # file/endpoint field varies by scanner module
    raw_path = (
        normalized.get("file")
        or normalized.get("endpoint")
        or normalized.get("url")
        or ""
    )
    norm_path = normalize_endpoint_path(raw_path)

    line = str(normalized.get("line_number") or 0)
    severity = (normalized.get("severity") or "info").lower()
    module = (
        normalized.get("module")
        or normalized.get("module_name")
        or normalized.get("scanner")
        or ""
    ).lower()

    raw = f"{vuln_type}|{norm_path}|{line}|{severity}|{module}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def is_duplicate(normalized: dict, dedup_set: set) -> bool:
    """
    Check whether a finding is a duplicate of one already seen this scan.

    O(1) set lookup.  Side-effect: adds the fingerprint to dedup_set when
    the finding is NEW (returns False).

    Usage in the scan hot loop:
        if is_duplicate(normalized, scan["dedup_set"]):
            scan["dedup_skipped"] += 1
            continue
    """
    fp = compute_finding_fingerprint(normalized)
    if fp in dedup_set:
        return True
    dedup_set.add(fp)
    return False


def compute_evidence_hash(normalized: dict) -> str:
    """
    Compute a content-based evidence hash for storage in Finding.evidence_hash.

    Unlike the fingerprint (which normalises paths for dedup), this hash
    captures the raw evidence so two findings at different locations with
    the same content can be identified at the DB level.

    Returns: 64-character hex digest string.
    """
    parts = [
        normalized.get("matched_content") or normalized.get("evidence") or "",
        normalized.get("file") or normalized.get("endpoint") or "",
        str(normalized.get("line_number") or 0),
        normalized.get("title") or "",
    ]
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def deduplicate_findings_list(findings: list) -> list:
    """
    Post-scan batch deduplication of a flat list of normalized finding dicts.

    Keeps the highest-confidence copy when duplicates are found.
    Call this once after all modules complete for a final cross-module pass.

    Returns: deduplicated list (order not guaranteed).
    """
    seen: dict[str, dict] = {}
    for f in findings:
        fp = compute_finding_fingerprint(f)
        if fp not in seen:
            seen[fp] = f
        else:
            existing_conf = float(seen[fp].get("confidence_score") or seen[fp].get("confidence") or 0)
            new_conf = float(f.get("confidence_score") or f.get("confidence") or 0)
            if new_conf > existing_conf:
                seen[fp] = f
    return list(seen.values())
