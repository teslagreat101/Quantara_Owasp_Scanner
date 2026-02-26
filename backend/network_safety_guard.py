"""
Network Safety Guard
====================
Prevents SSRF by blocking all requests that target private, loopback,
link-local, metadata, or internal-infrastructure IP ranges and hostnames.

All verification requests pass through this guard before execution.
A blocked target terminates verification immediately — no partial attempts.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ── Private / reserved networks (IPv4 + IPv6) ────────────────────────────────
_BLOCKED_NETWORKS_V4: list[ipaddress.IPv4Network] = [
    ipaddress.IPv4Network("127.0.0.0/8"),       # loopback
    ipaddress.IPv4Network("10.0.0.0/8"),         # RFC 1918
    ipaddress.IPv4Network("172.16.0.0/12"),      # RFC 1918
    ipaddress.IPv4Network("192.168.0.0/16"),     # RFC 1918
    ipaddress.IPv4Network("169.254.0.0/16"),     # link-local / AWS metadata
    ipaddress.IPv4Network("100.64.0.0/10"),      # shared address space (RFC 6598)
    ipaddress.IPv4Network("192.0.0.0/24"),       # IANA special-purpose
    ipaddress.IPv4Network("198.18.0.0/15"),      # benchmark testing
    ipaddress.IPv4Network("198.51.100.0/24"),    # TEST-NET-2
    ipaddress.IPv4Network("203.0.113.0/24"),     # TEST-NET-3
    ipaddress.IPv4Network("240.0.0.0/4"),        # reserved
    ipaddress.IPv4Network("0.0.0.0/8"),          # "this" network
    ipaddress.IPv4Network("255.255.255.255/32"), # broadcast
]

_BLOCKED_NETWORKS_V6: list[ipaddress.IPv6Network] = [
    ipaddress.IPv6Network("::1/128"),            # loopback
    ipaddress.IPv6Network("fc00::/7"),           # unique local
    ipaddress.IPv6Network("fe80::/10"),          # link-local
    ipaddress.IPv6Network("::/128"),             # unspecified
    ipaddress.IPv6Network("::ffff:0:0/96"),      # IPv4-mapped (could map to private)
    ipaddress.IPv6Network("64:ff9b::/96"),       # NAT64
    ipaddress.IPv6Network("100::/64"),           # discard
]

# ── Blocked hostnames (exact match, case-insensitive) ────────────────────────
_BLOCKED_HOSTNAMES: frozenset[str] = frozenset({
    "localhost",
    "ip6-localhost",
    "ip6-loopback",
    "broadcasthost",
    # Cloud metadata endpoints
    "169.254.169.254",              # AWS / Azure / GCP link-local
    "metadata.google.internal",
    "metadata",
    "instance-data",
    # Kubernetes internal DNS
    "kubernetes",
    "kubernetes.default",
    "kubernetes.default.svc",
    "kubernetes.default.svc.cluster",
    "kubernetes.default.svc.cluster.local",
    "kube-dns.kube-system.svc.cluster.local",
    # Docker
    "host.docker.internal",
    "gateway.docker.internal",
})

# ── Blocked hostname pattern suffixes / regex ────────────────────────────────
_BLOCKED_HOSTNAME_PATTERNS: list[re.Pattern] = [
    re.compile(r"169\.254\.", re.IGNORECASE),
    re.compile(r"\.local$", re.IGNORECASE),
    re.compile(r"\.internal$", re.IGNORECASE),
    re.compile(r"\.corp$", re.IGNORECASE),
    re.compile(r"\.lan$", re.IGNORECASE),
    re.compile(r"\.cluster\.local$", re.IGNORECASE),
    re.compile(r"\.svc$", re.IGNORECASE),
    re.compile(r"^metadata$", re.IGNORECASE),
    re.compile(r"^169\.254\.\d+\.\d+$"),
]

# ── Blocked URI schemes ───────────────────────────────────────────────────────
_BLOCKED_SCHEMES: frozenset[str] = frozenset({
    "file", "ftp", "dict", "gopher", "ldap", "ldaps",
    "tftp", "ssh", "telnet", "sftp", "smb", "netdoc",
    "jar", "expect", "php",
})


class SSRFBlockedError(Exception):
    """Raised when a target URL is identified as unsafe."""


# ─────────────────────────────────────────────────────────────────────────────
# Core predicates
# ─────────────────────────────────────────────────────────────────────────────

def is_private_ip(ip: str) -> bool:
    """
    Return True if the IP is in any blocked (private/reserved) range.
    Invalid IPs return True (treat as blocked — fail-safe).
    """
    try:
        addr = ipaddress.ip_address(ip)
        if isinstance(addr, ipaddress.IPv4Address):
            return any(addr in net for net in _BLOCKED_NETWORKS_V4)
        else:
            return any(addr in net for net in _BLOCKED_NETWORKS_V6)
    except ValueError:
        logger.warning(f"[SafetyGuard] Invalid IP string — blocking: {ip!r}")
        return True


def resolve_dns_securely(hostname: str) -> Optional[str]:
    """
    Resolve hostname to its first IPv4/IPv6 address.
    Returns None if resolution fails OR if the resolved IP is private.
    Never raises — returns None on any error.
    """
    try:
        # getaddrinfo returns list of (family, type, proto, canonname, sockaddr)
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC)
        for _fam, _typ, _proto, _canon, sockaddr in results:
            ip = sockaddr[0]
            if is_private_ip(ip):
                logger.warning(
                    f"[SafetyGuard] DNS resolved {hostname!r} → {ip} (PRIVATE — blocked)"
                )
                return None
        # Return first resolved IP that passed
        if results:
            return results[0][4][0]
        return None
    except (socket.gaierror, OSError) as exc:
        logger.debug(f"[SafetyGuard] DNS resolution failed for {hostname!r}: {exc}")
        return None


def is_safe_hostname(hostname: str) -> bool:
    """
    Return True ONLY when the hostname is safe to request.
    Checks: exact blocklist, pattern blocklist, then DNS resolution.
    """
    if not hostname:
        return False

    lower = hostname.lower().strip()

    # Exact match blocklist
    if lower in _BLOCKED_HOSTNAMES:
        logger.warning(f"[SafetyGuard] Hostname in exact blocklist: {lower!r}")
        return False

    # Pattern match blocklist
    for pat in _BLOCKED_HOSTNAME_PATTERNS:
        if pat.search(lower):
            logger.warning(f"[SafetyGuard] Hostname matched blocked pattern: {lower!r}")
            return False

    # If hostname looks like an IP, check directly
    try:
        ipaddress.ip_address(lower)
        return not is_private_ip(lower)
    except ValueError:
        pass  # not a raw IP — proceed to DNS check

    # DNS resolution check
    resolved = resolve_dns_securely(lower)
    if resolved is None:
        logger.warning(f"[SafetyGuard] DNS check failed for {lower!r} — blocking")
        return False

    return True


def block_internal_targets(url: str) -> bool:
    """
    Return True if the URL should be blocked.
    Checks: scheme, hostname, port, and DNS resolution.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return True  # unparseable → block

    # Block unsafe schemes
    scheme = (parsed.scheme or "").lower()
    if scheme in _BLOCKED_SCHEMES:
        logger.warning(f"[SafetyGuard] Blocked scheme: {scheme!r} in {url!r}")
        return True

    # Must be http/https
    if scheme not in ("http", "https"):
        return True

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return True

    # Block privileged ports (< 1024 except 80/443)
    port = parsed.port
    if port is not None and port not in (80, 443, 8080, 8443, 3000, 5000, 8000) and port < 1024:
        logger.warning(f"[SafetyGuard] Blocked privileged port {port} in {url!r}")
        return True

    return not is_safe_hostname(hostname)


def prevent_ssrf_execution(url: str) -> None:
    """
    Guard function — raises SSRFBlockedError if the target is unsafe.
    Call this before ANY outbound HTTP request during verification.

    Usage:
        prevent_ssrf_execution(target_url)   # raises if unsafe
        # ... proceed with request
    """
    if block_internal_targets(url):
        raise SSRFBlockedError(
            f"SSRF protection triggered: request to internal/private target blocked — {url!r}"
        )
    logger.debug(f"[SafetyGuard] Target approved: {url!r}")


def validate_url_batch(urls: list[str]) -> tuple[list[str], list[str]]:
    """
    Split a list of URLs into (safe_urls, blocked_urls).
    Useful for pre-filtering endpoint lists before verification.
    """
    safe, blocked = [], []
    for url in urls:
        if block_internal_targets(url):
            blocked.append(url)
        else:
            safe.append(url)
    return safe, blocked
