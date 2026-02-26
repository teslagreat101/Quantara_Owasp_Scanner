"""
Quantara Authenticated Scanning Engine
=======================================

Phase 2 of the Quantara enterprise scanner pipeline.

Provides authenticated HTTP sessions for:
  - Form-based login (POST credentials, extract session cookies)
  - JWT/Bearer token authentication
  - OAuth2 client_credentials flow
  - Cookie jar persistence across the entire scan session
  - Token auto-refresh on 401 responses
  - Multi-role scanning (admin vs user vs anonymous)
  - CSRF token extraction from pre-login pages
  - Session health monitoring (re-auth on session expiry)

Architecture:
  AuthConfig — authentication strategy + credentials descriptor
  AuthSession — authenticated httpx session wrapper
  QuantaraAuthEngine — manages auth strategy execution + session persistence
      ├─ FormAuthStrategy
      ├─ TokenAuthStrategy (JWT / Bearer / API Key)
      ├─ OAuth2AuthStrategy (client_credentials flow)
      └─ CookieAuthStrategy (pre-baked cookies)

  MultiRoleManager — orchestrate scanning across multiple auth contexts
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

logger = logging.getLogger("owasp_scanner.quantara_auth")

# ─────────────────────────────────────────────────────────────────────────────
# Auth Configuration Models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AuthConfig:
    """
    Describes an authentication strategy and its credentials.

    strategy: "form" | "token" | "oauth2" | "cookie" | "api_key"
    """
    strategy: str                        # "form", "token", "oauth2", "cookie", "api_key"
    role: str = "user"                   # "admin", "user", "readonly", "anonymous"

    # Form auth fields
    login_url: str = ""
    username_field: str = "username"
    password_field: str = "password"
    username: str = ""
    password: str = ""
    success_indicator: str = ""          # text in response body confirming login success
    failure_indicator: str = ""          # text indicating failure (e.g. "Invalid credentials")

    # Token auth fields
    token: str = ""                      # raw JWT / Bearer token
    token_header: str = "Authorization"
    token_prefix: str = "Bearer"         # "Bearer" / "Token" / "" (for raw key)

    # API key auth
    api_key: str = ""
    api_key_header: str = "X-API-Key"
    api_key_param: str = ""              # if passed as query param instead of header

    # OAuth2 fields
    oauth2_token_url: str = ""
    client_id: str = ""
    client_secret: str = ""
    scope: str = ""

    # Cookie auth
    cookies: dict[str, str] = field(default_factory=dict)

    # Refresh
    refresh_token: str = ""
    refresh_url: str = ""                # OAuth2 refresh endpoint
    token_expires_at: float = 0.0        # unix timestamp

    # Extra headers to inject on all requests
    extra_headers: dict[str, str] = field(default_factory=dict)

    def is_expired(self) -> bool:
        """True if the token is expired or about to expire (within 30s)."""
        if not self.token_expires_at:
            return False
        return time.time() > (self.token_expires_at - 30)


@dataclass
class AuthResult:
    """Result of an authentication attempt."""
    success: bool
    role: str
    strategy: str
    cookies: dict[str, str] = field(default_factory=dict)
    token: str = ""
    refresh_token: str = ""
    token_expires_at: float = 0.0
    session_headers: dict[str, str] = field(default_factory=dict)
    error: str = ""
    raw_response: str = ""


# ─────────────────────────────────────────────────────────────────────────────
# Auth Strategies
# ─────────────────────────────────────────────────────────────────────────────

class FormAuthStrategy:
    """
    Authenticates via HTML login form submission.

    Steps:
      1. GET login page → extract CSRF token (if present)
      2. POST credentials + CSRF token
      3. Detect success/failure from response body / redirect
      4. Persist session cookies
    """

    async def authenticate(self, client: Any, config: AuthConfig) -> AuthResult:
        """
        Execute form-based authentication.
        `client` is an httpx.AsyncClient.
        """
        result = AuthResult(success=False, role=config.role, strategy="form")

        if not config.login_url or not config.username or not config.password:
            result.error = "form auth requires login_url, username, password"
            return result

        # Step 1: GET the login page to extract CSRF token
        csrf_token = ""
        csrf_field = ""
        try:
            resp = await client.get(config.login_url)
            csrf_token, csrf_field = _extract_csrf(resp.text)
            logger.debug(f"[auth-form] login page status={resp.status_code}, csrf_field={csrf_field}")
        except Exception as e:
            logger.warning(f"[auth-form] GET login page failed: {e}")

        # Step 2: Build POST data
        post_data: dict[str, str] = {
            config.username_field: config.username,
            config.password_field: config.password,
        }
        if csrf_token and csrf_field:
            post_data[csrf_field] = csrf_token
            logger.debug(f"[auth-form] injecting CSRF: {csrf_field}={csrf_token[:20]}...")

        # Step 3: Submit credentials
        try:
            resp = await client.post(config.login_url, data=post_data)
            result.raw_response = resp.text[:500]

            # Detect success
            if config.success_indicator:
                result.success = config.success_indicator.lower() in resp.text.lower()
            elif config.failure_indicator:
                result.success = config.failure_indicator.lower() not in resp.text.lower()
            else:
                # Heuristic: redirect away from login page OR session cookie set
                final_url = str(resp.url)
                result.success = (
                    resp.status_code in (200, 302, 301) and
                    not any(w in final_url.lower() for w in ("login", "signin", "error", "failed"))
                )

            if result.success:
                # Extract cookies from the client's jar
                result.cookies = dict(client.cookies)
                result.session_headers = dict(config.extra_headers)
                logger.info(f"[auth-form] Login SUCCESS as {config.role} ({len(result.cookies)} cookies)")
            else:
                result.error = f"Login failed — response: {resp.text[:200]}"
                logger.warning(f"[auth-form] Login FAILED as {config.role}")

        except Exception as e:
            result.error = str(e)
            logger.error(f"[auth-form] POST failed: {e}")

        return result


class TokenAuthStrategy:
    """
    Injects a pre-configured JWT / Bearer / API token into all requests.
    No actual authentication flow — the token is provided directly.
    """

    async def authenticate(self, client: Any, config: AuthConfig) -> AuthResult:
        result = AuthResult(success=False, role=config.role, strategy="token")

        token = config.token
        if not token:
            result.error = "token auth requires token"
            return result

        # Inject token header
        prefix = (config.token_prefix + " ") if config.token_prefix else ""
        header_value = f"{prefix}{token}"
        result.session_headers = {
            config.token_header: header_value,
            **config.extra_headers,
        }
        result.token = token
        result.success = True
        logger.info(f"[auth-token] Token auth configured as {config.role}: {config.token_header}={header_value[:30]}...")
        return result


class OAuth2AuthStrategy:
    """
    Obtains a token via OAuth2 client_credentials flow.
    Supports token refresh.
    """

    async def authenticate(self, client: Any, config: AuthConfig) -> AuthResult:
        result = AuthResult(success=False, role=config.role, strategy="oauth2")

        if not config.oauth2_token_url or not config.client_id or not config.client_secret:
            result.error = "oauth2 requires oauth2_token_url, client_id, client_secret"
            return result

        payload = {
            "grant_type": "client_credentials",
            "client_id": config.client_id,
            "client_secret": config.client_secret,
        }
        if config.scope:
            payload["scope"] = config.scope

        try:
            resp = await client.post(config.oauth2_token_url, data=payload)
            if resp.status_code == 200:
                data = resp.json()
                token = data.get("access_token", "")
                expires_in = data.get("expires_in", 3600)

                if token:
                    result.success = True
                    result.token = token
                    result.refresh_token = data.get("refresh_token", "")
                    result.token_expires_at = time.time() + int(expires_in)
                    result.session_headers = {
                        "Authorization": f"Bearer {token}",
                        **config.extra_headers,
                    }
                    logger.info(f"[auth-oauth2] Token obtained as {config.role}, expires_in={expires_in}s")
                else:
                    result.error = f"no access_token in response: {resp.text[:200]}"
            else:
                result.error = f"token endpoint returned {resp.status_code}: {resp.text[:200]}"

        except Exception as e:
            result.error = str(e)
            logger.error(f"[auth-oauth2] Token request failed: {e}")

        return result

    async def refresh(self, client: Any, config: AuthConfig) -> AuthResult:
        """Refresh an expired OAuth2 token."""
        result = AuthResult(success=False, role=config.role, strategy="oauth2-refresh")

        if not config.refresh_token or not (config.refresh_url or config.oauth2_token_url):
            result.error = "refresh requires refresh_token + refresh_url"
            return result

        refresh_url = config.refresh_url or config.oauth2_token_url
        payload = {
            "grant_type": "refresh_token",
            "refresh_token": config.refresh_token,
            "client_id": config.client_id,
            "client_secret": config.client_secret,
        }

        try:
            resp = await client.post(refresh_url, data=payload)
            if resp.status_code == 200:
                data = resp.json()
                token = data.get("access_token", "")
                if token:
                    result.success = True
                    result.token = token
                    result.refresh_token = data.get("refresh_token", config.refresh_token)
                    result.token_expires_at = time.time() + int(data.get("expires_in", 3600))
                    result.session_headers = {"Authorization": f"Bearer {token}"}
                    logger.info(f"[auth-oauth2] Token refreshed successfully")
        except Exception as e:
            result.error = str(e)

        return result


class CookieAuthStrategy:
    """
    Injects pre-baked session cookies into all requests.
    Useful when session cookies are obtained externally (browser export, etc.)
    """

    async def authenticate(self, client: Any, config: AuthConfig) -> AuthResult:
        result = AuthResult(success=False, role=config.role, strategy="cookie")

        if not config.cookies:
            result.error = "cookie auth requires cookies dict"
            return result

        result.cookies = config.cookies
        result.session_headers = dict(config.extra_headers)
        result.success = True
        logger.info(f"[auth-cookie] Cookie auth configured as {config.role} ({len(config.cookies)} cookies)")
        return result


class ApiKeyAuthStrategy:
    """
    Injects an API key header or query parameter.
    """

    async def authenticate(self, client: Any, config: AuthConfig) -> AuthResult:
        result = AuthResult(success=False, role=config.role, strategy="api_key")

        if not config.api_key:
            result.error = "api_key auth requires api_key"
            return result

        if config.api_key_header:
            result.session_headers = {
                config.api_key_header: config.api_key,
                **config.extra_headers,
            }
        result.success = True
        logger.info(f"[auth-apikey] API key injected into {config.api_key_header} as {config.role}")
        return result


# ─────────────────────────────────────────────────────────────────────────────
# Auth Engine
# ─────────────────────────────────────────────────────────────────────────────

_STRATEGY_MAP = {
    "form": FormAuthStrategy,
    "token": TokenAuthStrategy,
    "oauth2": OAuth2AuthStrategy,
    "cookie": CookieAuthStrategy,
    "api_key": ApiKeyAuthStrategy,
}


class QuantaraAuthEngine:
    """
    Manages authentication for the Quantara scan session.

    Usage:
        config = AuthConfig(
            strategy="form",
            login_url="https://example.com/login",
            username="admin@example.com",
            password="secret",
            role="admin",
        )
        auth_engine = QuantaraAuthEngine(config)
        session = await auth_engine.get_session()
        # session.headers contains auth headers, session.cookies contains auth cookies
    """

    def __init__(self, configs: list[AuthConfig]):
        """
        configs: list of AuthConfig (one per role to test)
        """
        self.configs = configs
        self._sessions: dict[str, AuthResult] = {}  # role → AuthResult
        self._client: Optional[Any] = None

    async def authenticate_all(self) -> dict[str, AuthResult]:
        """
        Authenticate all configured roles.
        Returns dict of role → AuthResult.
        """
        try:
            import httpx
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=20.0,
                verify=False,
            ) as client:
                self._client = client
                for config in self.configs:
                    result = await self._authenticate_one(client, config)
                    self._sessions[config.role] = result
        except ImportError:
            logger.warning("[auth] httpx not available")

        return self._sessions

    async def _authenticate_one(self, client: Any, config: AuthConfig) -> AuthResult:
        """Run authentication for a single role."""
        strategy_cls = _STRATEGY_MAP.get(config.strategy)
        if not strategy_cls:
            logger.error(f"[auth] Unknown strategy: {config.strategy}")
            return AuthResult(
                success=False, role=config.role, strategy=config.strategy,
                error=f"Unknown strategy: {config.strategy}",
            )

        strategy = strategy_cls()
        result = await strategy.authenticate(client, config)
        return result

    def get_session(self, role: str = "user") -> Optional[AuthResult]:
        """Get the auth result for a specific role."""
        return self._sessions.get(role)

    def get_headers(self, role: str = "user") -> dict[str, str]:
        """Get session headers for a role (for injection into scan requests)."""
        result = self._sessions.get(role)
        return result.session_headers if result and result.success else {}

    def get_cookies(self, role: str = "user") -> dict[str, str]:
        """Get session cookies for a role."""
        result = self._sessions.get(role)
        return result.cookies if result and result.success else {}

    def all_roles(self) -> list[str]:
        return list(self._sessions.keys())

    def successful_roles(self) -> list[str]:
        return [role for role, result in self._sessions.items() if result.success]

    async def refresh_if_needed(self, client: Any, role: str = "user") -> bool:
        """
        Check if the token for `role` is expired and refresh it.
        Returns True if token was refreshed or is still valid.
        """
        config = next((c for c in self.configs if c.role == role), None)
        if not config:
            return False

        result = self._sessions.get(role)
        if not result or not result.success:
            return False

        if config.is_expired():
            if config.strategy == "oauth2" and config.refresh_token:
                logger.info(f"[auth] Refreshing expired OAuth2 token for role={role}")
                strategy = OAuth2AuthStrategy()
                new_result = await strategy.refresh(client, config)
                if new_result.success:
                    self._sessions[role] = new_result
                    config.token = new_result.token
                    config.refresh_token = new_result.refresh_token
                    config.token_expires_at = new_result.token_expires_at
                    return True
                else:
                    logger.warning(f"[auth] Token refresh failed for role={role}: {new_result.error}")
                    return False
            elif config.strategy == "form":
                # Re-authenticate
                logger.info(f"[auth] Re-authenticating expired form session for role={role}")
                new_result = await self._authenticate_one(client, config)
                if new_result.success:
                    self._sessions[role] = new_result
                    return True
        return True


# ─────────────────────────────────────────────────────────────────────────────
# Multi-Role Manager
# ─────────────────────────────────────────────────────────────────────────────

class MultiRoleManager:
    """
    Orchestrate scanning across multiple authentication contexts.

    Runs the same scan targets with different auth roles to discover
    authorization boundary violations (IDOR, privilege escalation, etc.)

    Usage:
        manager = MultiRoleManager(
            configs=[admin_config, user_config, anon_config],
            targets=["https://example.com/api/users/1",
                     "https://example.com/api/admin/settings"]
        )
        results = manager.run_multi_role_scan(scan_fn)
    """

    def __init__(self, configs: list[AuthConfig], targets: list[str]):
        self.configs = configs
        self.targets = targets
        self.auth_engine = QuantaraAuthEngine(configs)

    def run(self, scan_fn) -> list[dict]:
        """
        Run `scan_fn(url, headers, cookies)` for each role × target combination.
        Returns list of authorization violation findings.
        """
        try:
            return asyncio.run(self._run_async(scan_fn))
        except RuntimeError:
            # Already in event loop
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                return pool.submit(lambda: asyncio.run(self._run_async(scan_fn))).result()

    async def _run_async(self, scan_fn) -> list[dict]:
        findings = []

        # First authenticate all roles
        await self.auth_engine.authenticate_all()
        successful = self.auth_engine.successful_roles()

        if not successful:
            logger.warning("[multi-role] No successful authentications")
            return findings

        # For each target, compare responses across roles
        for target in self.targets:
            role_responses: dict[str, dict] = {}

            for role in successful + (["anonymous"] if "anonymous" not in successful else []):
                if role == "anonymous":
                    headers, cookies = {}, {}
                else:
                    headers = self.auth_engine.get_headers(role)
                    cookies = self.auth_engine.get_cookies(role)

                try:
                    resp_data = await scan_fn(target, headers, cookies)
                    role_responses[role] = resp_data
                except Exception as e:
                    logger.debug(f"[multi-role] scan_fn failed for {target} as {role}: {e}")

            # Analyze authorization violations
            violations = self._analyze_auth_boundaries(target, role_responses)
            findings.extend(violations)

        return findings

    def _analyze_auth_boundaries(
        self, url: str, role_responses: dict[str, dict]
    ) -> list[dict]:
        """
        Detect authorization boundary violations:
        - Anonymous can access admin-only resources
        - Low-privilege role can access high-privilege resources
        """
        violations = []

        anon = role_responses.get("anonymous", {})
        admin = role_responses.get("admin", {})
        user = role_responses.get("user", {})

        anon_status = anon.get("status", 0)
        admin_status = admin.get("status", 0)
        user_status = user.get("status", 0)

        # Anonymous accessing resources that require auth
        if anon_status == 200 and admin_status == 200:
            violations.append({
                "type": "broken-access-control",
                "url": url,
                "title": "Unauthenticated Access to Protected Resource",
                "description": (
                    f"Anonymous request returned HTTP 200 on a resource "
                    f"that also returns 200 for authenticated admin. "
                    f"No authentication required."
                ),
                "severity": "HIGH",
                "evidence": {
                    "anonymous_status": anon_status,
                    "admin_status": admin_status,
                },
                "cwe": "CWE-862",
                "owasp": "A01:2021",
            })

        # Low-privilege accessing high-privilege resources
        if user_status == 200 and admin_status == 200 and "/admin" in url.lower():
            violations.append({
                "type": "privilege-escalation",
                "url": url,
                "title": "Low-Privilege User Accessing Admin Resource",
                "description": (
                    f"User-role request returned HTTP 200 on an admin endpoint. "
                    f"Potential privilege escalation vulnerability."
                ),
                "severity": "HIGH",
                "evidence": {
                    "user_status": user_status,
                    "admin_status": admin_status,
                },
                "cwe": "CWE-269",
                "owasp": "A01:2021",
            })

        # IDOR: different users getting same resource content
        if user_status == 200 and "body" in user and "body" in anon:
            user_body = user.get("body", "")
            anon_body = anon.get("body", "")
            if user_body and anon_body and len(user_body) > 50:
                similarity = _body_similarity(user_body, anon_body)
                if similarity > 0.85:
                    violations.append({
                        "type": "idor",
                        "url": url,
                        "title": "Potential IDOR — Identical Response for Different Auth Levels",
                        "description": (
                            f"Response body for authenticated user and anonymous are {similarity:.0%} similar, "
                            f"suggesting the resource does not enforce access control."
                        ),
                        "severity": "MEDIUM",
                        "evidence": {"body_similarity": similarity},
                        "cwe": "CWE-284",
                        "owasp": "A01:2021",
                    })

        return violations


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _extract_csrf(html: str) -> tuple[str, str]:
    """
    Extract CSRF token and field name from an HTML form.
    Returns (token_value, field_name) or ("", "").
    """
    # Common CSRF field patterns
    patterns = [
        # <input type="hidden" name="csrf_token" value="...">
        re.compile(
            r'<input[^>]+name\s*=\s*["\']([^"\']*(?:csrf|_token|authenticity)[^"\']*)["\'][^>]*value\s*=\s*["\']([^"\']+)["\']',
            re.I,
        ),
        re.compile(
            r'<input[^>]+value\s*=\s*["\']([^"\']{20,})["\'][^>]*name\s*=\s*["\']([^"\']*(?:csrf|_token|authenticity)[^"\']*)["\']',
            re.I,
        ),
        # meta tag: <meta name="csrf-token" content="...">
        re.compile(r'<meta[^>]+name\s*=\s*["\']([^"\']*csrf[^"\']*)["\'][^>]*content\s*=\s*["\']([^"\']+)["\']', re.I),
    ]

    for pattern in patterns:
        m = pattern.search(html)
        if m:
            groups = m.groups()
            # Determine which group is field name and which is value
            if len(groups) == 2:
                field_name, value = groups[0], groups[1]
                if len(value) > len(field_name):  # value is usually longer
                    return value, field_name
                return field_name, value

    return "", ""


def _body_similarity(a: str, b: str) -> float:
    """Compute body similarity ratio using simple character comparison."""
    if not a or not b:
        return 0.0
    # Use SequenceMatcher for efficiency
    try:
        from difflib import SequenceMatcher
        # Truncate to first 2000 chars for performance
        return SequenceMatcher(None, a[:2000], b[:2000]).ratio()
    except Exception:
        # Fallback: word set overlap
        a_words = set(a.lower().split())
        b_words = set(b.lower().split())
        if not a_words or not b_words:
            return 0.0
        intersection = a_words & b_words
        union = a_words | b_words
        return len(intersection) / len(union)


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def create_auth_engine(configs: list[dict]) -> QuantaraAuthEngine:
    """
    Factory function: create QuantaraAuthEngine from list of config dicts.

    Example config dict:
      {
        "strategy": "form",
        "role": "admin",
        "login_url": "https://example.com/login",
        "username": "admin@example.com",
        "password": "secret",
      }
    """
    auth_configs = [AuthConfig(**c) for c in configs]
    return QuantaraAuthEngine(auth_configs)


def build_auth_headers(config: AuthConfig) -> dict[str, str]:
    """
    Build the authorization headers for a given config without executing a flow.
    Useful for pre-configured tokens.
    """
    if config.strategy in ("token",):
        prefix = (config.token_prefix + " ") if config.token_prefix else ""
        return {config.token_header: f"{prefix}{config.token}"}
    if config.strategy == "api_key" and config.api_key_header:
        return {config.api_key_header: config.api_key}
    return {}
