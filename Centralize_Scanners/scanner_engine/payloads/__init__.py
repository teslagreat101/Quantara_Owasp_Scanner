"""
payloads/ — Enterprise Payload Library
=======================================
Environment-aware, context-specific payload packs.

Auto-loaded by payload_context_detector and orchestrator based on target fingerprint.

Packs:
- base_payloads  : Universal cross-context payloads (XSS, SQLi, SSRF, LFI, SSTI, CMDI)
- mysql          : MySQL-specific injection payloads
- mssql          : MSSQL-specific injection payloads
- postgresql     : PostgreSQL-specific payloads
- node           : Node.js runtime-specific payloads
- aws            : AWS cloud environment payloads
- graphql        : GraphQL introspection + injection payloads
- headers        : HTTP header injection payloads
- api            : REST API-specific payloads
"""

from .base_payloads import (
    XSS_PAYLOADS,
    SQLI_PAYLOADS,
    SQLI_BLIND_TIME,
    SQLI_BOOLEAN,
    SSRF_PAYLOADS,
    LFI_PAYLOADS,
    SSTI_PAYLOADS,
    CMDI_PAYLOADS,
    CMDI_BLIND,
    OPEN_REDIRECT_PAYLOADS,
    XXE_PAYLOADS,
    IDOR_PATHS,
)

from .mysql import MYSQL_PAYLOADS, MYSQL_BLIND_TIME, MYSQL_OOB
from .mssql import MSSQL_PAYLOADS, MSSQL_BLIND_TIME, MSSQL_OOB
from .postgresql import PGSQL_PAYLOADS, PGSQL_BLIND_TIME
from .node import NODE_PROTOTYPE_POLLUTION, NODE_PATH_TRAVERSAL, NODE_RCE
from .aws import AWS_SSRF_PAYLOADS, AWS_METADATA_PATHS, AWS_ENV_VARS
from .graphql import GRAPHQL_INTROSPECTION, GRAPHQL_INJECTION, GRAPHQL_NOSQL
from .headers import HEADER_INJECTION_PAYLOADS, HOST_HEADER_PAYLOADS, CORS_PAYLOADS
from .api import API_DISCOVERY_PATHS, API_BOLA_PATTERNS, API_MASS_ASSIGNMENT


def get_pack(name: str):
    """Load a payload pack by name."""
    _packs = {
        "xss": XSS_PAYLOADS,
        "sqli": SQLI_PAYLOADS,
        "sqli_blind": SQLI_BLIND_TIME,
        "sqli_bool": SQLI_BOOLEAN,
        "ssrf": SSRF_PAYLOADS,
        "lfi": LFI_PAYLOADS,
        "ssti": SSTI_PAYLOADS,
        "cmdi": CMDI_PAYLOADS,
        "cmdi_blind": CMDI_BLIND,
        "redirect": OPEN_REDIRECT_PAYLOADS,
        "xxe": XXE_PAYLOADS,
        "idor": IDOR_PATHS,
        "mysql": MYSQL_PAYLOADS,
        "mysql_blind": MYSQL_BLIND_TIME,
        "mysql_oob": MYSQL_OOB,
        "mssql": MSSQL_PAYLOADS,
        "mssql_blind": MSSQL_BLIND_TIME,
        "mssql_oob": MSSQL_OOB,
        "pgsql": PGSQL_PAYLOADS,
        "pgsql_blind": PGSQL_BLIND_TIME,
        "node_proto": NODE_PROTOTYPE_POLLUTION,
        "node_path": NODE_PATH_TRAVERSAL,
        "node_rce": NODE_RCE,
        "aws_ssrf": AWS_SSRF_PAYLOADS,
        "aws_meta": AWS_METADATA_PATHS,
        "aws_env": AWS_ENV_VARS,
        "graphql": GRAPHQL_INTROSPECTION,
        "graphql_inject": GRAPHQL_INJECTION,
        "graphql_nosql": GRAPHQL_NOSQL,
        "header_inject": HEADER_INJECTION_PAYLOADS,
        "host_header": HOST_HEADER_PAYLOADS,
        "cors": CORS_PAYLOADS,
        "api_paths": API_DISCOVERY_PATHS,
        "api_bola": API_BOLA_PATTERNS,
        "api_mass": API_MASS_ASSIGNMENT,
    }
    return _packs.get(name, [])


def list_packs():
    """Return all available payload pack names."""
    return [
        "xss", "sqli", "sqli_blind", "sqli_bool", "ssrf", "lfi", "ssti",
        "cmdi", "cmdi_blind", "redirect", "xxe", "idor",
        "mysql", "mysql_blind", "mysql_oob",
        "mssql", "mssql_blind", "mssql_oob",
        "pgsql", "pgsql_blind",
        "node_proto", "node_path", "node_rce",
        "aws_ssrf", "aws_meta", "aws_env",
        "graphql", "graphql_inject", "graphql_nosql",
        "header_inject", "host_header", "cors",
        "api_paths", "api_bola", "api_mass",
    ]
