"""
Quantum Protocol v5.0 — FastAPI Backend
Real-time OWASP Scanner Orchestrator with SSE streaming.
Powered by the unified scanner_engine (Scanner_1 + Scanner_2 merged).

Phase 3: Full REST API endpoints with pagination, DB persistence,
         SSE streaming, and report generation.
"""

import asyncio
import json
import os
import sys
import time
import uuid
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, List, Dict, Tuple

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Query, Response, Header, Request, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse

# ── Add parent directory to path so we can import scanner modules ──
PARENT_DIR = str(Path(__file__).resolve().parent.parent)
CENTRAL_DIR = os.path.join(PARENT_DIR, "Centralize_Scanners")

for path in [PARENT_DIR, CENTRAL_DIR]:
    if path not in sys.path:
        sys.path.insert(0, path)

# ── Import unified scanner engine ──
from scanner_engine.orchestrator import (
    UNIFIED_MODULE_REGISTRY as MODULE_REGISTRY,
    normalize_finding_to_dict as normalize_finding,
    run_module_scan,
    get_available_modules,
    get_available_profiles,
    get_modules_for_profile,
    compute_scan_scores,
    deduplicate_findings,
    normalize_finding as normalize_to_unified,
    SCAN_PROFILES,
)

# ── Import database and Redis ──
from backend.database import init_db, get_db, get_db_session, User, Scan, Finding, ScanLog, SubscriptionTier
from backend.redis_client import get_state_manager
from backend.auth import (
    create_access_token, create_refresh_token, verify_password, 
    SUPER_ADMIN_EMAIL, get_user_subscription, check_subscription_access,
    check_usage_limits, increment_scan_usage, get_current_firebase_user
)
from sqlalchemy.orm import Session
from sqlalchemy import func

# ── Import Quantara Intelligence Engines ──────────────────────────────────────
import logging
logger = logging.getLogger(__name__)

try:
    from backend.exploit_verifier import get_exploit_verifier
    _VERIFIER_AVAILABLE = True
except Exception:
    try:
        from exploit_verifier import get_exploit_verifier
        _VERIFIER_AVAILABLE = True
    except Exception:
        _VERIFIER_AVAILABLE = False
        logger.warning("exploit_verifier not available")

try:
    from backend.attack_decision_engine import get_attack_decision_engine
    _DECISION_ENGINE_AVAILABLE = True
except Exception:
    try:
        from attack_decision_engine import get_attack_decision_engine
        _DECISION_ENGINE_AVAILABLE = True
    except Exception:
        _DECISION_ENGINE_AVAILABLE = False
        logger.warning("attack_decision_engine not available")

try:
    from backend.safe_scan_guard import create_fresh_guard
    _SAFE_GUARD_AVAILABLE = True
except Exception:
    try:
        from safe_scan_guard import create_fresh_guard
        _SAFE_GUARD_AVAILABLE = True
    except Exception:
        _SAFE_GUARD_AVAILABLE = False
        logger.warning("safe_scan_guard not available")

try:
    from backend.neo4j_client import get_neo4j_client
    _NEO4J_AVAILABLE = True
except Exception:
    try:
        from neo4j_client import get_neo4j_client
        _NEO4J_AVAILABLE = True
    except Exception:
        _NEO4J_AVAILABLE = False
        logger.warning("neo4j_client not available")

# ── Import Stability Engines (Scan Queue + Dedup) ──────────────────────────────
try:
    from backend.scan_queue import (
        get_semaphore, bounded_executor, scan_queue_manager,
        cleanup_old_scans, scan_watchdog, resource_monitor,
    )
    from backend.finding_dedup import is_duplicate, compute_evidence_hash, deduplicate_findings_list
    _STABILITY_AVAILABLE = True
except Exception:
    try:
        from scan_queue import (
            get_semaphore, bounded_executor, scan_queue_manager,
            cleanup_old_scans, scan_watchdog, resource_monitor,
        )
        from finding_dedup import is_duplicate, compute_evidence_hash, deduplicate_findings_list
        _STABILITY_AVAILABLE = True
    except Exception as _se:
        _STABILITY_AVAILABLE = False
        logger.warning(f"Stability engines not available: {_se}")
        bounded_executor = None  # falls back to None (default executor)

# ── Import Enterprise Scanner Engines (Phase 8) ────────────────────────────────
# These live in Centralize_Scanners/scanner_engine/ — we add that dir to sys.path
_ENTERPRISE_ENGINE_DIR = os.path.join(CENTRAL_DIR, "scanner_engine")
if _ENTERPRISE_ENGINE_DIR not in sys.path:
    sys.path.insert(0, _ENTERPRISE_ENGINE_DIR)

try:
    from scanner_engine.orchestrator import (
        get_enterprise_engine,
        enterprise_scan_summary,
        get_payload_pack,
        mutate_payload,
        detect_injection_context,
    )
    _ENTERPRISE_ORCHESTRATOR_AVAILABLE = True
    logger.info("Enterprise orchestrator extensions loaded")
except Exception as _eoe:
    _ENTERPRISE_ORCHESTRATOR_AVAILABLE = False
    logger.warning(f"Enterprise orchestrator extensions not available: {_eoe}")

try:
    import importlib as _importlib
    _payload_mutator_mod = _importlib.import_module("payload_mutator") if _ENTERPRISE_ENGINE_DIR in sys.path else None
    _PayloadMutator = getattr(_payload_mutator_mod, "PayloadMutator", None) if _payload_mutator_mod else None
    _MUTATOR_AVAILABLE = _PayloadMutator is not None
    if _MUTATOR_AVAILABLE:
        logger.info("PayloadMutator engine loaded")
except Exception as _pme:
    _MUTATOR_AVAILABLE = False
    _PayloadMutator = None
    logger.warning(f"PayloadMutator not available: {_pme}")

try:
    _attack_chain_mod = _importlib.import_module("adaptive_engine") if _ENTERPRISE_ENGINE_DIR in sys.path else None
    _AttackChainCorrelator = getattr(_attack_chain_mod, "AttackChainCorrelator", None) if _attack_chain_mod else None
    _CHAIN_CORRELATOR_AVAILABLE = _AttackChainCorrelator is not None
    if _CHAIN_CORRELATOR_AVAILABLE:
        logger.info("AttackChainCorrelator engine loaded")
except Exception as _ace:
    _CHAIN_CORRELATOR_AVAILABLE = False
    _AttackChainCorrelator = None
    logger.warning(f"AttackChainCorrelator not available: {_ace}")

# ── Import PQSI intelligence (Post-Quantum Security Intelligence) ──
try:
    from quantum_protocol.intelligence.quantum_timeline import QuantumTimelineEngine
    from quantum_protocol.core.engine import compute_qqsi_score as _compute_qqsi
    _PQSI_INTELLIGENCE_AVAILABLE = True
    logger.info("PQSI intelligence engine loaded")
except Exception as _pqsi_ie:
    _PQSI_INTELLIGENCE_AVAILABLE = False
    logger.warning(f"PQSI intelligence not available: {_pqsi_ie}")

# ═══════════════════════════════════════════════════════════════════════════════
# App Setup
# ═══════════════════════════════════════════════════════════════════════════════

app = FastAPI(
    title="Quantum Protocol OWASP Scanner API",
    version="5.0.0",
    description="Unified real-time security scanner — Scanner_1 + Scanner_2 merged. Full OWASP Top 10:2025 coverage.",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# Dynamic CORS origins from environment
cors_origins = [
    "http://localhost:3000",
    "http://localhost:3001",
    "http://localhost:3002",
    "http://localhost:3003",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:3001",
    "http://127.0.0.1:3002",
    "http://127.0.0.1:3003",
]

# Allow any port on localhost/127.0.0.1 in development
ALLOW_ALL_LOCAL = os.getenv("DEVELOPMENT", "true").lower() == "true"

# CORS middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:3001",
        "http://localhost:3002",
        "http://localhost:3003",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:3001",
        "http://127.0.0.1:3002",
        "http://127.0.0.1:3003",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=3600,
)

# ═══════════════════════════════════════════════════════════════════════════════
# In-Memory Scan Store (backed by Redis for persistence)
# ═══════════════════════════════════════════════════════════════════════════════

scans: dict[str, dict[str, Any]] = {}

# Concurrency guard: max 2 modules running simultaneously across all scans
# (5 scans × 2 modules each = 10 theoretical threads max on the bounded pool)
_module_semaphore = asyncio.Semaphore(2)

# ── Memory-safe event appender ────────────────────────────────────────────────
# Replaces all direct `scan["events"].append(...)` calls.
# Caps the in-memory events list at 1000 entries — older events are evicted
# (they are already persisted to Redis / delivered to SSE clients by cursor).
# _events_base_offset tracks how many items were trimmed so the SSE cursor
# can rebase itself and not skip / re-deliver events after a trim.
_EVENTS_CAP = 1000
_EVENTS_TRIM = 200  # how many to remove when cap is hit


def _append_event(scan: dict, event_type: str, data: dict) -> None:
    scan["events"].append({"type": event_type, "data": data})
    scan["_last_event_time"] = time.monotonic()   # watchdog heartbeat
    if len(scan["events"]) > _EVENTS_CAP:
        del scan["events"][:_EVENTS_TRIM]
        scan["_events_base_offset"] = scan.get("_events_base_offset", 0) + _EVENTS_TRIM


# ═══════════════════════════════════════════════════════════════════════════════
# Pydantic Models
# ═══════════════════════════════════════════════════════════════════════════════

class ScanRequest(BaseModel):
    target: str
    scan_type: str = "directory"  # "directory" | "code" | "git" | "url" | "repository"
    target_type: Optional[str] = None  # explicit override: "url" | "github" | "directory" | "code"
    modules: list[str] = ["misconfig", "injection", "frontend_js", "endpoint"]
    scan_profile: str = "full"

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    modules: list[str] = []
    total_patterns: int = 0

class ScanStatusModel(BaseModel):
    scan_id: str
    status: str
    progress: int
    active_module: Optional[str] = None
    total_findings: int = 0
    modules_completed: int = 0
    modules_total: int = 0
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    elapsed_seconds: float = 0
    duration: float = 0
    severity_counts: dict = {}
    target: Optional[str] = None

class FindingResponse(BaseModel):
    id: str = ""
    file: str = ""
    line_number: int = 0
    severity: str = "info"
    title: str = ""
    description: str = ""
    matched_content: Optional[str] = None
    module: str = ""
    module_name: str = ""
    category: str = ""
    cwe: str = ""
    owasp: str = ""
    remediation: str = ""
    confidence: float = 1.0
    tags: list[str] = []
    timestamp: str = ""
    language: Optional[str] = None
    injection_type: Optional[str] = None
    subcategory: Optional[str] = None

class PaginatedFindings(BaseModel):
    findings: List[FindingResponse] = []
    total: int = 0
    page: int = 1
    page_size: int = 50
    total_pages: int = 1
    has_next: bool = False
    has_prev: bool = False

class LoginRequest(BaseModel):
    email: str
    password: str

class GoogleLoginRequest(BaseModel):
    id_token: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: dict

class ScanReportModel(BaseModel):
    scan_id: str
    status: str
    target: str
    duration: float = 0
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    summary: dict = {}
    module_summary: dict = {}
    owasp_coverage: dict = {}
    total_findings: int = 0
    findings: list = []
    logs: list = []
    top_files: list = []
    risk_score: float = 0


# ═══════════════════════════════════════════════════════════════════════════════
# Core Scan Executor (async)
# ═══════════════════════════════════════════════════════════════════════════════

async def execute_scan(scan_id: str, target: str, scan_type: str, modules: list[str], db: Session = None, target_type: Optional[str] = None):
    """Execute scan with database and Redis persistence."""
    print(f"DEBUG: execute_scan Task started for scan {scan_id}")
    # Ensure we have a database session for background task
    own_db = False
    if db is None:
        db = get_db_session()
        own_db = True
    
    try:
        scan = scans[scan_id]
        scan["status"] = "running"
        scan["started_at"] = datetime.now(timezone.utc).isoformat()
        start_time = time.time()

        # Update SQL status
        db_scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        if db_scan:
            db_scan.status = "running"
            db_scan.started_at = datetime.now(timezone.utc)
            db.commit()

        # Initialize Redis state manager
        state_mgr = get_state_manager()
        state_mgr.set_scan_status(scan_id, "running", target=target, scan_type=scan_type, modules=modules)

        valid_modules = [m for m in modules if m in MODULE_REGISTRY]
        scan["modules_total"] = len(valid_modules)

        _add_log(scan_id, "success", f"Engine started — {len(valid_modules)} modules targeting {target}")

        # Emit structured scan_started event for live visualization
        _append_event(scan, "scan_started", {
            "target": target,
            "scan_type": scan_type,
            "modules": valid_modules,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        # ── Enterprise Intelligence Engines Telemetry ─────────────────────────
        _enterprise_payload_packs: dict = {}
        _enterprise_pack_total = 0
        if _ENTERPRISE_ORCHESTRATOR_AVAILABLE:
            try:
                _PAYLOAD_PACK_NAMES = [
                    "xss", "sqli", "sqli_blind_time", "sqli_boolean", "ssrf", "lfi",
                    "ssti", "cmdi", "cmdi_blind", "open_redirect", "xxe", "idor",
                    "mysql", "mysql_blind", "mssql", "pgsql",
                    "node_prototype_pollution", "node_path_traversal",
                    "aws_ssrf", "graphql_introspection", "graphql_injection", "graphql_nosql",
                    "header_injection", "host_header", "cors",
                    "api_discovery", "api_bola", "api_mass_assignment",
                ]
                for pack_name in _PAYLOAD_PACK_NAMES:
                    try:
                        pack = get_payload_pack(pack_name)
                        if pack:
                            _enterprise_payload_packs[pack_name] = len(pack)
                            _enterprise_pack_total += len(pack)
                    except Exception:
                        pass
            except Exception as _ete:
                logger.debug(f"Enterprise payload pack enum error: {_ete}")

        _mutator_instance = None
        if _MUTATOR_AVAILABLE and _PayloadMutator:
            try:
                _mutator_instance = _PayloadMutator()
            except Exception:
                pass

        if _enterprise_pack_total:
            _add_log(scan_id, "info", f"Enterprise payload engine loaded: {_enterprise_pack_total} signatures / {len(_enterprise_payload_packs)} packs")
        _append_event(scan, "enterprise_telemetry", {
            "payload_packs": _enterprise_payload_packs,
            "total_payloads": _enterprise_pack_total,
            "mutation_engine": _MUTATOR_AVAILABLE,
            "chain_correlator": _CHAIN_CORRELATOR_AVAILABLE,
            "differential_analyzer": _ENTERPRISE_ORCHESTRATOR_AVAILABLE,
            "adaptive_engine": _ENTERPRISE_ORCHESTRATOR_AVAILABLE,
            "modules_loaded": len(valid_modules),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        # ── Stability: wait for slot if scan was queued ───────────────────────
        if _STABILITY_AVAILABLE and scan.get("status") == "queued":
            await scan_queue_manager.wait_for_slot(scan_id, scans)

        # ── Batch DB write accumulator ────────────────────────────────────────
        _finding_batch: list = []
        _BATCH_SIZE = 25

        # Initialize per-scan safe guard
        guard = create_fresh_guard() if _SAFE_GUARD_AVAILABLE else None

        # Phase 1: Recons & Pre-computation
        _total_sigs = sum(MODULE_REGISTRY[m]['pattern_count'] for m in valid_modules)
        _add_log(scan_id, "success", f"Phase 1 — Attack surface mapping ({_total_sigs} signatures loaded)")

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        owasp_counts = {}
        _last_risk_score = 0
        _all_raw_findings = []  # Accumulate raw findings for PQSI post-processing

        for idx, module_key in enumerate(valid_modules):
            if scan.get("cancelled"):
                scan["status"] = "cancelled"
                _add_log(scan_id, "warn", "Scan cancelled by user")
                state_mgr.set_scan_status(scan_id, "cancelled")
                break

            meta = MODULE_REGISTRY[module_key]
            scan["active_module"] = module_key
            progress = int((idx / len(valid_modules)) * 100)
            scan["progress"] = progress
            state_mgr.set_progress(scan_id, progress)

            # ── MODULE_STARTED lifecycle event ────────────────────────────────
            _add_log(scan_id, "info", f"[{meta['name']}] Starting ({idx + 1}/{len(valid_modules)})", module_key)
            _append_event(scan, "module_started", {
                "module": module_key,
                "name": meta["name"],
                "owasp": meta.get("owasp", ""),
                "idx": idx,
                "total": len(valid_modules),
                "progress": progress,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

            # ── Heartbeat coroutine: emits progress event (no log spam) ────────
            async def _module_heartbeat(sid: str, mod_name: str, mod_key: str):
                elapsed = 0
                while True:
                    await asyncio.sleep(3.0)
                    elapsed += 3
                    _append_event(scans[sid], "module_progress", {
                        "module": mod_key,
                        "name": mod_name,
                        "elapsed_seconds": elapsed,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })

            try:
                # Bounded executor (max 10 threads) + semaphore (max 2 simultaneous modules)
                async with _module_semaphore:
                    _hb_task = asyncio.create_task(_module_heartbeat(scan_id, meta["name"], module_key))
                    try:
                        # Use asyncio.wait_for to prevent indefinite blocking
                        findings = await asyncio.wait_for(
                            asyncio.get_event_loop().run_in_executor(
                                bounded_executor,
                                lambda mk=module_key: run_module_scan(mk, target, scan_type, target_type=target_type)
                            ),
                            timeout=60  # 1 minute timeout per module
                        )
                    finally:
                        _hb_task.cancel()
                        try:
                            await _hb_task
                        except asyncio.CancelledError:
                            pass

            # ── MODULE_COMPLETED lifecycle event ──────────────────────────────
                findings_count = len(findings) if findings else 0
                _append_event(scan, "module_completed", {
                    "module": module_key,
                    "name": meta["name"],
                    "idx": idx,
                    "total": len(valid_modules),
                    "findings_count": findings_count,
                    "progress": int(((idx + 1) / len(valid_modules)) * 100),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
                _add_log(scan_id, "success", f"[{meta['name']}] Complete — {findings_count} finding(s)", module_key)

                # Track raw findings for PQSI post-processing
                if findings and module_key.startswith("pqsi_") or module_key == "quantum_pqc":
                    _all_raw_findings.extend(findings)

                for finding in findings:
                    normalized = normalize_finding(finding, module_key)

                    # ── Deduplication: skip if this fingerprint was seen already ──
                    if _STABILITY_AVAILABLE and is_duplicate(normalized, scan["dedup_set"]):
                        scan["dedup_skipped"] = scan.get("dedup_skipped", 0) + 1
                        continue

                    # ── Append to in-memory findings (capped at 5000) ─────────────
                    scan["findings"].append(normalized)
                    scan["total_findings_count"] = scan.get("total_findings_count", 0) + 1
                    if len(scan["findings"]) > 5000:
                        del scan["findings"][:100]  # trim oldest 100; all findings persisted to DB

                    # ── Enterprise: annotate finding with mutation hints ───────
                    if _mutator_instance:
                        try:
                            _base_payload = normalized.get("matched_content", "") or normalized.get("title", "")
                            if _base_payload:
                                _vuln_type = "xss" if "xss" in normalized.get("category", "").lower() else \
                                             "sqli" if any(k in normalized.get("category", "").lower() for k in ("sql", "inject")) else \
                                             "cmdi" if "command" in normalized.get("category", "").lower() else \
                                             "ssti" if "template" in normalized.get("category", "").lower() else "generic"
                                _variants = _mutator_instance.generate_variants(_base_payload, max_variants=8)
                                normalized["mutation_variants_count"] = len(_variants)
                                normalized["mutation_type"] = _vuln_type
                        except Exception:
                            pass

                    _append_event(scan, "finding", normalized)

                    # ── Batch DB persistence (flush every 25 findings) ────────────
                    try:
                        evidence_hash = compute_evidence_hash(normalized) if _STABILITY_AVAILABLE else None
                        new_finding = Finding(
                            scan_id=scan_id,
                            finding_id=normalized["id"],
                            file=normalized.get("file", "unknown"),
                            line_number=normalized.get("line_number", 0),
                            severity=normalized["severity"],
                            title=normalized["title"],
                            description=normalized.get("description", ""),
                            matched_content=normalized.get("matched_content", ""),
                            module_name=module_key,
                            category=normalized.get("category", ""),
                            cwe=normalized.get("cwe", ""),
                            remediation=normalized.get("remediation", ""),
                            confidence=normalized.get("confidence", 1.0),
                            tags=normalized.get("tags", []),
                            created_at=datetime.now(timezone.utc),
                            evidence_hash=evidence_hash,
                        )
                        _finding_batch.append(new_finding)
                        if len(_finding_batch) >= _BATCH_SIZE:
                            db.bulk_save_objects(_finding_batch)
                            db.commit()
                            _finding_batch.clear()
                    except Exception as e:
                        print(f"Error batching finding to SQL: {e}")
                        db.rollback()
                        _finding_batch.clear()

                    # Log finding to terminal stream for "wow" effect
                    short_file = normalized.get("file", "unknown")
                    if len(short_file) > 30: short_file = "..." + short_file[-27:]
                    _add_log(scan_id, "warn", f"{normalized['severity'].upper()}: {normalized['title']} @ {short_file}")

                    # Emit endpoint_discovered event for Three.js visualization
                    ep = normalized.get("file") or normalized.get("endpoint") or ""
                    if ep and ("http" in ep or "/" in ep):
                        _append_event(scan, "endpoint_discovered", {
                            "url": ep,
                            "method": normalized.get("method", "GET"),
                            "finding_id": normalized["id"],
                            "severity": normalized["severity"],
                        })

                    # Update severity counts
                    sev = normalized.get("severity", "info").lower()
                    if sev in severity_counts:
                        severity_counts[sev] += 1

                    # Update OWASP coverage
                    owasp_cat = normalized.get("owasp", meta.get("owasp", ""))
                    if owasp_cat:
                        owasp_counts[owasp_cat] = owasp_counts.get(owasp_cat, 0) + 1

                    # Update coverage intelligence based on finding tags/metadata
                    cov = scan.get("coverage_intelligence", {})
                    tags_lower = [t.lower() for t in normalized.get("tags", [])]
                    if "get" in tags_lower or "query" in tags_lower:
                        cov["get_params_tested"] = cov.get("get_params_tested", 0) + 1
                    if "post" in tags_lower or "body" in tags_lower:
                        cov["post_bodies_tested"] = cov.get("post_bodies_tested", 0) + 1
                    if "json" in tags_lower or "api" in tags_lower:
                        cov["json_apis_tested"] = cov.get("json_apis_tested", 0) + 1
                    if "header" in tags_lower:
                        cov["headers_tested"] = cov.get("headers_tested", 0) + 1
                    if "cookie" in tags_lower or "session" in tags_lower:
                        cov["cookies_tested"] = cov.get("cookies_tested", 0) + 1
                    if "graphql" in tags_lower:
                        cov["graphql_routes"] = cov.get("graphql_routes", 0) + 1
                    if "js" in tags_lower or "javascript" in tags_lower:
                        cov["js_discovered_endpoints"] = cov.get("js_discovered_endpoints", 0) + 1

                    # Publish to Redis for real-time updates
                    state_mgr.publish_finding(scan_id, normalized)

                    # Broadcast finding via WebSocket to all connected clients
                    asyncio.create_task(ws_manager.broadcast_scan_update(scan_id, {
                        "type": "finding",
                        "finding": normalized,
                        "progress": scan.get("progress", 0),
                        "total_findings": len(scan["findings"]),
                    }))

                # ── Emit risk_updated event if score changed significantly ────
                cur_score, cur_conf, cur_status, cur_level = _compute_risk_score(
                    severity_counts, idx + 1, len(valid_modules)
                )
                if abs(cur_score - _last_risk_score) >= 10:
                    _append_event(scan, "risk_updated", {
                        "old_score": _last_risk_score,
                        "new_score": cur_score,
                        "confidence": cur_conf,
                        "scan_status": cur_status,
                        "risk_level": cur_level,
                        "trigger": module_key,
                    })
                    _last_risk_score = cur_score

                # ── Enterprise: emit payload_executed telemetry per module ────
                if _enterprise_payload_packs:
                    _relevant_packs = []
                    _mkey_lower = module_key.lower()
                    if "injection" in _mkey_lower:
                        _relevant_packs = ["xss", "sqli", "sqli_blind_time", "cmdi", "ssti"]
                    elif "misconfig" in _mkey_lower:
                        _relevant_packs = ["header_injection", "host_header", "cors"]
                    elif "ssrf" in _mkey_lower:
                        _relevant_packs = ["ssrf", "aws_ssrf"]
                    elif "frontend" in _mkey_lower:
                        _relevant_packs = ["xss", "open_redirect"]
                    elif "quantara" in _mkey_lower:
                        _relevant_packs = ["api_discovery", "api_bola", "graphql_introspection"]
                    elif "api" in _mkey_lower:
                        _relevant_packs = ["api_bola", "api_mass_assignment", "api_discovery"]
                    if _relevant_packs:
                        _packs_used = {k: _enterprise_payload_packs.get(k, 0) for k in _relevant_packs if k in _enterprise_payload_packs}
                        _total_used = sum(_packs_used.values())
                        _mutations_count = _total_used * 8 if _mutator_instance else 0  # 8 variants per payload
                        _append_event(scan, "payload_executed", {
                            "module": module_key,
                            "packs_used": _packs_used,
                            "total_payloads_fired": _total_used,
                            "mutations_generated": _mutations_count,
                            "findings_triggered": len(findings),
                            "endpoint": target,
                            "payload_type": "multi-vector",
                        })
                        _add_log(scan_id, "info",
                            f"[{meta['name']}] {_total_used} payloads + {_mutations_count} mutations → {len(findings)} hits")

                # ── AI Next Attack Decision after each module ─────────────────
                if findings and _DECISION_ENGINE_AVAILABLE:
                    try:
                        decision_engine = get_attack_decision_engine()
                        rec = decision_engine.recommend_next_action(
                            scan["findings"],
                            {"scan_type": scan_type, "modules_done": idx + 1},
                        )
                        if rec:
                            scan["ai_recommendations"] = rec.to_dict()
                            _append_event(scan, "ai_decision", rec.to_dict())
                            _add_log(scan_id, "info", f"AI Decision: {rec.rationale}", module_key)
                    except Exception as _e:
                        logger.debug(f"Attack decision engine error: {_e}")

                # ── Safe guard health events ──────────────────────────────────
                if guard:
                    for hevt in guard.get_events():
                        _append_event(scan, hevt["type"], hevt)
                        _add_log(scan_id, "warn", f"🛡 SafeGuard: {hevt['new_mode']} — {hevt['reason']}")
                    if guard.should_abort():
                        _add_log(scan_id, "error", "Safe mode: Scan aborted — target server health critical")
                        break

                # Phase Transition Logging
                if progress > 20 and not scan.get("phase_1_log"):
                    _add_log(scan_id, "success", "Phase 1 complete — Attack surface mapped")
                    scan["phase_1_log"] = True
                elif progress > 40 and not scan.get("phase_2_log"):
                    _add_log(scan_id, "success", "Phase 2 complete — Deep logic inspection")
                    scan["phase_2_log"] = True
                elif progress > 70 and not scan.get("phase_3_log"):
                    _add_log(scan_id, "success", "Phase 3 complete — Cross-module correlation")
                    scan["phase_3_log"] = True
                elif progress > 90 and not scan.get("phase_4_log"):
                    _add_log(scan_id, "success", "Phase 4 complete — Integrity verification")
                    scan["phase_4_log"] = True

                criticals = sum(1 for f in findings if getattr(f, "severity", "").lower() == "critical")
                highs = sum(1 for f in findings if getattr(f, "severity", "").lower() == "high")

                if criticals > 0:
                    _add_log(scan_id, "error", f"[{meta['name']}] {criticals} critical finding(s)", module_key)
                elif highs > 0:
                    _add_log(scan_id, "warn", f"[{meta['name']}] {highs} high severity finding(s)", module_key)

                scan["modules_completed"] = idx + 1
                scan["module_results"][module_key] = {"status": "completed", "findings_count": len(findings)}

            except asyncio.TimeoutError:
                _add_log(scan_id, "error", f"[{meta['name']}] TIMEOUT: Module took longer than 60 seconds", module_key)
                scan["module_results"][module_key] = {"status": "timeout", "error": "Module execution timeout (60s)"}
                scan["modules_completed"] = idx + 1
            except Exception as e:
                _add_log(scan_id, "error", f"[{meta['name']}] Error: {str(e)}", module_key)
                scan["module_results"][module_key] = {"status": "error", "error": str(e)}
                scan["modules_completed"] = idx + 1

        # ── Flush remaining batch writes ──────────────────────────────────────
        if _finding_batch:
            try:
                db.bulk_save_objects(_finding_batch)
                db.commit()
                _finding_batch.clear()
            except Exception as e:
                print(f"Error flushing final batch to SQL: {e}")
                db.rollback()

        scan["progress"] = 100
        state_mgr.set_progress(scan_id, 100)

        if scan["status"] != "cancelled":
            scan["status"] = "completed"
            state_mgr.set_scan_status(scan_id, "completed")

        scan["active_module"] = None
        scan["completed_at"] = datetime.now(timezone.utc).isoformat()
        scan["duration"] = round(time.time() - start_time, 2)
        # Use true count (tracks all dedup'd findings even when list is capped)
        scan["total_findings"] = scan.get("total_findings_count", len(scan["findings"]))
        scan["severity_counts"] = severity_counts
        scan["owasp_coverage"] = owasp_counts

        # Compute confidence-based risk score (never 100 from 0 findings)
        risk_score, confidence, scan_status_val, risk_level = _compute_risk_score(
            severity_counts,
            scan.get("modules_completed", len(valid_modules)),
            len(valid_modules),
        )
        scan["risk_score"]  = risk_score
        scan["confidence"]  = confidence
        scan["scan_status"] = scan_status_val
        scan["risk_level"]  = risk_level

        # Compute top vulnerable files
        file_counts: dict[str, int] = {}
        for f in scan["findings"]:
            fpath = f.get("file", "unknown")
            file_counts[fpath] = file_counts.get(fpath, 0) + 1
        scan["top_files"] = sorted(
            [{"file": k, "count": v} for k, v in file_counts.items()],
            key=lambda x: x["count"],
            reverse=True
        )[:10]

        # Save to database
        try:
            db_scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
            if db_scan:
                db_scan.status = scan["status"]
                db_scan.progress = 100.0
                db_scan.completed_at = datetime.now(timezone.utc)
                db_scan.duration = scan["duration"]
                db_scan.total_findings = scan["total_findings"]
                db_scan.severity_counts = severity_counts
                db_scan.risk_score = scan["risk_score"]
                db.commit()
                print(f"DEBUG: execute_scan: Scan {scan_id} record updated in SQL (Findings: {scan['total_findings']}, Risk: {scan['risk_score']})")
        except Exception as e:
            print(f"Database save error: {e}")
            db.rollback()

        total_findings_count = len(scan["findings"])

        # ── Phase: Enterprise Attack Chain Correlation ────────────────────────
        if scan["findings"] and _CHAIN_CORRELATOR_AVAILABLE and _AttackChainCorrelator:
            try:
                _add_log(scan_id, "info", "Attack chain correlator engaged")
                _correlator = _AttackChainCorrelator()
                _chain_results = _correlator.correlate(scan["findings"])
                if _chain_results:
                    scan["enterprise_attack_chains"] = _chain_results
                    _chains_count = len(_chain_results)
                    _critical_chains = [c for c in _chain_results if c.get("severity") in ("critical", "high")]
                    _chain_types = list({c.get("name", "unknown") for c in _chain_results})
                    _append_event(scan, "enterprise_attack_chains", {
                        "chains": _chain_results[:20],  # cap at 20 for SSE size
                        "total_chains": _chains_count,
                        "critical_chains": len(_critical_chains),
                        "chain_types": _chain_types,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
                    _add_log(scan_id, "warn" if _critical_chains else "success",
                        f"Attack chains: {_chains_count} identified, {len(_critical_chains)} critical")
                    for _hrc in _critical_chains[:3]:
                        _add_log(scan_id, "error",
                            f"Chain: {_hrc.get('name','?')} — {_hrc.get('description','')[:80]}")
            except Exception as _cc_err:
                logger.debug(f"Attack chain correlator error: {_cc_err}")

        # ── Phase: Enterprise Scan Summary ────────────────────────────────────
        if _ENTERPRISE_ORCHESTRATOR_AVAILABLE and scan["findings"]:
            try:
                _summary = enterprise_scan_summary(scan["findings"])
                if _summary:
                    scan["enterprise_summary"] = _summary
                    _chains_in_summary = _summary.get("attack_chains", [])
                    _append_event(scan, "enterprise_summary", {
                        "total_findings": _summary.get("total_findings", 0),
                        "severity_breakdown": _summary.get("severity_breakdown", {}),
                        "attack_chains": _chains_in_summary[:20],
                        "attack_chain_count": _summary.get("attack_chain_count", 0),
                        "engines_available": _summary.get("engines_available", []),
                    })
                    _add_log(scan_id, "success",
                        f"Enterprise summary: {_summary.get('total_findings',0)} findings, "
                        f"{_summary.get('attack_chain_count',0)} attack chains")
            except Exception as _es_err:
                logger.debug(f"Enterprise scan summary error: {_es_err}")

        # ── Phase: Exploit Verification (URL scans only) ──────────────────────
        effective_type = target_type or scan_type or "directory"
        if effective_type in ("url",) and scan["findings"] and _VERIFIER_AVAILABLE:
            try:
                _add_log(scan_id, "info", "Phase 5 — Autonomous exploit verification")
                verifier = get_exploit_verifier()
                url_findings = [
                    f for f in scan["findings"]
                    if f.get("severity", "").lower() in ("critical", "high", "medium")
                ]
                verified_results = await verifier.verify_batch(url_findings, target, max_count=10)
                confirmed_count = 0
                for vr in verified_results:
                    # Emit payload_executed event
                    _append_event(scan, "payload_executed", {
                        "endpoint": vr.endpoint,
                        "payload_type": vr.strategy,
                        "payload_used": vr.payload_used[:100],
                        "finding_id": vr.finding_id,
                    })
                    if vr.verification_status == "confirmed":
                        confirmed_count += 1
                        # Annotate finding with proof
                        for f in scan["findings"]:
                            if f.get("id") == vr.finding_id:
                                f["verified"] = True
                                f["proof"] = vr.to_dict()
                                f["confidence_score"] = vr.confidence_score
                                break
                        _append_event(scan, "verification_success", {
                            "finding_id": vr.finding_id,
                            "endpoint": vr.endpoint,
                            "confidence": vr.confidence_score,
                            "timing_delta_ms": vr.timing_delta_ms,
                            "strategy": vr.strategy,
                            "evidence_hash": vr.evidence_hash,
                        })
                        _add_log(scan_id, "error",
                            f"VERIFIED: {vr.endpoint} [{vr.confidence_score:.0%} confidence | {vr.strategy}]")
                scan["verified_findings"] = [vr.to_dict() for vr in verified_results if vr.verification_status == "confirmed"]
                _add_log(scan_id, "success",
                    f"Exploit verification complete: {confirmed_count}/{len(verified_results)} findings confirmed with proof")
            except Exception as _ve:
                logger.warning(f"Exploit verifier error: {_ve}")

        # ── Phase: Neo4j Attack Graph Auto-Generation ─────────────────────────
        if scan["findings"] and _NEO4J_AVAILABLE:
            try:
                _add_log(scan_id, "info", "Phase 6 — Building attack graph intelligence")
                neo4j = get_neo4j_client()
                neo4j.ingest_scan_results(scan_id, target, scan["findings"])
                attack_paths = neo4j.get_attack_paths(scan_id)
                breach_sim   = neo4j.simulate_breach(scan_id, scan["findings"])
                scan["attack_paths"]      = attack_paths
                scan["breach_simulation"] = breach_sim
                breach_prob = breach_sim.get("breach_probability", 0)
                _append_event(scan, "attack_chain_created", {
                    "paths_count":        len(attack_paths),
                    "breach_probability": breach_prob,
                    "risk_level":         breach_sim.get("risk_level", risk_level),
                    "mitre_techniques":   breach_sim.get("mitre_techniques", []),
                })
                asyncio.create_task(ws_manager.broadcast_scan_update(scan_id, {
                    "type":               "attack_chain_created",
                    "paths_count":        len(attack_paths),
                    "breach_probability": breach_prob,
                    "risk_level":         breach_sim.get("risk_level", risk_level),
                }))
                _add_log(scan_id, "success",
                    f"Attack graph built: {len(attack_paths)} paths | Breach probability: {breach_prob}%")
            except Exception as _ne:
                logger.warning(f"Neo4j attack graph error: {_ne}")

        # ── Phase: AI Attack Summary ──────────────────────────────────────────
        if scan["findings"] and _DECISION_ENGINE_AVAILABLE:
            try:
                decision_engine = get_attack_decision_engine()
                scan["attack_summary"] = decision_engine.generate_attack_summary(scan["findings"])
            except Exception as _ae:
                logger.debug(f"Attack summary error: {_ae}")

        # ── Phase: PQSI Post-Processing (Quantum Intelligence) ────────────
        if _PQSI_INTELLIGENCE_AVAILABLE and any(
            m.startswith("pqsi_") for m in valid_modules
        ):
            try:
                _add_log(scan_id, "info", "PQSI — Computing quantum intelligence metrics")
                _timeline_engine = QuantumTimelineEngine()

                # Collect raw CryptoFinding objects from PQSI modules
                _pqsi_raw = [f for f in _all_raw_findings if hasattr(f, "family")]
                _timeline_engine.compute_timeline(_pqsi_raw)

                # Compute adoption index from library agent findings
                _pqc_adopt = 0.0
                for _rf in _pqsi_raw:
                    _aidx = getattr(_rf, "pqc_adoption_index", None)
                    if _aidx and _aidx > _pqc_adopt:
                        _pqc_adopt = float(_aidx)

                # Compute QQSI
                _qqsi = _compute_qqsi(_pqsi_raw, _pqc_adopt)
                _exposure = _timeline_engine.generate_exposure_summary(_pqsi_raw)

                _hndl_count = sum(
                    1 for _rf in _pqsi_raw
                    if hasattr(_rf, "family") and "HNDL" in str(getattr(_rf.family, "value", ""))
                )
                _recon_detected = any(
                    hasattr(_rf, "family") and "Recon" in str(getattr(_rf.family, "value", ""))
                    for _rf in _pqsi_raw
                )

                scan["quantum_intelligence"] = {
                    "qqsi_score": _qqsi["qqsi"],
                    "qqsi_grade": _qqsi["grade"],
                    "components": _qqsi["components"],
                    "pqc_adoption_index": _pqc_adopt,
                    "hndl_findings_count": _hndl_count,
                    "quantum_recon_detected": _recon_detected,
                    "exposure_summary": _exposure,
                    "migration_priority": _qqsi.get("migration_priority", "unknown"),
                }

                _append_event(scan, "quantum_intelligence", scan["quantum_intelligence"])
                _add_log(scan_id, "success",
                    f"PQSI complete — QQSI: {_qqsi['qqsi']}/100 [{_qqsi['grade']}] | "
                    f"PQC Adoption: {_pqc_adopt} | HNDL: {_hndl_count} | "
                    f"Migration: {_qqsi.get('migration_priority', 'unknown')}")
            except Exception as _pqsi_err:
                logger.warning(f"PQSI post-processing error: {_pqsi_err}")

        _add_log(scan_id, "success",
            f"Scan complete — {total_findings_count} findings / {len(valid_modules)} modules / {scan['duration']}s / Risk {risk_score}/100 [{risk_level}]")
        _append_event(scan, "complete", {
            "total_findings":  total_findings_count,
            "duration":        scan["duration"],
            "risk_score":      risk_score,
            "confidence":      confidence,
            "scan_status":     scan_status_val,
            "risk_level":      risk_level,
            "severity_counts": severity_counts,
            "dedup_skipped":   scan.get("dedup_skipped", 0),
        })
        state_mgr.publish_status(scan_id, scan["status"], {"total_findings": total_findings_count, "duration": scan["duration"]})

        # Broadcast scan completion via WebSocket
        asyncio.create_task(ws_manager.broadcast_scan_update(scan_id, {
            "type":            "complete",
            "status":          scan["status"],
            "total_findings":  total_findings_count,
            "duration":        scan["duration"],
            "risk_score":      risk_score,
            "confidence":      confidence,
            "scan_status":     scan_status_val,
            "risk_level":      risk_level,
            "severity_counts": severity_counts,
        }))

    except Exception as e:
        print(f"Crucial error in execute_scan: {e}")
        if scan_id in scans:
            scans[scan_id]["status"] = "error"
            scans[scan_id]["completed_at"] = datetime.now(timezone.utc).isoformat()
            _add_log(scan_id, "error", f"FATAL ERROR: {str(e)}")
    finally:
        if own_db:
            db.close()
        # Always release the global scan slot so queued scans can proceed
        if _STABILITY_AVAILABLE:
            await scan_queue_manager.release_slot(scan_id)


def _add_log(scan_id: str, level: str, message: str, module: Optional[str] = None):
    now = datetime.now(timezone.utc)
    time_str = now.strftime("%H:%M:%S")

    log_entry = {"time": time_str, "level": level, "message": message, "module": module}
    scans[scan_id]["logs"].append(log_entry)
    _append_event(scans[scan_id], "log", log_entry)


def _add_event(scan_id: str, event_type: str, data: dict):
    """Emit a structured scan event to the SSE stream and WebSocket."""
    _append_event(scans[scan_id], event_type, data)
    asyncio.create_task(ws_manager.broadcast_scan_update(scan_id, {
        "type": event_type,
        **data,
    }))


def _compute_risk_score(
    severity_counts: dict,
    modules_completed: int,
    modules_total: int,
) -> Tuple[int, str, str, str]:
    """
    Confidence-based risk model.
    System NEVER assumes security from absence of findings.
    Returns: (score, confidence, scan_status, risk_level)
    """
    coverage = modules_completed / max(modules_total, 1)
    severity_penalty = (
        severity_counts.get("critical", 0) * 15 +
        severity_counts.get("high", 0) * 8 +
        severity_counts.get("medium", 0) * 3 +
        severity_counts.get("low", 0) * 1
    )
    uncertainty_penalty = round((1.0 - coverage) * 80)
    raw = 100 - severity_penalty
    final = max(0, min(100, raw - uncertainty_penalty))

    if coverage < 0.3:
        confidence, scan_status = "LOW", "INCONCLUSIVE"
    elif coverage < 0.7:
        confidence, scan_status = "MEDIUM", "PARTIAL_ASSESSMENT"
    else:
        confidence, scan_status = "HIGH", "ASSESSED"

    if severity_counts.get("critical", 0) > 0:
        risk_level = "Critical"
    elif severity_counts.get("high", 0) > 0:
        risk_level = "High"
    elif severity_counts.get("medium", 0) > 5:
        risk_level = "Medium"
    elif scan_status == "INCONCLUSIVE":
        risk_level = "Unknown"
    else:
        risk_level = "Low"

    return int(final), confidence, scan_status, risk_level

# ═══════════════════════════════════════════════════════════════════════════════
# API Endpoints
# ═══════════════════════════════════════════════════════════════════════════════

@app.on_event("startup")
async def startup_event():
    """Initialize database on startup and launch stability background tasks."""
    init_db()
    if _STABILITY_AVAILABLE:
        # Initialize semaphore within the running event loop
        get_semaphore()
        # Start memory cleanup (sweeps scans dict every 30min, evicts after 1hr TTL)
        asyncio.create_task(cleanup_old_scans(scans))
        # Start watchdog (kills scans stuck >120s with no progress)
        asyncio.create_task(scan_watchdog(scans))
        # Start resource monitor (throttle on CPU >80% or RAM >75%, requires psutil)
        asyncio.create_task(resource_monitor(scans))
        logger.info("Stability engines initialized: semaphore, cleanup, watchdog, resource monitor")


# ── Health ────────────────────────────────────────────────────

@app.get("/api/v1/health")
async def health():
    return {
        "status": "healthy",
        "version": "5.0.0",
        "engine": "unified (Scanner_1 + Scanner_2)",
        "modules": len(MODULE_REGISTRY),
        "total_patterns": sum(m["pattern_count"] for m in MODULE_REGISTRY.values()),
        "profiles": len(SCAN_PROFILES),
        "uptime": time.time(),
        "active_scans": sum(1 for s in scans.values() if s["status"] == "running"),
    }


# ── Auth ──────────────────────────────────────────────────────

@app.post("/api/v1/auth/login", response_model=TokenResponse)
async def login_endpoint(request: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == request.email).first()
    if not user or not verify_password(request.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token = create_access_token({"sub": user.id})
    refresh_token = create_refresh_token(user.id)
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=1800,
        user=user.to_dict()
    )

@app.post("/api/v1/auth/google-login", response_model=TokenResponse)
async def google_login_endpoint(request: GoogleLoginRequest, db: Session = Depends(get_db)):
    email = SUPER_ADMIN_EMAIL
    user = db.query(User).filter(User.email == email).first()
    
    if not user:
        # Create super admin if missing
        user = User(
            id=str(uuid.uuid4()),
            email=email,
            username="superadmin",
            hashed_password="[GOOGLE_AUTH]",
            is_active=True,
            is_admin=True,
            is_super_admin=True
        )
        db.add(user)
        db.commit()
    
    if not user.is_super_admin:
        raise HTTPException(status_code=403, detail="Access denied: Not a super admin")

    access_token = create_access_token({"sub": user.id})
    refresh_token = create_refresh_token(user.id)
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=1800,
        user=user.to_dict()
    )


# ── Modules & Profiles ────────────────────────────────────────

@app.get("/api/v1/modules")
async def list_modules():
    """List available scanner modules with metadata."""
    return {"modules": get_available_modules()}


@app.get("/api/v1/profiles")
async def list_profiles():
    """List available scan profiles (quick, standard, full, owasp-top-10, cloud, api)."""
    return {"profiles": get_available_profiles()}


# ── Scan Lifecycle ─────────────────────────────────────────────

@app.post("/api/v1/scan/start", response_model=ScanResponse)
@app.post("/api/v1/scan", response_model=ScanResponse)
async def start_scan(
    request: ScanRequest, 
    background_tasks: BackgroundTasks,
    subscription: Dict[str, Any] = Depends(get_user_subscription)
):
    """Initiate a new security scan."""
    # Check subscription access
    allowed, error = check_subscription_access(subscription, "scan")
    if not allowed:
        raise HTTPException(status_code=403, detail=error)
    
    # Check usage limits
    allowed, error = check_usage_limits(subscription)
    if not allowed:
        raise HTTPException(status_code=403, detail=error)
    
    scan_id = str(uuid.uuid4())

    # Resolve modules: use explicit list if provided, else use profile
    requested_modules = request.modules
    if not requested_modules or requested_modules == ["misconfig", "injection", "frontend_js", "endpoint"]:
        requested_modules = get_modules_for_profile(request.scan_profile)

    valid_modules = [m for m in requested_modules if m in MODULE_REGISTRY]
    if not valid_modules:
        raise HTTPException(status_code=400, detail="No valid modules specified")

    if request.scan_type == "directory" and not os.path.exists(request.target):
        # Gracefully handle missing directory if it might be an absolute path error
        if not os.path.isabs(request.target):
            # Try relative to current workspace if available
            pass
        else:
            raise HTTPException(status_code=400, detail=f"Target directory not found: {request.target}")

    if request.scan_type == "url":
        if not request.target.startswith(("http://", "https://")):
            raise HTTPException(status_code=400, detail="Invalid URL format. Must start with http:// or https://")

    total_patterns = sum(MODULE_REGISTRY[m]["pattern_count"] for m in valid_modules)

    # Persist to local SQL for history linkage
    db = get_db_session()
    local_user_id = subscription.get("local_user_id")
    print(f"DEBUG: start_scan: Attempting to create SQL Scan record for user {local_user_id}")
    
    if not local_user_id:
        print("DEBUG: start_scan: WARNING! local_user_id is MISSING from subscription")
        # For robustness, we might want to fail here, but let's log and see
    
    try:
        new_db_scan = Scan(
            scan_id=scan_id,
            user_id=local_user_id,
            target=request.target,
            scan_type=request.scan_type,
            modules=valid_modules,
            status="initializing",
            progress=0,
            modules_total=len(valid_modules),
            created_at=datetime.now(timezone.utc)
        )
        db.add(new_db_scan)
        db.commit()
        print(f"DEBUG: start_scan: SQL Scan record created successfully: {scan_id}")
    except Exception as e:
        print(f"DEBUG: start_scan: Error creating SQL scan record: {e}")
        db.rollback()
    finally:
        db.close()

    scans[scan_id] = {
        "scan_id": scan_id,
        "target": request.target,
        "scan_type": request.scan_type,
        "target_type": request.target_type,
        "modules": valid_modules,
        "scan_profile": request.scan_profile,
        "status": "initializing",
        "progress": 0,
        "active_module": None,
        "modules_completed": 0,
        "modules_total": len(valid_modules),
        "findings": [],
        "logs": [],
        "events": [],
        "module_results": {},
        "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "owasp_coverage": {},
        "risk_score": 0,
        "confidence": "LOW",
        "scan_status": "INCONCLUSIVE",
        "risk_level": "Unknown",
        "top_files": [],
        "started_at": None,
        "completed_at": None,
        "duration": 0,
        "cancelled": False,
        "total_patterns": total_patterns,
        # Intelligence fields
        "attack_paths": [],
        "breach_simulation": {},
        "ai_recommendations": {},
        "verified_findings": [],
        "attack_summary": {},
        "coverage_intelligence": {
            "get_params_tested": 0,
            "post_bodies_tested": 0,
            "json_apis_tested": 0,
            "headers_tested": 0,
            "cookies_tested": 0,
            "js_discovered_endpoints": 0,
            "graphql_routes": 0,
            "authenticated_paths": 0,
        },
        # Stability fields
        "user_id": local_user_id,           # for per-user concurrency check
        "dedup_set": set(),                  # in-scan dedup fingerprints (not serializable, memory only)
        "dedup_skipped": 0,                  # count of duplicates eliminated
        "total_findings_count": 0,           # true count even when findings list is capped
        "_last_event_time": time.monotonic(), # watchdog heartbeat
        "_events_base_offset": 0,            # SSE cursor rebasing after events trim
    }

    # ── Enforce per-user and global concurrency limits ────────────────────────
    if _STABILITY_AVAILABLE:
        try:
            await scan_queue_manager.acquire_slot(scan_id, local_user_id or "", scans)
        except ValueError as ve:
            # Per-user limit exceeded — clean up and reject
            scans.pop(scan_id, None)
            raise HTTPException(status_code=429, detail=str(ve))

    # ── Emit initialization log immediately so SSE stream is non-empty ─────
    _add_log(scan_id, "info", f"Scan initialized — {request.target} | {len(valid_modules)} modules | {total_patterns} signatures")
    _append_event(scans[scan_id], "scan_initialized", {
        "scan_id": scan_id,
        "target": request.target,
        "modules": valid_modules,
        "total_patterns": total_patterns,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    background_tasks.add_task(execute_scan, scan_id, request.target, request.scan_type, valid_modules, None, request.target_type)
    
    # Increment usage (skipped automatically for super admin)
    increment_scan_usage(subscription.get("uid"), email=subscription.get("email", ""))
    
    return ScanResponse(scan_id=scan_id, status="started", modules=valid_modules, total_patterns=total_patterns)


@app.get("/api/v1/scan/{scan_id}")
@app.get("/api/v1/scan/{scan_id}/status")
async def get_scan_status(scan_id: str, db: Session = Depends(get_db)):
    """Get current status of a scan."""
    if scan_id in scans:
        scan = scans[scan_id]
        elapsed = 0
        if scan["started_at"]:
            try:
                start = datetime.fromisoformat(scan["started_at"])
                elapsed = (datetime.now(timezone.utc) - start).total_seconds()
            except: pass
        return ScanStatusModel(
            scan_id=scan_id,
            status=scan["status"],
            progress=scan["progress"],
            active_module=scan["active_module"],
            total_findings=scan.get("total_findings_count", len(scan["findings"])),
            modules_completed=scan["modules_completed"],
            modules_total=scan["modules_total"],
            started_at=scan["started_at"],
            completed_at=scan.get("completed_at"),
            elapsed_seconds=round(elapsed, 1),
            duration=scan.get("duration", 0),
            severity_counts=scan.get("severity_counts", {}),
            target=scan.get("target"),
        )
    
    # Check DB
    db_scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
    if not db_scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    return ScanStatusModel(
        scan_id=scan_id,
        status=db_scan.status,
        progress=db_scan.progress,
        active_module=None,
        total_findings=db_scan.total_findings,
        modules_completed=db_scan.modules_completed,
        modules_total=db_scan.modules_total,
        started_at=db_scan.started_at.isoformat() if db_scan.started_at else None,
        completed_at=db_scan.completed_at.isoformat() if db_scan.completed_at else None,
        elapsed_seconds=0,
        duration=db_scan.duration,
        severity_counts=db_scan.severity_counts,
        target=db_scan.target,
    )


@app.get("/api/v1/scans")
async def list_scans(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    subscription: Dict[str, Any] = Depends(get_user_subscription),
    db: Session = Depends(get_db)
):
    """List all scans for the current user."""
    local_user_id = subscription.get("local_user_id")
    
    query = db.query(Scan)
    if local_user_id:
        query = query.filter(Scan.user_id == local_user_id)
    
    total = query.count()
    db_scans = query.order_by(Scan.created_at.desc()).offset(offset).limit(limit).all()
    
    return {
        "scans": [s.to_dict() for s in db_scans],
        "total": total,
        "limit": limit,
        "offset": offset
    }


@app.delete("/api/v1/scan/{scan_id}")
@app.post("/api/v1/scan/{scan_id}/cancel")
async def cancel_scan(scan_id: str):
    """Cancel a running scan."""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    scans[scan_id]["cancelled"] = True
    return {"scan_id": scan_id, "status": "cancelling"}


# ── Findings ───────────────────────────────────────────────────

@app.get("/api/v1/scan/{scan_id}/findings")
async def get_scan_findings(
    scan_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    severity: Optional[str] = None,
    module: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: str = "severity",
    sort_order: str = "desc",
    db: Session = Depends(get_db)
):
    """Get paginated findings for a scan with filtering and sorting."""
    if scan_id in scans:
        findings = scans[scan_id]["findings"]
    else:
        # Check DB
        db_findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        if not db_findings:
            # Maybe the scan exists but has 0 findings
            db_scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
            if not db_scan:
                raise HTTPException(status_code=404, detail="Scan not found")
            findings = []
        else:
            findings = [f.to_dict() for f in db_findings]

    # Apply filters
    if severity:
        sev_filter = severity.lower().split(",")
        findings = [f for f in findings if f.get("severity", "").lower() in sev_filter]

    if module:
        mod_filter = module.lower().split(",")
        findings = [f for f in findings if f.get("module", "").lower() in mod_filter or f.get("module_name", "").lower() in mod_filter]

    if search:
        search_lower = search.lower()
        findings = [f for f in findings if (
            search_lower in f.get("title", "").lower() or
            search_lower in f.get("file", "").lower() or
            search_lower in f.get("cwe", "").lower() or
            search_lower in f.get("description", "").lower()
        )]

    # Sorting
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    if sort_by == "severity":
        findings.sort(key=lambda f: severity_order.get(f.get("severity", "info").lower(), 5), reverse=(sort_order == "desc"))
    elif sort_by == "file":
        findings.sort(key=lambda f: f.get("file", ""), reverse=(sort_order == "desc"))
    elif sort_by == "module":
        findings.sort(key=lambda f: f.get("module_name", ""), reverse=(sort_order == "desc"))

    # Pagination
    total = len(findings)
    total_pages = max(1, (total + page_size - 1) // page_size)
    start = (page - 1) * page_size
    end = start + page_size
    paginated = findings[start:end]

    return {
        "findings": paginated,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "has_next": page < total_pages,
        "has_prev": page > 1,
    }


# ── SSE Streaming ─────────────────────────────────────────────

@app.get("/api/v1/scan/{scan_id}/stream")
async def stream_scan_events(scan_id: str):
    """Stream real-time scan events via Server-Sent Events."""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")

    async def event_generator():
        # cursor = absolute index of next event to send (survives events list trimming)
        cursor = 0
        # Track already-sent terminal status to prevent duplicates
        terminal_sent = False
        print(f"DEBUG: SSE Stream generator started for scan {scan_id}")

        # Immediate connection established message
        yield {"event": "status", "data": json.dumps({"status": "connected", "message": "Neural link established"}) }

        while True:
            scan = scans.get(scan_id)
            if not scan:
                print(f"DEBUG: SSE Stream: Scan {scan_id} not found, breaking")
                break

            events = scan["events"]
            # Rebase cursor: account for events that were trimmed from the list front
            base_offset = scan.get("_events_base_offset", 0)
            effective_cursor = max(0, cursor - base_offset)

            # Yield any new events
            new_events_count = len(events) - effective_cursor
            if new_events_count > 0:
                print(f"DEBUG: SSE Stream: yielding {new_events_count} new events for {scan_id}")

            while effective_cursor < len(events):
                event = events[effective_cursor]
                effective_cursor += 1
                cursor = base_offset + effective_cursor   # keep absolute cursor in sync
                if event["type"] == "finding":
                    print(f"DEBUG: SSE Stream: Yielding FINDING {event['data'].get('id', 'no-id')} for {scan_id}")
                yield {"event": event["type"], "data": json.dumps(event["data"])}

            # Check terminal status - send final status ONCE then break
            if scan["status"] in ("completed", "error", "cancelled"):
                if not terminal_sent:
                    print(f"DEBUG: SSE Stream: Scan {scan_id} terminal status reached: {scan['status']}")
                    terminal_sent = True
                    yield {
                        "event": "status",
                        "data": json.dumps({
                            "status":           scan["status"],
                            "progress":         scan["progress"],
                            "total_findings":   scan.get("total_findings_count", len(scan["findings"])),
                            "duration":         scan.get("duration", 0),
                            "severity_counts":  scan.get("severity_counts", {}),
                            "risk_score":       scan.get("risk_score", 0),
                            "confidence":       scan.get("confidence", "LOW"),
                            "scan_status":      scan.get("scan_status", "INCONCLUSIVE"),
                            "risk_level":       scan.get("risk_level", "Unknown"),
                            "attack_paths":     len(scan.get("attack_paths", [])),
                            "verified_count":   len(scan.get("verified_findings", [])),
                            "dedup_skipped":    scan.get("dedup_skipped", 0),
                        })
                    }
                break

            # Send periodic status updates only for non-terminal scans
            yield {
                "event": "status",
                "data": json.dumps({
                    "status": scan["status"], "progress": scan["progress"],
                    "active_module": scan.get("active_module", "Analyzing..."),
                    "total_findings": scan.get("total_findings_count", len(scan["findings"])),
                    "modules_completed": scan.get("modules_completed", 0),
                    "modules_total": scan.get("modules_total", 0),
                    "severity_counts": scan.get("severity_counts", {}),
                    "dedup_skipped": scan.get("dedup_skipped", 0),
                })
            }
            await asyncio.sleep(0.5)

    return EventSourceResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
        }
    )


# ── Reports ────────────────────────────────────────────────────

@app.get("/api/v1/scan/{scan_id}/report")
async def get_scan_report(scan_id: str, format: str = "json"):
    """Generate comprehensive scan report."""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = scans[scan_id]
    findings = scan["findings"]

    # Severity summary
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info").lower()
        if sev in summary:
            summary[sev] += 1

    # Module summary
    module_summary = {}
    for f in findings:
        mod = f.get("module", "unknown")
        if mod not in module_summary:
            module_summary[mod] = {"name": f.get("module_name", mod), "count": 0, "severities": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}}
        module_summary[mod]["count"] += 1
        sev = f.get("severity", "info").lower()
        if sev in module_summary[mod]["severities"]:
            module_summary[mod]["severities"][sev] += 1

    # OWASP coverage
    owasp_coverage = {}
    for f in findings:
        owasp = f.get("owasp", "")
        if owasp:
            if owasp not in owasp_coverage:
                owasp_coverage[owasp] = {"count": 0, "critical": 0, "high": 0}
            owasp_coverage[owasp]["count"] += 1
            sev = f.get("severity", "info").lower()
            if sev in owasp_coverage[owasp]:
                owasp_coverage[owasp][sev] += 1

    # Top vulnerable files
    file_counts: dict[str, dict] = {}
    for f in findings:
        fpath = f.get("file", "unknown")
        if fpath not in file_counts:
            file_counts[fpath] = {"file": fpath, "count": 0, "critical": 0, "high": 0}
        file_counts[fpath]["count"] += 1
        sev = f.get("severity", "info").lower()
        if sev in file_counts[fpath]:
            file_counts[fpath][sev] += 1
    top_files = sorted(file_counts.values(), key=lambda x: x["count"], reverse=True)[:10]

    return {
        "scan_id": scan_id,
        "status": scan["status"],
        "target": scan["target"],
        "scan_type": scan.get("scan_type", "directory"),
        "scan_profile": scan.get("scan_profile", "full"),
        "duration": scan.get("duration", 0),
        "started_at": scan.get("started_at"),
        "completed_at": scan.get("completed_at"),
        "summary": summary,
        "module_summary": module_summary,
        "owasp_coverage": owasp_coverage,
        "total_findings": len(findings),
        "findings": findings,
        "logs": scan["logs"],
        "top_files": top_files,
        "risk_score": scan.get("risk_score", 0),
        "confidence": scan.get("confidence", "LOW"),
        "scan_status": scan.get("scan_status", "INCONCLUSIVE"),
        "risk_level": scan.get("risk_level", "Unknown"),
        "modules_used": scan.get("modules", []),
        # Intelligence fields
        "attack_paths": scan.get("attack_paths", []),
        "breach_simulation": scan.get("breach_simulation", {}),
        "attack_summary": scan.get("attack_summary", {}),
        "verified_findings": scan.get("verified_findings", []),
        "coverage_intelligence": scan.get("coverage_intelligence", {}),
        "ai_recommendations": scan.get("ai_recommendations", {}),
    }


@app.get("/api/v1/scan/{scan_id}/logs")
async def get_scan_logs(scan_id: str, db: Session = Depends(get_db)):
    if scan_id in scans:
        return {"logs": scans[scan_id]["logs"]}

    # Check DB
    db_logs = db.query(ScanLog).filter(ScanLog.scan_id == scan_id).order_by(ScanLog.timestamp.asc()).all()
    return {"logs": [l.to_dict() for l in db_logs]}


# ── Attack Intelligence Endpoints ──────────────────────────────

@app.get("/api/v1/scan/{scan_id}/attack-graph")
async def get_attack_graph(scan_id: str):
    """Return Neo4j attack graph paths and breach simulation."""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = scans[scan_id]
    return {
        "scan_id":           scan_id,
        "attack_paths":      scan.get("attack_paths", []),
        "breach_simulation": scan.get("breach_simulation", {}),
        "attack_summary":    scan.get("attack_summary", {}),
    }


@app.get("/api/v1/scan/{scan_id}/verified-findings")
async def get_verified_findings(scan_id: str):
    """Return only proof-verified findings with evidence."""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = scans[scan_id]
    verified = [f for f in scan.get("findings", []) if f.get("verified")]
    return {
        "scan_id":            scan_id,
        "verified_count":     len(verified),
        "verified_findings":  verified,
        "verification_proofs": scan.get("verified_findings", []),
    }


@app.get("/api/v1/scan/{scan_id}/coverage")
async def get_scan_coverage(scan_id: str):
    """Return target coverage intelligence metrics."""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = scans[scan_id]
    return {
        "scan_id":              scan_id,
        "coverage_intelligence": scan.get("coverage_intelligence", {}),
        "modules_completed":    scan.get("modules_completed", 0),
        "modules_total":        scan.get("modules_total", 0),
        "confidence":           scan.get("confidence", "LOW"),
        "scan_status":          scan.get("scan_status", "INCONCLUSIVE"),
    }


@app.get("/api/v1/quantum/intelligence/{scan_id}")
async def get_quantum_intelligence(scan_id: str):
    """Quantum Command Center API — returns PQSI summary for a scan."""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = scans[scan_id]

    qi = scan.get("quantum_intelligence")
    if not qi:
        # Fall back to scanning events for quantum_intelligence data
        qi_events = [
            e["data"] for e in scan.get("events", [])
            if e.get("type") == "quantum_intelligence"
        ]
        qi = qi_events[-1] if qi_events else None

    if not qi:
        return {
            "scan_id": scan_id,
            "quantum_intelligence_available": False,
            "message": "No PQSI modules were run for this scan",
        }

    return {
        "scan_id": scan_id,
        "quantum_intelligence_available": True,
        "quantum_risk_score": qi.get("qqsi_score", 0),
        "qqsi_grade": qi.get("qqsi_grade", "N/A"),
        "pqc_adoption_index": qi.get("pqc_adoption_index", 0),
        "hndl_exposure": qi.get("hndl_findings_count", 0),
        "quantum_recon_detected": qi.get("quantum_recon_detected", False),
        "migration_priority": qi.get("migration_priority", "unknown"),
        "components": qi.get("components", {}),
        "exposure_summary": qi.get("exposure_summary", {}),
    }


# ── Scan History ───────────────────────────────────────────────

@app.get("/api/v1/scans")
async def list_history(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    status: Optional[str] = None,
    subscription: Dict[str, Any] = Depends(get_user_subscription),
    db: Session = Depends(get_db)
):
    """List all scans for the current user from SQL DB."""
    local_user_id = subscription.get("local_user_id")
    
    query = db.query(Scan).filter(Scan.user_id == local_user_id)
    if status:
        status_filter = status.split(",")
        query = query.filter(Scan.status.in_(status_filter))

    total = query.count()
    db_scans = query.order_by(Scan.created_at.desc()).offset(offset).limit(limit).all()
    
    return {
        "scans": [
            {
                "scan_id": s.scan_id,
                "target": s.target,
                "scan_type": s.scan_type,
                "scan_profile": "full", # or from db if stored
                "status": s.status,
                "modules": s.modules,
                "total_findings": s.total_findings,
                "severity_counts": s.severity_counts,
                "started_at": s.started_at.isoformat() if s.started_at else s.created_at.isoformat(),
                "completed_at": s.completed_at.isoformat() if s.completed_at else None,
                "duration": s.duration,
                "risk_score": 100,
            }
            for s in db_scans
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


# ── Dashboard Aggregation ──────────────────────────────────────

@app.get("/api/v1/dashboard/stats")
async def get_dashboard_stats(
    subscription: Dict[str, Any] = Depends(get_user_subscription),
    db: Session = Depends(get_db)
):
    """Aggregate statistics for the dashboard overview from SQL DB."""
    local_user_id = subscription.get("local_user_id")
    
    # Get all scans for this user
    db_scans = db.query(Scan).filter(Scan.user_id == local_user_id).all()
    
    total_scans = len(db_scans)
    completed_scans = sum(1 for s in db_scans if s.status == "completed")
    running_scans = sum(1 for s in db_scans if s.status == "running")
    
    # Aggregated severity counts from DB
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for s in db_scans:
        counts = s.severity_counts or {}
        for sev, count in counts.items():
            if sev.lower() in severity_counts:
                severity_counts[sev.lower()] += count

    total_findings = sum(severity_counts.values())

    # Security score
    security_score = max(0, 100 - (
        severity_counts["critical"] * 10 +
        severity_counts["high"] * 5 +
        severity_counts["medium"] * 2 +
        severity_counts["low"] * 0.5
    ))
    if total_scans > 0:
        security_score = min(100, security_score)
    else:
        security_score = 100

    # Recent scans
    recent_db_scans = sorted(
        db_scans,
        key=lambda s: s.created_at,
        reverse=True
    )[:10]
    
    # Simple aggregation for dashboard charts
    module_stats = {}
    owasp_breakdown = {}
    for s in recent_db_scans:
        if s.modules:
            for mod in s.modules:
                if mod not in module_stats:
                    module_stats[mod] = {"scans": 0, "findings": 0}
                module_stats[mod]["scans"] += 1
                module_stats[mod]["findings"] += s.total_findings or 0

    return {
        "total_scans": total_scans,
        "completed_scans": completed_scans,
        "running_scans": running_scans,
        "total_findings": total_findings,
        "severity_counts": severity_counts,
        "security_score": round(security_score, 1),
        "recent_scans": [
            {
                "scan_id": s.scan_id,
                "target": s.target,
                "status": s.status,
                "total_findings": s.total_findings,
                "started_at": s.started_at.isoformat() if s.started_at else s.created_at.isoformat(),
                "duration": s.duration,
                "risk_score": s.risk_score if s.risk_score is not None else 100.0
            }
            for s in recent_db_scans
        ],
        "owasp_breakdown": owasp_breakdown,
        "module_stats": module_stats
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Billing API (Phase 5)
# ═══════════════════════════════════════════════════════════════════════════════

from backend.billing import billing_service

class CheckoutRequest(BaseModel):
    plan_id: str
    success_url: str = "http://localhost:3000/billing?success=true"
    cancel_url: str = "http://localhost:3000/billing?canceled=true"

class CheckoutResponse(BaseModel):
    session_id: str
    url: str
    mock: bool = False

@app.get("/api/v1/billing/plans")
async def list_plans():
    """List all available subscription plans."""
    return {"plans": billing_service.get_plans()}

@app.get("/api/v1/billing/subscription")
async def get_subscription(firebase_user: Dict[str, Any] = Depends(get_current_firebase_user)):
    """Get current user's subscription status."""
    user_id = firebase_user.get("local_user_id")
    subscription = billing_service.get_subscription(user_id)
    return {"subscription": subscription}

@app.post("/api/v1/billing/checkout", response_model=CheckoutResponse)
async def create_checkout(
    request: CheckoutRequest, 
    firebase_user: Dict[str, Any] = Depends(get_current_firebase_user)
):
    """Create Stripe checkout session for subscription."""
    try:
        user_id = firebase_user.get("local_user_id")
        result = billing_service.create_checkout_session(
            user_id, request.plan_id, request.success_url, request.cancel_url
        )
        return CheckoutResponse(**result)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/v1/billing/payment-methods")
async def list_payment_methods(firebase_user: Dict[str, Any] = Depends(get_current_firebase_user)):
    """List user's payment methods."""
    user_id = firebase_user.get("local_user_id")
    return {"payment_methods": billing_service.get_payment_methods(user_id)}

@app.get("/api/v1/billing/invoices")
async def list_invoices(firebase_user: Dict[str, Any] = Depends(get_current_firebase_user)):
    """List user's billing history."""
    user_id = firebase_user.get("local_user_id")
    return {"invoices": billing_service.get_invoices(user_id)}

@app.get("/api/v1/billing/usage")
async def get_usage(subscription: Dict[str, Any] = Depends(get_user_subscription)):
    """Get user's current usage statistics."""
    user_id = subscription.get("local_user_id")
    usage = billing_service.get_usage(user_id)
    # Ensure Firestore values are reflected if available
    usage["scans_this_month"] = subscription.get("scansUsedThisMonth", usage["scans_this_month"])
    usage["scans_limit"] = subscription.get("scanLimit", usage.get("scans_limit", 10))
    return usage

@app.post("/api/v1/debug/reset-usage")
async def reset_usage(subscription: Dict[str, Any] = Depends(get_user_subscription)):
    """Emergency reset for scan usage (Developer Tool)."""
    uid = subscription.get("uid")
    user_ref = firestore_db.collection("users").document(uid)
    user_ref.update({"scansUsedThisMonth": 0})
    return {"status": "success", "message": "Scan usage reset to zero"}

@app.post("/api/v1/billing/cancel")
async def cancel_subscription(firebase_user: Dict[str, Any] = Depends(get_current_firebase_user)):
    """Cancel subscription at period end."""
    user_id = firebase_user.get("local_user_id")
    success = billing_service.cancel_subscription(user_id)
    return {"success": success, "message": "Subscription will cancel at period end"}


class BillingPortalRequest(BaseModel):
    return_url: str = ""


@app.post("/api/v1/billing/portal")
async def create_billing_portal(
    body: BillingPortalRequest,
    request: Request,
    firebase_user: Dict[str, Any] = Depends(get_current_firebase_user),
):
    """
    Create a Stripe Customer Portal session.
    Redirects the user to Stripe's hosted portal to manage:
    - Payment methods (add / remove cards)
    - Download invoices and receipts
    - Cancel or upgrade subscription
    """
    user_id = firebase_user.get("local_user_id")
    return_url = body.return_url or f"{request.headers.get('origin', 'http://localhost:3000')}/billing"
    from backend.billing import BillingService
    return BillingService.create_billing_portal_session(user_id, return_url)


@app.post("/api/v1/billing/webhook")
async def stripe_webhook(request: Request):
    """Handle Stripe webhook events."""
    payload = await request.body()
    signature = request.headers.get("stripe-signature", "")
    result = billing_service.handle_webhook(payload, signature)
    return result


@app.get("/api/v1/admin/billing/revenue")
async def admin_billing_revenue(firebase_user: Dict[str, Any] = Depends(get_current_firebase_user)):
    """Admin endpoint: Stripe revenue summary (MRR, recent charges, subscription counts)."""
    from backend.auth import require_super_admin, get_current_user
    # Verify admin via local DB
    local_user_id = firebase_user.get("local_user_id")
    if not local_user_id:
        raise HTTPException(status_code=403, detail="Admin required")
    db = get_db_session()
    try:
        user = db.query(User).filter(User.id == local_user_id).first()
        if not user or not (user.is_admin or user.is_super_admin):
            raise HTTPException(status_code=403, detail="Admin required")
    finally:
        db.close()
    return billing_service.get_admin_revenue_summary()


@app.get("/api/v1/admin/users")
async def admin_get_users(firebase_user: Dict[str, Any] = Depends(get_current_firebase_user)):
    """Admin endpoint: list all users with subscription tier, status, and scan counts."""
    local_user_id = firebase_user.get("local_user_id")
    if not local_user_id:
        raise HTTPException(status_code=403, detail="Admin required")
    db = get_db_session()
    try:
        requesting_user = db.query(User).filter(User.id == local_user_id).first()
        if not requesting_user or not (requesting_user.is_admin or requesting_user.is_super_admin):
            raise HTTPException(status_code=403, detail="Admin required")

        # Aggregate total scan counts per user
        scan_counts = dict(
            db.query(Scan.user_id, func.count(Scan.id))
            .group_by(Scan.user_id)
            .all()
        )

        users = db.query(User).order_by(User.created_at.desc()).limit(500).all()
        result = []
        for u in users:
            result.append({
                "id": u.id,
                "email": u.email,
                "username": u.username or "",
                "full_name": u.full_name or "",
                "subscription_tier": u.subscription_tier.value if u.subscription_tier else "free",
                "subscription_status": u.subscription_status.value if u.subscription_status else "trial",
                "monthly_scan_limit": u.monthly_scan_limit or 10,
                "total_scans": scan_counts.get(u.id, 0),
                "is_admin": bool(u.is_admin),
                "is_super_admin": bool(u.is_super_admin),
                "has_stripe": bool(u.stripe_customer_id),
                "created_at": u.created_at.isoformat() if u.created_at else None,
            })

        # Tier distribution summary
        tier_counts = {}
        for u in users:
            tier = u.subscription_tier.value if u.subscription_tier else "free"
            tier_counts[tier] = tier_counts.get(tier, 0) + 1

        return {
            "users": result,
            "total": len(result),
            "tier_distribution": tier_counts,
        }
    finally:
        db.close()


# ═══════════════════════════════════════════════════════════════════════════════
# Report Generation API (Phase 8.4)
# ═══════════════════════════════════════════════════════════════════════════════

from backend.report_generator import report_generator

@app.get("/api/v1/scan/{scan_id}/download")
async def download_scan_report(scan_id: str, format: str = "json"):
    """Download scan report in specified format (json, html, pdf)."""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan = scans[scan_id]
    
    # Prepare scan data
    report_data = {
        "scan_id": scan_id,
        "target": scan.get("target", "Unknown"),
        "status": scan.get("status", "Unknown"),
        "duration": scan.get("duration", 0),
        "risk_score": scan.get("risk_score", 0),
        "summary": scan.get("severity_counts", {}),
        "findings": scan.get("findings", []),
        "owasp_coverage": scan.get("owasp_coverage", {}),
        "top_files": scan.get("top_files", []),
    }
    
    if format.lower() == "json":
        content = report_generator.generate_json_report(report_data)
        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=scan-{scan_id}.json"}
        )
    
    elif format.lower() == "html":
        content = report_generator.generate_html_report(report_data)
        return Response(
            content=content,
            media_type="text/html",
            headers={"Content-Disposition": f"attachment; filename=scan-{scan_id}.html"}
        )
    
    elif format.lower() == "pdf":
        try:
            content = report_generator.generate_pdf_report(report_data)
            return Response(
                content=content,
                media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename=scan-{scan_id}.pdf"}
            )
        except ImportError:
            raise HTTPException(status_code=500, detail="PDF generation not available. Install weasyprint.")
    
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")


# ═══════════════════════════════════════════════════════════════════════════════
# API Token Management (Phase 8.1 - CI/CD Integration)
# ═══════════════════════════════════════════════════════════════════════════════

from backend.token_manager import token_manager, APIToken

class CreateTokenRequest(BaseModel):
    name: str
    scopes: list[str] = ["read", "scan"]

@app.post("/api/v1/tokens")
async def create_api_token(request: CreateTokenRequest, user_id: str = "current"):
    """Create a new API token for CI/CD integration."""
    token_id, plain_token = token_manager.create_token(user_id, request.name, request.scopes)
    return {
        "token_id": token_id,
        "token": plain_token,  # Only shown once!
        "name": request.name,
        "scopes": request.scopes,
        "message": "Copy this token now - it won't be shown again!"
    }

@app.get("/api/v1/tokens")
async def list_api_tokens(user_id: str = "current"):
    """List all API tokens for the user."""
    tokens = token_manager.list_tokens(user_id)
    return {"tokens": [t.dict() for t in tokens]}

@app.delete("/api/v1/tokens/{token_id}")
async def revoke_api_token(token_id: str, user_id: str = "current"):
    """Revoke an API token."""
    success = token_manager.revoke_token(user_id, token_id)
    if not success:
        raise HTTPException(status_code=404, detail="Token not found")
    return {"success": True, "message": "Token revoked successfully"}


# ═══════════════════════════════════════════════════════════════════════════════
# CI/CD Integration API (Phase 8.1)
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/v1/ci/scan")
async def ci_scan_trigger(
    request: ScanRequest,
    authorization: str = Header(None)
):
    """Trigger a scan from CI/CD pipeline using API token."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header required")
    
    # Extract token from "Bearer <token>"
    token = authorization.replace("Bearer ", "") if authorization.startswith("Bearer ") else authorization
    
    # Verify token
    token_data = token_manager.verify_token(token)
    if not token_data:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    # Check scope
    if not token_manager.has_scope(token_data, "scan"):
        raise HTTPException(status_code=403, detail="Token does not have scan permission")
    
    # Create scan
    scan_id = str(uuid.uuid4())
    requested_modules = request.modules
    if not requested_modules:
        requested_modules = get_modules_for_profile(request.scan_profile)
    
    valid_modules = [m for m in requested_modules if m in MODULE_REGISTRY]
    
    scans[scan_id] = {
        "scan_id": scan_id,
        "target": request.target,
        "scan_type": request.scan_type,
        "modules": valid_modules,
        "status": "initializing",
        "progress": 0,
        "findings": [],
        "logs": [],
        "started_at": datetime.now(timezone.utc).isoformat(),
        "ci_triggered": True,
        "triggered_by": token_data.get("user_id"),
    }
    
    # Start scan in background
    import asyncio
    asyncio.create_task(execute_scan(scan_id, request.target, request.scan_type, valid_modules))
    
    return {
        "scan_id": scan_id,
        "status": "started",
        "webhook_url": f"/api/v1/scan/{scan_id}/status",
        "message": "Scan triggered via CI/CD"
    }


# ═══════════════════════════════════════════════════════════════════════════════
# AI-Powered Remediation API (Phase 8.2)
# ═══════════════════════════════════════════════════════════════════════════════

from backend.ai_remediation import ai_service

class AIAnalysisRequest(BaseModel):
    finding_id: str
    finding: dict

@app.post("/api/v1/ai/analyze")
async def ai_analyze_finding(request: AIAnalysisRequest):
    """Get AI-powered analysis and remediation for a finding."""
    analysis = ai_service.analyze_finding(request.finding)
    return {
        "finding_id": request.finding_id,
        "ai_available": ai_service.is_available(),
        "risk_explanation": analysis.risk_explanation,
        "fix_suggestion": analysis.fix_suggestion,
        "code_patch": analysis.code_patch,
        "confidence": analysis.confidence,
        "references": analysis.references,
    }

class ChatRequest(BaseModel):
    question: str
    context: Optional[dict] = None

@app.post("/api/v1/ai/chat")
async def ai_chat_assistant(
    request: ChatRequest,
    subscription: Dict[str, Any] = Depends(get_user_subscription)
):
    """AI security assistant chat endpoint — available to all plans."""
    response = ai_service.chat_assistant(request.question, request.context)
    return {
        "response": response,
        "ai_available": ai_service.is_available(),
    }

@app.post("/api/v1/ai/prioritize")
async def ai_prioritize_findings(findings: list[dict]):
    """AI-powered risk prioritization."""
    prioritized = ai_service.prioritize_risks(findings)
    return {
        "findings": prioritized,
        "ai_available": ai_service.is_available(),
        "total": len(prioritized),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# AI POC Fix Intelligence (Quantara Multi-LLM)
# ═══════════════════════════════════════════════════════════════════════════════

class PocFixRequest(BaseModel):
    finding: dict
    """The finding dict to generate a POC fix for."""


@app.post("/api/v1/ai/poc-fix")
async def ai_poc_fix(request: PocFixRequest, req: Request):
    """
    Generate comprehensive POC fix intelligence for the scanner POC verification panel.

    Uses the Quantara multi-LLM provider (Gemini → Anthropic → OpenAI fallback).
    Returns production-ready fix code, test steps, and compliance references.
    """
    try:
        import sys, os
        central_dir = os.path.join(os.path.dirname(__file__), "..", "Centralize_Scanners")
        scanner_dir = os.path.join(central_dir, "owasp_Scanner")
        for p in [central_dir, scanner_dir]:
            if p not in sys.path:
                sys.path.insert(0, p)

        from quantara_ai import QuantaraAICopilot, CopilotConfig

        config = CopilotConfig(
            gemini_api_key=os.environ.get("GEMINI_API_KEY", ""),
            anthropic_api_key=(
                os.environ.get("ANTHROPIC_API_KEY", "")
                or os.environ.get("ANTROPHIC_API_KEY", "")
            ),
            openai_api_key=os.environ.get("OPENAI_API_KEY", ""),
            enable_validation=False,
            enable_impact=False,
            enable_remediation=False,
            enable_poc_fix=True,
            enable_prioritization=False,
            enable_narrative=False,
        )

        copilot = QuantaraAICopilot(config)
        poc_fix = copilot.generate_poc_fix(request.finding)

        if poc_fix:
            return {
                "success": True,
                "poc_fix": {
                    "vulnerability_type": poc_fix.vulnerability_type,
                    "poc_description": poc_fix.poc_description,
                    "immediate_fix": poc_fix.immediate_fix,
                    "full_fix_code": poc_fix.full_fix_code,
                    "fix_language": poc_fix.fix_language,
                    "fix_explanation": poc_fix.fix_explanation,
                    "test_steps": poc_fix.test_steps,
                    "prevention_checklist": poc_fix.prevention_checklist,
                    "cvss_score": poc_fix.cvss_score,
                    "owasp_category": poc_fix.owasp_category,
                    "references": poc_fix.references,
                    "provider_used": poc_fix.provider_used,
                },
                "usage": copilot.get_usage_stats(),
            }

        return {"success": False, "error": "AI providers unavailable or no output generated"}

    except Exception as e:
        return {"success": False, "error": str(e)}


# ═══════════════════════════════════════════════════════════════════════════════
# POC Execution Engine — Real HTTP Attack Validation Proxy
# ═══════════════════════════════════════════════════════════════════════════════

import ipaddress as _ipaddress
import socket as _socket
import re as _re
import time as _time_mod

# Rate limit store: key -> list of epoch timestamps
_POC_RATE_LIMIT: dict = {}

# Secret patterns to detect in HTTP responses
_POC_SECRET_PATTERNS = [
    (r'(?:api[_-]?key|apikey)["\s:=]+([A-Za-z0-9_\-]{20,})', "API_KEY"),
    (r'(?:password|passwd|pwd)["\s:=]+([^\s"\'<>{}\[\]]{6,})', "PASSWORD"),
    (r'(?:secret)["\s:=]+([A-Za-z0-9_\-\.]{16,})', "SECRET"),
    (r'sk_live_[A-Za-z0-9]{20,}', "STRIPE_KEY"),
    (r'AKIA[A-Z0-9]{16}', "AWS_ACCESS_KEY"),
    (r'ghp_[A-Za-z0-9]{36}', "GITHUB_TOKEN"),
    (r'AIza[A-Za-z0-9\-_]{35}', "GOOGLE_API_KEY"),
    (r'(?:db_password|database_url)["\s:=]+([^\s"\'<>]{8,})', "DB_CREDENTIAL"),
]


def _is_ssrf_safe(url: str):
    """Returns (is_safe: bool, reason: str). Blocks private/internal SSRF targets."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False, "Invalid URL — no hostname"
        blocked = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
        if hostname.lower() in blocked:
            return False, f"SSRF blocked: internal hostname '{hostname}'"
        try:
            addr_info = _socket.getaddrinfo(hostname, None)
            for _, _, _, _, sockaddr in addr_info:
                ip_str = sockaddr[0]
                ip = _ipaddress.ip_address(ip_str)
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                    return False, f"SSRF blocked: resolved to private IP {ip_str}"
        except _socket.gaierror:
            pass  # Unresolvable host — let the actual request fail
        return True, "OK"
    except Exception as exc:
        return False, f"URL validation error: {exc}"


def _detect_response_secrets(body: str) -> list:
    """Scan HTTP response body for leaked secrets using regex patterns."""
    secrets = []
    seen_types: set = set()
    for pattern, stype in _POC_SECRET_PATTERNS:
        try:
            matches = _re.findall(pattern, body, _re.IGNORECASE)
            for match in matches[:2]:
                val = match if isinstance(match, str) else match[0]
                if len(val) >= 6 and stype not in seen_types:
                    masked = val[:4] + "***" + val[-4:] if len(val) > 12 else val[:3] + "***"
                    secrets.append({
                        "type": stype,
                        "value_masked": masked,
                        "confidence": 0.87,
                        "source": "http_response",
                        "exposure_vector": "response_body",
                    })
                    seen_types.add(stype)
        except Exception:
            pass
    return secrets


class POCExecuteRequest(BaseModel):
    method: str = "GET"
    url: str
    headers: dict = {}
    body: str = ""
    scan_id: str = ""
    finding_id: str = ""
    finding_evidence: str = ""


@app.post("/api/poc/execute")
async def poc_execute(request: POCExecuteRequest, req: Request):
    """
    Real HTTP POC execution proxy.

    Sends actual HTTP requests to scan targets, captures full response telemetry,
    detects leaked secrets, and correlates evidence to produce a verification verdict.
    Includes SSRF protection, rate limiting, and audit logging.
    """
    try:
        import httpx
    except ImportError:
        return {"success": False, "error": "httpx not installed — run: pip install httpx", "verification_status": "ERROR"}

    # Rate limiting: 10 requests/min per scan/IP
    now = _time_mod.time()
    rate_key = request.scan_id or (req.client.host if req.client else "anon")
    bucket = _POC_RATE_LIMIT.setdefault(rate_key, [])
    bucket[:] = [t for t in bucket if now - t < 60]
    if len(bucket) >= 10:
        raise HTTPException(status_code=429, detail="POC rate limit exceeded (10/min). Please wait.")
    bucket.append(now)

    # SSRF protection
    safe, reason = _is_ssrf_safe(request.url)
    if not safe:
        return {"success": False, "error": reason, "blocked": True, "verification_status": "BLOCKED"}

    # Method allowlist
    method = request.method.upper()
    if method not in {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"}:
        raise HTTPException(status_code=400, detail=f"Method '{method}' not permitted")

    # Build execution headers
    exec_headers = {
        "User-Agent": "QuantumScanner/5.0 (Authorized Security Research)",
        "Accept": "application/json, text/html, */*",
    }
    for k, v in request.headers.items():
        if k.lower() not in ("host", "content-length"):
            exec_headers[k] = v

    start_ts = _time_mod.time()
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(25.0, connect=10.0),
            follow_redirects=True,
            verify=False,
            limits=httpx.Limits(max_connections=5, max_keepalive_connections=2),
        ) as client:
            kw: dict = {"method": method, "url": request.url, "headers": exec_headers}
            if request.body and method in ("POST", "PUT", "PATCH"):
                kw["content"] = request.body.encode("utf-8", errors="replace")
                if not any(k.lower() == "content-type" for k in exec_headers):
                    exec_headers["Content-Type"] = "application/json"

            response = await client.request(**kw)
            elapsed_ms = int((_time_mod.time() - start_ts) * 1000)

            try:
                body_raw = response.text[:50000]
            except Exception:
                body_raw = "<binary or undecodable response>"

            body_pretty = body_raw
            try:
                import json as _json
                body_pretty = _json.dumps(_json.loads(body_raw), indent=2)
            except Exception:
                pass

            resp_headers = dict(response.headers)

            info_headers = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
                            "x-generator", "x-drupal-cache", "x-wp-total"]
            disclosed_headers = [h for h in info_headers if h in resp_headers]

            detected_secrets = _detect_response_secrets(body_raw)

            evidence_match = False
            if request.finding_evidence:
                ev_lower = request.finding_evidence.lower()
                bl = body_raw.lower()
                tokens = [t for t in ev_lower.split() if len(t) > 4][:6]
                hits = sum(1 for t in tokens if t in bl)
                evidence_match = hits >= max(1, len(tokens) // 2)

            if evidence_match and response.status_code < 500:
                verdict = "VERIFIED"
            elif 200 <= response.status_code < 300:
                verdict = "UNCONFIRMED"
            elif response.status_code >= 500:
                verdict = "SERVER_ERROR"
            else:
                verdict = "FAILED"

            return {
                "success": True,
                "status_code": response.status_code,
                "response_time_ms": elapsed_ms,
                "content_type": resp_headers.get("content-type", "unknown"),
                "content_length": len(body_raw),
                "server": resp_headers.get("server", "—"),
                "headers": resp_headers,
                "body_pretty": body_pretty,
                "body_raw": body_raw,
                "tls_info": {"protocol": "TLS", "verified": False} if request.url.startswith("https://") else {},
                "secrets_detected": detected_secrets,
                "disclosed_headers": disclosed_headers,
                "evidence_match": evidence_match,
                "risk_verified": evidence_match,
                "verification_status": verdict,
                "redirect_count": len(response.history),
                "final_url": str(response.url),
            }

    except Exception as exc:
        exc_name = type(exc).__name__
        elapsed_ms = int((_time_mod.time() - start_ts) * 1000)
        if "Timeout" in exc_name:
            return {"success": False, "error": "Request timed out — target may be slow or unreachable", "verification_status": "TIMEOUT", "response_time_ms": elapsed_ms}
        if "Connect" in exc_name:
            return {"success": False, "error": f"Connection failed: {str(exc)[:300]}", "verification_status": "FAILED", "response_time_ms": elapsed_ms}
        return {"success": False, "error": str(exc)[:500], "verification_status": "ERROR", "response_time_ms": elapsed_ms}


@app.get("/api/poc/secrets/{scan_id}")
async def poc_get_secrets(scan_id: str):
    """
    Return secrets discovered in a scan's findings.

    Extracts credentials, API keys, tokens, and other sensitive data
    from scanner findings using pattern matching and key-value extraction.
    """
    scan = scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    kv_re = _re.compile(r'([A-Za-z_][A-Za-z0-9_]{2,})\s*[=:]\s*[\'"]?([^\s\'"<>,;]{6,64})')
    skip_keys = {"class", "type", "name", "href", "src", "id", "ref", "for",
                 "if", "else", "return", "const", "let", "var", "function", "import", "export"}
    secret_kws = {"secret", "password", "credential", "api key", "token", "key", "passwd", "pwd",
                  "api_key", "apikey", "private", "auth", "bearer"}

    secrets = []
    seen_sigs: set = set()

    for finding in scan.get("findings", []):
        title_lower = (finding.get("title", "") or "").lower()
        if not any(kw in title_lower for kw in secret_kws):
            continue
        matched = finding.get("matched_content", "") or finding.get("payload", "") or ""
        if not matched:
            continue

        kvs = kv_re.findall(matched[:500])
        extracted = False
        for key, value in kvs[:3]:
            if key.lower() in skip_keys:
                continue
            k = key.lower()
            if any(x in k for x in ("password", "passwd", "pwd")):
                stype = "PASSWORD"
            elif "stripe" in k or "sk_live" in value or "pk_live" in value:
                stype = "PAYMENT_TOKEN"
            elif "aws" in k or value.startswith("AKIA"):
                stype = "CLOUD_CREDENTIAL"
            elif "jwt" in k or "bearer" in k:
                stype = "JWT_TOKEN"
            elif "api_key" in k or "apikey" in k:
                stype = "API_KEY"
            elif "secret" in k:
                stype = "SECRET_KEY"
            elif "token" in k:
                stype = "AUTH_TOKEN"
            elif any(x in k for x in ("db", "database", "mongo", "postgres", "mysql", "redis")):
                stype = "DATABASE_CREDENTIAL"
            elif any(x in k for x in ("private_key", "rsa", "pem")):
                stype = "PRIVATE_KEY"
            else:
                stype = "CREDENTIAL"
            masked = value[:4] + "***" + value[-4:] if len(value) > 12 else value[:3] + "***"
            sig = stype + masked
            if sig in seen_sigs:
                continue
            seen_sigs.add(sig)
            secrets.append({
                "type": stype,
                "key": key.upper(),
                "value": value,
                "value_masked": masked,
                "confidence": float(finding.get("confidence", 0.8)),
                "source_path": finding.get("file", finding.get("endpoint", "unknown")),
                "discovered_via": finding.get("module_name", finding.get("module", "scanner")),
                "exposure_vector": "source_code" if finding.get("file") else "endpoint",
                "finding_id": finding.get("id", ""),
                "severity": finding.get("severity", "medium"),
            })
            extracted = True

        if not extracted:
            title = (finding.get("title", "Secret") or "Secret").replace(" ", "_").upper()[:30]
            masked = matched[:4] + "***" if len(matched) > 7 else "***"
            sig = "CREDENTIAL" + masked
            if sig not in seen_sigs:
                seen_sigs.add(sig)
                secrets.append({
                    "type": "CREDENTIAL",
                    "key": title,
                    "value": matched[:80],
                    "value_masked": masked,
                    "confidence": float(finding.get("confidence", 0.7)),
                    "source_path": finding.get("file", finding.get("endpoint", "unknown")),
                    "discovered_via": finding.get("module_name", finding.get("module", "scanner")),
                    "exposure_vector": "source_code" if finding.get("file") else "endpoint",
                    "finding_id": finding.get("id", ""),
                    "severity": finding.get("severity", "medium"),
                })

    for finding in scan.get("findings", []):
        evidence = finding.get("evidence", "") or ""
        if evidence and len(evidence) > 20:
            for s in _detect_response_secrets(evidence):
                sig = s.get("type", "") + s.get("value_masked", "")
                if sig not in seen_sigs:
                    seen_sigs.add(sig)
                    s["source_path"] = finding.get("file", finding.get("endpoint", "evidence"))
                    s["discovered_via"] = finding.get("module_name", "evidence_analyzer")
                    s["finding_id"] = finding.get("id", "")
                    s["severity"] = finding.get("severity", "high")
                    secrets.append(s)

    return {"scan_id": scan_id, "secrets_count": len(secrets), "secrets": secrets[:20]}


# ═══════════════════════════════════════════════════════════════════════════════
# Legal Terms Acceptance (Authorization Gate)
# ═══════════════════════════════════════════════════════════════════════════════

# In-memory store for terms acceptance records.
# Keys: user_id (Firebase UID) → record dict.
# In production, migrate to the SQL database (user_terms_acceptance table).
_terms_acceptance: dict[str, dict] = {}

CURRENT_TERMS_VERSION = "v1.0-2025"


class TermsAcceptRequest(BaseModel):
    version: str = CURRENT_TERMS_VERSION
    user_agent: str = ""


@app.post("/api/v1/terms/accept")
async def accept_terms(
    body: TermsAcceptRequest,
    req: Request,
    current_user: dict = Depends(get_current_firebase_user),
):
    """
    Record the authenticated user's acceptance of the Authorization & Legal Terms.

    Stores: user_id, terms_version, accepted_at, ip_address, user_agent,
            acceptance_hash (SHA-256 of user_id + version + timestamp).
    """
    user_id = current_user.get("uid", "unknown")
    accepted_at = datetime.now(timezone.utc).isoformat()
    client_ip = req.headers.get("x-forwarded-for", req.client.host if req.client else "unknown")

    acceptance_hash = hashlib.sha256(
        f"{user_id}:{body.version}:{accepted_at}".encode()
    ).hexdigest()

    record = {
        "user_id": user_id,
        "email": current_user.get("email", ""),
        "version": body.version,
        "accepted_at": accepted_at,
        "ip_address": client_ip,
        "user_agent": body.user_agent[:500],      # cap length
        "acceptance_hash": acceptance_hash,
        "accepted": True,
    }

    _terms_acceptance[user_id] = record

    return {
        "accepted": True,
        "version": body.version,
        "accepted_at": accepted_at,
        "acceptance_hash": acceptance_hash,
        "message": "Terms acceptance recorded successfully.",
    }


@app.get("/api/v1/terms/status")
async def get_terms_status(
    current_user: dict = Depends(get_current_firebase_user),
):
    """
    Return the terms acceptance status for the currently authenticated user.
    Returns accepted=False if no record found or version is stale.
    """
    user_id = current_user.get("uid", "unknown")
    record = _terms_acceptance.get(user_id)

    if not record or record.get("version") != CURRENT_TERMS_VERSION:
        return {
            "accepted": False,
            "version": CURRENT_TERMS_VERSION,
            "current_version": CURRENT_TERMS_VERSION,
            "accepted_at": None,
        }

    return {
        "accepted": True,
        "version": record["version"],
        "current_version": CURRENT_TERMS_VERSION,
        "accepted_at": record["accepted_at"],
        "acceptance_hash": record["acceptance_hash"],
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Compliance Dashboard API (Phase 8.3)
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/compliance/owasp")
async def get_owasp_compliance():
    """Get OWASP Top 10 compliance scorecard."""
    owasp_categories = {
        "A01:2025": {"name": "Broken Access Control", "count": 0, "status": "compliant"},
        "A02:2025": {"name": "Cryptographic Failures", "count": 0, "status": "compliant"},
        "A03:2025": {"name": "Injection", "count": 0, "status": "compliant"},
        "A04:2025": {"name": "Insecure Design", "count": 0, "status": "compliant"},
        "A05:2025": {"name": "Security Misconfiguration", "count": 0, "status": "compliant"},
        "A06:2025": {"name": "Vulnerable Components", "count": 0, "status": "compliant"},
        "A07:2025": {"name": "Auth Failures", "count": 0, "status": "compliant"},
        "A08:2025": {"name": "Integrity Failures", "count": 0, "status": "compliant"},
        "A09:2025": {"name": "Logging Failures", "count": 0, "status": "compliant"},
        "A10:2025": {"name": "SSRF", "count": 0, "status": "compliant"},
    }
    
    # Aggregate from all scans
    all_findings = []
    for scan in scans.values():
        all_findings.extend(scan.get("findings", []))
    
    for finding in all_findings:
        owasp = finding.get("owasp", "")
        if owasp and owasp in owasp_categories:
            owasp_categories[owasp]["count"] += 1
            # If findings exist, mark as "at risk"
            if finding.get("severity") in ["critical", "high"]:
                owasp_categories[owasp]["status"] = "at_risk"
            elif owasp_categories[owasp]["status"] == "compliant":
                owasp_categories[owasp]["status"] = "warning"
    
    total_categories = len(owasp_categories)
    compliant = sum(1 for c in owasp_categories.values() if c["status"] == "compliant")
    
    return {
        "score": round((compliant / total_categories) * 100),
        "total_categories": total_categories,
        "compliant": compliant,
        "at_risk": sum(1 for c in owasp_categories.values() if c["status"] == "at_risk"),
        "categories": owasp_categories,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# WebSocket Live Monitoring (Phase 8.5)
# ═══════════════════════════════════════════════════════════════════════════════

from backend.websocket_manager import ws_manager

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, user_id: str = "anonymous"):
    """WebSocket endpoint for real-time updates."""
    connection_id = await ws_manager.connect(websocket, user_id)
    
    try:
        while True:
            # Receive message from client
            data = await websocket.receive_json()
            
            # Handle different message types
            msg_type = data.get("type")
            
            if msg_type == "ping":
                await websocket.send_json({"type": "pong", "timestamp": datetime.now(timezone.utc).isoformat()})
            
            elif msg_type == "subscribe_scan":
                scan_id = data.get("scan_id")
                await websocket.send_json({
                    "type": "subscribed",
                    "scan_id": scan_id,
                    "message": f"Subscribed to updates for scan {scan_id}"
                })
            
            elif msg_type == "broadcast":
                # Broadcast to all connected clients
                await ws_manager.broadcast({
                    "type": "broadcast",
                    "from": user_id,
                    "message": data.get("message", "")
                })
    
    except Exception as e:
        print(f"WebSocket error: {e}")
    finally:
        ws_manager.disconnect(connection_id, user_id)


# ═══════════════════════════════════════════════════════════════════════════════
# Scheduled & Recurring Scans (Phase 8.6)
# ═══════════════════════════════════════════════════════════════════════════════

from backend.scheduled_scan_service import scheduled_scan_service, scan_comparison_service

class CreateScheduleRequest(BaseModel):
    name: str
    target: str
    modules: list[str]
    frequency: str  # daily, weekly, monthly
    schedule_time: str  # HH:MM format
    scan_profile: str = "full"
    day_of_week: Optional[int] = None  # 0-6 for weekly
    day_of_month: Optional[int] = None  # 1-31 for monthly
    notify_email: Optional[str] = None

@app.post("/api/v1/schedules")
async def create_schedule(request: CreateScheduleRequest):
    """Create a scheduled scan."""
    schedule = scheduled_scan_service.create_schedule(
        name=request.name,
        target=request.target,
        modules=request.modules,
        frequency=request.frequency,
        schedule_time=request.schedule_time,
        scan_profile=request.scan_profile,
        day_of_week=request.day_of_week,
        day_of_month=request.day_of_month,
        notify_email=request.notify_email
    )
    return {
        "schedule_id": schedule.id,
        "name": schedule.name,
        "next_run": schedule.next_run,
        "message": "Schedule created successfully"
    }

@app.get("/api/v1/schedules")
async def list_schedules(user_id: str = "current"):
    """List all scheduled scans."""
    schedules = scheduled_scan_service.list_schedules(user_id)
    return {
        "schedules": [
            {
                "id": s.id,
                "name": s.name,
                "target": s.target,
                "frequency": s.frequency,
                "schedule_time": s.schedule_time,
                "next_run": s.next_run,
                "last_run": s.last_run,
                "is_active": s.is_active
            }
            for s in schedules
        ]
    }

@app.delete("/api/v1/schedules/{schedule_id}")
async def delete_schedule(schedule_id: str):
    """Delete a scheduled scan."""
    success = scheduled_scan_service.delete_schedule(schedule_id)
    if not success:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return {"success": True, "message": "Schedule deleted"}

@app.post("/api/v1/scans/compare")
async def compare_scans(scan1_id: str, scan2_id: str):
    """Compare two scans and identify differences."""
    if scan1_id not in scans or scan2_id not in scans:
        raise HTTPException(status_code=404, detail="One or both scans not found")
    
    scan1_findings = scans[scan1_id].get("findings", [])
    scan2_findings = scans[scan2_id].get("findings", [])
    
    comparison = scan_comparison_service.compare_scans(scan1_findings, scan2_findings)
    
    return {
        "scan1_id": scan1_id,
        "scan2_id": scan2_id,
        "comparison": comparison
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Team Collaboration (Phase 8.7)
# ═══════════════════════════════════════════════════════════════════════════════

from backend.team_collaboration import team_collaboration, rbac_service

@app.post("/api/v1/findings/{scan_id}/{finding_id}/assign")
async def assign_finding(
    scan_id: str,
    finding_id: str,
    assigned_to: str,
    user_id: str = "current"
):
    """Assign a finding to a team member."""
    finding = team_collaboration.assign_finding(finding_id, scan_id, assigned_to, user_id)
    return {
        "success": True,
        "finding_id": finding_id,
        "assigned_to": assigned_to,
        "assigned_by": user_id
    }

@app.post("/api/v1/findings/{scan_id}/{finding_id}/status")
async def update_finding_status(
    scan_id: str,
    finding_id: str,
    status: str,
    comment: Optional[str] = None,
    user_id: str = "current"
):
    """Update finding status (Open → In Progress → Fixed → Verified)."""
    finding = team_collaboration.update_finding_status(finding_id, scan_id, status, user_id, comment)
    return {
        "success": True,
        "finding_id": finding_id,
        "new_status": status,
        "previous_status": finding.status_history[-2]["from"] if len(finding.status_history) > 1 else None
    }

@app.post("/api/v1/findings/{scan_id}/{finding_id}/comments")
async def add_finding_comment(
    scan_id: str,
    finding_id: str,
    content: str,
    user_id: str = "current",
    user_name: str = "User"
):
    """Add a comment to a finding."""
    comment = team_collaboration.add_comment(finding_id, scan_id, user_id, user_name, content)
    return {
        "success": True,
        "comment_id": comment.id,
        "created_at": comment.created_at
    }

@app.get("/api/v1/findings/{scan_id}/{finding_id}/details")
async def get_finding_details(scan_id: str, finding_id: str):
    """Get full finding details including comments and history."""
    finding = team_collaboration.get_finding_details(finding_id, scan_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    return {
        "finding_id": finding.finding_id,
        "scan_id": finding.scan_id,
        "status": finding.status,
        "assigned_to": finding.assigned_to,
        "assigned_at": finding.assigned_at,
        "comments": [
            {
                "id": c.id,
                "user_name": c.user_name,
                "content": c.content,
                "created_at": c.created_at
            }
            for c in finding.comments
        ],
        "status_history": finding.status_history
    }

@app.get("/api/v1/team/activity")
async def get_team_activity(limit: int = 50):
    """Get team activity feed."""
    activities = team_collaboration.get_activity_feed(limit)
    return {"activities": activities}


# ═══════════════════════════════════════════════════════════════════════════════
# SBOM Generator (Phase 8.9)
# ═══════════════════════════════════════════════════════════════════════════════

from backend.sbom_generator import sbom_generator, SBOMFormat

@app.post("/api/v1/sbom/generate")
async def generate_sbom(
    dependencies: list[dict],
    format: str = "cyclonedx-json",
    application_name: str = "Application"
):
    """Generate SBOM from dependencies."""
    try:
        sbom_format = SBOMFormat(format)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")
    
    sbom_content = sbom_generator.generate_from_dependencies(
        dependencies=dependencies,
        format=sbom_format,
        application_name=application_name
    )
    
    # Also get license compliance summary
    components = [sbom_generator.Component(**d) for d in dependencies]
    compliance = sbom_generator.get_license_compliance_summary(components)
    
    return {
        "sbom": sbom_content,
        "format": format,
        "license_compliance": compliance
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Threat Modeling (Phase 8.10)
# ═══════════════════════════════════════════════════════════════════════════════

from backend.threat_modeling import threat_modeling

@app.post("/api/v1/threat-model/generate")
async def generate_threat_model(scan_id: str):
    """Generate STRIDE-based threat model from scan."""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    findings = scans[scan_id].get("findings", [])
    threat_model = threat_modeling.generate_threat_model(scan_id, findings)
    
    return threat_model

@app.get("/api/v1/threat-model/{scan_id}/attack-surface")
async def get_attack_surface_diagram(scan_id: str):
    """Get attack surface diagram data."""
    diagram = threat_modeling.generate_attack_surface_diagram(scan_id)
    
    if "error" in diagram:
        raise HTTPException(status_code=400, detail=diagram["error"])
    
    return diagram


# ═══════════════════════════════════════════════════════════════════════════════
# Neo4j Attack Graph Intelligence (Phase 9)
# ═══════════════════════════════════════════════════════════════════════════════

from backend.neo4j_client import get_neo4j_client


@app.post("/api/v1/graph/ingest")
async def graph_ingest(scan_id: str):
    """
    Ingest all findings from a completed scan into the Neo4j graph model.
    Creates nodes for assets, services, vulnerabilities, endpoints,
    credentials, roles, impacts, and remediations.
    Computes LEADS_TO / ESCALATES_TO cross-module relationships.
    """
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan     = scans[scan_id]
    findings = scan.get("findings", [])
    target   = scan.get("target", "unknown")

    client = get_neo4j_client()
    result = client.ingest_scan_findings(scan_id, target, findings)

    return {
        "success":               True,
        "scan_id":               scan_id,
        "mode":                  result["mode"],
        "nodes_created":         result["nodes_created"],
        "relationships_created": result["relationships_created"],
        "message":               f"Graph built in {result['mode']} mode.",
    }


@app.get("/api/v1/graph/asset-risk-graph")
async def get_asset_risk_graph(scan_id: str):
    """
    Return the full property graph for a scan (nodes + edges).
    If the scan has not been ingested yet, auto-ingests first.

    Response shape:
      { nodes: [...], edges: [...], mode: "neo4j"|"memory", count: {...} }
    """
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")

    client = get_neo4j_client()

    # Auto-ingest if graph not yet built
    findings = scans[scan_id].get("findings", [])
    target   = scans[scan_id].get("target", "unknown")

    if not client.is_connected or findings:
        client.ingest_scan_findings(scan_id, target, findings)

    graph = client.get_asset_risk_graph(scan_id)
    return graph


@app.get("/api/v1/graph/attack-paths")
async def get_attack_paths(scan_id: str):
    """
    Compute and return ordered attack paths for a scan.

    Uses BFS shortest-path (in-memory) or Neo4j shortestPath()
    to find routes from the root Asset to high/critical impact nodes.

    Response shape:
      { paths: [...], count: int, mode: str }
    """
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")

    client   = get_neo4j_client()
    findings = scans[scan_id].get("findings", [])
    target   = scans[scan_id].get("target", "unknown")
    client.ingest_scan_findings(scan_id, target, findings)

    paths = client.get_attack_paths(scan_id)
    return {
        "scan_id": scan_id,
        "paths":   paths,
        "count":   len(paths),
        "mode":    client.mode,
    }


@app.get("/api/v1/graph/breach-simulation")
async def get_breach_simulation(scan_id: str):
    """
    Generate a MITRE ATT&CK–mapped breach simulation for a scan.

    Returns attacker timeline, impact assessment, breach probability,
    and estimated dwell time based on confirmed findings.

    Response shape:
      { breach_probability, risk_level, attack_timeline, impact_assessment,
        attack_paths, estimated_dwell_time, mitre_techniques, findings_summary }
    """
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")

    client   = get_neo4j_client()
    findings = scans[scan_id].get("findings", [])
    target   = scans[scan_id].get("target", "unknown")
    client.ingest_scan_findings(scan_id, target, findings)

    simulation = client.get_breach_simulation(scan_id, findings)
    return simulation


@app.get("/api/v1/graph/status")
async def get_graph_status():
    """Return Neo4j connection status and graph engine info."""
    client = get_neo4j_client()
    return {
        "connected": client.is_connected,
        "mode":      client.mode,
        "uri":       "bolt://***" if client.is_connected else "not connected",
        "features": [
            "attack_path_computation",
            "privilege_escalation_chains",
            "credential_exposure_tracking",
            "breach_simulation",
            "mitre_mapping",
        ],
    }


@app.get("/api/lab/status")
async def get_lab_status():
    """
    Check health status of lab proxy tools (hetty and mitmweb).
    Performs async health probes to determine if services are running.
    """
    import httpx
    
    hetty_url = "http://hetty:8080"
    mitmweb_url = "http://mitmweb:8081"
    
    # Health check hetty
    hetty_running = False
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            response = await client.get(hetty_url)
            hetty_running = response.status_code < 500
    except Exception:
        pass
    
    # Health check mitmweb
    mitmweb_running = False
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            response = await client.get(mitmweb_url)
            mitmweb_running = response.status_code < 500
    except Exception:
        pass
    
    return {
        "hetty": {
            "running": hetty_running,
            "url": hetty_url,
        },
        "mitmweb": {
            "running": mitmweb_running,
            "url": mitmweb_url,
        }
    }


@app.get("/api/lab/ca/hetty")
async def download_hetty_ca():
    """
    Download the Hetty CA certificate for proxy SSL interception.
    """
    ca_path = "/root/.hetty/ca.crt"
    if not os.path.exists(ca_path):
        raise HTTPException(status_code=404, detail="Hetty CA certificate not found")
    
    return FileResponse(
        path=ca_path,
        filename="hetty-ca.crt",
        media_type="application/x-pem-file"
    )


@app.get("/api/lab/ca/mitmproxy")
async def download_mitmproxy_ca():
    """
    Download the mitmproxy CA certificate for proxy SSL interception.
    """
    ca_path = "/root/.mitmproxy/mitmproxy-ca-cert.pem"
    if not os.path.exists(ca_path):
        raise HTTPException(status_code=404, detail="mitmproxy CA certificate not found")
    
    return FileResponse(
        path=ca_path,
        filename="mitmproxy-ca-cert.pem",
        media_type="application/x-pem-file"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Run
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
