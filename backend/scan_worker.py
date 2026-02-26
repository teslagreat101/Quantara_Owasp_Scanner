"""
Asynchronous Scan Job Queue (User-Centric)
Refactored to remove all Multi-Tenancy (Tenant) logic.
Each job is now directly associated with a User.
"""

import os
import sys
import uuid
import json
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List, Callable
from pathlib import Path

from celery import Celery
from celery.signals import task_prerun, task_postrun, task_failure
from sqlalchemy.orm import Session

from backend.database import (
    get_db_session, ScanJob, ScanJobStatus, User, Scan,
    ScanStatus, Finding, Base
)

# Make scanner modules importable from within the Celery worker
_PARENT_DIR = str(Path(__file__).resolve().parent.parent)
_CENTRAL_DIR = os.path.join(_PARENT_DIR, "Centralize_Scanners")
for _p in [_PARENT_DIR, _CENTRAL_DIR]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    from scanner_engine.orchestrator import run_module_scan, normalize_finding_to_dict, UNIFIED_MODULE_REGISTRY
    _SCANNER_AVAILABLE = True
except ImportError as _e:
    print(f"scan_worker: scanner_engine import failed: {_e}")
    _SCANNER_AVAILABLE = False

# ═══════════════════════════════════════════════════════════════════════════════
# Celery Configuration
# ═══════════════════════════════════════════════════════════════════════════════

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery(
    "quantum_scanner",
    broker=REDIS_URL,
    backend=REDIS_URL
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,
)

# ═══════════════════════════════════════════════════════════════════════════════
# Task Definitions
# ═══════════════════════════════════════════════════════════════════════════════

@celery_app.task(bind=True, max_retries=3)
def execute_scan_job(self, job_id: str):
    db = get_db_session()
    try:
        job = db.query(ScanJob).filter(ScanJob.job_id == job_id).first()
        if not job: raise ValueError(f"Job {job_id} not found")
        
        job.status = ScanJobStatus.RUNNING
        job.worker_id = self.request.hostname
        job.started_at = datetime.now(timezone.utc)
        db.commit()
        
        # Create scan record linked to user
        scan = Scan(
            scan_id=str(uuid.uuid4()),
            user_id=job.user_id,
            target=job.target,
            scan_type=job.scan_type,
            modules=job.modules,
            status="running",
        )
        db.add(scan)
        db.commit()
        
        job.scan_id = scan.scan_id
        db.commit()
        
        # Execute scan
        result = _run_scan(scan, job, db)
        
        job.status = ScanJobStatus.COMPLETED
        job.completed_at = datetime.now(timezone.utc)
        job.result_data = result
        db.commit()
        
        return result
    
    except Exception as exc:
        job = db.query(ScanJob).filter(ScanJob.job_id == job_id).first()
        if job:
            job.status = ScanJobStatus.FAILED
            job.error_message = str(exc)
            job.retry_count += 1
            db.commit()
            if job.retry_count < 3:
                raise self.retry(exc=exc, countdown=60)
        raise exc
    finally:
        db.close()

# ═══════════════════════════════════════════════════════════════════════════════
# Execution Logic
# ═══════════════════════════════════════════════════════════════════════════════

def _run_scan(scan: Scan, job: ScanJob, db: Session) -> Dict[str, Any]:
    """Run the actual scan using the unified scanner engine."""
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    total_findings = 0

    if not _SCANNER_AVAILABLE:
        scan.progress = 100
        scan.status = "completed"
        scan.total_findings = 0
        scan.severity_counts = severity_counts
        scan.completed_at = datetime.now(timezone.utc)
        db.commit()
        return {"scan_id": scan.scan_id, "status": "completed", "findings": 0, "error": "scanner_engine unavailable"}

    modules = job.modules or list(UNIFIED_MODULE_REGISTRY.keys())
    valid_modules = [m for m in modules if m in UNIFIED_MODULE_REGISTRY]
    total_modules = len(valid_modules)

    for idx, module_key in enumerate(valid_modules):
        try:
            findings = run_module_scan(module_key, scan.target, scan.scan_type)
            for raw in findings:
                normalized = normalize_finding_to_dict(raw, module_key)
                try:
                    new_finding = Finding(
                        scan_id=scan.scan_id,
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
                    )
                    db.add(new_finding)
                    db.commit()
                except Exception as e:
                    db.rollback()
                    print(f"scan_worker: DB persist error for finding: {e}")

                sev = normalized.get("severity", "info").lower()
                if sev in severity_counts:
                    severity_counts[sev] += 1
                total_findings += 1

        except Exception as e:
            print(f"scan_worker: module {module_key} error: {e}")

        # Update progress in DB
        progress = int(((idx + 1) / max(total_modules, 1)) * 100)
        try:
            scan.progress = progress
            scan.modules_completed = idx + 1
            db.commit()
        except Exception:
            db.rollback()

    scan.progress = 100
    scan.status = "completed"
    scan.total_findings = total_findings
    scan.severity_counts = severity_counts
    scan.completed_at = datetime.now(timezone.utc)
    db.commit()

    return {
        "scan_id": scan.scan_id,
        "status": "completed",
        "findings": total_findings,
        "severity_counts": severity_counts,
    }

# ═══════════════════════════════════════════════════════════════════════════════
# Job Management
# ═══════════════════════════════════════════════════════════════════════════════

def queue_scan_job(
    db: Session,
    user_id: str,
    target: str,
    scan_type: str,
    modules: List[str],
    priority: int = 5
) -> ScanJob:
    job_id = str(uuid.uuid4())
    job = ScanJob(
        job_id=job_id,
        user_id=user_id,
        target=target,
        scan_type=scan_type,
        modules=modules,
        priority=priority,
        status=ScanJobStatus.QUEUED,
        queued_at=datetime.now(timezone.utc),
    )
    db.add(job)
    db.commit()
    
    execute_scan_job.apply_async(args=[job_id], priority=priority)
    return job

def cancel_job(db: Session, job_id: str) -> bool:
    job = db.query(ScanJob).filter(ScanJob.job_id == job_id).first()
    if not job or job.status not in [ScanJobStatus.PENDING, ScanJobStatus.QUEUED]:
        return False
    
    celery_app.control.revoke(job_id, terminate=True)
    job.status = ScanJobStatus.CANCELLED
    db.commit()
    return True
