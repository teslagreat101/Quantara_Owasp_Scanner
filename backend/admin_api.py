"""
Admin Dashboard API (Direct User Model)
Super admin endpoints for platform management.
Removed all Multi-Tenancy / Tenant isolation logic.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status, Request
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.database import (
    get_db, get_db_session, User, Scan, Finding, ScanJob,
    SecurityEvent, APIToken,
    SubscriptionTier, SubscriptionStatus, seed_super_admin
)
from backend.auth import require_super_admin, SUPER_ADMIN_EMAIL, get_password_hash
from backend.billing import get_subscription, create_checkout_session, TIER_CONFIG

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])

# ═══════════════════════════════════════════════════════════════════════════════
# Pydantic Models
# ═══════════════════════════════════════════════════════════════════════════════

class DashboardStats(BaseModel):
    total_users: int
    active_users: int
    users_this_month: int
    total_scans: int
    scans_today: int
    revenue_this_month: float
    security_events_24h: int

class UserUpdateRequest(BaseModel):
    is_active: Optional[bool] = None
    is_admin: Optional[bool] = None
    role: Optional[str] = None
    full_name: Optional[str] = None
    subscription_tier: Optional[SubscriptionTier] = None
    subscription_status: Optional[SubscriptionStatus] = None

class SubscriptionOverrideRequest(BaseModel):
    tier: SubscriptionTier
    scan_limit: Optional[int] = None
    reason: str

# ═══════════════════════════════════════════════════════════════════════════════
# Startup
# ═══════════════════════════════════════════════════════════════════════════════

@router.on_event("startup")
async def init_super_admin():
    db = get_db_session()
    try:
        seed_super_admin(db, SUPER_ADMIN_EMAIL)
    finally:
        db.close()

# ═══════════════════════════════════════════════════════════════════════════════
# Dashboard Overview
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    db: Session = Depends(get_db),
    admin: User = Depends(require_super_admin)
):
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    month_start = today_start.replace(day=1)
    
    total_users = db.query(func.count(User.id)).scalar() or 0
    active_users = db.query(func.count(User.id)).filter(User.is_active == True).scalar() or 0
    users_this_month = db.query(func.count(User.id)).filter(User.created_at >= month_start).scalar() or 0
    
    total_scans = db.query(func.count(Scan.id)).scalar() or 0
    scans_today = db.query(func.count(Scan.id)).filter(Scan.created_at >= today_start).scalar() or 0
    
    # Calculate revenue based on active subscriptions
    pro_users = db.query(func.count(User.id)).filter(
        User.subscription_tier == SubscriptionTier.PRO,
        User.subscription_status == SubscriptionStatus.ACTIVE
    ).scalar() or 0
    
    enterprise_users = db.query(func.count(User.id)).filter(
        User.subscription_tier == SubscriptionTier.ENTERPRISE,
        User.subscription_status == SubscriptionStatus.ACTIVE
    ).scalar() or 0
    
    revenue = (pro_users * TIER_CONFIG[SubscriptionTier.PRO]["price_monthly"]) + \
              (enterprise_users * TIER_CONFIG[SubscriptionTier.ENTERPRISE]["price_monthly"])
    
    security_events = db.query(func.count(SecurityEvent.id)).filter(
        SecurityEvent.created_at >= (now - timedelta(hours=24))
    ).scalar() or 0
    
    return DashboardStats(
        total_users=total_users,
        active_users=active_users,
        users_this_month=users_this_month,
        total_scans=total_scans,
        scans_today=scans_today,
        revenue_this_month=float(revenue),
        security_events_24h=security_events,
    )

@router.get("/dashboard/recent-activity")
async def get_recent_activity(
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    admin: User = Depends(require_super_admin)
):
    recent_scans = db.query(Scan).order_by(Scan.created_at.desc()).limit(limit).all()
    recent_events = db.query(SecurityEvent).order_by(SecurityEvent.created_at.desc()).limit(limit).all()
    
    return {
        "recent_scans": [
            {
                "scan_id": s.scan_id,
                "user_id": s.user_id,
                "target": s.target,
                "status": s.status,
                "created_at": s.created_at.isoformat() if s.created_at else None,
            }
            for s in recent_scans
        ],
        "recent_security_events": [
            {
                "id": e.id,
                "user_id": e.user_id,
                "event_type": e.event_type,
                "severity": e.severity,
                "description": e.description,
                "created_at": e.created_at.isoformat() if e.created_at else None,
            }
            for e in recent_events
        ]
    }

# ═══════════════════════════════════════════════════════════════════════════════
# User Management
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/users")
async def list_users(
    search: Optional[str] = None,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    admin: User = Depends(require_super_admin)
):
    query = db.query(User)
    if search:
        query = query.filter(
            (User.email.ilike(f"%{search}%")) |
            (User.username.ilike(f"%{search}%"))
        )
    
    total = query.count()
    users = query.order_by(User.created_at.desc()).offset(offset).limit(limit).all()
    
    return {
        "total": total,
        "users": [u.to_dict() for u in users],
    }

@router.get("/users/{user_id}")
async def get_user_admin(
    user_id: str,
    db: Session = Depends(get_db),
    admin: User = Depends(require_super_admin)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    scans_count = db.query(func.count(Scan.id)).filter(Scan.user_id == user_id).scalar()
    
    return {
        "user": user.to_dict(),
        "stats": {
            "scans_count": scans_count,
        }
    }

@router.patch("/users/{user_id}")
async def update_user_admin(
    user_id: str,
    request: UserUpdateRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(require_super_admin)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user.is_super_admin and user.email == SUPER_ADMIN_EMAIL:
        raise HTTPException(status_code=403, detail="Cannot modify primary super admin")

    data = request.dict(exclude_unset=True)
    for key, value in data.items():
        setattr(user, key, value)
    
    db.commit()
    return user.to_dict()

# ═══════════════════════════════════════════════════════════════════════════════
# Security & Monitoring
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/security/events")
async def list_security_events(
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    admin: User = Depends(require_super_admin)
):
    query = db.query(SecurityEvent)
    if severity: query = query.filter(SecurityEvent.severity == severity)
    if event_type: query = query.filter(SecurityEvent.event_type == event_type)
    
    events = query.order_by(SecurityEvent.created_at.desc()).limit(limit).all()
    return {"events": [e.id for e in events]} # Placeholder for actual to_dict if needed

@router.get("/platform/health")
async def get_platform_health(
    db: Session = Depends(get_db),
    admin: User = Depends(require_super_admin)
):
    return {"status": "healthy", "database": "connected"}
