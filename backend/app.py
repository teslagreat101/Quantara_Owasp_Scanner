"""
Quantum Protocol v5.0 — Direct User SaaS FastAPI Backend
Enterprise-grade security scanner refactored for direct user subscriptions.
Removed all Multi-Tenancy / Tenant isolation logic.
"""

import os
import sys
from pathlib import Path
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, HTTPException, status, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from typing import List, Optional, Dict, Any, Union

# Add parent directory to path for scanner modules
PARENT_DIR = str(Path(__file__).resolve().parent.parent)
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

# Import all modules
from backend.database import init_db, get_db, get_db_session, User, Scan, Finding, seed_super_admin
from backend.auth import (
    create_access_token, create_refresh_token, verify_password, decode_token,
    get_current_user, require_admin, require_super_admin,
    SUPER_ADMIN_EMAIL, get_password_hash, record_login_attempt,
    get_user_subscription, increment_scan_usage
)
from backend.billing import (
    create_checkout_session, handle_stripe_webhook,
    TIER_CONFIG
)
from backend.rate_limiter import RateLimitMiddleware, WAFMiddleware, get_scan_limiter
from backend.scan_worker import queue_scan_job, cancel_job
from backend.admin_api import router as admin_router

# Security scheme
security = HTTPBearer()

# ═══════════════════════════════════════════════════════════════════════════════
# App Lifecycle
# ═══════════════════════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🚀 Quantum Protocol v5.0 Starting...")
    init_db()
    db = get_db_session()
    try:
        seed_super_admin(db, SUPER_ADMIN_EMAIL)
    finally:
        db.close()
    print("✅ Database initialized")
    print(f"👑 Super Admin: {SUPER_ADMIN_EMAIL}")
    yield
    print("🛑 Shutting down...")

# ═══════════════════════════════════════════════════════════════════════════════
# App Setup
# ═══════════════════════════════════════════════════════════════════════════════

app = FastAPI(
    title="Quantum Protocol",
    version="5.0.0",
    description="Direct Subscription Security Scanner Platform",
    lifespan=lifespan,
)

# CORS middleware
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
)

# Security middlewares
app.add_middleware(WAFMiddleware)
app.add_middleware(RateLimitMiddleware)

# Include admin router
app.include_router(admin_router)

# ═══════════════════════════════════════════════════════════════════════════════
# Models
# ═══════════════════════════════════════════════════════════════════════════════

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str
    password: str

class GoogleLoginRequest(BaseModel):
    id_token: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: dict

class ScanRequest(BaseModel):
    target: str
    scan_type: str = "directory"
    modules: List[str] = ["misconfig", "injection", "frontend_js"]
    priority: int = 5

# ═══════════════════════════════════════════════════════════════════════════════
# Endpoints
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/health")
async def health_check():
    return {"status": "healthy", "version": "5.0.0", "mode": "direct-subscription"}

@app.post("/api/v1/auth/login", response_model=TokenResponse)
async def login(request: LoginRequest, http_request: Request, db = Depends(get_db)):
    user = db.query(User).filter(User.email == request.email).first()
    if not user or not verify_password(request.password, user.hashed_password):
        if user: record_login_attempt(db, user, False, http_request.client.host if http_request.client else None)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")

    record_login_attempt(db, user, True, http_request.client.host if http_request.client else None)
    access_token = create_access_token({"sub": user.id})
    refresh_token = create_refresh_token(user.id)
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=1800,
        user=user.to_dict()
    )

@app.post("/api/v1/auth/register")
async def register(request: RegisterRequest, db = Depends(get_db)):
    if db.query(User).filter(User.email == request.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    
    user = User(
        email=request.email,
        username=request.username,
        hashed_password=get_password_hash(request.password),
    )
    db.add(user)
    db.commit()
    
    access_token = create_access_token({"sub": user.id})
    refresh_token = create_refresh_token(user.id)
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": 1800,
        "user": user.to_dict()
    }

@app.get("/api/v1/scans")
async def list_my_scans(
    status: Optional[str] = None,
    limit: int = 20,
    offset: int = 0,
    user: User = Depends(get_current_user),
    db = Depends(get_db)
):
    query = db.query(Scan).filter(Scan.user_id == user.id)
    if status: query = query.filter(Scan.status == status)
    
    total = query.count()
    scans = query.order_by(Scan.created_at.desc()).offset(offset).limit(limit).all()
    
    return {"total": total, "scans": [s.to_dict() for s in scans]}

@app.post("/api/v1/scans")
async def create_scan(
    request: ScanRequest,
    subscription: Dict[str, Any] = Depends(get_user_subscription),
    db = Depends(get_db)
):
    user_id = subscription.get("local_user_id")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=500, detail="User context not found")

    # Queue the scan
    job = queue_scan_job(
        db=db,
        user_id=user.id,
        target=request.target,
        scan_type=request.scan_type,
        modules=request.modules,
        priority=request.priority
    )
    
    # Increment usage in Firestore
    increment_scan_usage(subscription.get("uid"))
    
    return {"scan_id": job.job_id, "status": "queued"}

@app.post("/webhooks/stripe")
async def stripe_webhook(request: Request, db = Depends(get_db)):
    payload = await request.body()
    signature = request.headers.get("stripe-signature")
    if not signature: raise HTTPException(status_code=400, detail="Missing signature")
    
    handled = handle_stripe_webhook(payload, signature, db)
    return {"status": "success" if handled else "ignored"}

@app.get("/api/v1/me")
async def get_my_profile(user: User = Depends(get_current_user)):
    return user.to_dict()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
