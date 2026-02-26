"""
Authentication & Authorization System (Direct User Model)
JWT-based auth refactored for direct user subscriptions.
Removed all Multi-Tenancy / Tenant isolation logic.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Tuple
from functools import wraps
import uuid
import hashlib
import secrets
import os

from fastapi import Depends, HTTPException, Security, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from backend.database import (
    get_db, get_db_session, User, SecurityEvent, 
    SubscriptionTier, SubscriptionStatus, APIToken
)
from backend.firebase_config import db as firestore_db
from firebase_admin import auth as firebase_auth

# ═══════════════════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════════════════

SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7
SUPER_ADMIN_EMAIL = "threathunter369@gmail.com"

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
security = HTTPBearer()

# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "type": "access", "iat": datetime.now(timezone.utc)})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(user_id: str) -> str:
    to_encode = {
        "sub": user_id,
        "type": "refresh",
        "exp": datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        "iat": datetime.now(timezone.utc),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None

def hash_api_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

# ═══════════════════════════════════════════════════════════════════════════════
# Dependencies
# ═══════════════════════════════════════════════════════════════════════════════

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(security),
    db: Session = Depends(get_db)
) -> User:
    token = credentials.credentials
    
    # Try Firebase Auth sync
    try:
        decoded_token = firebase_auth.verify_id_token(token)
        uid = decoded_token.get("uid")
        user = db.query(User).filter(User.firebase_uid == uid).first()
        if user: return user
        
        email = decoded_token.get("email")
        user = db.query(User).filter(User.email == email).first()
        if user:
            user.firebase_uid = uid
            db.commit()
            return user
    except:
        pass

    payload = decode_token(token)
    if not payload or payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user_id = payload.get("sub")
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user: raise HTTPException(status_code=401, detail="User not found")
    if not user.is_active: raise HTTPException(status_code=403, detail="Account disabled")
    
    return user

async def get_current_firebase_user(
    credentials: HTTPAuthorizationCredentials = Security(security)
) -> Dict[str, Any]:
    token = credentials.credentials
    try:
        decoded_token = firebase_auth.verify_id_token(token)
        uid = decoded_token.get("uid")
        email = decoded_token.get("email")
        
        db = get_db_session()
        try:
            user = db.query(User).filter(User.firebase_uid == uid).first()
            if not user:
                user = db.query(User).filter(User.email == email).first()
                if user:
                    user.firebase_uid = uid
                else:
                    user = User(
                        email=email,
                        username=email,
                        firebase_uid=uid,
                        subscription_tier=SubscriptionTier.FREE,
                        hashed_password="FIREBASE_AUTHED",
                        is_active=True,
                    )
                    db.add(user)
                db.commit()
                db.refresh(user)
            decoded_token["local_user_id"] = user.id
        finally:
            db.close()
            
        return decoded_token
    except Exception as e:
        import traceback
        print(f"DEBUG: Firebase token verification failed: {e}")
        # traceback.print_exc()
        raise HTTPException(status_code=401, detail=f"Firebase Error: {str(e)}")

async def get_user_subscription(
    firebase_user: Dict[str, Any] = Depends(get_current_firebase_user)
) -> Dict[str, Any]:
    uid = firebase_user.get("uid")
    email = firebase_user.get("email", "")
    if not uid:
        print("DEBUG: get_user_subscription: No UID found in firebase_user")
        raise HTTPException(status_code=401, detail="Missing user UID")

    # Super admin always gets unrestricted elite access — bypass Firestore lookup
    if email == SUPER_ADMIN_EMAIL:
        print(f"DEBUG: Super admin detected ({email}), returning elite subscription")
        return {
            "uid": uid,
            "email": email,
            "plan": "elite",
            "scanLimit": 999999,
            "scansUsedThisMonth": 0,
            "subscriptionStatus": "active",
            "local_user_id": firebase_user.get("local_user_id"),
            "is_super_admin": True,
        }

    user_ref = firestore_db.collection("users").document(uid)
    doc = user_ref.get()

    if not doc.exists:
        print(f"DEBUG: get_user_subscription: Creating new Firestore record for {uid}")
        new_data = {
            "uid": uid,
            "email": email,
            "plan": "free",
            "scanLimit": 5,
            "scansUsedThisMonth": 0,
            "subscriptionStatus": "active",
            "billingCycleEnd": datetime.now(timezone.utc) + timedelta(days=30),
            "created_at": datetime.now(timezone.utc)
        }
        user_ref.set(new_data)
        subscription = new_data
    else:
        subscription = doc.to_dict()

    subscription["local_user_id"] = firebase_user.get("local_user_id")
    print(f"DEBUG: get_user_subscription: Resolved UID={uid}, local_user_id={subscription.get('local_user_id')}, scansUsed={subscription.get('scansUsedThisMonth')}")
    return subscription

async def require_admin(user: User = Depends(get_current_user)) -> User:
    if not user.is_admin and not user.is_super_admin:
        raise HTTPException(status_code=403, detail="Admin required")
    return user

async def require_super_admin(user: User = Depends(get_current_user)) -> User:
    if not user.is_super_admin or user.email != SUPER_ADMIN_EMAIL:
        raise HTTPException(status_code=403, detail="Super admin required")
    return user

# ═══════════════════════════════════════════════════════════════════════════════
# Logging & Audit
# ═══════════════════════════════════════════════════════════════════════════════

def log_security_event(
    db: Session,
    user_id: Optional[str],
    event_type: str,
    severity: str,
    description: str,
    ip_address: Optional[str] = None,
    metadata: Optional[Dict] = None
):
    event = SecurityEvent(
        user_id=user_id,
        event_type=event_type,
        severity=severity,
        description=description,
        ip_address=ip_address,
        metadata=metadata or {},
    )
    db.add(event)
    db.commit()

def record_login_attempt(db: Session, user: User, success: bool, ip_address: Optional[str] = None):
    if success:
        user.failed_login_attempts = 0
        user.last_login_at = datetime.now(timezone.utc)
        user.last_login_ip = ip_address
        log_security_event(db, user.id, "login_success", "info", f"Login successful", ip_address)
    else:
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= 5:
            user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=30)
            log_security_event(db, user.id, "account_locked", "high", "Account locked", ip_address)
    db.commit()

def check_subscription_access(subscription: Dict[str, Any], feature: str) -> Tuple[bool, Optional[str]]:
    """Check if the user's subscription allows a specific feature."""
    # Super admin bypasses all feature gates
    if subscription.get("is_super_admin") or subscription.get("email") == SUPER_ADMIN_EMAIL:
        return True, None

    sub_status = subscription.get("subscriptionStatus", "active")

    # Allow "active" and "trialing"; block "past_due", "cancelled", etc.
    if sub_status not in ("active", "trialing"):
        return False, f"Your subscription is not active (status: {sub_status}). Please update your payment method."

    plan = subscription.get("plan", "free")

    # Feature gate: advanced features require pro or elite
    PRO_FEATURES = {"advanced_scan", "ai_remediation"}
    ELITE_FEATURES = {"unlimited_scans", "soc_module", "enterprise_report"}

    if feature in ELITE_FEATURES and plan not in ("elite",):
        return False, f"The '{feature}' feature requires an Enterprise plan. Please upgrade."

    if feature in PRO_FEATURES and plan not in ("pro", "elite"):
        return False, f"The '{feature}' feature requires a Pro plan or higher. Please upgrade."

    return True, None

def check_usage_limits(subscription: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """Check if the user has reached their monthly scan limit."""
    # Super admin has unlimited scans
    if subscription.get("is_super_admin") or subscription.get("email") == SUPER_ADMIN_EMAIL:
        return True, None

    used = subscription.get("scansUsedThisMonth", 0)
    limit = subscription.get("scanLimit", 5)

    if used >= limit:
        return False, f"You have reached your monthly scan limit ({limit}). Please upgrade your plan."

    return True, None

def increment_scan_usage(uid: str, email: str = ""):
    # Super admin has unlimited scans — skip the counter
    if email == SUPER_ADMIN_EMAIL:
        return

    print(f"DEBUG: increment_scan_usage called for {uid}")
    user_ref = firestore_db.collection("users").document(uid)
    from google.cloud import firestore as google_firestore
    try:
        user_ref.update({
            "scansUsedThisMonth": google_firestore.Increment(1),
            "last_active_at": google_firestore.SERVER_TIMESTAMP
        })
        print(f"DEBUG: increment_scan_usage success for {uid}")
    except Exception as e:
        print(f"DEBUG: increment_scan_usage failed for {uid}: {e}")
