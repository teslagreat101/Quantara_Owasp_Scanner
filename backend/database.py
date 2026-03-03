"""
Unified Database Schema for Quantum Protocol SaaS
Direct User-based model with subscription usage tracking.
Removed Multi-Tenancy layer for simplification.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any
from enum import Enum as PyEnum
import uuid
import json
import os

from sqlalchemy import (
    Column,
    String,
    Integer,
    BigInteger,
    Float,
    DateTime,
    JSON,
    ForeignKey,
    Text,
    Boolean,
    Enum,
    create_engine,
    Index,
    event,
    text,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker, Session
from sqlalchemy.pool import NullPool
import os

Base = declarative_base()

# ═══════════════════════════════════════════════════════════════════════════════
# Enums
# ═══════════════════════════════════════════════════════════════════════════════

class SubscriptionTier(PyEnum):
    """Subscription tiers for the platform."""
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"

class SubscriptionStatus(PyEnum):
    """Subscription status states."""
    ACTIVE = "active"
    PAST_DUE = "past_due"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    TRIAL = "trial"
    SUSPENDED = "suspended"

class ScanJobStatus(PyEnum):
    """Async scan job statuses."""
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"

class ScanStatus(PyEnum):
    """Execution status for security scans."""
    INITIALIZING = "initializing"
    RUNNING = "running"
    COMPLETED = "completed"
    ERROR = "error"
    CANCELLED = "cancelled"

class SandboxType(PyEnum):
    """Sandbox isolation levels."""
    DOCKER = "docker"
    GVISOR = "gvisor"
    FIRECRACKER = "firecracker"

class ReportType(PyEnum):
    """Types of security reports."""
    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    COMPLIANCE = "compliance"
    TIMELINE = "timeline"

# ═══════════════════════════════════════════════════════════════════════════════
# User Model
# ═══════════════════════════════════════════════════════════════════════════════

class User(Base):
    """
    User account model. Each user has their own scans and subscription.
    """
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    firebase_uid = Column(String(128), unique=True, nullable=True, index=True)
    
    # Profile
    email = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(100), unique=True, nullable=False)
    full_name = Column(String(255), nullable=True)
    hashed_password = Column(String(255), nullable=False)
    
    # Role & Permissions
    is_admin = Column(Boolean, default=False)
    is_super_admin = Column(Boolean, default=False)
    role = Column(String(50), default="member")
    permissions = Column(JSON, default=list)
    
    # Security
    is_active = Column(Boolean, default=True)
    email_verified = Column(Boolean, default=False)
    last_login_at = Column(DateTime, nullable=True)
    last_login_ip = Column(String(45), nullable=True)
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)
    
    # API Access
    api_rate_limit = Column(Integer, default=100)
    
    # Subscription Metadata (Mirroring Firestore/Billing)
    subscription_tier = Column(Enum(SubscriptionTier), default=SubscriptionTier.FREE)
    subscription_status = Column(Enum(SubscriptionStatus), default=SubscriptionStatus.TRIAL)
    stripe_customer_id = Column(String(255), nullable=True)
    stripe_subscription_id = Column(String(255), nullable=True)
    
    # Usage limits
    monthly_scan_limit = Column(Integer, default=10)
    storage_limit_mb = Column(Integer, default=100)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    deleted_at = Column(DateTime, nullable=True)
    
    # Relationships
    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan")
    scan_jobs = relationship("ScanJob", back_populates="user", cascade="all, delete-orphan")
    security_events = relationship("SecurityEvent", back_populates="user", cascade="all, delete-orphan")
    api_tokens = relationship("APIToken", back_populates="user", cascade="all, delete-orphan")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "firebase_uid": self.firebase_uid,
            "email": self.email,
            "username": self.username,
            "full_name": self.full_name,
            "is_admin": self.is_admin,
            "is_super_admin": self.is_super_admin,
            "subscription_tier": self.subscription_tier.value if self.subscription_tier else "free",
            "subscription_status": self.subscription_status.value if self.subscription_status else "trial",
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

# ═══════════════════════════════════════════════════════════════════════════════
# Scan Models
# ═══════════════════════════════════════════════════════════════════════════════

class Scan(Base):
    """
    Scan record - belongs to a user.
    """
    __tablename__ = "scans"
    
    __table_args__ = (
        Index('idx_scan_status', 'status'),
        Index('idx_scan_user_created', 'user_id', 'created_at'),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), unique=True, nullable=False, index=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    
    # Configuration
    target = Column(String(500), nullable=False)
    scan_type = Column(String(50), nullable=False)  # url, directory, git, code
    scan_profile = Column(String(100), default="standard")
    modules = Column(JSON, default=list)
    
    # Execution
    status = Column(String(50), default="initializing", index=True)
    progress = Column(Integer, default=0)
    active_module = Column(String(100), nullable=True)
    
    modules_total = Column(Integer, default=0)
    modules_completed = Column(Integer, default=0)
    
    # Metrics
    total_findings = Column(Integer, default=0)
    severity_counts = Column(JSON, default=lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})
    risk_score = Column(Float, default=0.0)
    
    # Time Tracking
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    duration = Column(Float, default=0.0)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    logs = relationship("ScanLog", back_populates="scan", cascade="all, delete-orphan")
    evidence_artifacts = relationship("EvidenceArtifact", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="scan", cascade="all, delete-orphan")

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "user_id": self.user_id,
            "target": self.target,
            "scan_type": self.scan_type,
            "status": self.status,
            "progress": self.progress,
            "modules_total": self.modules_total,
            "modules_completed": self.modules_completed,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration": self.duration,
            "total_findings": self.total_findings,
            "severity_counts": self.severity_counts,
        }

class Finding(Base):
    """
    Security finding - belongs to a scan.
    """
    __tablename__ = "findings"
    
    __table_args__ = (
        Index('idx_finding_severity', 'severity'),
        Index('idx_finding_scan', 'scan_id', 'created_at'),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    finding_id = Column(String(36), unique=True, nullable=False)
    scan_id = Column(String(36), ForeignKey("scans.scan_id"), nullable=False, index=True)
    
    # Finding details
    file = Column(String(500), nullable=False)
    line_number = Column(Integer, default=0)
    column = Column(Integer, nullable=True)
    severity = Column(String(20), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    matched_content = Column(Text, nullable=True)
    module_name = Column(String(100), nullable=False)
    category = Column(String(100), nullable=True)
    cwe = Column(String(50), nullable=True)
    remediation = Column(Text, nullable=True)
    confidence = Column(Float, default=1.0)
    tags = Column(JSON, default=list)
    
    evidence_hash = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    scan = relationship("Scan", back_populates="findings")
    
    def to_dict(self) -> dict:
        return {
            "id": self.finding_id,
            "scan_id": self.scan_id,
            "file": self.file,
            "line_number": self.line_number,
            "column": self.column,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "matched_content": self.matched_content,
            "module_name": self.module_name,
            "category": self.category,
            "cwe": self.cwe,
            "remediation": self.remediation,
            "confidence": self.confidence,
            "tags": self.tags,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

class ScanLog(Base):
    """
    Scan execution log.
    """
    __tablename__ = "scan_logs"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.scan_id"), nullable=False, index=True)
    
    level = Column(String(20), default="info")
    message = Column(Text, nullable=False)
    module = Column(String(100), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    scan = relationship("Scan", back_populates="logs")
    
    def to_dict(self) -> dict:
        return {
            "level": self.level,
            "message": self.message,
            "module": self.module,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }

# ═══════════════════════════════════════════════════════════════════════════════
# Infrastructure & Storage
# ═══════════════════════════════════════════════════════════════════════════════

class ScanJob(Base):
    """
    Async scan job.
    """
    __tablename__ = "scan_jobs"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    job_id = Column(String(36), unique=True, nullable=False, index=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    scan_id = Column(String(36), ForeignKey("scans.scan_id"), nullable=True)
    
    target = Column(String(500), nullable=False)
    scan_type = Column(String(50), nullable=False)
    modules = Column(JSON, default=list)
    status = Column(Enum(ScanJobStatus), default=ScanJobStatus.PENDING)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="scan_jobs")

class EvidenceArtifact(Base):
    """
    Evidence storage for scan findings.
    """
    __tablename__ = "evidence_artifacts"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    artifact_id = Column(String(36), unique=True, nullable=False)
    scan_id = Column(String(36), ForeignKey("scans.scan_id"), nullable=False, index=True)
    finding_id = Column(String(36), ForeignKey("findings.finding_id"), nullable=True)
    
    storage_backend = Column(String(50), default="s3")
    bucket_name = Column(String(255), nullable=False)
    object_key = Column(String(500), nullable=False)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    scan = relationship("Scan", back_populates="evidence_artifacts")

class Report(Base):
    """
    Generated security reports.
    """
    __tablename__ = "reports"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    report_id = Column(String(36), unique=True, nullable=False)
    scan_id = Column(String(36), ForeignKey("scans.scan_id"), nullable=True)
    generated_by = Column(String(36), ForeignKey("users.id"), nullable=False)
    
    report_type = Column(Enum(ReportType), nullable=False)
    title = Column(String(255), nullable=False)
    status = Column(String(50), default="completed")
    
    object_key = Column(String(500), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    scan = relationship("Scan", back_populates="reports")

# ═══════════════════════════════════════════════════════════════════════════════
# Authentication & Audit
# ═══════════════════════════════════════════════════════════════════════════════

class SecurityEvent(Base):
    """
    Security audit events.
    """
    __tablename__ = "security_events"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True, index=True)
    event_type = Column(String(100), nullable=False)
    severity = Column(String(20), default="info")
    description = Column(Text, nullable=False)
    ip_address = Column(String(45), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="security_events")

class APIToken(Base):
    """
    API tokens for external access.
    """
    __tablename__ = "api_tokens"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    token_hash = Column(String(64), unique=True, nullable=False, index=True)
    token_preview = Column(String(20), nullable=False)
    name = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="api_tokens")

# ═══════════════════════════════════════════════════════════════════════════════
# Initialization & Helpers
# ═══════════════════════════════════════════════════════════════════════════════

_engine = None
_SessionLocal = None

def get_database_url() -> str:
    """Get database URL from environment or default to SQLite."""
    # Use standard DATABASE_URL if provided
    return os.getenv(
        "DATABASE_URL",
        "sqlite:///./secretscanner.db"
    )

def init_db():
    """Initialize database engine and session."""
    global _engine, _SessionLocal

    database_url = get_database_url()
    if database_url.startswith("sqlite"):
        _engine = create_engine(database_url, connect_args={"check_same_thread": False})
    else:
        _engine = create_engine(database_url, poolclass=NullPool)

    _SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_engine)
    Base.metadata.create_all(bind=_engine)
    return _engine, _SessionLocal

def get_db():
    """FastAPI dependency for database sessions."""
    if _SessionLocal is None: init_db()
    db = _SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_db_session() -> Session:
    """Direct database session provider."""
    if _SessionLocal is None: init_db()
    return _SessionLocal()

def seed_super_admin(db: Session, email: str = "threathunter369@gmail.com", password: str = None):
    """Seed the platform super admin."""
    from passlib.context import CryptContext
    pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
    
    existing = db.query(User).filter(User.email == email).first()
    if existing: return existing
    
    if password is None:
        import secrets
        password = secrets.token_urlsafe(16)
        print(f"SEEDED SUPER ADMIN PASSWORD: {password}")
    
    super_admin = User(
        email=email,
        username="superadmin",
        hashed_password=pwd_context.hash(password),
        is_admin=True,
        is_super_admin=True,
        role="owner",
        email_verified=True,
        is_active=True,
    )
    db.add(super_admin)
    db.commit()
    return super_admin
