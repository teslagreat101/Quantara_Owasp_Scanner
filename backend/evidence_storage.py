"""
Secure Evidence Storage (User-Centric)
Handles immutable evidence artifacts with hash verification.
Refactored to remove all Multi-Tenancy (Tenant) logic.
Each artifact is now directly associated with a User.
"""

import os
import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, BinaryIO, Dict, Any, Tuple
from io import BytesIO

import boto3
from botocore.exceptions import ClientError
from minio import Minio
from minio.error import S3Error
from sqlalchemy.orm import Session

from backend.database import EvidenceArtifact, User, Scan

# ═══════════════════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════════════════

STORAGE_BACKEND = os.getenv("STORAGE_BACKEND", "minio")

MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "localhost:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "minioadmin")
MINIO_BUCKET = os.getenv("MINIO_BUCKET", "quantum-evidence")
MINIO_SECURE = os.getenv("MINIO_SECURE", "false").lower() == "true"

AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
S3_BUCKET = os.getenv("S3_BUCKET", "quantum-evidence")

DEFAULT_RETENTION_DAYS = int(os.getenv("EVIDENCE_RETENTION_DAYS", "90"))
MAX_FILE_SIZE_MB = int(os.getenv("MAX_EVIDENCE_SIZE_MB", "100"))

# ═══════════════════════════════════════════════════════════════════════════════
# Storage Client Factory
# ═══════════════════════════════════════════════════════════════════════════════

class StorageClient:
    def __init__(self):
        self.backend = STORAGE_BACKEND
    
    def upload(self, bucket: str, key: str, data: bytes, content_type: str) -> bool:
        raise NotImplementedError
    
    def download(self, bucket: str, key: str) -> Optional[bytes]:
        raise NotImplementedError
    
    def delete(self, bucket: str, key: str) -> bool:
        raise NotImplementedError
    
    def generate_presigned_url(self, bucket: str, key: str, expires: int = 3600) -> Optional[str]:
        raise NotImplementedError

class MinIOStorageClient(StorageClient):
    def __init__(self):
        super().__init__()
        self.client = Minio(
            MINIO_ENDPOINT,
            access_key=MINIO_ACCESS_KEY,
            secret_key=MINIO_SECRET_KEY,
            secure=MINIO_SECURE
        )
        self._ensure_bucket(MINIO_BUCKET)
    
    def _ensure_bucket(self, bucket: str):
        try:
            if not self.client.bucket_exists(bucket):
                self.client.make_bucket(bucket)
        except S3Error as e:
            print(f"Bucket error: {e}")
    
    def upload(self, bucket: str, key: str, data: bytes, content_type: str) -> bool:
        try:
            self.client.put_object(
                bucket_name=bucket,
                object_name=key,
                data=BytesIO(data),
                length=len(data),
                content_type=content_type,
                metadata={"Uploaded-At": datetime.now(timezone.utc).isoformat()}
            )
            return True
        except S3Error:
            return False
    
    def download(self, bucket: str, key: str) -> Optional[bytes]:
        try:
            response = self.client.get_object(bucket, key)
            return response.read()
        except S3Error:
            return None
    
    def delete(self, bucket: str, key: str) -> bool:
        try:
            self.client.remove_object(bucket, key)
            return True
        except S3Error:
            return False
    
    def generate_presigned_url(self, bucket: str, key: str, expires: int = 3600) -> Optional[str]:
        try:
            return self.client.presigned_get_object(bucket, key, expires=timedelta(seconds=expires))
        except S3Error:
            return None

def get_storage_client() -> StorageClient:
    if STORAGE_BACKEND == "minio":
        return MinIOStorageClient()
    # AWS S3 can be added here if needed
    return MinIOStorageClient()

# ═══════════════════════════════════════════════════════════════════════════════
# Evidence Management
# ═══════════════════════════════════════════════════════════════════════════════

class EvidenceManager:
    def __init__(self, db: Session):
        self.db = db
        self.storage = get_storage_client()
        self.bucket = MINIO_BUCKET if STORAGE_BACKEND == "minio" else S3_BUCKET
    
    @staticmethod
    def calculate_hash(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()
    
    def store_evidence(
        self,
        user_id: str,
        scan_id: str,
        finding_id: Optional[str],
        artifact_type: str,
        data: bytes,
        content_type: str,
        description: Optional[str] = None
    ) -> Tuple[Optional[EvidenceArtifact], Optional[str]]:
        size_mb = len(data) / (1024 * 1024)
        if size_mb > MAX_FILE_SIZE_MB:
            return None, "File too large"
        
        artifact_id = str(uuid.uuid4())
        object_key = f"{user_id}/{scan_id}/{artifact_type}/{artifact_id}"
        
        if not self.storage.upload(self.bucket, object_key, data, content_type):
            return None, "Upload failed"
        
        artifact = EvidenceArtifact(
            artifact_id=artifact_id,
            scan_id=scan_id,
            finding_id=finding_id,
            storage_backend=STORAGE_BACKEND,
            bucket_name=self.bucket,
            object_key=object_key,
        )
        self.db.add(artifact)
        self.db.commit()
        return artifact, None

    def retrieve_evidence(self, artifact_id: str) -> Optional[bytes]:
        artifact = self.db.query(EvidenceArtifact).filter(EvidenceArtifact.artifact_id == artifact_id).first()
        if not artifact: return None
        return self.storage.download(artifact.bucket_name, artifact.object_key)

def store_scan_evidence(db: Session, user_id: str, scan_id: str, data: bytes, artifact_type: str, content_type: str) -> Optional[EvidenceArtifact]:
    manager = EvidenceManager(db)
    artifact, error = manager.store_evidence(user_id, scan_id, None, artifact_type, data, content_type)
    return artifact
