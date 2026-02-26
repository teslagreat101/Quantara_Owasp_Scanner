"""
Rate Limiting & Protection Layer
Refactored for direct User-based limits (removed Multi-Tenancy).
"""

import time
import re
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Callable
from functools import wraps

from fastapi import Request, HTTPException, status, Depends
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
import redis

# ═══════════════════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════════════════

REDIS_URL = __import__('os').getenv("REDIS_URL", "redis://localhost:6379/0")

# Default rate limits per tier (now per User)
TIER_RATE_LIMITS = {
    "free": {
        "requests_per_minute": 60,
        "scans_per_day": 5,
    },
    "pro": {
        "requests_per_minute": 300,
        "scans_per_day": 50,
    },
    "elite": {
        "requests_per_minute": 1000,
        "scans_per_day": 10000,
    },
}

SUSPICIOUS_PATTERNS = [
    r"(?i)(union\s+select|insert\s+into|delete\s+from|drop\s+table)",
    r"(?i)(<script|javascript:|on\w+\s*=)",
    r"(?i)(\.\./|\.\.\\|%2e%2e%2f)",
]

# ═══════════════════════════════════════════════════════════════════════════════
# Rate Limiter Service
# ═══════════════════════════════════════════════════════════════════════════════

class RateLimiter:
    def __init__(self):
        try:
            self.redis = redis.from_url(REDIS_URL, decode_responses=True)
        except:
            self.redis = None # Fallback for local dev without redis

    def is_rate_limited(self, key: str, limit: int, window: int = 60) -> bool:
        if not self.redis: return False
        
        current = self.redis.get(key)
        if current and int(current) >= limit:
            return True
        
        pipe = self.redis.pipeline()
        pipe.incr(key)
        pipe.expire(key, window)
        pipe.execute()
        return False

    def can_start_scan(self, user_id: str, tier: str) -> (bool, str):
        if not self.redis: return True, ""
        
        limit = TIER_RATE_LIMITS.get(tier, TIER_RATE_LIMITS["free"])["scans_per_day"]
        key = f"scans_day:{user_id}:{datetime.now(timezone.utc).strftime('%Y-%m-%d')}"
        
        count = self.redis.get(key) or 0
        if int(count) >= limit:
            return False, f"Daily scan limit reached for {tier} tier"
        
        return True, ""

    def start_scan(self, user_id: str, scan_id: str):
        if not self.redis: return
        key = f"scans_day:{user_id}:{datetime.now(timezone.utc).strftime('%Y-%m-%d')}"
        self.redis.incr(key)
        self.redis.expire(key, 86400) # 24 hours

# ═══════════════════════════════════════════════════════════════════════════════
# Middlewares
# ═══════════════════════════════════════════════════════════════════════════════

class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # We handle rate limiting after auth where possible, 
        # or by IP for public endpoints.
        # This is a simplified placeholder.
        return await call_next(request)

class WAFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        query = request.url.query
        
        for pattern in SUSPICIOUS_PATTERNS:
            if re.search(pattern, path) or re.search(pattern, query):
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Security Violation Detected"}
                )
        
        return await call_next(request)

_limiter = RateLimiter()

def get_scan_limiter():
    return _limiter
