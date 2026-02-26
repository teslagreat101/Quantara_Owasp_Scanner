"""
Quantum Protocol v5.0 — API Token Management
CI/CD integration tokens for automated scanning.

Phase 8.1: CI/CD Integration - API Tokens
"""

import secrets
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Optional
from pydantic import BaseModel


class APIToken(BaseModel):
    id: str
    name: str
    token_preview: str  # Last 4 chars
    scopes: List[str]
    created_at: str
    last_used_at: Optional[str]
    expires_at: Optional[str]
    is_active: bool


class TokenManager:
    """Manage API tokens for CI/CD integration."""

    def __init__(self):
        # In-memory storage - would use database in production
        self._tokens: Dict[str, Dict] = {}
        self._token_hash_map: Dict[str, str] = {}  # hash -> token_id

    def create_token(self, user_id: str, name: str, scopes: List[str] = None) -> tuple[str, str]:
        """
        Create a new API token.
        Returns (token_id, plain_token) - plain_token is shown only once!
        """
        token_id = secrets.token_urlsafe(16)
        # Generate a secure token with prefix for identification
        plain_token = f"qp_{secrets.token_urlsafe(32)}"
        
        # Store hash of token for verification
        token_hash = hashlib.sha256(plain_token.encode()).hexdigest()
        
        now = datetime.now(timezone.utc).isoformat()
        
        self._tokens[token_id] = {
            "id": token_id,
            "user_id": user_id,
            "name": name,
            "token_hash": token_hash,
            "scopes": scopes or ["read", "scan"],
            "created_at": now,
            "last_used_at": None,
            "expires_at": None,  # Could set expiration
            "is_active": True,
        }
        
        self._token_hash_map[token_hash] = token_id
        
        return token_id, plain_token

    def list_tokens(self, user_id: str) -> List[APIToken]:
        """List all tokens for a user."""
        tokens = []
        for token_id, token_data in self._tokens.items():
            if token_data["user_id"] == user_id and token_data["is_active"]:
                tokens.append(APIToken(
                    id=token_data["id"],
                    name=token_data["name"],
                    token_preview="****" + token_data["token_hash"][-4:],
                    scopes=token_data["scopes"],
                    created_at=token_data["created_at"],
                    last_used_at=token_data["last_used_at"],
                    expires_at=token_data["expires_at"],
                    is_active=token_data["is_active"],
                ))
        return tokens

    def verify_token(self, plain_token: str) -> Optional[Dict]:
        """Verify a token and return token data if valid."""
        token_hash = hashlib.sha256(plain_token.encode()).hexdigest()
        
        token_id = self._token_hash_map.get(token_hash)
        if not token_id:
            return None
        
        token_data = self._tokens.get(token_id)
        if not token_data or not token_data["is_active"]:
            return None
        
        # Check expiration
        if token_data["expires_at"]:
            expires = datetime.fromisoformat(token_data["expires_at"])
            if datetime.now(timezone.utc) > expires:
                return None
        
        # Update last used
        token_data["last_used_at"] = datetime.now(timezone.utc).isoformat()
        
        return token_data

    def revoke_token(self, user_id: str, token_id: str) -> bool:
        """Revoke a token."""
        token_data = self._tokens.get(token_id)
        if not token_data or token_data["user_id"] != user_id:
            return False
        
        token_data["is_active"] = False
        
        # Remove from hash map
        token_hash = token_data["token_hash"]
        if token_hash in self._token_hash_map:
            del self._token_hash_map[token_hash]
        
        return True

    def has_scope(self, token_data: Dict, scope: str) -> bool:
        """Check if token has a specific scope."""
        return scope in token_data.get("scopes", [])


# Singleton instance
token_manager = TokenManager()
