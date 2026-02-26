"""
Quantum Protocol v5.0 — WebSocket Live Monitoring
Real-time WebSocket for bidirectional communication and notifications.

Phase 8.5: WebSocket Live Monitoring
"""

import json
import asyncio
from typing import Dict, Set, Callable
from datetime import datetime, timezone
import uuid

try:
    from fastapi import WebSocket, WebSocketDisconnect
    from starlette.websockets import WebSocketState
    FASTAPI_WS_AVAILABLE = True
except ImportError:
    FASTAPI_WS_AVAILABLE = False


class WebSocketManager:
    """Manage WebSocket connections for real-time updates."""

    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.user_connections: Dict[str, Set[str]] = {}  # user_id -> set of connection_ids
        self.notification_handlers: Dict[str, Callable] = {}

    async def connect(self, websocket: WebSocket, user_id: str = "anonymous"):
        """Accept and store a new WebSocket connection."""
        await websocket.accept()
        connection_id = str(uuid.uuid4())
        self.active_connections[connection_id] = websocket
        
        if user_id not in self.user_connections:
            self.user_connections[user_id] = set()
        self.user_connections[user_id].add(connection_id)
        
        # Send welcome message
        await websocket.send_json({
            "type": "connected",
            "connection_id": connection_id,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        
        return connection_id

    def disconnect(self, connection_id: str, user_id: str = "anonymous"):
        """Remove a WebSocket connection."""
        if connection_id in self.active_connections:
            del self.active_connections[connection_id]
        
        if user_id in self.user_connections:
            self.user_connections[user_id].discard(connection_id)

    async def broadcast(self, message: dict, exclude: str = None):
        """Broadcast message to all connected clients."""
        disconnected = []
        for conn_id, websocket in self.active_connections.items():
            if conn_id != exclude:
                try:
                    await websocket.send_json(message)
                except Exception:
                    disconnected.append(conn_id)
        
        # Clean up disconnected clients
        for conn_id in disconnected:
            self.active_connections.pop(conn_id, None)

    async def send_to_user(self, user_id: str, message: dict):
        """Send message to all connections of a specific user."""
        if user_id not in self.user_connections:
            return
        
        disconnected = []
        for conn_id in self.user_connections[user_id]:
            if conn_id in self.active_connections:
                try:
                    await self.active_connections[conn_id].send_json(message)
                except Exception:
                    disconnected.append(conn_id)
        
        # Clean up
        for conn_id in disconnected:
            self.active_connections.pop(conn_id, None)
            self.user_connections[user_id].discard(conn_id)

    async def send_notification(self, user_id: str, title: str, message: str, severity: str = "info"):
        """Send a notification to a user."""
        await self.send_to_user(user_id, {
            "type": "notification",
            "title": title,
            "message": message,
            "severity": severity,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

    async def broadcast_scan_update(self, scan_id: str, data: dict):
        """Broadcast scan update to all connected clients."""
        await self.broadcast({
            "type": "scan_update",
            "scan_id": scan_id,
            "data": data,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })


# Singleton instance
ws_manager = WebSocketManager()
