import json
import os
import logging
from typing import Optional, Dict, Any, List
import redis
from redis.connection import ConnectionPool
from redis.exceptions import ConnectionError, TimeoutError

logger = logging.getLogger("backend.redis_client")

# Redis connection pool
_redis_pool: Optional[ConnectionPool] = None


def get_redis_url() -> str:
    """Get Redis URL from environment."""
    return os.getenv("REDIS_URL", "redis://localhost:6379/0")


def init_redis() -> Optional[redis.Redis]:
    """Initialize Redis connection with safety check."""
    global _redis_pool
    try:
        if _redis_pool is None:
            redis_url = get_redis_url()
            # Short timeout to fail fast if Redis isn't there
            _redis_pool = ConnectionPool.from_url(
                redis_url, 
                max_connections=20, 
                socket_timeout=2.0,
                socket_connect_timeout=2.0
            )

        client = redis.Redis(connection_pool=_redis_pool, decode_responses=True)
        # Verify connection
        client.ping()
        return client
    except (ConnectionError, TimeoutError, Exception) as e:
        logger.warning(f"Redis connection failed: {e}. Falling back to in-memory state management.")
        return None


class ScanStateManager:
    """Manages scan state with Redis support and in-memory fallback."""

    KEY_PREFIX = "scan:"
    TTL = 86400 * 7  # 7 days

    def __init__(self):
        self.redis = init_redis()
        self._local_state: Dict[str, Any] = {}
        self._local_events: Dict[str, List[Dict]] = {}
        self._local_progress: Dict[str, float] = {}

    def _key(self, scan_id: str) -> str:
        return f"{self.KEY_PREFIX}{scan_id}"

    def _progress_key(self, scan_id: str) -> str:
        return f"{self.KEY_PREFIX}{scan_id}:progress"

    def _events_key(self, scan_id: str) -> str:
        return f"{self.KEY_PREFIX}{scan_id}:events"

    def set_scan_status(self, scan_id: str, status: str, **kwargs) -> None:
        """Update scan status and metadata."""
        data = {"status": status, **kwargs}
        if self.redis:
            try:
                key = self._key(scan_id)
                mapping = {k: json.dumps(v) if isinstance(v, (dict, list)) else str(v) for k, v in data.items()}
                self.redis.hset(key, mapping=mapping)
                self.redis.expire(key, self.TTL)
                return
            except Exception as e:
                logger.error(f"Redis hset error: {e}")
        
        # Local Fallback
        if scan_id not in self._local_state:
            self._local_state[scan_id] = {}
        self._local_state[scan_id].update(data)

    def get_scan_status(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get current scan status."""
        if self.redis:
            try:
                key = self._key(scan_id)
                data = self.redis.hgetall(key)
                if data:
                    result = {}
                    for k, v in data.items():
                        try:
                            result[k] = json.loads(v)
                        except (json.JSONDecodeError, TypeError):
                            result[k] = v
                    return result
            except Exception as e:
                logger.error(f"Redis hgetall error: {e}")
        
        return self._local_state.get(scan_id)

    def set_progress(self, scan_id: str, progress: float) -> None:
        """Set scan progress."""
        if self.redis:
            try:
                key = self._progress_key(scan_id)
                self.redis.set(key, str(progress), ex=self.TTL)
                return
            except Exception as e:
                logger.error(f"Redis set progress error: {e}")
        
        self._local_progress[scan_id] = float(progress)

    def get_progress(self, scan_id: str) -> float:
        """Get current progress."""
        if self.redis:
            try:
                key = self._progress_key(scan_id)
                value = self.redis.get(key)
                if value is not None:
                    return float(value)
            except Exception as e:
                logger.error(f"Redis get progress error: {e}")
        
        return self._local_progress.get(scan_id, 0.0)

    def add_event(self, scan_id: str, event_type: str, data: Dict[str, Any]) -> None:
        """Add event to stream."""
        event = {"type": event_type, "data": data}
        if self.redis:
            try:
                key = self._events_key(scan_id)
                self.redis.lpush(key, json.dumps(event))
                self.redis.ltrim(key, 0, 999)
                self.redis.expire(key, self.TTL)
                return
            except Exception as e:
                logger.error(f"Redis add_event error: {e}")

        if scan_id not in self._local_events:
            self._local_events[scan_id] = []
        self._local_events[scan_id].insert(0, event)
        self._local_events[scan_id] = self._local_events[scan_id][:1000]

    def get_events(self, scan_id: str, count: int = 100) -> list:
        """Get recent events."""
        if self.redis:
            try:
                key = self._events_key(scan_id)
                events = self.redis.lrange(key, 0, count - 1)
                return [json.loads(e) for e in events]
            except Exception as e:
                logger.error(f"Redis get_events error: {e}")
        
        return self._local_events.get(scan_id, [])[:count]

    def publish_finding(self, scan_id: str, finding: Dict[str, Any]) -> None:
        """Publish finding to channel."""
        if self.redis:
            try:
                channel = f"scan:{scan_id}:findings"
                self.redis.publish(channel, json.dumps({"type": "finding", "data": finding}))
            except Exception:
                pass

    def publish_log(self, scan_id: str, log: Dict[str, Any]) -> None:
        """Publish log to channel."""
        if self.redis:
            try:
                channel = f"scan:{scan_id}:logs"
                self.redis.publish(channel, json.dumps({"type": "log", "data": log}))
            except Exception:
                pass

    def publish_status(self, scan_id: str, status: str, data: Optional[Dict] = None) -> None:
        """Publish status to channel."""
        if self.redis:
            try:
                channel = f"scan:{scan_id}:status"
                message = {"type": "status", "status": status}
                if data:
                    message.update(data)
                self.redis.publish(channel, json.dumps(message))
            except Exception:
                pass


# Global state manager instance
_state_manager: Optional[ScanStateManager] = None


def get_state_manager() -> ScanStateManager:
    """Get global scan state manager."""
    global _state_manager
    if _state_manager is None:
        _state_manager = ScanStateManager()
    return _state_manager
