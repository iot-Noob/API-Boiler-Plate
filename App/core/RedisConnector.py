# App/core/RedisConnector.py
import redis.asyncio as redis
from redis.exceptions import RedisError
from App.core.settings import settings
from App.core.LoggingInit import get_core_logger

logger = get_core_logger(__name__)


class RedisClient:
    def __init__(self):
        self._client: redis.Redis | None = None
        self._is_connected: bool = False

    async def connect(self) -> None:
        try:
            self._client = redis.from_url(
                settings.REDIS_URL,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
                max_connections=50,
            )
            await self._client.ping()
            self._is_connected = True
            logger.info("Redis connected")
        except (RedisError, OSError, ConnectionError, TimeoutError) as e:
            self._client = None
            self._is_connected = False
            logger.error(f"Redis connection failed: {e}")
            raise RuntimeError("Redis unavailable") from e
        except Exception as e:
            self._client = None
            self._is_connected = False
            logger.error(f"Redis connection failed: {e}")
            raise RuntimeError("Redis unavailable") from e

    async def disconnect(self) -> None:
        if self._client:
            await self._client.aclose()
            self._is_connected = False
            logger.info("Redis disconnected")

    async def health_check(self) -> dict:
        try:
            if not self._client:
                return {"status": "disconnected", "connected": False}
            await self._client.ping()
            return {"status": "healthy", "connected": True}
        except Exception as e:
            return {"status": "error", "connected": False, "error": str(e)}

    @property
    def client(self) -> redis.Redis:
        if not self._client or not self._is_connected:
            raise RuntimeError("Redis not connected. Call connect() first.")
        return self._client

    async def ensure_connected(self) -> redis.Redis:
        """Attempt to reconnect if Redis was previously disconnected."""
        if not self._client or not self._is_connected:
            await self.connect()
        return self._client


redis_client = RedisClient()


async def get_redis() -> redis.Redis:
    """FastAPI dependency."""
    return redis_client.client