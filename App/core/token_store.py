# App/core/token_store.py
import json
from typing import Optional

from App.core.RedisConnector import redis_client
from App.core.redis_keys import (
    refresh_key,
    revoked_rt_key,
    family_key,
    blocklist_at_key,
)


# ========== REFRESH TOKENS ==========

async def store_refresh(jti: str, user_id: int, family_id: str, ttl: int) -> None:
    """Store refresh token metadata + track in family set."""
    c = redis_client.client
    await c.set(
        refresh_key(jti),
        json.dumps({"user_id": user_id, "family_id": family_id}),
        ex=ttl,
    )
    await c.sadd(family_key(family_id), jti)
    await c.expire(family_key(family_id), ttl)


async def consume_refresh(jti: str) -> Optional[dict]:
    """Atomic get+delete. Returns None if already used/expired."""
    data = await redis_client.client.getdel(refresh_key(jti))
    if not data:
        return None
    return json.loads(data)


async def revoke_refresh(jti: str, ttl: int) -> None:
    """Mark a refresh token as revoked until its natural expiry."""
    await redis_client.client.set(revoked_rt_key(jti), "1", ex=ttl)


async def is_refresh_revoked(jti: str) -> bool:
    return await redis_client.client.exists(revoked_rt_key(jti)) == 1


async def revoke_family(family_id: str) -> None:
    """Kill every refresh token in a family (reuse detected)."""
    c = redis_client.client
    jtis = await c.smembers(family_key(family_id))
    if jtis:
        await c.delete(*[refresh_key(j) for j in jtis])
    await c.delete(family_key(family_id))


# ========== ACCESS TOKEN BLOCKLIST ==========

async def blocklist_access(jti: str, ttl: int) -> None:
    """Blocklist an access token jti until its natural expiry."""
    await redis_client.client.set(blocklist_at_key(jti), "1", ex=ttl)


async def is_access_blocked(jti: str) -> bool:
    return await redis_client.client.exists(blocklist_at_key(jti)) == 1


# ========== LOGIN RATE LIMIT ==========

async def check_login_rate(email: str, ip: str, max_attempts: int = 10, window: int = 300) -> bool:
    """Returns True if allowed, False if rate-limited."""
    from App.core.redis_keys import login_attempts_key
    key = login_attempts_key(email, ip)
    c = redis_client.client
    count = await c.incr(key)
    if count == 1:
        await c.expire(key, window)
    return count <= max_attempts