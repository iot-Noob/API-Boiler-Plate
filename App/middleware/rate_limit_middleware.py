# App/core/rate_limit_middleware.py
"""
Global Redis-backed rate limiter middleware.

- Applies to ALL routes automatically (no decorators needed)
- Per-endpoint overrides via PER_ENDPOINT dict
- Whitelist via EXEMPT_PATHS
- Fails OPEN if Redis is down (doesn't block traffic)
- Adds X-RateLimit-* headers to every response
- Uses sliding time buckets in Redis

Usage in main.py:
    from App.core.rate_limit_middleware import GlobalRateLimitMiddleware
    app.add_middleware(GlobalRateLimitMiddleware, default_limit="100/minute")
"""

import time
from typing import Optional, Tuple
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from App.core.RedisConnector import redis_client
from App.core.LoggingInit import get_core_logger

logger = get_core_logger(__name__)


# ============================================================
# Limit parsing
# ============================================================

_PERIODS = {
    "second": 1,
    "minute": 60,
    "hour": 3600,
    "day": 86400,
}


def parse_limit(limit_str: str) -> Tuple[int, int]:
    """
    Parse "100/minute" → (100, 60).
    Raises ValueError on invalid format.
    """
    try:
        count_part, period_part = limit_str.strip().lower().split("/")
        count = int(count_part.strip())
        period = period_part.strip()

        if period not in _PERIODS:
            raise ValueError(f"Unknown period '{period}'. Use: {list(_PERIODS.keys())}")

        if count <= 0:
            raise ValueError(f"Count must be > 0, got {count}")

        return count, _PERIODS[period]
    except Exception as e:
        raise ValueError(f"Invalid rate limit '{limit_str}': {e}") from e


# ============================================================
# Global rate limit middleware
# ============================================================

class GlobalRateLimitMiddleware(BaseHTTPMiddleware):
    """
    Per-IP rate limiter, global by default, with per-endpoint overrides.

    The rate limit is keyed on: (client_ip, method, path, time_bucket).
    Uses INCR + EXPIRE for atomic counting.
    """

    # Paths that are NEVER rate limited
    EXEMPT_PATHS = (
        "/health",
        "/metrics",
        "/docs",
        "/redoc",
        "/openapi.json",
        "/favicon.ico",
    )

    # Per-endpoint overrides.
    # Format: "METHOD /exact/path" → "limit"
    # Longest matching prefix wins.
    PER_ENDPOINT = {
        "POST /app/v1/auth/basic_auth/login":       "10/minute",
        "POST /app/v1/auth/basic_auth/signup":      "5/hour",
        "POST /app/v1/auth/basic_auth/logout":      "30/minute",
        "POST /app/v1/users/users_config/refresh":  "60/minute",
        "POST /app/v1/admin/admin_access/account/temp_token": "10/minute",
        "POST /app/v1/admin/admin_access/account/restore":    "10/minute",
        "DELETE /app/v1/admin/admin_access/account":          "10/minute",
        "PUT /app/v1/admin/admin_access/account/password":    "10/minute",
    }

    def __init__(self, app, default_limit: str = "100/minute"):
        super().__init__(app)
    
        self.default_count, self.default_window = parse_limit(default_limit)
        self.endpoint_limits = {
            key: parse_limit(limit) for key, limit in self.PER_ENDPOINT.items()
        }

        logger.info(
            f"GlobalRateLimitMiddleware initialized: "
            f"default={default_limit}, overrides={len(self.endpoint_limits)}"
        )

    # ---------- helpers ----------

    def _is_exempt(self, path: str) -> bool:
        return any(path == p or path.startswith(p + "/") or path == p for p in self.EXEMPT_PATHS) \
            or path in self.EXEMPT_PATHS

    def _get_limit(self, method: str, path: str) -> Tuple[int, int]:
        """Longest-prefix match against PER_ENDPOINT. Falls back to default."""
        best: Optional[Tuple[int, int]] = None
        best_len = -1

        for key, (count, window) in self.endpoint_limits.items():
            k_method, _, k_path = key.partition(" ")
            if k_method != method:
                continue
            if not path.startswith(k_path):
                continue
            if len(k_path) > best_len:
                best = (count, window)
                best_len = len(k_path)

        return best if best else (self.default_count, self.default_window)

    def _client_ip(self, request: Request) -> str:
        """Extract client IP, respecting X-Forwarded-For if present."""
        xff = request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip.strip()
        return request.client.host if request.client else "unknown"

    # ---------- main dispatch ----------

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # 1. Skip exempt paths
        if self._is_exempt(path):
            return await call_next(request)

        # 2. Determine limit
        method = request.method.upper()
        limit, window = self._get_limit(method, path)

        # 3. Build Redis key
        client_ip = self._client_ip(request)
        bucket = int(time.time() // window)
        key = f"rl:{client_ip}:{method}:{path}:{bucket}"

        # 4. Redis check
        try:
            c = redis_client.client
            count = await c.incr(key)
            if count == 1:
                # First request in this bucket — set TTL
                await c.expire(key, window + 1)

        except Exception as e:
            # Redis down → FAIL OPEN. Never block traffic on limiter failure.
            logger.error(f"Rate limiter Redis error (failing open): {e}")
            return await call_next(request)

        # 5. Compute response headers
        remaining = max(0, limit - count)
        reset_at = (bucket + 1) * window
        retry_after = max(1, reset_at - int(time.time()))

        # 6. Over limit → 429
        if count > limit:
            logger.warning(
                f"Rate limit exceeded: ip={client_ip} method={method} "
                f"path={path} count={count}/{limit}"
            )
            return JSONResponse(
                status_code=429,
                headers={
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(reset_at),
                    "Retry-After": str(retry_after),
                },
                content={
                    "error": "rate_limit_exceeded",
                    "message": f"Too many requests. Limit: {limit} per {window}s.",
                    "retry_after": retry_after,
                },
            )

        # 7. Under limit → pass through, add headers
        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(reset_at)
        return response