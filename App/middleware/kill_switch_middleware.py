# App/middleware/kill_switch_middleware.py
"""
Kill switch middleware with two modes:

1. Manual kill:  settings.KILL_SWITCH_ENABLED = true → all requests 503
2. Auto kill:    Unhandled exception → 60s cooldown (Redis-backed)

Redis-backed state means multiple workers share the same auto-kill flag.
Whitelisted paths (/health, /docs, etc.) always pass through.

Redis keys:
    kill_switch:auto_kill_until  →  Unix timestamp (float), TTL = recovery_seconds
"""

import time
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from App.core.settings import settings
from App.core.LoggingInit import get_core_logger
from App.core.RedisConnector import redis_client

logger = get_core_logger(__name__)


class KillSwitchMiddleware(BaseHTTPMiddleware):
    WHITELIST = ("/health", "/docs", "/redoc", "/openapi.json")
    AUTO_KILL_KEY = "kill_switch:auto_kill_until"

    def __init__(self, app, recovery_seconds: int = 60):
        super().__init__(app)
        self.recovery_seconds = recovery_seconds

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        is_whitelisted = any(path.startswith(w) for w in self.WHITELIST)

        if not is_whitelisted:
            # 1. Manual kill
            if settings.KILL_SWITCH_ENABLED:
                logger.warning(f"Manual kill switch ON — blocking {path}")
                return JSONResponse(
                    status_code=503,
                    content={
                        "detail": "Service unavailable (maintenance)",
                        "type": "manual_kill",
                    },
                )

            # 2. Auto kill (Redis-backed, multi-worker safe)
            try:
                until_raw = await redis_client.client.get(self.AUTO_KILL_KEY)
                if until_raw:
                    until = float(until_raw)
                    if time.time() < until:
                        remaining = int(until - time.time())
                        logger.warning(
                            f"Auto kill active — blocking {path} (retry in {remaining}s)"
                        )
                        return JSONResponse(
                            status_code=503,
                            content={
                                "detail": "Service recovering",
                                "type": "auto_kill",
                                "retry_in": remaining,
                            },
                        )
            except Exception as e:
                # Redis down → fail open (don't block traffic on limiter failure)
                logger.error(f"Auto-kill check failed (failing open): {e}")

        # 3. Pass through
        try:
            return await call_next(request)
        except Exception as e:
            logger.exception(
                f"Unhandled exception — entering safety mode for {self.recovery_seconds}s: {e}"
            )

            # Set auto-kill in Redis with TTL (atomic, shared across workers)
            try:
                until = time.time() + self.recovery_seconds
                await redis_client.client.setex(
                    self.AUTO_KILL_KEY,
                    self.recovery_seconds,
                    str(until),
                )
                logger.error(
                    f"Auto-kill set until {time.ctime(until)} "
                    f"({self.recovery_seconds}s cooldown)"
                )
            except Exception as redis_err:
                logger.error(f"Failed to set auto-kill in Redis: {redis_err}")

            return JSONResponse(
                status_code=500,
                content={"detail": "Internal error"},
            )