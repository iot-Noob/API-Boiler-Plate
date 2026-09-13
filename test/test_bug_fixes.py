"""
Standalone verification tests for the 5 real bug fixes applied to master.

These tests do NOT touch MinIO. They verify:
    Bug 1 — Connector.py respects settings.get_connection_pool_params()
    Bug 2 — BodySizeLimitMiddleware rejects chunked transfer encoding
    Bug 4 — revoke_family calls pass explicit TTL
    Bug 5 — _is_exempt has no dead code
    Bug 7 — Routes are protected by default (informational; may be skipped)

Bug 3 (MinIO TLS) and Bug 6 (auto-commit, retracted) are intentionally
excluded because MinIO is not on master yet.

Run with:
    uv run python -m pytest test/test_bug_fixes.py -v
"""

import inspect

import pytest
from httpx import AsyncClient, ASGITransport


# ===========================================================================
# Bug 1 — Pool params must come from settings, not hardcoded values
# ===========================================================================

class TestBug1PoolParams:
    """Connector.py must respect DATABASE_POOL_SIZE / MAX_OVERFLOW / RECYCLE."""

    async def test_pool_size_matches_settings(self):
        from App.core.Connector import database
        from App.core.settings import settings

        await database.connect()
        try:
            actual = database._engine.pool.size()
            expected = settings.DATABASE_POOL_SIZE
            assert actual == expected, (
                f"Pool size mismatch: settings says {expected}, "
                f"engine has {actual}. Connector.py is hardcoding pool params."
            )
        finally:
            await database.disconnect()

    async def test_max_overflow_matches_settings(self):
        from App.core.Connector import database
        from App.core.settings import settings

        await database.connect()
        try:
            actual = database._engine.pool._max_overflow
            expected = settings.DATABASE_MAX_OVERFLOW
            assert actual == expected, (
                f"Max overflow mismatch: settings says {expected}, "
                f"engine has {actual}."
            )
        finally:
            await database.disconnect()

    async def test_pool_recycle_matches_settings(self):
        from App.core.Connector import database
        from App.core.settings import settings

        await database.connect()
        try:
            actual = database._engine.pool._recycle
            expected = settings.DATABASE_POOL_RECYCLE
            assert actual == expected, (
                f"Pool recycle mismatch: settings says {expected}, "
                f"engine has {actual}."
            )
        finally:
            await database.disconnect()


# ===========================================================================
# Bug 2 — Chunked encoding must not bypass MAX_BODY_SIZE
# ===========================================================================

class TestBug2ChunkedBodyBypass:
    """BodySizeLimitMiddleware must reject chunked transfer encoding."""

    def test_middleware_source_mentions_transfer_encoding(self):
        from App.middleware import body_size_middleware

        source = inspect.getsource(body_size_middleware)
        assert "transfer-encoding" in source.lower(), (
            "BodySizeLimitMiddleware does not check Transfer-Encoding. "
            "Chunked requests bypass MAX_BODY_SIZE."
        )

    async def test_chunked_request_gets_413(self):
        from main import app

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            r = await client.post(
                "/app/v1/auth/basic_auth/login",
                headers={"Transfer-Encoding": "chunked"},
                content=b'{"username":"x","password":"y"}',
            )
            assert r.status_code == 413, (
                f"Chunked request returned {r.status_code}, expected 413. "
                f"Body: {r.text}"
            )


# ===========================================================================
# Bug 4 — revoke_family must be called with explicit TTL
# ===========================================================================

class TestBug4RevokeFamilyTTL:
    """AuthService.revoke_* must pass revoke_ttl explicitly."""

    def test_revoke_session_passes_ttl(self):
        from App.services import auth_service

        source = inspect.getsource(auth_service.AuthService.revoke_session)
        assert "revoke_ttl=settings.REFRESH_TOKEN_TTL_SECONDS" in source, (
            "revoke_session does not pass revoke_ttl. If "
            "REFRESH_TOKEN_TTL_SECONDS is ever bumped beyond 7 days, "
            "reuse detection silently breaks."
        )

    def test_revoke_all_sessions_passes_ttl(self):
        from App.services import auth_service

        source = inspect.getsource(
            auth_service.AuthService.revoke_all_sessions_for_user
        )
        assert "revoke_ttl=settings.REFRESH_TOKEN_TTL_SECONDS" in source, (
            "revoke_all_sessions_for_user does not pass revoke_ttl."
        )


# ===========================================================================
# Bug 5 — _is_exempt must not have dead code
# ===========================================================================

class TestBug5IsExempt:
    """Rate-limit middleware's _is_exempt must be clean."""

    def test_no_duplicate_path_equality(self):
        from App.middleware import rate_limit_middleware

        source = inspect.getsource(
            rate_limit_middleware.GlobalRateLimitMiddleware._is_exempt
        )
        count = source.count("path == p")
        assert count == 1, (
            f"'path == p' appears {count} times in _is_exempt. Expected 1."
        )

    def test_no_redundant_trailing_check(self):
        from App.middleware import rate_limit_middleware

        source = inspect.getsource(
            rate_limit_middleware.GlobalRateLimitMiddleware._is_exempt
        )
        assert "or path in self.EXEMPT_PATHS" not in source, (
            "Redundant trailing `or path in self.EXEMPT_PATHS` still present."
        )


# ===========================================================================
# Bug 7 — Router-level default auth (informational)
# ===========================================================================
class TestBug7DefaultAuth:
    """
    Informational check. If master's router isn't using a default auth
    dependency, this test fails. It's not a code bug — it's a design
    decision. Skip this class if you're a solo dev who reviews routes.
    """

    @pytest.mark.skip(reason="Bug 7 deliberately not applied — solo dev reviews routes")
    def test_router_has_default_auth(self):
        import App.api.v1 as v1

        source = inspect.getsource(v1)
        assert "dependencies=[Depends(get_current_user)]" in source, (
            "App/api/v1/__init__.py does not declare a router-level "
            "default auth dependency. New routes are public by default. "
            "This is a design choice — mark this test skipped if you "
            "deliberately chose not to apply it."
        )