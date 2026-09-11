import asyncio

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from App.api.dependencies.auth import authenticate_user
from App.middleware.kill_switch_middleware import KillSwitchMiddleware


def test_authenticate_user_unknown_user_does_not_crash():
    async def _run():
        class DummyRepo:
            async def get_by_name(self, uname):
                return None

        class DummySession:
            pass

        import App.api.dependencies.auth as auth_mod

        original_repo = auth_mod.UserRepository
        auth_mod.UserRepository = lambda db: DummyRepo()
        try:
            result = await authenticate_user("missing@example.com", "WrongPassword123!", DummySession())
            assert result is None
        finally:
            auth_mod.UserRepository = original_repo

    asyncio.run(_run())


def test_kill_switch_does_not_swallow_http_exceptions():
    async def _run():
        async def call_next(request):
            raise HTTPException(status_code=401, detail="bad token")

        app = object()
        middleware = KillSwitchMiddleware(app=app, recovery_seconds=60)
        request = Request({"type": "http", "method": "GET", "path": "/test", "headers": []})

        with pytest.raises(HTTPException, match="bad token"):
            await middleware.dispatch(request, call_next)

    asyncio.run(_run())
