"""
Pytest fixtures.

Important: the app uses a module-level singleton database engine
(`App.core.Connector.database`) whose connection pool is bound to the
event loop it was first used under. pytest-asyncio by default gives
each test a fresh loop, which makes connection reuse across tests fail
with "Event loop is closed".

The fix: one session-scoped event loop for the whole test run, and
explicitly dispose the engine between tests so no connection is ever
carried across.
"""
import asyncio

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy import text

from main import app
from App.core.Connector import database
from App.core.RedisConnector import redis_client


# ---------------------------------------------------------------------------
# One event loop for the entire test session.
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def event_loop():
    """
    Override pytest-asyncio's default per-test loop.

    This fixture is picked up automatically by pytest-asyncio for every
    async test in the session, so all async work — including any
    background connection the app opened — happens under one loop.
    """
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# ---------------------------------------------------------------------------
# Connect/disconnect the app's DB + Redis once per test, not per request.
# ---------------------------------------------------------------------------
@pytest_asyncio.fixture(scope="function", autouse=True)
async def reset_app_connections():
    """
    Before each test: ensure DB + Redis are connected under the current loop.
    After each test: dispose the engine so no connection leaks into the next loop.
    """
    # Connect on demand if not already connected.
    if not database.is_connected:
        await database.connect()
    try:
        c = await redis_client.ensure_connected()
        await c.ping()
    except Exception:
        pass  # tests that don't need Redis can still run

    yield

    # Dispose the DB pool so the next test starts clean.
    try:
        await database.disconnect()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# HTTP client pointed at the FastAPI app (no real network).
# ---------------------------------------------------------------------------
@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


# ---------------------------------------------------------------------------
# Shared login payload for tests.
# ---------------------------------------------------------------------------
@pytest.fixture
def login_payload():
    return {"username": "talha", "password": "Talha@6295"}