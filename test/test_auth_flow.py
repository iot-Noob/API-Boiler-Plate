"""Auth flow regression tests.

These lock in the behavior of login, refresh rotation, family kill,
and logout (both cookie and Bearer paths) so future refactors can't
silently break them.
"""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


# ============================================================================
# Login
# ============================================================================

async def test_login_success(client, login_payload):
    r = await client.post(
        "/app/v1/auth/basic_auth/login?cookie_login=false",
        json=login_payload,
    )
    assert r.status_code == 200
    body = r.json()
    assert "access_token" in body
    assert "refresh_token" in body


async def test_login_wrong_password(client):
    r = await client.post(
        "/app/v1/auth/basic_auth/login?cookie_login=false",
        json={"username": "talha", "password": "definitely-wrong"},
    )
    assert r.status_code == 401


# ============================================================================
# Access token lifecycle
# ============================================================================

async def test_access_token_works_before_logout(client, login_payload):
    r = await client.post(
        "/app/v1/auth/basic_auth/login?cookie_login=false",
        json=login_payload,
    )
    access = r.json()["access_token"]

    r = await client.get(
        "/app/v1/users/users_config/me",
        headers={"Authorization": f"Bearer {access}"},
    )
    assert r.status_code == 200


# ============================================================================
# Logout — the whole point of this suite
# ============================================================================

async def test_logout_revokes_access_token(client, login_payload):
    """After logout, the same access token must be rejected."""
    r = await client.post(
        "/app/v1/auth/basic_auth/login?cookie_login=false",
        json=login_payload,
    )
    access = r.json()["access_token"]
    refresh = r.json()["refresh_token"]

    await client.post(
        "/app/v1/auth/basic_auth/logout",
        headers={"Authorization": f"Bearer {access}"},
        json={"refresh_token": refresh},
    )

    r = await client.get(
        "/app/v1/users/users_config/me",
        headers={"Authorization": f"Bearer {access}"},
    )
    assert r.status_code == 401, "access token still valid after logout"


async def test_logout_revokes_refresh_token(client, login_payload):
    """After logout, the same refresh token must be rejected."""
    r = await client.post(
        "/app/v1/auth/basic_auth/login?cookie_login=false",
        json=login_payload,
    )
    access = r.json()["access_token"]
    refresh = r.json()["refresh_token"]

    await client.post(
        "/app/v1/auth/basic_auth/logout",
        headers={"Authorization": f"Bearer {access}"},
        json={"refresh_token": refresh},
    )

    r = await client.post(
        "/app/v1/users/users_config/refresh",
        json={"refresh_token": refresh},
    )
    assert r.status_code == 401, "refresh token still valid after logout"


async def test_logout_with_only_access_token_kills_refresh_family(client, login_payload):
    """The Bearer-only logout path — Fix 2.

    Client sends only the access token. The server must still revoke
    every refresh family for that user so the client's stored refresh
    token can't mint new sessions.
    """
    r = await client.post(
        "/app/v1/auth/basic_auth/login?cookie_login=false",
        json=login_payload,
    )
    access = r.json()["access_token"]
    refresh = r.json()["refresh_token"]

    # Logout with ONLY the access token — no refresh_token in body
    await client.post(
        "/app/v1/auth/basic_auth/logout",
        headers={"Authorization": f"Bearer {access}"},
    )

    # The client's stored refresh token must now be dead
    r = await client.post(
        "/app/v1/users/users_config/refresh",
        json={"refresh_token": refresh},
    )
    assert r.status_code == 401, (
        "Bearer-only logout left the refresh token alive — Fix 2 missing"
    )


# ============================================================================
# Refresh rotation
# ============================================================================

async def test_refresh_rotation_issues_new_pair(client, login_payload):
    r = await client.post(
        "/app/v1/auth/basic_auth/login?cookie_login=false",
        json=login_payload,
    )
    refresh = r.json()["refresh_token"]

    r = await client.post(
        "/app/v1/users/users_config/refresh",
        json={"refresh_token": refresh},
    )
    assert r.status_code == 200
    body = r.json()
    assert "access_token" in body
    assert "refresh_token" in body
    assert body["refresh_token"] != refresh, "refresh token was not rotated"


async def test_refresh_reuse_kills_family(client, login_payload):
    """Reusing an already-rotated refresh token must kill the whole family."""
    r = await client.post(
        "/app/v1/auth/basic_auth/login?cookie_login=false",
        json=login_payload,
    )
    refresh_1 = r.json()["refresh_token"]

    # First rotation — succeeds, gives us refresh_2
    r = await client.post(
        "/app/v1/users/users_config/refresh",
        json={"refresh_token": refresh_1},
    )
    assert r.status_code == 200
    refresh_2 = r.json()["refresh_token"]

    # Reuse the OLD token — must be rejected
    r = await client.post(
        "/app/v1/users/users_config/refresh",
        json={"refresh_token": refresh_1},
    )
    assert r.status_code == 401

    # The new token must also be dead (family kill)
    r = await client.post(
        "/app/v1/users/users_config/refresh",
        json={"refresh_token": refresh_2},
    )
    assert r.status_code == 401, "family kill did not propagate to descendant"


# ============================================================================
# Permissions
# ============================================================================

async def test_admin_endpoint_denied_for_regular_user(client, login_payload):
    """Regular user must get 403 on an admin-only endpoint."""
    r = await client.post(
        "/app/v1/auth/basic_auth/login?cookie_login=false",
        json=login_payload,
    )
    access = r.json()["access_token"]

    r = await client.get(
        "/app/v1/users/users_config/users",
        headers={"Authorization": f"Bearer {access}"},
    )
    assert r.status_code == 403