import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def test_login_success(client: AsyncClient, login_payload):
    r = await client.post(
        "/app/v1/auth/basic_auth/login?cookie_login=false",
        json=login_payload,
    )
    assert r.status_code == 200
    body = r.json()
    assert "access_token" in body
    assert "refresh_token" in body


async def test_login_wrong_password(client: AsyncClient):
    r = await client.post(
        "/app/v1/auth/basic_auth/login?cookie_login=false",
        json={"username": "talha", "password": "wrong-password"},
    )
    assert r.status_code == 401


async def test_logout_revokes_access_token(client: AsyncClient, login_payload):
    r = await client.post(
        "/app/v1/auth/basic_auth/login?cookie_login=false", json=login_payload
    )
    access = r.json()["access_token"]

    # Works before logout
    r = await client.get(
        "/app/v1/users/users_config/me",
        headers={"Authorization": f"Bearer {access}"},
    )
    assert r.status_code == 200

    # Logout
    await client.post(
        "/app/v1/auth/basic_auth/logout",
        headers={"Authorization": f"Bearer {access}"},
    )

    # Must now be rejected
    r = await client.get(
        "/app/v1/users/users_config/me",
        headers={"Authorization": f"Bearer {access}"},
    )
    assert r.status_code == 401


async def test_logout_revokes_refresh_token(client: AsyncClient, login_payload):
    r = await client.post(
        "/app/v1/auth/basic_auth/login?cookie_login=false", json=login_payload
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
    assert r.status_code == 401


async def test_refresh_rotation_works(client: AsyncClient, login_payload):
    r = await client.post(
        "/app/v1/auth/basic_auth/login?cookie_login=false", json=login_payload
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
    assert body["refresh_token"] != refresh   # rotated


async def test_refresh_reuse_kills_family(client: AsyncClient, login_payload):
    r = await client.post(
        "/app/v1/auth/basic_auth/login?cookie_login=false", json=login_payload
    )
    refresh_1 = r.json()["refresh_token"]

    # Use it once → get refresh_2
    r = await client.post(
        "/app/v1/users/users_config/refresh",
        json={"refresh_token": refresh_1},
    )
    assert r.status_code == 200
    refresh_2 = r.json()["refresh_token"]

    # Reuse old one → must fail
    r = await client.post(
        "/app/v1/users/users_config/refresh",
        json={"refresh_token": refresh_1},
    )
    assert r.status_code == 401

    # The new one must ALSO be dead (family killed)
    r = await client.post(
        "/app/v1/users/users_config/refresh",
        json={"refresh_token": refresh_2},
    )
    assert r.status_code == 401


async def test_admin_endpoint_denied_for_user(client: AsyncClient, login_payload):
    # talha is a regular user, not admin
    r = await client.post(
        "/app/v1/auth/basic_auth/login?cookie_login=false", json=login_payload
    )
    access = r.json()["access_token"]

    r = await client.get(
        "/app/v1/users/users_config/users",
        headers={"Authorization": f"Bearer {access}"},
    )
    assert r.status_code == 403


async def test_admin_endpoint_granted_for_admin(client: AsyncClient):
    # Use admin credentials from .env
    import os
    admin_user = os.getenv("ADMIN_USERNAME", "admin")
    admin_pass = os.getenv("ADMIN_PASSWORD", "ChangeMe@12345")

    r = await client.post(
        "/app/v1/auth/basic_auth/login?cookie_login=false",
        json={"username": admin_user, "password": admin_pass},
    )
    if r.status_code != 200:
        pytest.skip("Admin credentials not available in this environment")
    access = r.json()["access_token"]

    r = await client.get(
        "/app/v1/users/users_config/users",
        headers={"Authorization": f"Bearer {access}"},
    )
    assert r.status_code == 200