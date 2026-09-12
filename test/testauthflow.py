import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def test_login_success(client, login_payload):
    r = await client.post(
        "/app/v1/auth/basic_auth/login?cookie_login=false", json=login_payload
    )
    assert r.status_code == 200
    body = r.json()
    assert "access_token" in body
    assert "refresh_token" in body


async def test_login_wrong_password(client):
    r = await client.post(
        "/app/v1/auth/basic_auth/login?cookie_login=false",
        json={"username": "talha", "password": "wrong"},
    )
    assert r.status_code == 401


async def test_access_token_works_before_logout(client, login_payload):
    r = await client.post(
        "/app/v1/auth/basic_auth/login?cookie_login=false", json=login_payload
    )
    access = r.json()["access_token"]
    r = await client.get(
        "/app/v1/users/users_config/me",
        headers={"Authorization": f"Bearer {access}"},
    )
    assert r.status_code == 200


async def test_logout_revokes_access_token(client, login_payload):
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

    r = await client.get(
        "/app/v1/users/users_config/me",
        headers={"Authorization": f"Bearer {access}"},
    )
    assert r.status_code == 401, "access token still valid after logout"


async def test_logout_revokes_refresh_token(client, login_payload):
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


async def test_refresh_rotation(client, login_payload):
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
    assert body["refresh_token"] != refresh


async def test_refresh_reuse_kills_family(client, login_payload):
    r = await client.post(
        "/app/v1/auth/basic_auth/login?cookie_login=false", json=login_payload
    )
    refresh_1 = r.json()["refresh_token"]

    r = await client.post(
        "/app/v1/users/users_config/refresh",
        json={"refresh_token": refresh_1},
    )
    assert r.status_code == 200
    refresh_2 = r.json()["refresh_token"]

    # Reuse old token → must fail
    r = await client.post(
        "/app/v1/users/users_config/refresh",
        json={"refresh_token": refresh_1},
    )
    assert r.status_code == 401

    # Family killed → new token also dead
    r = await client.post(
        "/app/v1/users/users_config/refresh",
        json={"refresh_token": refresh_2},
    )
    assert r.status_code == 401, "family kill didn't propagate"


async def test_admin_denied_for_regular_user(client, login_payload):
    r = await client.post(
        "/app/v1/auth/basic_auth/login?cookie_login=false", json=login_payload
    )
    access = r.json()["access_token"]

    r = await client.get(
        "/app/v1/users/users_config/users",
        headers={"Authorization": f"Bearer {access}"},
    )
    assert r.status_code == 403