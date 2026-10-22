import pytest
from httpx import AsyncClient
from src.core.config import settings


@pytest.mark.asyncio
async def test_login_success(client: AsyncClient, create_user):
    user, pwd = await create_user(username="bob_user", password="Str0ng!P@ssword1")

    response = await client.post(
        "/api/auth/login",
        json={"username": "bob_user", "password": pwd},
    )
    assert response.status_code == 200
    data = response.json()
    assert "csrf_token" in data
    assert data["user"]["username"] == "bob_user"

    # Verify session cookie attributes
    cookies = response.cookies
    assert settings.SESSION_COOKIE_NAME in cookies
    cookie = response.headers.get("set-cookie", "")
    assert "HttpOnly" in cookie
    assert "SameSite=Strict" in cookie


@pytest.mark.asyncio
async def test_login_invalid_password(client: AsyncClient, create_user):
    user, pwd = await create_user(username="valid_user", password="Str0ng!P@ssword1")

    response = await client.post(
        "/api/auth/login",
        json={"username": "valid_user", "password": "WrongPassword!123"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"


@pytest.mark.asyncio
async def test_login_nonexistent_user_returns_identical_401(client: AsyncClient):
    response = await client.post(
        "/api/auth/login",
        json={"username": "ghost_user_999", "password": "AnyPassword!123"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"


@pytest.mark.asyncio
async def test_account_lockout_after_consecutive_failures(client: AsyncClient, create_user):
    user, pwd = await create_user(username="target_user", password="Str0ng!P@ssword1")

    # 4 failed attempts from distinct IPs to test account lockout independently of IP rate limiting
    for i in range(4):
        resp = await client.post(
            "/api/auth/login",
            json={"username": "target_user", "password": "BadPassword!123"},
            headers={"X-Forwarded-For": f"198.51.100.{i+1}, 127.0.0.1"},
        )
        assert resp.status_code == 401

    # 5th failed attempt triggers lockout
    resp5 = await client.post(
        "/api/auth/login",
        json={"username": "target_user", "password": "BadPassword!123"},
        headers={"X-Forwarded-For": "198.51.100.5, 127.0.0.1"},
    )
    assert resp5.status_code == 401

    # 6th attempt (even with CORRECT password) returns 423 Locked
    resp_locked = await client.post(
        "/api/auth/login",
        json={"username": "target_user", "password": pwd},
        headers={"X-Forwarded-For": "198.51.100.6, 127.0.0.1"},
    )
    assert resp_locked.status_code == 423
    assert "Account temporarily locked" in resp_locked.json()["detail"]


@pytest.mark.asyncio
async def test_login_disabled_account_rejected(client: AsyncClient, create_user):
    user, pwd = await create_user(username="disabled_user", password="Str0ng!P@ssword1", is_active=False)

    response = await client.post(
        "/api/auth/login",
        json={"username": "disabled_user", "password": pwd},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Account is disabled"
