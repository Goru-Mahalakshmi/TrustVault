import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_user_registration_success(client: AsyncClient):
    payload = {
        "username": "alice_sec",
        "email": "alice@trustvault.com",
        "password": "Compl3x!P@ssword123",
    }
    response = await client.post("/api/auth/register", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["username"] == "alice_sec"
    assert data["email"] == "alice@trustvault.com"
    assert data["role"] == "owner"
    assert data["is_active"] is True
    assert "password" not in data
    assert "password_hash" not in data


@pytest.mark.asyncio
async def test_duplicate_username_or_email_rejected(client: AsyncClient, create_user):
    await create_user(username="existing_user", email="existing@example.com")

    # Duplicate username
    resp_user = await client.post(
        "/api/auth/register",
        json={"username": "existing_user", "email": "other@example.com", "password": "Str0ng!P@ss123"},
    )
    assert resp_user.status_code == 409

    # Duplicate email
    resp_email = await client.post(
        "/api/auth/register",
        json={"username": "new_user", "email": "existing@example.com", "password": "Str0ng!P@ss123"},
    )
    assert resp_email.status_code == 409


@pytest.mark.asyncio
async def test_password_strength_enforcement(client: AsyncClient):
    # Too short (< 10 chars)
    r1 = await client.post(
        "/api/auth/register",
        json={"username": "short_pwd", "email": "short@example.com", "password": "Sh0rt!1"},
    )
    assert r1.status_code == 422

    # Missing uppercase
    r2 = await client.post(
        "/api/auth/register",
        json={"username": "no_upper", "email": "noupper@example.com", "password": "password123!"},
    )
    assert r2.status_code == 422

    # Missing lowercase
    r3 = await client.post(
        "/api/auth/register",
        json={"username": "no_lower", "email": "nolower@example.com", "password": "PASSWORD123!"},
    )
    assert r3.status_code == 422

    # Missing digit
    r4 = await client.post(
        "/api/auth/register",
        json={"username": "no_digit", "email": "nodigit@example.com", "password": "PasswordSpecial!"},
    )
    assert r4.status_code == 422

    # Missing special character
    r5 = await client.post(
        "/api/auth/register",
        json={"username": "no_special", "email": "nospecial@example.com", "password": "Password1234"},
    )
    assert r5.status_code == 422
