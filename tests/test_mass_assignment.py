import pytest
from httpx import AsyncClient
from src.core.config import settings


@pytest.mark.asyncio
async def test_mass_assignment_on_register_rejected(client: AsyncClient):
    # Attempt to inject role="admin" during registration
    payload = {
        "username": "sneaky_admin",
        "email": "sneaky@example.com",
        "password": "Compl3x!P@ssword123",
        "role": "admin",
    }
    response = await client.post("/api/auth/register", json=payload)
    assert response.status_code == 422
    assert "extra_forbidden" in str(response.json())


@pytest.mark.asyncio
async def test_mass_assignment_hidden_flags_rejected(client: AsyncClient):
    payload = {
        "username": "flag_injector",
        "email": "flags@example.com",
        "password": "Compl3x!P@ssword123",
        "security_version": 999,
        "is_active": True,
        "failed_login_attempts": 0,
    }
    response = await client.post("/api/auth/register", json=payload)
    assert response.status_code == 422
    assert "extra_forbidden" in str(response.json())


@pytest.mark.asyncio
async def test_mass_assignment_on_login_rejected(client: AsyncClient):
    payload = {
        "username": "alice",
        "password": "ValidPassword!123",
        "is_admin": True,
    }
    response = await client.post("/api/auth/login", json=payload)
    assert response.status_code == 422
    assert "extra_forbidden" in str(response.json())


@pytest.mark.asyncio
async def test_mass_assignment_on_admin_role_update_rejected(client: AsyncClient, create_user, auth_session):
    admin, _ = await create_user(username="admin_strict", role="admin")
    admin_sess, admin_csrf = await auth_session(admin)
    target, _ = await create_user(username="target_strict", role="owner")

    payload = {
        "role": "viewer",
        "email": "hacked@example.com",
    }
    response = await client.post(
        f"/api/admin/users/{target.id}/role",
        json=payload,
        cookies={settings.SESSION_COOKIE_NAME: admin_sess},
        headers={"X-CSRF-Token": admin_csrf},
    )
    assert response.status_code == 422
    assert "extra_forbidden" in str(response.json())
