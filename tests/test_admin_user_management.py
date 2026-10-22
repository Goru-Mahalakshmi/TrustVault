import pytest
from httpx import AsyncClient
from src.core.config import settings


@pytest.mark.asyncio
async def test_admin_list_users_success(client: AsyncClient, create_user, auth_session):
    admin, _ = await create_user(username="super_admin", role="admin")
    sess_tok, csrf_tok = await auth_session(admin)

    response = await client.get(
        "/api/admin/users",
        cookies={settings.SESSION_COOKIE_NAME: sess_tok},
    )
    assert response.status_code == 200
    users = response.json()
    assert len(users) >= 1
    assert any(u["username"] == "super_admin" for u in users)


@pytest.mark.asyncio
async def test_non_admin_cannot_access_admin_endpoints(client: AsyncClient, create_user, auth_session):
    owner, _ = await create_user(username="standard_owner", role="owner")
    sess_tok, csrf_tok = await auth_session(owner)

    response = await client.get(
        "/api/admin/users",
        cookies={settings.SESSION_COOKIE_NAME: sess_tok},
    )
    assert response.status_code == 403
    assert "requires 'admin' role" in response.json()["detail"]


@pytest.mark.asyncio
async def test_admin_change_role_invalidates_target_session(client: AsyncClient, create_user, auth_session):
    admin, _ = await create_user(username="admin_role_mgr", role="admin")
    admin_sess, admin_csrf = await auth_session(admin)

    target_user, _ = await create_user(username="target_employee", role="owner")
    target_sess, target_csrf = await auth_session(target_user)

    # Confirm target session is initially active
    r_me_before = await client.get(
        "/api/auth/me",
        cookies={settings.SESSION_COOKIE_NAME: target_sess},
    )
    assert r_me_before.status_code == 200

    # Admin changes target's role from owner to viewer
    r_role = await client.post(
        f"/api/admin/users/{target_user.id}/role",
        json={"role": "viewer"},
        cookies={settings.SESSION_COOKIE_NAME: admin_sess},
        headers={"X-CSRF-Token": admin_csrf},
    )
    assert r_role.status_code == 200
    assert r_role.json()["role"] == "viewer"

    # Target session must be immediately invalidated (0ms delay)
    r_me_after = await client.get(
        "/api/auth/me",
        cookies={settings.SESSION_COOKIE_NAME: target_sess},
    )
    assert r_me_after.status_code == 401
    assert "Session invalidated" in r_me_after.json()["detail"]


@pytest.mark.asyncio
async def test_admin_disable_user_invalidates_target_session(client: AsyncClient, create_user, auth_session):
    admin, _ = await create_user(username="admin_disable_mgr", role="admin")
    admin_sess, admin_csrf = await auth_session(admin)

    target_user, _ = await create_user(username="bad_actor", role="owner")
    target_sess, _ = await auth_session(target_user)

    # Admin disables target account
    r_status = await client.post(
        f"/api/admin/users/{target_user.id}/status",
        json={"is_active": False},
        cookies={settings.SESSION_COOKIE_NAME: admin_sess},
        headers={"X-CSRF-Token": admin_csrf},
    )
    assert r_status.status_code == 200
    assert r_status.json()["is_active"] is False

    # Target session is immediately invalidated
    r_me_after = await client.get(
        "/api/auth/me",
        cookies={settings.SESSION_COOKIE_NAME: target_sess},
    )
    assert r_me_after.status_code == 401


@pytest.mark.asyncio
async def test_admin_trigger_reset_cannot_set_password(client: AsyncClient, create_user, auth_session):
    admin, _ = await create_user(username="admin_reset_mgr", role="admin")
    admin_sess, admin_csrf = await auth_session(admin)

    target_user, target_pwd = await create_user(username="forgotten_employee", role="owner")

    # Admin triggers reset
    r_trigger = await client.post(
        f"/api/admin/users/{target_user.id}/trigger-reset",
        cookies={settings.SESSION_COOKIE_NAME: admin_sess},
        headers={"X-CSRF-Token": admin_csrf},
    )
    assert r_trigger.status_code == 200
    assert "Password reset triggered" in r_trigger.json()["message"]

    # Verify that the admin has NO endpoint to directly update password or email.
    # (The old check compared against app.routes, which never contains included routers, so it could not fail.)
    import re
    from src.main import app
    paths = app.openapi()["paths"]
    assert len(paths) > 20, "route table looks empty: this check would be vacuous"
    assert not [p for p in paths if p.startswith("/api/admin") and re.search(r"/(password|email|credentials)", p)]
