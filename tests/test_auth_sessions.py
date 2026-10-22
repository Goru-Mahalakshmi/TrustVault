from datetime import datetime, timezone, timedelta
import pytest
from httpx import AsyncClient
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession
from src.core.config import settings
from src.models.session import Session


@pytest.mark.asyncio
async def test_session_auth_and_me_endpoint(client: AsyncClient, create_user, auth_session):
    user, _ = await create_user(username="charlie_auth")
    session_tok, csrf_tok = await auth_session(user)

    # Valid session
    response = await client.get(
        "/api/auth/me",
        cookies={settings.SESSION_COOKIE_NAME: session_tok},
    )
    assert response.status_code == 200
    assert response.json()["username"] == "charlie_auth"


@pytest.mark.asyncio
async def test_session_missing_or_tampered_rejected(client: AsyncClient):
    # Missing cookie
    r1 = await client.get("/api/auth/me")
    assert r1.status_code == 401

    # Tampered/invalid cookie
    r2 = await client.get(
        "/api/auth/me",
        cookies={settings.SESSION_COOKIE_NAME: "invalid_fake_session_token"},
    )
    assert r2.status_code == 401


@pytest.mark.asyncio
async def test_csrf_token_required_on_mutations(client: AsyncClient, create_user, auth_session):
    user, pwd = await create_user(username="csrf_victim")
    session_tok, csrf_tok = await auth_session(user)

    # Missing X-CSRF-Token header on POST
    r_missing = await client.post(
        "/api/auth/change-password",
        json={"current_password": pwd, "new_password": "NewCompl3x!P@ss1"},
        cookies={settings.SESSION_COOKIE_NAME: session_tok},
    )
    assert r_missing.status_code == 403
    assert "CSRF token missing" in r_missing.json()["detail"]

    # Invalid X-CSRF-Token header
    r_invalid = await client.post(
        "/api/auth/change-password",
        json={"current_password": pwd, "new_password": "NewCompl3x!P@ss1"},
        cookies={settings.SESSION_COOKIE_NAME: session_tok},
        headers={"X-CSRF-Token": "bogus_csrf_token_value"},
    )
    assert r_invalid.status_code == 403
    assert "Invalid CSRF token" in r_invalid.json()["detail"]


@pytest.mark.asyncio
async def test_logout_revokes_session_immediately(client: AsyncClient, create_user, auth_session):
    user, _ = await create_user(username="logout_user")
    session_tok, csrf_tok = await auth_session(user)

    # Logout
    r_logout = await client.post(
        "/api/auth/logout",
        cookies={settings.SESSION_COOKIE_NAME: session_tok},
        headers={"X-CSRF-Token": csrf_tok},
    )
    assert r_logout.status_code == 200

    # Subsequent request with old session token fails immediately
    r_subsequent = await client.get(
        "/api/auth/me",
        cookies={settings.SESSION_COOKIE_NAME: session_tok},
    )
    assert r_subsequent.status_code == 401


@pytest.mark.asyncio
async def test_password_change_invalidates_all_active_sessions(client: AsyncClient, create_user, auth_session):
    user, pwd = await create_user(username="pw_change_user")
    session_tok1, csrf_tok1 = await auth_session(user)

    # Change password
    r_change = await client.post(
        "/api/auth/change-password",
        json={"current_password": pwd, "new_password": "BrandNew!Passw0rd1"},
        cookies={settings.SESSION_COOKIE_NAME: session_tok1},
        headers={"X-CSRF-Token": csrf_tok1},
    )
    assert r_change.status_code == 200

    # Prior session token is immediately invalid because user.security_version was incremented
    r_after = await client.get(
        "/api/auth/me",
        cookies={settings.SESSION_COOKIE_NAME: session_tok1},
    )
    assert r_after.status_code == 401
    assert "Session invalidated" in r_after.json()["detail"]


@pytest.mark.asyncio
async def test_idle_timeout_invalidates_session(
    client: AsyncClient, create_user, auth_session, db_session: AsyncSession
):
    user, _ = await create_user(username="idle_user")
    session_tok, _ = await auth_session(user)

    # Simulate 31 minutes of inactivity by rewinding last_active_at in DB
    past_time = datetime.now(timezone.utc) - timedelta(minutes=31)
    await db_session.execute(
        update(Session).where(Session.user_id == user.id).values(last_active_at=past_time)
    )
    await db_session.commit()

    # Request after idle timeout must fail with 401
    response = await client.get(
        "/api/auth/me",
        cookies={settings.SESSION_COOKIE_NAME: session_tok},
    )
    assert response.status_code == 401
    assert "Session expired due to inactivity" in response.json()["detail"]


@pytest.mark.asyncio
async def test_absolute_timeout_invalidates_session(
    client: AsyncClient, create_user, auth_session, db_session: AsyncSession
):
    user, _ = await create_user(username="abs_user")
    session_tok, _ = await auth_session(user)

    # Simulate past absolute expiry (12 hours)
    past_expiry = datetime.now(timezone.utc) - timedelta(minutes=1)
    await db_session.execute(
        update(Session).where(Session.user_id == user.id).values(expires_at=past_expiry)
    )
    await db_session.commit()

    response = await client.get(
        "/api/auth/me",
        cookies={settings.SESSION_COOKIE_NAME: session_tok},
    )
    assert response.status_code == 401
    assert "absolute limit reached" in response.json()["detail"]


@pytest.mark.asyncio
async def test_email_change_flow(client: AsyncClient, create_user, auth_session, db_session: AsyncSession):
    user, pwd = await create_user(username="email_change_user", email="old_email@example.com")
    session_tok, csrf_tok = await auth_session(user)

    # Request email change
    r_req = await client.post(
        "/api/auth/email-change-request",
        json={"current_password": pwd, "new_email": "new_email@example.com"},
        cookies={settings.SESSION_COOKIE_NAME: session_tok},
        headers={"X-CSRF-Token": csrf_tok},
    )
    assert r_req.status_code == 200

    # Retrieve generated token using auth_service helper or mock
    from src.services.auth_service import request_email_change, confirm_email_change
    raw_token = await request_email_change(
        db=db_session,
        user=user,
        current_password=pwd,
        new_email="verified_new@example.com",
    )

    r_confirm = await client.post(
        "/api/auth/email-change-confirm",
        json={"token": raw_token},
    )
    assert r_confirm.status_code == 200

    # Verify email was updated in DB
    await db_session.refresh(user)
    assert user.email == "verified_new@example.com"

    # Prior session is invalidated because security_version incremented
    r_me = await client.get(
        "/api/auth/me",
        cookies={settings.SESSION_COOKIE_NAME: session_tok},
    )
    assert r_me.status_code == 401



@pytest.mark.asyncio
async def test_session_of_a_user_disabled_directly_in_the_database_is_rejected(
    client: AsyncClient, create_user, auth_session, db_session: AsyncSession
):
    """Second layer: even WITHOUT a security_version bump (manual DB edit, a future code path), a disabled user's
    existing session must stop working."""
    from src.models.user import User
    user, _ = await create_user(username="manual_disable")
    session_tok, _ = await auth_session(user)
    ok = await client.get("/api/auth/me", cookies={settings.SESSION_COOKIE_NAME: session_tok})
    assert ok.status_code == 200
    await db_session.execute(update(User).where(User.id == user.id).values(is_active=False))   # no security_version change
    await db_session.commit()
    gone = await client.get("/api/auth/me", cookies={settings.SESSION_COOKIE_NAME: session_tok})
    assert gone.status_code == 401
