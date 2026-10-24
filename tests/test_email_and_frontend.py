import re
import pytest
from sqlalchemy import select
from src.core.config import settings
from src.models.audit import AuditLog
from src.services import email_service
from tests.test_documents import actor, storage, PDF  # noqa: F401  (reuse fixtures)

@pytest.fixture(autouse=True)
def mail(monkeypatch):
    monkeypatch.setattr(settings, "EMAIL_BACKEND", "memory"); email_service.OUTBOX.clear()
    return email_service.OUTBOX

def token_in(mail_, n=-1): return re.search(r"#(?:reset|confirm-email)=([\w-]+)", mail_[n]["body"]).group(1)

async def test_forgot_password_is_generic_and_token_only_goes_by_email(client, create_user, mail, db_session):
    u, pwd = await create_user(username="dana")
    ok = await client.post("/api/auth/forgot-password", json={"email": u.email})
    no = await client.post("/api/auth/forgot-password", json={"email": "ghost@example.com"})
    assert ok.json() == no.json() and ok.status_code == no.status_code == 200
    assert len(mail) == 1 and mail[0]["to"] == u.email
    assert token_in(mail) not in ok.text
    r = await client.post("/api/auth/reset-password", json={"token": token_in(mail), "new_password": "Br@ndNewPass9"})
    assert r.status_code == 200
    assert (await client.post("/api/auth/reset-password", json={"token": token_in(mail), "new_password": "An0ther!Pass99"})).status_code == 400  # single use
    assert (await client.post("/api/auth/login", json={"username": "dana", "password": "Br@ndNewPass9"})).status_code == 200
    rows = (await db_session.execute(select(AuditLog))).scalars().all()
    assert not any(token_in(mail) in str(r.metadata_json) for r in rows)        # no secrets in the audit log

async def test_admin_reset_emails_user_not_admin(actor, mail):
    adm, u = await actor("root", "admin"), await actor("erin")
    r = await adm.req("POST", f"/api/admin/users/{u.user.id}/trigger-reset")
    assert r.status_code == 200 and mail[0]["to"] == u.email and token_in(mail) not in r.text

async def test_email_change_goes_to_old_address_and_confirm_works(actor, mail, client, db_session):
    a = await actor("fay")
    old = a.email
    r = await a.req("POST", "/api/auth/email-change-request", json={"current_password": "Str0ngP@ssw0rd!", "new_email": "fay2@example.com"})
    assert r.status_code == 200 and mail[0]["to"] == old
    r = await client.post("/api/auth/email-change-confirm", json={"token": token_in(mail)})
    assert r.status_code == 200
    await db_session.refresh(a.user); assert a.user.email == "fay2@example.com"
    assert (await a.req("GET", "/api/auth/me")).status_code == 401              # security_version bumped

async def test_me_returns_fresh_csrf_and_old_token_dies(actor):
    a = await actor("gus")
    first = (await a.req("GET", "/api/auth/me")).json()["csrf_token"]
    a.h = {"X-CSRF-Token": first}
    await a.req("GET", "/api/auth/me")                                          # rotates again
    r = await a.req("POST", "/api/auth/change-password", json={"current_password": "x", "new_password": "Str0ngP@ssw0rd!2"})
    assert r.status_code == 403

async def test_grant_creation_is_rate_limited_per_owner(actor):
    a = await actor("hal"); await actor("ivy", "viewer")
    doc = (await a.upload()).json()["id"]
    codes = [(await a.req("POST", f"/api/documents/{doc}/grants", json={"grantee_email": f"nobody{i}@example.com"})).status_code for i in range(12)]
    assert codes[:10] == [404] * 10 and codes[10:] == [429, 429]

async def test_frontend_served_with_strict_csp_and_no_inline_script(client):
    r = await client.get("/")
    assert r.status_code == 200 and "script-src 'self'" in r.headers["content-security-policy"]
    assert "<script>" not in r.text and "onclick=" not in r.text
    assert (await client.get("/static/app.js")).status_code == 200


async def test_forgot_password_is_limited_to_three_per_hour_per_ip_and_per_email(client, create_user, mail):
    u, _ = await create_user(username="rate")
    codes = [(await client.post("/api/auth/forgot-password", json={"email": f"who{i}@example.com"})).status_code for i in range(4)]
    assert codes == [200, 200, 200, 429]                                           # per IP, whatever the address
    other_ips = lambda i: {"X-Forwarded-For": f"198.51.100.{i}"}
    codes = [(await client.post("/api/auth/forgot-password", json={"email": u.email}, headers=other_ips(i))).status_code for i in range(10, 14)]
    assert codes == [200, 200, 200, 429]                                           # per email, even from different IPs
    r = await client.post("/api/auth/forgot-password", json={"email": u.email}, headers=other_ips(99))
    assert r.status_code == 429 and "Retry-After" in r.headers

async def test_registration_is_limited_to_five_per_minute_per_ip(client):
    codes = [(await client.post("/api/auth/register", json={"username": f"user{i}", "email": f"u{i}@example.com",
                                                            "password": "Compl3x!P@ssword123"})).status_code for i in range(7)]
    assert codes == [201] * 5 + [429, 429]

async def test_reset_and_email_change_links_live_fifteen_minutes_and_expired_ones_are_refused(client, create_user, db_session, mail):
    import datetime as dt
    from sqlalchemy import select, update
    from src.core.config import settings
    from src.models.auth_tokens import PasswordResetToken
    assert settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES == 15 and settings.EMAIL_CHANGE_TOKEN_EXPIRE_MINUTES == 15
    u, _ = await create_user(username="slow")
    await client.post("/api/auth/forgot-password", json={"email": u.email})
    row = (await db_session.execute(select(PasswordResetToken))).scalar_one()
    life = (row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=dt.timezone.utc)) - dt.datetime.now(dt.timezone.utc)
    assert dt.timedelta(minutes=14) < life <= dt.timedelta(minutes=15)
    await db_session.execute(update(PasswordResetToken).values(expires_at=dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1)))
    await db_session.commit()
    r = await client.post("/api/auth/reset-password", json={"token": token_in(mail), "new_password": "Br@ndNewPass9"})
    assert r.status_code == 400
