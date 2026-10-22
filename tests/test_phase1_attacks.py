"""Phase 1 'attack your own work' tests: auth, sessions, rate limiting, audit locking under real concurrency."""
import asyncio, re, uuid
import pytest, pytest_asyncio
from httpx import AsyncClient, ASGITransport
from starlette.requests import Request
from sqlalchemy import select
from src.core.config import settings
from src.db.session import get_db
from src.main import app
from src.models.audit import AuditLog
from src.services.audit_service import log_event, verify_audit_chain
from src.services.rate_limiter import check_rate_limit, get_client_ip
from tests.conftest import TestingSessionLocal
from tests.routes_util import all_api_routes

@pytest_asyncio.fixture
async def fresh_client(db_session):
    """Every request gets its OWN DB session/connection, so concurrency is real (the default client shares one)."""
    async def fresh_db():
        async with TestingSessionLocal() as s:
            yield s
    app.dependency_overrides[get_db] = fresh_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
        yield c
    app.dependency_overrides.clear()

def req(peer, xff=None):
    h = [(b"x-forwarded-for", xff.encode())] if xff else []
    return Request({"type": "http", "headers": h, "client": (peer, 1), "method": "GET", "path": "/"})

# --- 1. forwarded-IP spoofing --------------------------------------------------------------
def test_ip_resolution_uses_rightmost_untrusted_hop():
    assert get_client_ip(req("127.0.0.1", "6.6.6.6, 203.0.113.9")) == "203.0.113.9"          # proxy appended the real client
    assert get_client_ip(req("127.0.0.1", "6.6.6.6, 203.0.113.9, 127.0.0.1")) == "203.0.113.9"
    assert get_client_ip(req("198.51.100.7", "1.2.3.4")) == "198.51.100.7"                  # untrusted peer: header ignored
    assert get_client_ip(req("127.0.0.1")) == "127.0.0.1"

async def test_spoofed_xff_cannot_dodge_the_login_rate_limit(fresh_client):
    codes = []
    for i in range(7):
        r = await fresh_client.post("/api/auth/login", json={"username": f"nobody{i}", "password": "Wrong!Pass123"},
                                    headers={"X-Forwarded-For": f"10.9.8.{i}, 203.0.113.50"})   # varying leftmost = attacker-controlled
        codes.append(r.status_code)
    assert codes[:5] == [401] * 5 and codes[5:] == [429, 429], codes

# --- 2. rate limiter races -----------------------------------------------------------------
async def test_rate_limit_counter_is_atomic_under_concurrency(db_session):
    async def hit():
        async with TestingSessionLocal() as s:
            return (await check_rate_limit(s, "race", "k", 10, 60))[0]
    results = await asyncio.gather(*[hit() for _ in range(40)])
    assert sum(results) == 10, f"{sum(results)} requests were allowed through a limit of 10"

async def test_concurrent_password_guessing_still_locks_the_account(fresh_client, create_user):
    user, pwd = await create_user(username="victim")
    async def guess(i):
        return (await fresh_client.post("/api/auth/login", json={"username": "victim", "password": "Wrong!Pass123"},
                                        headers={"X-Forwarded-For": f"198.51.100.{i}"})).status_code
    await asyncio.gather(*[guess(i) for i in range(1, 13)])
    ok = await fresh_client.post("/api/auth/login", json={"username": "victim", "password": pwd},
                                 headers={"X-Forwarded-For": "198.51.100.99"})
    assert ok.status_code == 423, "12 parallel wrong guesses must have locked the account (lost-update race)"

# --- 3. audit lock cannot deadlock between requests ------------------------------------------
async def test_audit_chain_survives_concurrent_writers_without_deadlock(db_session):
    async def writer(n):
        async with TestingSessionLocal() as s:
            await log_event(s, f"W{n}_A", "system")
            await asyncio.sleep(0.05)            # hold the chain lock while others queue up
            await log_event(s, f"W{n}_B", "system")   # 2nd write in the same transaction must not wait on an in-process lock
            await s.commit()
    await asyncio.wait_for(asyncio.gather(*[writer(n) for n in range(8)]), timeout=20)
    async with TestingSessionLocal() as s:
        ok, total, broken = await verify_audit_chain(s)
    assert (ok, total, broken) == (True, 16, None)

# --- 4. sessions ---------------------------------------------------------------------------
async def _login(client, username, password):
    r = await client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return re.search(rf"{settings.SESSION_COOKIE_NAME}=([^;]+)", r.headers["set-cookie"]).group(1), r.json()["csrf_token"]

async def test_login_rotates_sessions_old_cookie_dies(fresh_client, create_user):
    user, pwd = await create_user(username="rot")
    old, _ = await _login(fresh_client, "rot", pwd)
    new, _ = await _login(fresh_client, "rot", pwd)
    me = lambda c: fresh_client.get("/api/auth/me", cookies={settings.SESSION_COOKIE_NAME: c})
    assert (await me(old)).status_code == 401 and (await me(new)).status_code == 200

async def test_disable_then_enable_does_not_resurrect_old_sessions(fresh_client, create_user, auth_session):
    admin, _ = await create_user(username="adm", role="admin"); a_s, a_c = await auth_session(admin)
    target, _ = await create_user(username="tgt"); t_s, _ = await auth_session(target)
    h = {"X-CSRF-Token": a_c}; ck = {settings.SESSION_COOKIE_NAME: a_s}
    for state in (False, True):
        r = await fresh_client.post(f"/api/admin/users/{target.id}/status", json={"is_active": state}, headers=h, cookies=ck)
        assert r.status_code == 200
    assert (await fresh_client.get("/api/auth/me", cookies={settings.SESSION_COOKIE_NAME: t_s})).status_code == 401

async def test_every_mutating_route_rejects_a_missing_csrf_header(fresh_client, create_user, auth_session):
    from tests.test_routes import PUBLIC
    user, _ = await create_user(username="csrf"); s, _ = await auth_session(user)
    checked = 0
    for r in all_api_routes(app):
        for m in r.methods & {"POST", "PUT", "PATCH", "DELETE"}:
            if (m, r.path) in PUBLIC or r.path == "/api/auth/logout" and False:
                continue
            path = re.sub(r"\{[^}]+\}", str(uuid.uuid4()), r.path)
            resp = await fresh_client.request(m, path, cookies={settings.SESSION_COOKIE_NAME: s}, json={})
            assert resp.status_code == 403 and "CSRF" in resp.text, (m, r.path, resp.status_code)
            checked += 1
    assert checked >= 15, f"only {checked} mutating routes were exercised"

async def test_disabled_account_state_is_not_probeable_without_the_password(fresh_client, create_user):
    await create_user(username="gone", is_active=False)
    probe = await fresh_client.post("/api/auth/login", json={"username": "gone", "password": "Wrong!Pass123"},
                                    headers={"X-Forwarded-For": "198.51.100.1"})
    ghost = await fresh_client.post("/api/auth/login", json={"username": "never_existed", "password": "Wrong!Pass123"},
                                    headers={"X-Forwarded-For": "198.51.100.2"})
    assert (probe.status_code, probe.json()) == (ghost.status_code, ghost.json()) == (401, {"detail": "Invalid credentials"})
