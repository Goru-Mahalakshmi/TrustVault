import io, os, uuid, zipfile
import pytest
from sqlalchemy import select, text, update
from src.core import crypto
from src.core.config import settings
from src.models.audit import AuditLog
from src.models.document import Grant
import src.db.session as dbm

PDF = b"%PDF-1.4 TOP-SECRET-PLAINTEXT-MARKER"

@pytest.fixture(autouse=True)
def storage(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "STORAGE_DIR", str(tmp_path / "files"))
    return tmp_path / "files"

class Actor:
    def __init__(self, client, user, sess, csrf):
        self.c, self.user = client, user
        self.cookies = {settings.SESSION_COOKIE_NAME: sess}
        self.h = {"X-CSRF-Token": csrf}
    async def req(self, method, url, **kw):
        return await self.c.request(method, url, cookies=self.cookies, headers=self.h, **kw)
    async def upload(self, data=PDF, name="a.pdf", title="Doc", category="finance"):
        return await self.req("POST", "/api/documents", data={"title": title, "category": category},
                              files={"file": (name, data)})

@pytest.fixture
def actor(client, create_user, auth_session):
    async def _make(username, role="owner"):
        u, _ = await create_user(username=username, role=role)
        s, c = await auth_session(u)
        a = Actor(client, u, s, c); a.email = u.email; a.uid = u.id        # plain copy: ORM objects expire on rollback
        return a
    return _make

async def audit_rows(db_session, action):
    return (await db_session.execute(select(AuditLog).where(AuditLog.action == action))).scalars().all()

async def shared(a, b, level="read", doc=None):
    doc = doc or (await a.upload()).json()["id"]
    r = await a.req("POST", f"/api/documents/{doc}/grants", json={"grantee_email": b.email, "level": level})
    assert r.status_code == 201, r.text
    return doc, r.json()["grant_id"]

async def test_roundtrip_encrypted_at_rest_and_headers(actor, storage):
    a = await actor("alice")
    doc = (await a.upload(name='../../x"y.pdf')).json()["id"]
    blob = open(os.path.join(storage, os.listdir(storage)[0]), "rb").read()
    assert b"PLAINTEXT-MARKER" not in blob
    r = await a.req("GET", f"/api/documents/{doc}/download")
    assert r.status_code == 200 and r.content == PDF
    cd = r.headers["content-disposition"]
    assert cd.startswith("attachment;") and ".." not in cd and "/" not in cd.split("filename=")[1].split(";")[0]
    assert r.headers["x-content-type-options"] == "nosniff" and "sandbox" in r.headers["content-security-policy"]

async def test_viewer_and_admin_cannot_upload(actor):
    for role in ("viewer", "admin"):
        a = await actor(f"u_{role}", role)
        assert (await a.upload()).status_code == 403

async def test_stranger_and_missing_are_identical_404_and_audited(actor, db_session):
    a, b = await actor("alice"), await actor("bob")
    doc = (await a.upload()).json()["id"]
    r1 = await b.req("GET", f"/api/documents/{doc}")
    r2 = await b.req("GET", f"/api/documents/{uuid.uuid4()}")
    assert (r1.status_code, r1.json()) == (r2.status_code, r2.json()) == (404, {"detail": "Document not found"})
    assert len(await audit_rows(db_session, "ACCESS_REFUSED")) == 2

async def test_admin_without_grant_gets_404(actor):
    a, adm = await actor("alice"), await actor("root", "admin")
    doc = (await a.upload()).json()["id"]
    assert (await adm.req("GET", f"/api/documents/{doc}/download")).status_code == 404
    assert (await adm.req("GET", "/api/documents")).json()["total"] == 0

async def test_grant_levels_and_instant_revocation(actor):
    a, b = await actor("alice"), await actor("bob", "viewer")
    doc, gid = await shared(a, b, "read")
    assert (await b.req("GET", f"/api/documents/{doc}/download")).content == PDF
    up = await b.req("POST", f"/api/documents/{doc}/versions", files={"file": ("n.pdf", PDF + b"2")})
    assert up.status_code == 403                                    # read grant: exists, but not allowed
    assert (await b.req("DELETE", f"/api/documents/{doc}")).status_code == 403
    assert (await b.req("GET", f"/api/documents/{doc}/grants")).status_code == 403
    # upgrade to edit -> versions allowed, newest version downloads
    await shared(a, b, "edit", doc)
    up = await b.req("POST", f"/api/documents/{doc}/versions", files={"file": ("n.pdf", PDF + b"2")})
    assert up.status_code == 201 and up.json()["version_number"] == 2
    assert (await a.req("GET", f"/api/documents/{doc}/download")).content == PDF + b"2"
    gid2 = (await a.req("GET", f"/api/documents/{doc}/grants")).json()
    live = [g for g in gid2 if g["revoked_at"] is None][0]["id"]
    assert (await a.req("POST", f"/api/documents/{doc}/grants/{live}/revoke")).status_code == 200
    assert (await b.req("GET", f"/api/documents/{doc}/download")).status_code == 404

async def test_revoked_mid_download_releases_zero_bytes(actor, db_session, monkeypatch):
    a, b = await actor("alice"), await actor("bob", "viewer")
    doc, gid = await shared(a, b)
    import datetime as dt
    from src.api import documents as docs_api
    real = docs_api.still_authorized
    async def revoke_then_recheck(*args, **kw):
        # The owner's revoke COMMITS after decryption finished but before the response is released
        async with dbm.AsyncSessionLocal() as s:
            await s.execute(update(Grant).values(revoked_at=dt.datetime.now(dt.timezone.utc)))
            await s.commit()
        return await real(*args, **kw)
    monkeypatch.setattr(docs_api, "still_authorized", revoke_then_recheck)
    r = await b.req("GET", f"/api/documents/{doc}/download")
    assert r.status_code == 404 and PDF not in r.content
    assert await audit_rows(db_session, "DOCUMENT_DOWNLOAD") == []

async def test_tampered_ciphertext_never_released(actor, storage):
    a = await actor("alice")
    doc = (await a.upload()).json()["id"]
    p = os.path.join(storage, os.listdir(storage)[0]); raw = open(p, "rb").read()
    open(p, "wb").write(raw[:-1] + bytes([raw[-1] ^ 1]))
    r = await a.req("GET", f"/api/documents/{doc}/download")
    assert r.status_code == 500 and PDF not in r.content

async def test_soft_delete_restore_preserves_grants(actor):
    a, b = await actor("alice"), await actor("bob", "viewer")
    doc, _ = await shared(a, b)
    assert (await a.req("DELETE", f"/api/documents/{doc}")).status_code == 200
    assert (await b.req("GET", f"/api/documents/{doc}/download")).status_code == 404
    assert (await b.req("POST", f"/api/documents/{doc}/restore")).status_code == 404
    assert (await a.req("POST", f"/api/documents/{doc}/restore")).status_code == 200
    assert (await b.req("GET", f"/api/documents/{doc}/download")).status_code == 200

async def test_grant_rules(actor):
    a, b = await actor("alice"), await actor("bob", "viewer")
    doc = (await a.upload()).json()["id"]
    g = lambda **kw: a.req("POST", f"/api/documents/{doc}/grants", json=kw)
    assert (await g(grantee_email=a.email)).status_code == 400                    # self-grant
    assert (await g(grantee_email="nobody@example.com")).status_code == 404
    assert (await g(grantee_email=b.email, expires_at="2020-01-01T00:00:00Z")).status_code == 400
    assert (await g(grantee_email=b.email, level="admin")).status_code == 422
    assert (await g(grantee_email=b.email, role="x")).status_code == 422          # extra=forbid

async def test_two_step_transfer(actor):
    a, b, c, v = await actor("alice"), await actor("bob"), await actor("carol"), await actor("vic", "viewer")
    doc, _ = await shared(a, c)                                                   # carol holds a grant
    assert (await a.req("POST", f"/api/documents/{doc}/transfer-request", json={"target_email": v.email})).status_code == 400
    assert (await a.req("POST", f"/api/documents/{doc}/transfer-request", json={"target_email": b.email})).status_code == 200
    pend = (await b.req("GET", "/api/documents/pending-transfers")).json()
    assert pend == [{"document_id": doc, "category": "finance", "from_username": "alice"}]
    assert (await b.req("GET", f"/api/documents/{doc}/download")).status_code == 404   # no access pre-acceptance
    r_other = await c.req("POST", f"/api/documents/{doc}/transfer-accept")
    r_missing = await c.req("POST", f"/api/documents/{uuid.uuid4()}/transfer-accept")
    assert (r_other.status_code, r_other.json()) == (r_missing.status_code, r_missing.json()) == (404, {"detail": "Document not found"})
    assert (await b.req("POST", f"/api/documents/{doc}/transfer-accept")).status_code == 200
    assert (await a.req("GET", f"/api/documents/{doc}/download")).status_code == 404   # old owner keeps nothing
    assert (await b.req("GET", f"/api/documents/{doc}/download")).status_code == 200
    assert (await c.req("GET", f"/api/documents/{doc}/download")).status_code == 200   # existing grant survives

async def test_transfer_reject_cancel_and_delete_cancels(actor):
    a, b = await actor("alice"), await actor("bob")
    doc = (await a.upload()).json()["id"]
    req = lambda: a.req("POST", f"/api/documents/{doc}/transfer-request", json={"target_email": b.email})
    await req(); assert (await b.req("POST", f"/api/documents/{doc}/transfer-reject")).status_code == 200
    await req(); assert (await b.req("POST", f"/api/documents/{doc}/transfer-cancel")).status_code == 404
    assert (await a.req("POST", f"/api/documents/{doc}/transfer-cancel")).status_code == 200
    await req(); await a.req("DELETE", f"/api/documents/{doc}")
    assert (await b.req("GET", "/api/documents/pending-transfers")).json() == []

async def test_upload_validation(actor):
    a = await actor("alice")
    bomb = io.BytesIO()
    with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as z: z.writestr("a", b"0" * 20_000_000)
    for data, name in [(b"MZ\x90\x00" + b"x" * 40, "evil.pdf"), (b"<svg onload=1>", "x.png"),
                       (b"<html><script>", "x.txt"), (bomb.getvalue(), "b.docx"), (PDF, "x.exe")]:
        assert (await a.upload(data, name)).status_code == 400, name

async def test_search_is_permission_filtered_and_paginated(actor):
    a, b = await actor("alice"), await actor("bob", "viewer")
    d1 = (await a.upload(title="one")).json()["id"]; await a.upload(title="two")
    await shared(a, b, doc=d1)
    r = (await b.req("GET", "/api/documents?limit=1")).json()
    assert r["total"] == 1 and len(r["items"]) == 1
    assert (await a.req("GET", "/api/documents?sort=title;DROP TABLE users")).status_code == 422
    assert (await a.req("GET", "/api/documents")).json()["total"] == 2

async def test_admin_audit_endpoints(actor):
    a, adm = await actor("alice"), await actor("root", "admin")
    await a.upload()
    assert (await adm.req("POST", "/api/admin/audit/verify")).json()["status"] == "VALID"
    assert (await a.req("POST", "/api/admin/audit/verify")).status_code == 403
    assert (await adm.req("GET", "/api/admin/audit")).status_code == 200
    assert (await adm.req("GET", "/api/admin/dashboard")).status_code == 200

async def test_app_role_cannot_modify_audit_rows(actor, db_session):
    """Layer 1: DB grants. The runtime role has INSERT + SELECT only on audit_logs."""
    from sqlalchemy.exc import DBAPIError
    a = await actor("alice"); await a.upload()
    for sql in ("update audit_logs set actor_username='forged'", "delete from audit_logs", "truncate audit_logs"):
        with pytest.raises(DBAPIError) as e:
            await db_session.execute(text(sql))
        assert "permission denied" in str(e.value).lower(), sql
        await db_session.rollback()
    assert len(await audit_rows(db_session, "DOCUMENT_UPLOAD")) == 1

async def test_immutability_trigger_blocks_even_the_owner(actor, as_owner):
    """Layer 2: the trigger. The schema OWNER can neither UPDATE nor DELETE nor TRUNCATE."""
    from sqlalchemy.exc import DBAPIError
    a = await actor("alice"); await a.upload()
    for sql in ("update audit_logs set actor_username='forged'", "delete from audit_logs", "truncate audit_logs"):
        with pytest.raises(DBAPIError) as e:
            await as_owner(sql)
        assert "append-only" in str(e.value), sql

async def test_deliberate_trigger_bypass_is_still_detected_by_the_chain(actor, as_owner):
    """Layer 3: a DBA who DISABLES the trigger and edits history still breaks the HMAC chain (key is not in the DB).
    What this does NOT stop: someone who also holds AUDIT_HMAC_KEY can recompute the chain; only anchoring detects that."""
    a, adm = await actor("alice"), await actor("root", "admin")
    await a.upload()
    assert (await adm.req("POST", "/api/admin/audit/verify")).json()["status"] == "VALID"
    await as_owner("alter table audit_logs disable trigger audit_logs_no_change")
    await as_owner("update audit_logs set actor_username='forged' where sequence_number=1")
    await as_owner("alter table audit_logs enable trigger audit_logs_no_change")
    r = (await adm.req("POST", "/api/admin/audit/verify")).json()
    assert r == {"status": "CORRUPTED", "broken_sequence": 1}
    assert (await adm.req("GET", "/api/admin/dashboard")).json()["failed_audit_verifications"] >= 1

async def test_ai_suggestions_are_advisory_and_validated(actor, db_session, monkeypatch):
    from src.services import ai_service
    a, b = await actor("alice"), await actor("bob", "viewer")
    d1 = (await a.upload()).json()["id"]; await shared(a, b, doc=d1)
    d2 = (await a.upload(title="Q3")).json()["id"]
    assert (await a.req("POST", f"/api/documents/{d2}/grantee-suggestions")).status_code == 503
    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "test")
    seen = {}
    async def fake(prompt):
        seen["p"] = prompt
        return f'[{{"user_id": "{b.user.id}", "reason": "past collaborator"}}, {{"user_id": "{uuid.uuid4()}", "reason": "hallucinated"}}]'
    monkeypatch.setattr(ai_service, "_call_model", fake)
    r = await a.req("POST", f"/api/documents/{d2}/grantee-suggestions")
    assert [s["user_id"] for s in r.json()["suggestions"]] == [str(b.user.id)]
    assert "TOP-SECRET" not in seen["p"] and b.email not in seen["p"]
    assert len((await db_session.execute(select(Grant))).scalars().all()) == 1       # nothing was granted
    assert (await b.req("POST", f"/api/documents/{d2}/grantee-suggestions")).status_code == 404

async def test_probing_is_throttled_with_429_and_never_silently_dropped(actor, db_session):
    import datetime as dt
    a = await actor("prober"); adm = await actor("root2", "admin")
    codes = [(await a.req("GET", f"/api/documents/{uuid.uuid4()}")).status_code for _ in range(25)]
    assert codes[:20] == [404] * 20 and codes[20:] == [429] * 5
    r = await a.req("GET", f"/api/documents/{uuid.uuid4()}")
    assert r.status_code == 429 and "retry-after" in r.headers and r.json() != {"detail": "Document not found"}
    assert len(await audit_rows(db_session, "ACCESS_REFUSED")) == 20            # audit table cannot be flooded
    # make the suppression window look old, then the admin dashboard must report it as ONE aggregate event
    from src.models.rate_limit import RateLimitBucket
    await db_session.execute(update(RateLimitBucket).where(RateLimitBucket.key.like("refsupp:%"))
                             .values(window_start=dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=5)))
    await db_session.commit()
    assert (await adm.req("GET", "/api/admin/dashboard")).status_code == 200
    agg = await audit_rows(db_session, "REFUSALS_RATE_LIMITED_AGGREGATE")
    assert len(agg) == 1 and agg[0].metadata_json["suppressed_count"] == 6

async def test_refusal_never_waits_on_a_lock_held_by_the_same_request(db_session):
    """The request's own session holds an uncommitted audit write (SQLite write lock / PG advisory lock).
    authorize() must roll that back BEFORE the isolated refusal write, so the refusal cannot wait on it."""
    import asyncio
    from types import SimpleNamespace
    from fastapi import HTTPException
    from starlette.requests import Request
    from src.services.audit_service import log_event
    from src.services.authz import authorize, Action
    req = Request({"type": "http", "headers": [], "client": ("127.0.0.1", 1), "method": "GET", "path": "/"})
    ctx = SimpleNamespace(user_id=uuid.uuid4(), username="u", role="owner")
    async with dbm.AsyncSessionLocal() as s:
        await log_event(s, "PENDING_IN_SAME_REQUEST", "system")            # flushed, NOT committed: lock is held
        with pytest.raises(HTTPException) as e:
            await asyncio.wait_for(authorize(s, ctx, req, uuid.uuid4(), Action.READ), timeout=5)
        assert e.value.status_code == 404
    assert len(await audit_rows(db_session, "ACCESS_REFUSED")) == 1          # refusal persisted
    assert await audit_rows(db_session, "PENDING_IN_SAME_REQUEST") == []     # request's own work was rolled back

async def test_restore_on_a_live_document_is_a_404_for_everyone_including_the_owner(actor):
    a, b = await actor("alice"), await actor("bob", "viewer")
    doc, _ = await shared(a, b, "edit")
    for who in (a, b):                                   # nothing to restore: no 403 that would confirm existence/state
        r = await who.req("POST", f"/api/documents/{doc}/restore")
        assert (r.status_code, r.json()) == (404, {"detail": "Document not found"})

async def test_recipient_demoted_before_accepting_cannot_accept(actor, db_session, auth_session):
    a, b, adm = await actor("alice"), await actor("bob"), await actor("root", "admin")
    doc = (await a.upload()).json()["id"]
    assert (await a.req("POST", f"/api/documents/{doc}/transfer-request", json={"target_email": b.email})).status_code == 200
    assert (await adm.req("POST", f"/api/admin/users/{b.user.id}/role", json={"role": "viewer"})).status_code == 200
    await db_session.refresh(b.user)
    s, c = await auth_session(b.user)                    # fresh session after the role change (old one was killed)
    b2 = Actor(b.c, b.user, s, c)
    assert (await b2.req("POST", f"/api/documents/{doc}/transfer-accept")).status_code == 400
    assert (await a.req("GET", f"/api/documents/{doc}")).status_code == 200      # alice still owns it

async def test_cannot_transfer_a_document_to_yourself(actor):
    a = await actor("alice")
    doc = (await a.upload()).json()["id"]
    r = await a.req("POST", f"/api/documents/{doc}/transfer-request", json={"target_email": a.email})
    assert r.status_code == 400
    assert (await a.req("GET", "/api/documents/pending-transfers")).json() == []
