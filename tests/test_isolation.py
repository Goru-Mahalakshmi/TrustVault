"""Isolation suite. Every route that takes a document id is discovered FROM THE APP, so a new document route cannot
ship without joining this suite (test_payload_table_covers_every_document_route fails until it is added)."""
import datetime as dt
import uuid
import pytest
from sqlalchemy import update
from src.main import app
from src.models.document import Grant
from tests.routes_util import all_api_routes
from tests.test_documents import actor, storage, shared, PDF  # noqa: F401

PAYLOADS = {
    ("GET", "/api/documents/{doc_id}"): {},
    ("GET", "/api/documents/{doc_id}/download"): {},
    ("GET", "/api/documents/{doc_id}/versions"): {},
    ("GET", "/api/documents/{doc_id}/versions/{version_number}/download"): {},
    ("POST", "/api/documents/{doc_id}/versions"): {"files": {"file": ("n.pdf", PDF + b"x")}},
    ("DELETE", "/api/documents/{doc_id}"): {},
    ("POST", "/api/documents/{doc_id}/restore"): {},
    ("GET", "/api/documents/{doc_id}/grants"): {},
    ("POST", "/api/documents/{doc_id}/grants"): {"json": {"grantee_email": "x@example.com"}},
    ("POST", "/api/documents/{doc_id}/grants/{grant_id}/revoke"): {},
    ("POST", "/api/documents/{doc_id}/transfer-request"): {"json": {"target_email": "x@example.com"}},
    ("POST", "/api/documents/{doc_id}/transfer-accept"): {},
    ("POST", "/api/documents/{doc_id}/transfer-reject"): {},
    ("POST", "/api/documents/{doc_id}/transfer-cancel"): {},
    ("POST", "/api/documents/{doc_id}/grantee-suggestions"): {},
    ("POST", "/api/documents/{doc_id}/grantee-suggestions/{suggestion_id}/decisions"):
        {"json": {"user_id": "00000000-0000-4000-8000-000000000001", "action": "reject"}},
}
DOC_ROUTES = sorted((m, r.path) for r in all_api_routes(app) if "{doc_id}" in r.path for m in r.methods - {"HEAD"})

def test_payload_table_covers_every_document_route():
    assert set(DOC_ROUTES) == set(PAYLOADS), (set(DOC_ROUTES) ^ set(PAYLOADS))
    assert len(DOC_ROUTES) >= 14

def _call(a, method, template, doc_id):
    url = (template.replace("{doc_id}", str(doc_id)).replace("{grant_id}", str(uuid.uuid4()))
           .replace("{version_number}", "1").replace("{suggestion_id}", str(uuid.uuid4())))
    return a.req(method, url, **PAYLOADS[(method, template)])

async def _same_as_missing(a, method, template, doc, who):
    real, ghost = await _call(a, method, template, doc), await _call(a, method, template, uuid.uuid4())
    assert real.status_code == 404, f"{who}: {method} {template} -> {real.status_code} {real.text[:120]}"
    assert (real.status_code, real.json()) == (ghost.status_code, ghost.json()), \
        f"{who}: {method} {template} answers differently for a real vs a missing document"

@pytest.mark.parametrize("method,template", DOC_ROUTES, ids=[f"{m} {p.replace('/api/documents/', '')}" for m, p in DOC_ROUTES])
async def test_user_b_cannot_reach_user_a_document_on_any_route(actor, db_session, method, template):
    a, b = await actor("alice"), await actor("bob")
    viewer, admin = await actor("vera", "viewer"), await actor("root", "admin")
    doc = (await a.upload()).json()["id"]
    boss = await actor("boss", "admin")

    # 1. never granted: another owner, a viewer, and an admin (admins have no content access)
    for who, label in ((b, "other owner"), (viewer, "viewer"), (admin, "admin")):
        await _same_as_missing(who, method, template, doc, label)

    # 2. granted, then revoked
    _, gid = await shared(a, b, "edit", doc)
    assert (await b.req("GET", f"/api/documents/{doc}")).status_code == 200      # grant really worked
    await a.req("POST", f"/api/documents/{doc}/grants/{gid}/revoke")
    await _same_as_missing(b, method, template, doc, "after revoke")

    # 3. granted, then expired (clock moved by rewriting expires_at into the past)
    await shared(a, b, "edit", doc)
    await db_session.execute(update(Grant).where(Grant.revoked_at.is_(None)).values(
        expires_at=dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)))
    await db_session.commit()
    await _same_as_missing(b, method, template, doc, "after expiry")

    # nothing above may have changed anything
    assert (await a.req("GET", f"/api/documents/{doc}")).json()["versions"] == 1
    assert len((await a.req("GET", f"/api/documents/{doc}/grants")).json()) == 2

    # 4. granted, then the owner soft-deletes: grantees lose access to everything, including restore
    await shared(a, b, "edit", doc)
    assert (await a.req("DELETE", f"/api/documents/{doc}")).status_code == 200
    await _same_as_missing(b, method, template, doc, "while deleted")

    # 5. a role change kills the grantee's existing session outright
    await a.req("POST", f"/api/documents/{doc}/restore")
    await shared(a, b, "edit", doc)
    r = await boss.req("POST", f"/api/admin/users/{b.user.id}/role", json={"role": "viewer"})
    assert r.status_code == 200
    assert (await _call(b, method, template, doc)).status_code == 401

async def test_other_users_documents_do_not_appear_in_audit_or_admin_views(actor):
    a, b, adm = await actor("alice"), await actor("bob"), await actor("root", "admin")
    doc = (await a.upload(title="TOP-SECRET-TITLE")).json()["id"]
    assert (await b.req("GET", "/api/admin/audit")).status_code == 403
    assert (await b.req("GET", "/api/admin/dashboard")).status_code == 403
    assert (await b.req("GET", "/api/documents")).json()["total"] == 0
    # even for the admin the audit shows ids only: no titles, filenames or contents
    rows = (await adm.req("GET", "/api/admin/audit")).text
    assert "TOP-SECRET-TITLE" not in rows and "a.pdf" not in rows and "PLAINTEXT" not in rows
    assert (await adm.req("GET", f"/api/documents/{doc}")).status_code == 404

async def test_admin_cannot_demote_or_disable_themselves(actor):
    adm = await actor("root", "admin")
    assert (await adm.req("POST", f"/api/admin/users/{adm.user.id}/role", json={"role": "viewer"})).status_code == 400
    assert (await adm.req("POST", f"/api/admin/users/{adm.user.id}/status", json={"is_active": False})).status_code == 400


async def test_unauthorised_requests_are_stopped_before_any_decryption(actor, db_session, monkeypatch):
    """Defence in depth means the pre-send re-check would also refuse a stranger, hiding a deleted first gate.
    This test pins the first gate: no file is read or decrypted for someone who is not allowed, and the audit
    names the first gate (NOT_FOUND_OR_UNGRANTED), not the late re-check (REVOKED_DURING_DOWNLOAD)."""
    from src.core import crypto
    from tests.test_documents import audit_rows
    calls = []
    real = crypto.decrypt_file
    monkeypatch.setattr(crypto, "decrypt_file", lambda *a, **k: (calls.append(1), real(*a, **k))[1])
    a, b = await actor("alice"), await actor("bob")
    doc = (await a.upload()).json()["id"]
    urls = (f"/api/documents/{doc}/download", f"/api/documents/{doc}/versions/1/download")
    for url in urls:
        assert (await b.req("GET", url)).status_code == 404
    _, gid = await shared(a, b)
    await a.req("POST", f"/api/documents/{doc}/grants/{gid}/revoke")
    for url in urls:
        assert (await b.req("GET", url)).status_code == 404
    assert calls == [], "decryption ran for an unauthorised caller"
    reasons = {r.reason for r in await audit_rows(db_session, "ACCESS_REFUSED")}
    assert reasons == {"NOT_FOUND_OR_UNGRANTED"}, reasons
