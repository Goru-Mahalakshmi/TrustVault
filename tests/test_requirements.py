"""One test group per requirement in the challenge brief that was not already proven elsewhere:
organise/manage (metadata, trash), owner + admin activity views, upload throttling, and the HTTP-level basics."""
import json
import os
import uuid
import pytest
from sqlalchemy import select, text
from src.core.config import settings, normalize_db_url
from src.models.audit import AuditLog
from tests.test_documents import actor, storage, shared, audit_rows, PDF  # noqa: F401

# ---------------- organise / manage: metadata ----------------
async def test_owner_can_rename_and_recategorise_and_it_is_audited(actor, db_session):
    a = await actor("alice")
    doc = (await a.upload(title="Draft", category="hr")).json()["id"]
    r = await a.req("PATCH", f"/api/documents/{doc}", json={"title": "Final", "category": "legal"})
    assert r.status_code == 200 and r.json()["title"] == "Final" and r.json()["category"] == "legal"
    items = (await a.req("GET", "/api/documents?q=final&category=legal")).json()["items"]
    assert [i["id"] for i in items] == [doc]                                      # search sees the new labels
    assert (await a.req("GET", "/api/documents?q=draft")).json()["total"] == 0
    rows = await audit_rows(db_session, "DOCUMENT_METADATA_UPDATE")
    assert len(rows) == 1 and rows[0].metadata_json == {"document_id": doc, "count": 2}
    assert "Final" not in json.dumps(rows[0].metadata_json) and "legal" not in json.dumps(rows[0].metadata_json)

async def test_only_the_owner_may_relabel_even_with_an_edit_grant(actor):
    a, b = await actor("alice"), await actor("bob", "viewer")
    doc, _ = await shared(a, b, "edit")
    r = await b.req("PATCH", f"/api/documents/{doc}", json={"title": "hijacked"})
    assert r.status_code == 403                                                    # relationship exists, so 403 (not 404)
    assert (await a.req("GET", f"/api/documents/{doc}")).json()["title"] == "Doc"

@pytest.mark.parametrize("body", [{}, {"title": ""}, {"title": "x" * 201}, {"category": "c" * 101}, {"title": "ok", "owner_id": "x"},
                                  {"is_deleted": True}, {"title": None, "category": None}])
async def test_metadata_edit_rejects_bad_or_extra_fields(actor, body):
    a = await actor("alice")
    doc = (await a.upload()).json()["id"]
    assert (await a.req("PATCH", f"/api/documents/{doc}", json=body)).status_code == 422

async def test_changing_a_category_never_changes_who_can_see_the_document(actor):
    a, b = await actor("alice"), await actor("bob", "viewer")
    doc = (await a.upload(category="public")).json()["id"]
    await a.req("PATCH", f"/api/documents/{doc}", json={"category": "hr"})
    assert (await b.req("GET", f"/api/documents/{doc}")).status_code == 404
    assert (await b.req("GET", "/api/documents?category=hr")).json()["total"] == 0

# ---------------- organise / manage: trash and restore ----------------
async def test_trash_lists_only_my_deleted_documents_and_restore_empties_it(actor):
    a, b = await actor("alice"), await actor("bob", "viewer")
    doc, _ = await shared(a, b)
    other = (await a.upload(title="kept")).json()["id"]
    assert (await a.req("GET", "/api/documents/trash")).json() == []
    await a.req("DELETE", f"/api/documents/{doc}")
    t = (await a.req("GET", "/api/documents/trash")).json()
    assert [x["id"] for x in t] == [doc] and other not in [x["id"] for x in t]
    assert (await b.req("GET", "/api/documents/trash")).json() == []               # a grantee has no trash entry for it
    assert (await b.req("GET", "/api/documents?limit=50")).json()["total"] == 0
    assert (await a.req("POST", f"/api/documents/{doc}/restore")).status_code == 200
    assert (await a.req("GET", "/api/documents/trash")).json() == []
    assert (await b.req("GET", f"/api/documents/{doc}")).status_code == 200         # grant came back with it

# ---------------- owner: who touched my document ----------------
async def test_owner_sees_every_access_including_refused_attempts_and_the_view_is_audited(actor, db_session):
    a, b, c = await actor("alice"), await actor("bob", "viewer"), await actor("mallory")
    doc, gid = await shared(a, b)
    await b.req("GET", f"/api/documents/{doc}/download")                           # permitted
    await c.req("GET", f"/api/documents/{doc}/download")                           # refused: mallory was never granted
    await a.req("POST", f"/api/documents/{doc}/grants/{gid}/revoke")
    other = (await a.upload(title="elsewhere")).json()["id"]
    await c.req("GET", f"/api/documents/{other}/download")                         # a refusal on a DIFFERENT document
    log = (await a.req("GET", f"/api/documents/{doc}/audit")).json()
    assert other not in json.dumps(log), "events of another document leaked into this document's history"
    assert all(r["action"] != "DOCUMENT_UPLOAD" or r["metadata"]["document_id"] == doc for r in log)
    seen = {(r["action"], r["actor_username"], r["status"]) for r in log}
    assert {("DOCUMENT_UPLOAD", "alice", "SUCCESS"), ("PERMISSION_GRANT", "alice", "SUCCESS"),
            ("DOCUMENT_DOWNLOAD", "bob", "SUCCESS"), ("ACCESS_REFUSED", "mallory", "DENIED"),
            ("PERMISSION_REVOKE", "alice", "SUCCESS")} <= seen
    assert "a.pdf" not in json.dumps(log) and "Doc" not in json.dumps([r["metadata"] for r in log])   # ids only
    assert len(await audit_rows(db_session, "DOCUMENT_AUDIT_VIEW")) == 1
    seqs = [r["sequence_number"] for r in log]; assert seqs == sorted(seqs, reverse=True)

async def test_only_the_owner_can_read_a_documents_audit_history(actor):
    a, b, c, adm = await actor("alice"), await actor("bob", "viewer"), await actor("carol"), await actor("root", "admin")
    doc, _ = await shared(a, b, "edit")
    assert (await b.req("GET", f"/api/documents/{doc}/audit")).status_code == 403   # grantee: relationship exists
    assert (await c.req("GET", f"/api/documents/{doc}/audit")).status_code == 404   # stranger: concealed
    assert (await adm.req("GET", f"/api/documents/{doc}/audit")).status_code == 404  # admin has no document access

# ---------------- admin: document activity and permission changes ----------------
async def _mixed_activity(actor):
    a, b, c, adm = await actor("alice"), await actor("bob", "viewer"), await actor("mallory"), await actor("root", "admin")
    doc, gid = await shared(a, b)
    await b.req("GET", f"/api/documents/{doc}/download")
    await c.req("GET", f"/api/documents/{doc}/download")
    await a.req("POST", f"/api/documents/{doc}/grants/{gid}/revoke")
    dave = await actor("dave")                                                      # someone ELSE's status changes, so mallory's session stays valid
    await adm.req("POST", f"/api/admin/users/{dave.uid}/status", json={"is_active": True})
    return a, b, c, adm, doc

async def test_admin_activity_view_filters_document_activity_and_permission_changes(actor):
    a, b, c, adm, doc = await _mixed_activity(actor)
    get = lambda q: adm.req("GET", f"/api/admin/audit?limit=200&{q}")
    docs = {r["action"] for r in (await get("kind=document")).json()}
    perms = {r["action"] for r in (await get("kind=permission")).json()}
    admin = {r["action"] for r in (await get("kind=admin")).json()}
    assert {"DOCUMENT_UPLOAD", "DOCUMENT_DOWNLOAD", "ACCESS_REFUSED"} <= docs and "PERMISSION_GRANT" not in docs
    assert {"PERMISSION_GRANT", "PERMISSION_REVOKE"} <= perms and "DOCUMENT_DOWNLOAD" not in perms
    assert "ADMIN_USER_STATUS_CHANGED" in admin
    denied = (await get("status=DENIED")).json()
    assert denied and all(r["status"] == "DENIED" for r in denied) and {r["actor_username"] for r in denied} == {"mallory"}
    assert {r["action"] for r in (await get("actor=bob")).json()} == {"DOCUMENT_DOWNLOAD"}
    only_doc = (await get(f"resource_id={doc}")).json()
    assert only_doc and all(r["resource_id"] == doc for r in only_doc)
    assert {r["action"] for r in (await get("action=PERMISSION_REVOKE")).json()} == {"PERMISSION_REVOKE"}
    assert (await get("kind=everything")).status_code == 422 and (await get("status=maybe")).status_code == 422
    assert (await get("since=2999-01-01T00:00:00Z")).json() == []

async def test_admin_activity_view_has_ids_only_and_is_closed_to_everyone_else(actor):
    a, b, c, adm, doc = await _mixed_activity(actor)
    text_ = (await adm.req("GET", "/api/admin/audit?limit=200")).text
    assert "a.pdf" not in text_ and '"Doc"' not in text_ and "PLAINTEXT" not in text_
    for who in (a, b, c):
        assert (await who.req("GET", "/api/admin/audit")).status_code == 403

# ---------------- upload throttling ----------------
async def test_uploads_are_rate_limited_per_user(actor, monkeypatch):
    monkeypatch.setattr(settings, "RATE_LIMIT_UPLOADS_PER_MIN", 3)
    a, b = await actor("alice"), await actor("bob")
    codes = [(await a.upload()).status_code for _ in range(5)]
    assert codes == [201, 201, 201, 429, 429]
    assert (await b.upload()).status_code == 201                                   # per user, not global
    doc = (await b.req("GET", "/api/documents")).json()["items"][0]["id"]
    assert (await b.req("POST", f"/api/documents/{doc}/versions", files={"file": ("v.pdf", PDF + b"2")})).status_code == 201

# ---------------- HTTP-level basics ----------------
async def test_head_and_options_do_not_open_side_doors(actor, client):
    a = await actor("alice")
    doc = (await a.upload()).json()["id"]
    for url in (f"/api/documents/{doc}/download", f"/api/documents/{doc}", "/api/documents"):
        assert (await a.req("HEAD", url)).status_code == 405
    r = await client.options(f"/api/documents/{doc}/download", headers={"Origin": "https://evil.example",
                             "Access-Control-Request-Method": "GET"})
    assert "access-control-allow-origin" not in r.headers
    r = await a.c.request("GET", f"/api/documents/{doc}", cookies=a.cookies, headers={**a.h, "Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in r.headers and r.headers["x-frame-options"] == "DENY"

async def test_unauthenticated_requests_get_no_information(client):
    for method, url in (("GET", "/api/documents"), ("GET", f"/api/documents/{uuid.uuid4()}"), ("GET", "/api/documents/trash"),
                        ("GET", "/api/admin/audit"), ("POST", "/api/documents")):
        r = await client.request(method, url)
        assert r.status_code == 401 and r.json() == {"detail": "Not authenticated"}, (method, url)

# ---------------- storage in the database (hosts without a persistent disk) ----------------
async def test_database_storage_backend_is_encrypted_revocable_and_leaves_no_files(actor, db_session, storage, monkeypatch):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "db")
    a, b = await actor("alice"), await actor("bob", "viewer")
    doc, gid = await shared(a, b)
    assert not os.path.exists(storage) or os.listdir(storage) == []                 # nothing written to disk
    blob = (await db_session.execute(text("select blob from document_versions"))).scalar_one()
    assert blob and b"PLAINTEXT" not in bytes(blob) and PDF not in bytes(blob)       # ciphertext only
    assert (await b.req("GET", f"/api/documents/{doc}/download")).content == PDF
    await a.req("POST", f"/api/documents/{doc}/versions", files={"file": ("v2.pdf", PDF + b"-2")})
    assert (await a.req("GET", f"/api/documents/{doc}/versions/1/download")).content == PDF
    assert "blob" not in (await a.req("GET", f"/api/documents/{doc}/versions")).text
    await a.req("POST", f"/api/documents/{doc}/grants/{gid}/revoke")
    assert (await b.req("GET", f"/api/documents/{doc}/download")).status_code == 404

async def test_database_storage_detects_tampering(actor, as_owner, monkeypatch):
    monkeypatch.setattr(settings, "STORAGE_BACKEND", "db")
    a = await actor("alice")
    doc = (await a.upload()).json()["id"]
    await as_owner("update document_versions set blob = set_byte(blob, 0, get_byte(blob, 0) # 1)")   # flip one bit
    r = await a.req("GET", f"/api/documents/{doc}/download")
    assert r.status_code == 500 and PDF not in r.content

def test_host_style_database_urls_are_normalised():
    assert normalize_db_url("postgres://u:p@h/db") == "postgresql+asyncpg://u:p@h/db"
    assert normalize_db_url("postgresql://u:p@h:5432/db?sslmode=require") == "postgresql+asyncpg://u:p@h:5432/db?ssl=require"
    assert normalize_db_url("postgresql+asyncpg://u:p@h/db") == "postgresql+asyncpg://u:p@h/db"

async def test_new_versions_count_toward_the_upload_limit_too(actor, monkeypatch):
    monkeypatch.setattr(settings, "RATE_LIMIT_UPLOADS_PER_MIN", 3)
    a = await actor("alice")
    doc = (await a.upload()).json()["id"]                                          # 1
    codes = [(await a.req("POST", f"/api/documents/{doc}/versions", files={"file": ("v.pdf", PDF + bytes([i]))})).status_code
             for i in range(4)]                                                     # 2, 3, then over the limit
    assert codes == [201, 201, 429, 429]

async def test_viewing_the_audit_log_and_the_dashboard_is_itself_audited(actor, db_session):
    adm = await actor("root", "admin")
    assert (await adm.req("GET", "/api/admin/audit")).status_code == 200
    assert (await adm.req("GET", "/api/admin/dashboard")).status_code == 200
    views = await audit_rows(db_session, "AUDIT_LOG_VIEW")
    assert len(views) == 1 and views[0].actor_username == "root" and views[0].actor_role == "admin"
    assert len(await audit_rows(db_session, "ADMIN_DASHBOARD_VIEW")) == 1
    seen = {r["action"] for r in (await adm.req("GET", "/api/admin/audit?kind=admin")).json()}
    assert {"AUDIT_LOG_VIEW", "ADMIN_DASHBOARD_VIEW"} <= seen                       # the admin's own looking is in the record
