import datetime as dt
import uuid
import pytest
from sqlalchemy import update
from src.models.document import Document
from tests.test_documents import actor, storage, shared, PDF  # noqa: F401  (fixtures + helpers)

async def titles(a, qs=""):
    r = (await a.req("GET", f"/api/documents?limit=100{qs}")).json()
    return sorted(i["title"] for i in r["items"]), r

async def test_search_by_name_is_case_insensitive_and_wildcards_are_literal(actor):
    a = await actor("alice")
    for t in ("Salary Letter", "salary review", "Contract 100%", "Drawing_A"):
        await a.upload(title=t)
    assert (await titles(a, "&q=SALARY"))[0] == ["Salary Letter", "salary review"]
    assert (await titles(a, "&q=%25"))[0] == ["Contract 100%"]            # '%' is a literal, not 'match everything'
    assert (await titles(a, "&q=_"))[0] == ["Drawing_A"]                  # '_' is a literal too
    assert (await titles(a, "&q=x'%20OR%201=1;--"))[0] == []              # injection string is just text

async def test_search_by_owner_category_and_date(actor):
    a, b = await actor("alice"), await actor("bob")
    d1 = (await a.upload(title="A1", category="hr")).json()["id"]
    await a.upload(title="A2", category="legal")
    d3 = (await b.upload(title="B1", category="hr")).json()["id"]
    await shared(a, b, doc=d1); await shared(b, a, doc=d3)
    assert (await titles(a, "&owner=bob"))[0] == ["B1"]
    assert (await titles(a, "&owner=alice"))[0] == ["A1", "A2"]
    assert (await titles(a, "&category=hr"))[0] == ["A1", "B1"]
    today = dt.date.today()
    assert len((await titles(a, f"&created_from={today}&created_to={today}"))[0]) == 3      # inclusive of 'today'
    assert (await titles(a, f"&created_to={today - dt.timedelta(days=1)}"))[0] == []
    assert (await titles(a, f"&created_from={today + dt.timedelta(days=1)}"))[0] == []
    assert (await a.req("GET", "/api/documents?created_from=not-a-date")).status_code == 422

async def test_search_results_counts_and_facets_never_leak_other_peoples_documents(actor):
    a, b = await actor("alice"), await actor("bob", "viewer")
    shared_doc = (await a.upload(title="shared", category="hr")).json()["id"]
    for i in range(5):
        await a.upload(title=f"secret{i}", category="payroll")
    await shared(a, b, doc=shared_doc)
    names, r = await titles(b)
    assert names == ["shared"] and r["total"] == 1
    assert r["facets"]["category"] == {"hr": 1}                           # no 'payroll' bucket, no counts of hidden docs
    names, r = await titles(b, "&q=secret")
    assert names == [] and r["total"] == 0 and r["facets"]["category"] == {}
    assert (await titles(b, "&owner=alice&category=payroll"))[1]["total"] == 0
    assert (await b.req("GET", "/api/documents?page=99")).json()["items"] == []

async def test_pagination_is_stable_and_complete(actor):
    a = await actor("alice")
    for i in range(7):
        await a.upload(title=f"t{i}")
    seen = []
    for page in (1, 2, 3):
        seen += [i["id"] for i in (await a.req("GET", f"/api/documents?limit=3&page={page}")).json()["items"]]
    assert len(seen) == 7 == len(set(seen))

async def test_revoked_and_deleted_documents_vanish_from_search(actor, db_session):
    a, b = await actor("alice"), await actor("bob", "viewer")
    doc, gid = await shared(a, b)
    assert (await titles(b))[0] == ["Doc"]
    await a.req("POST", f"/api/documents/{doc}/grants/{gid}/revoke")
    assert (await titles(b))[0] == []
    doc2, _ = await shared(a, b)
    await a.req("DELETE", f"/api/documents/{doc2}")
    assert (await titles(b))[0] == []

# ---------------- version history ----------------
async def test_version_history_and_old_version_download(actor):
    a, b, c = await actor("alice"), await actor("bob", "viewer"), await actor("carol")
    doc = (await a.upload()).json()["id"]
    await a.req("POST", f"/api/documents/{doc}/versions", files={"file": ("v2.pdf", PDF + b"-two")})
    vs = (await a.req("GET", f"/api/documents/{doc}/versions")).json()
    assert [v["version_number"] for v in vs] == [2, 1]
    assert (await a.req("GET", f"/api/documents/{doc}/versions/1/download")).content == PDF
    assert (await a.req("GET", f"/api/documents/{doc}/versions/2/download")).content == PDF + b"-two"
    assert (await a.req("GET", f"/api/documents/{doc}/versions/9/download")).status_code == 404
    # a stranger sees neither the list nor any version; a grantee loses it all on revoke
    for url in (f"/api/documents/{doc}/versions", f"/api/documents/{doc}/versions/1/download"):
        assert (await c.req("GET", url)).status_code == 404
    _, gid = await shared(a, b, doc=doc)
    assert (await b.req("GET", f"/api/documents/{doc}/versions/1/download")).content == PDF
    await a.req("POST", f"/api/documents/{doc}/grants/{gid}/revoke")
    for url in (f"/api/documents/{doc}/versions", f"/api/documents/{doc}/versions/1/download"):
        assert (await b.req("GET", url)).status_code == 404

async def test_expired_grants_vanish_from_search_and_facets(actor, db_session):
    from src.models.document import Grant
    a, b = await actor("alice"), await actor("bob", "viewer")
    doc, _ = await shared(a, b)
    names, r = await titles(b)
    assert names == ["Doc"] and r["facets"]["category"] == {"finance": 1}
    await db_session.execute(update(Grant).values(expires_at=dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)))
    await db_session.commit()
    names, r = await titles(b)
    assert names == [] and r["total"] == 0 and r["facets"]["category"] == {}
