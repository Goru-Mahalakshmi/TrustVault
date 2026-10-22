from sqlalchemy import select, func
from src.models.document import Document
from src.models.user import User
from scripts import seed
from tests.test_documents import audit_rows  # noqa: F401

async def test_seed_builds_the_demo_world_and_is_idempotent(db_session, client):
    first = await seed.run()
    assert sorted(first["created_users"]) == sorted(seed.DEFAULTS)
    roles = {u.username: u.role for u in (await db_session.execute(select(User))).scalars()}
    assert roles == {n: r for n, (r, _) in seed.DEFAULTS.items()}
    docs = (await db_session.execute(select(func.count()).select_from(Document))).scalar_one()
    assert docs == 4
    again = await seed.run()
    assert again["created_users"] == []
    assert (await db_session.execute(select(func.count()).select_from(Document))).scalar_one() == docs

async def test_seeded_viewer_reaches_exactly_one_document_and_the_contract_is_unreachable(db_session):
    await seed.run()
    owner, viewer, admin = await seed.login("owner_demo"), await seed.login("viewer_demo"), await seed.login("admin_demo")
    mine = {d["title"]: d["id"] for d in (await owner.get("/api/documents")).json()["items"]}
    assert set(mine) == {"Salary letter - A. Rao", "Contract - Acme Ltd", "Board minutes Q3", "Site drawings"}   # own 3 + 1 granted
    seen = (await viewer.get("/api/documents")).json()
    assert [i["title"] for i in seen["items"]] == ["Salary letter - A. Rao"] and seen["total"] == 1
    assert (await viewer.get(f"/api/documents/{mine['Salary letter - A. Rao']}/download")).status_code == 200
    for title in ("Contract - Acme Ltd", "Board minutes Q3"):
        assert (await viewer.get(f"/api/documents/{mine[title]}/download")).status_code == 404
        assert (await admin.get(f"/api/documents/{mine[title]}/download")).status_code == 404     # admin: no content access
    assert (await admin.get("/api/admin/audit")).status_code == 200
    verify = (await admin.post("/api/admin/audit/verify")).json()
    assert verify["status"] == "VALID" and verify["total_records"] > 20
