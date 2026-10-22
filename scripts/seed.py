"""Demo data: one account per role + sample documents and grants. Idempotent.
    python -m scripts.seed
Everything goes through the real API (in-process), so uploads, grants and the audit chain are produced by the same
code paths a user would exercise. Admin/viewer roles are set directly in the database because there is deliberately
no public way to become admin.

Demo passwords are PUBLIC (they are in the README). Override them with SEED_PASSWORD_<NAME> before seeding a
system that matters."""
import asyncio, os
import httpx
from sqlalchemy import select, update
import src.db.session as dbm
from src.main import app
from src.models.user import User

DEFAULTS = {"admin_demo": ("admin", "Admin!Demo-2026"), "owner_demo": ("owner", "Owner!Demo-2026"),
            "owner_two": ("owner", "Owner2!Demo-2026"), "viewer_demo": ("viewer", "Viewer!Demo-2026")}
PDF = b"%PDF-1.4\n% TrustVault demo document\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"

def password(name: str) -> str:
    return os.getenv(f"SEED_PASSWORD_{name.upper()}", DEFAULTS[name][1])

def client() -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://seed")   # https: Secure cookies are kept

async def login(name: str):
    c = client()
    r = await c.post("/api/auth/login", json={"username": name, "password": password(name)})
    r.raise_for_status()
    c.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    return c

async def upload(c, title, category, filename, data):
    r = await c.post("/api/documents", data={"title": title, "category": category}, files={"file": (filename, data)})
    r.raise_for_status()
    return r.json()["id"]

async def grant(c, doc, email, level):
    (await c.post(f"/api/documents/{doc}/grants", json={"grantee_email": email, "level": level})).raise_for_status()

async def run() -> dict:
    created = []
    async with dbm.AsyncSessionLocal() as s:
        existing = {u for (u,) in (await s.execute(select(User.username))).all()}
    async with client() as anon:
        for name in DEFAULTS:
            if name in existing:
                continue
            r = await anon.post("/api/auth/register", json={"username": name, "email": f"{name}@example.com", "password": password(name)})
            r.raise_for_status()
            created.append(name)
    async with dbm.AsyncSessionLocal() as s:
        for name in created:
            role = DEFAULTS[name][0]
            if role != "owner":
                await s.execute(update(User).where(User.username == name).values(role=role))
        await s.commit()

    owner = await login("owner_demo")
    if (await owner.get("/api/documents")).json()["total"] == 0:          # content only on a fresh database
        two = await login("owner_two")
        salary = await upload(owner, "Salary letter - A. Rao", "hr", "salary-letter.txt", b"Confidential: salary revision for A. Rao.\n")
        await upload(owner, "Contract - Acme Ltd", "legal", "acme-contract.pdf", PDF)        # shared with NOBODY
        minutes = await upload(owner, "Board minutes Q3", "finance", "board-minutes.txt", b"Minutes of the Q3 board meeting.\n")
        drawings = await upload(two, "Site drawings", "engineering", "site-drawings.pdf", PDF)
        (await two.post(f"/api/documents/{drawings}/versions", files={"file": ("site-drawings-v2.pdf", PDF + b"% rev 2\n")})).raise_for_status()
        await grant(owner, salary, "viewer_demo@example.com", "read")        # viewer sees ONLY this document
        await grant(owner, minutes, "owner_two@example.com", "read")
        await grant(two, drawings, "owner_demo@example.com", "edit")
        await two.aclose()
    await owner.aclose()
    return {"created_users": created}

if __name__ == "__main__":
    print(asyncio.run(run()))
    print("Demo accounts: " + ", ".join(f"{n} ({r})" for n, (r, _) in DEFAULTS.items()) + "  (passwords: see README)")
