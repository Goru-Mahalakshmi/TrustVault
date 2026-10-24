"""Create the schema and apply role grants + the audit immutability trigger.
Run as the OWNER role:  OWNER_DATABASE_URL=postgresql+asyncpg://trustvault_owner:...@host/trustvault python -m scripts.init_db
The API itself connects as trustvault_app and can neither create tables nor touch the trigger."""
import asyncio, os, pathlib, sys
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from src.core.config import normalize_db_url
from src.db.base import Base
import src.models  # noqa: F401

SQL = pathlib.Path(__file__).resolve().parent.parent / "db" / "hardening.sql"

async def init(owner_url: str, drop_first: bool = False):
    eng = create_async_engine(normalize_db_url(owner_url))
    async with eng.begin() as c:
        if drop_first:
            await c.run_sync(Base.metadata.drop_all)
        await c.run_sync(Base.metadata.create_all)
        if eng.dialect.name == "postgresql":
            raw = await c.get_raw_connection()
            await raw.driver_connection.execute(SQL.read_text())     # multi-statement script via asyncpg
    await eng.dispose()

if __name__ == "__main__":
    url = os.environ.get("OWNER_DATABASE_URL") or sys.exit("set OWNER_DATABASE_URL (owner role, not the app role)")
    asyncio.run(init(url)); print("schema + hardening applied")
