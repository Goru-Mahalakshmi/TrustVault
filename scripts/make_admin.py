import asyncio, sys
from sqlalchemy import select
import src.db.session as db
from src.models.user import User

async def main(username: str):
    async with db.AsyncSessionLocal() as s:
        u = (await s.execute(select(User).where(User.username == username))).scalar_one_or_none()
        if not u: sys.exit(f"no such user: {username}")
        u.role, u.security_version = "admin", u.security_version + 1
        await s.commit(); print(f"{username} is now admin")

if __name__ == "__main__":
    asyncio.run(main(sys.argv[1]))
