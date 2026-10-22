"""Append the newest audit sequence + hash to a file kept OUTSIDE the app host/DB (e.g. a cloned separate git repo,
then `git commit && git push` from cron). Verify later: recompute the chain and compare to the anchored hash.
Usage: python -m scripts.anchor_audit /path/to/anchor-repo/anchors.log"""
import asyncio, sys
from datetime import datetime, timezone
from sqlalchemy import select
import src.db.session as db
from src.models.audit import AuditLog

async def main(path: str):
    async with db.AsyncSessionLocal() as s:
        row = (await s.execute(select(AuditLog.sequence_number, AuditLog.row_hash)
                               .order_by(AuditLog.sequence_number.desc()).limit(1))).first()
    if not row:
        print("audit log is empty; nothing to anchor"); return
    line = f"{datetime.now(timezone.utc).isoformat()} seq={row[0]} hash={row[1]}\n"
    with open(path, "a", encoding="utf-8") as f: f.write(line)
    print(line.strip())

if __name__ == "__main__":
    asyncio.run(main(sys.argv[1]))
