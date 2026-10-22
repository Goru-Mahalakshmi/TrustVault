import ipaddress
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple
from fastapi import Request, HTTPException, status
from sqlalchemy import case
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession
from src.core.config import settings
from src.models.rate_limit import RateLimitBucket


def _is_trusted_proxy(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for entry in settings.TRUSTED_PROXIES:
        try:
            if addr in ipaddress.ip_network(entry.strip(), strict=False):
                return True
        except ValueError:
            continue
    return False


def get_client_ip(request: Request) -> str:
    """Client IP. Forwarded headers are honoured ONLY when the direct peer is a trusted proxy, and then we take the
    RIGHTMOST entry that is not itself a trusted proxy: that is the address our proxy actually saw. The leftmost entry
    is client-controlled and must never be used."""
    direct_ip = request.client.host if request.client else "127.0.0.1"
    if not _is_trusted_proxy(direct_ip):
        return direct_ip
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        for hop in reversed([h.strip() for h in forwarded_for.split(",") if h.strip()]):
            if not _is_trusted_proxy(hop):
                return hop
    return direct_ip


async def check_rate_limit(
    db: AsyncSession,
    key_prefix: str,
    identifier: str,
    limit: int,
    window_seconds: int = 60,
) -> Tuple[bool, int, int]:
    """Atomic DB-backed fixed-window counter (one INSERT .. ON CONFLICT DO UPDATE .. RETURNING statement), so
    concurrent requests from any number of workers cannot lose updates or crash on the first-hit race.
    Blocked requests still count; the window resets on schedule.

    Returns (allowed, current_count, retry_after_seconds).
    """
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=window_seconds)
    bucket_key = f"{key_prefix}:{identifier}"
    insert = pg_insert if db.get_bind().dialect.name == "postgresql" else sqlite_insert
    expired = RateLimitBucket.window_start <= cutoff
    stmt = (
        insert(RateLimitBucket)
        .values(key=bucket_key, count=1, window_start=now, updated_at=now)
        .on_conflict_do_update(
            index_elements=[RateLimitBucket.key],
            set_={
                "count": case((expired, 1), else_=RateLimitBucket.count + 1),
                "window_start": case((expired, now), else_=RateLimitBucket.window_start),
                "updated_at": now,
            },
        )
        .returning(RateLimitBucket.count, RateLimitBucket.window_start)
    )
    count, window_start = (await db.execute(stmt)).one()
    await db.commit()
    if window_start.tzinfo is None:
        window_start = window_start.replace(tzinfo=timezone.utc)
    if count <= limit:
        return True, count, 0
    retry_after = max(1, int(window_seconds - (now - window_start).total_seconds()) + 1)
    return False, count, retry_after


async def enforce_rate_limit(
    db: AsyncSession,
    request: Request,
    key_prefix: str,
    limit: int,
    window_seconds: int = 60,
    identifier: Optional[str] = None,
):
    """Enforce rate limit or raise HTTP 429."""
    if not identifier:
        identifier = get_client_ip(request)

    allowed, current_count, retry_after = await check_rate_limit(
        db=db,
        key_prefix=key_prefix,
        identifier=identifier,
        limit=limit,
        window_seconds=window_seconds,
    )

    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)},
        )
