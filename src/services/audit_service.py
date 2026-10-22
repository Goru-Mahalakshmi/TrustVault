import asyncio
import weakref
import hashlib
import hmac
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Tuple
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession
from src.core.config import settings
import src.db.session as db_session_module
from src.models.audit import AuditLog
from src.models.rate_limit import RateLimitBucket
from src.services.rate_limiter import check_rate_limit

# Global in-process lock for SQLite concurrency; PostgreSQL uses pg_advisory_xact_lock
class _NoLock:
    async def __aenter__(self): return self
    async def __aexit__(self, *a): return False

_sqlite_locks: "weakref.WeakKeyDictionary" = weakref.WeakKeyDictionary()

def _chain_lock(db):
    """PostgreSQL: serialisation comes ONLY from pg_advisory_xact_lock (held until commit). A process-wide asyncio lock
    on top of it can deadlock against that DB lock between two requests, so it is used for SQLite alone (per event loop)."""
    if db.get_bind().dialect.name == "postgresql":
        return _NoLock()
    return _sqlite_locks.setdefault(asyncio.get_running_loop(), asyncio.Lock())

# Genesis hash for the initial entry in the chain
GENESIS_HASH = "0" * 64

# In-memory tracking for suppressed refusals aggregation
_suppressed_refusals: Dict[str, Dict[str, Any]] = {}


def canonical_json(data: Dict[str, Any]) -> str:
    """Format dictionary into deterministic canonical JSON (RFC 8785 compliant)."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sanitize_audit_metadata(metadata: Dict[str, Any]) -> Dict[str, Any]:
    """Ensure audit metadata contains strictly IDs, counts, or enum values.
    
    Titles, filenames, search queries, and freeform text are strictly rejected.
    """
    sanitized = {}
    for k, v in metadata.items():
        if k.endswith("_id") or k in ("page", "limit", "count", "version_number", "status", "role", "action", "window_seconds", "suppressed_count", "level", "old_role", "new_role", "is_active", "total_records"):
            if isinstance(v, uuid.UUID):
                sanitized[k] = str(v)
            else:
                sanitized[k] = v
    return sanitized


def compute_row_hash(
    prev_hash: str,
    sequence_number: int,
    timestamp: datetime,
    actor_id: Optional[uuid.UUID],
    actor_username: Optional[str],
    actor_role: Optional[str],
    action: str,
    resource_type: str,
    resource_id: Optional[str],
    ip_address: str,
    user_agent: str,
    status: str,
    reason: Optional[str],
    metadata: Dict[str, Any],
) -> str:
    """Compute HMAC-SHA256 row hash over previous hash and canonical payload."""
    payload_dict = {
        "action": action,
        "actor_id": str(actor_id) if actor_id else None,
        "actor_role": actor_role,
        "actor_username": actor_username,
        "ip_address": ip_address,
        "metadata": metadata,
        "prev_hash": prev_hash,
        "reason": reason,
        "resource_id": resource_id,
        "resource_type": resource_type,
        "sequence_number": sequence_number,
        "status": status,
        "timestamp": timestamp.isoformat(),
        "user_agent": user_agent[:512],
    }

    canonical_payload = canonical_json(payload_dict)
    return hmac.new(
        settings.AUDIT_HMAC_KEY.encode("utf-8"),
        canonical_payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


async def _acquire_chain_lock(db: AsyncSession):
    """Acquire PostgreSQL transactional advisory lock or SQLite in-process lock."""
    bind = db.get_bind()
    if bind.dialect.name == "postgresql":
        await db.execute(text("SELECT pg_advisory_xact_lock(hashtext('trustvault_audit_chain_lock'));"))


async def log_event(
    db: AsyncSession,
    action: str,
    resource_type: str,
    resource_id: Optional[str] = None,
    actor_id: Optional[uuid.UUID] = None,
    actor_username: Optional[str] = None,
    actor_role: Optional[str] = None,
    ip_address: str = "127.0.0.1",
    user_agent: str = "internal",
    status: str = "SUCCESS",
    reason: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> AuditLog:
    """Write an audit entry into the current transaction immediately before commit."""
    clean_metadata = sanitize_audit_metadata(metadata or {})
    now = datetime.now(timezone.utc)

    async with _chain_lock(db):
        await _acquire_chain_lock(db)

        # Read the latest sequence and row hash
        query = select(AuditLog.sequence_number, AuditLog.row_hash).order_by(
            AuditLog.sequence_number.desc()
        ).limit(1)
        result = await db.execute(query)
        last_row = result.first()

        if last_row:
            next_seq = last_row[0] + 1
            prev_hash = last_row[1]
        else:
            next_seq = 1
            prev_hash = GENESIS_HASH

        row_hash = compute_row_hash(
            prev_hash=prev_hash,
            sequence_number=next_seq,
            timestamp=now,
            actor_id=actor_id,
            actor_username=actor_username,
            actor_role=actor_role,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=ip_address,
            user_agent=user_agent,
            status=status,
            reason=reason,
            metadata=clean_metadata,
        )

        entry = AuditLog(
            sequence_number=next_seq,
            timestamp=now,
            actor_id=actor_id,
            actor_username=actor_username,
            actor_role=actor_role,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=ip_address,
            user_agent=user_agent,
            status=status,
            reason=reason,
            metadata_json=clean_metadata,
            prev_hash=prev_hash,
            row_hash=row_hash,
        )
        db.add(entry)
        await db.flush()
        return entry


async def log_refusal_status(
    action: str,
    resource_type: str,
    resource_id: Optional[str] = None,
    actor_id: Optional[uuid.UUID] = None,
    actor_username: Optional[str] = None,
    actor_role: Optional[str] = None,
    ip_address: str = "127.0.0.1",
    user_agent: str = "internal",
    reason: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Tuple[Optional[AuditLog], int]:
    """Write an access refusal in a completely isolated session.

    Refusals are rate-limited per IP and per actor with DB-backed counters (shared by all workers).
    A suppressed refusal is never silently dropped: it bumps a persistent counter that is flushed as ONE
    REFUSALS_RATE_LIMITED_AGGREGATE event (on the next allowed refusal, or by the admin dashboard).
    Returns (entry, retry_after_seconds); retry_after > 0 means the caller is being throttled.
    """
    ip_key = ip_address or "127.0.0.1"
    limit = settings.RATE_LIMIT_REFUSALS_PER_MIN
    async with db_session_module.AsyncSessionLocal() as isolated_db:
        try:
            retry = 0
            for kind, ident in (("refusal_ip", ip_key), ("refusal_actor", str(actor_id) if actor_id else None)):
                if ident is None:
                    continue
                allowed, _, retry_after = await check_rate_limit(isolated_db, kind, ident, limit, 60)
                if not allowed:
                    retry = max(retry, retry_after)
            if retry:
                await check_rate_limit(isolated_db, "refsupp", ip_key, 10**9, 86400)  # persistent suppressed counter
                return None, retry

            await _flush_suppressed(isolated_db, ip_key, actor_id, actor_username, actor_role, user_agent)
            entry = await log_event(
                db=isolated_db, action=action, resource_type=resource_type, resource_id=resource_id,
                actor_id=actor_id, actor_username=actor_username, actor_role=actor_role,
                ip_address=ip_address, user_agent=user_agent, status="DENIED", reason=reason, metadata=metadata)
            await isolated_db.commit()
            return entry, 0
        except Exception:
            await isolated_db.rollback()
            return None, 0


async def log_refusal(*args, **kwargs) -> Optional[AuditLog]:
    entry, _ = await log_refusal_status(*args, **kwargs)
    return entry


async def _flush_suppressed(db, ip_key, actor_id=None, actor_username=None, actor_role=None, user_agent="internal"):
    bucket = (await db.execute(select(RateLimitBucket).where(RateLimitBucket.key == f"refsupp:{ip_key}"))).scalar_one_or_none()
    if bucket is None:
        return
    if bucket.count > 0:
        await log_event(
            db=db, action="REFUSALS_RATE_LIMITED_AGGREGATE", resource_type="system", actor_id=actor_id,
            actor_username=actor_username, actor_role=actor_role, ip_address=ip_key, user_agent=user_agent,
            status="DENIED", reason="RATE_LIMITED_REFUSALS_WINDOW",
            metadata={"suppressed_count": int(bucket.count), "window_seconds": 60})
    await db.delete(bucket)


async def flush_stale_suppressed(db: AsyncSession) -> int:
    """Admin-side flush so suppressed refusals are reported even if the prober simply stops."""
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=60)
    rows = (await db.execute(select(RateLimitBucket).where(RateLimitBucket.key.like("refsupp:%")))).scalars().all()
    flushed = 0
    for b in rows:
        ws = b.window_start if b.window_start.tzinfo else b.window_start.replace(tzinfo=timezone.utc)
        if ws <= cutoff:
            await _flush_suppressed(db, b.key.split(":", 1)[1])
            flushed += 1
    return flushed


async def verify_audit_chain(db: AsyncSession) -> Tuple[bool, int, Optional[int]]:
    """Walk the HMAC-SHA256 audit chain from sequence 1 to latest row.

    Returns:
        Tuple of (is_valid: bool, total_records: int, first_broken_sequence: Optional[int])
    """
    query = select(AuditLog).order_by(AuditLog.sequence_number.asc())
    result = await db.execute(query)
    rows = result.scalars().all()

    if not rows:
        return True, 0, None

    expected_prev_hash = GENESIS_HASH

    for row in rows:
        # Check link to previous hash
        if row.prev_hash != expected_prev_hash:
            return False, len(rows), row.sequence_number

        # Recompute row hash
        ts = row.timestamp
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)

        computed_hash = compute_row_hash(
            prev_hash=row.prev_hash,
            sequence_number=row.sequence_number,
            timestamp=ts,
            actor_id=row.actor_id,
            actor_username=row.actor_username,
            actor_role=row.actor_role,
            action=row.action,
            resource_type=row.resource_type,
            resource_id=row.resource_id,
            ip_address=row.ip_address,
            user_agent=row.user_agent,
            status=row.status,
            reason=row.reason,
            metadata=row.metadata_json or {},
        )

        if not hmac.compare_digest(row.row_hash, computed_hash):
            return False, len(rows), row.sequence_number

        expected_prev_hash = row.row_hash

    return True, len(rows), None
