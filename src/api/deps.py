import hmac, uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from src.core.config import settings
from src.core.security import hash_token
from src.db.session import get_db
from src.models.session import Session
from src.models.user import User
from src.services.audit_service import log_event
from src.services.rate_limiter import get_client_ip

def _utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

def client_meta(request: Request) -> dict:
    return {"ip_address": get_client_ip(request), "user_agent": request.headers.get("user-agent", "unknown")[:512]}

@dataclass
class AuthContext:
    user: User
    session: Session
    # plain copies: ORM objects expire after a rollback, and refusals roll back before logging
    user_id: uuid.UUID = None
    username: str = ""
    role: str = ""
    session_id: uuid.UUID = None

def _401(msg: str):
    return HTTPException(status.HTTP_401_UNAUTHORIZED, msg)

async def current_auth(request: Request, db: AsyncSession = Depends(get_db)) -> AuthContext:
    raw = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if not raw:
        raise _401("Not authenticated")
    sess = (await db.execute(select(Session).where(Session.session_token_hash == hash_token(raw))
                             .execution_options(populate_existing=True))).scalar_one_or_none()
    if not sess or sess.revoked_at is not None:
        raise _401("Not authenticated")
    now = datetime.now(timezone.utc)
    if _utc(sess.expires_at) <= now:
        raise _401("Session expired: absolute limit reached")
    if now - _utc(sess.last_active_at) > timedelta(minutes=settings.SESSION_IDLE_TIMEOUT_MINUTES):
        raise _401("Session expired due to inactivity")
    user = (await db.execute(select(User).where(User.id == sess.user_id)
                             .execution_options(populate_existing=True))).scalar_one_or_none()
    if not user or not user.is_active or user.security_version != sess.user_security_version:
        raise _401("Session invalidated")
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        sent = request.headers.get("X-CSRF-Token")
        if not sent:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "CSRF token missing")
        if not hmac.compare_digest(hash_token(sent), sess.csrf_token_hash):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Invalid CSRF token")
    sess.last_active_at = now
    await db.commit()
    return AuthContext(user, sess, user.id, user.username, user.role, sess.id)

def require_role(role: str):
    async def _dep(ctx: AuthContext = Depends(current_auth)) -> AuthContext:
        if ctx.user.role != role:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Endpoint requires '{role}' role")
        return ctx
    return _dep


async def audit(db, ctx: AuthContext, request: Request, action: str, resource_type: str,
                resource_id=None, **metadata):
    """Audit row written in the caller's transaction: no mutation without its audit record."""
    await log_event(db=db, action=action, resource_type=resource_type,
                    resource_id=str(resource_id) if resource_id else None,
                    actor_id=ctx.user_id, actor_username=ctx.username, actor_role=ctx.role,
                    metadata=metadata, **client_meta(request))
