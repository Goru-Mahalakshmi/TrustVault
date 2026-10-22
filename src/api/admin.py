import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from src.api.deps import AuthContext, require_role, audit
from src.db.session import get_db
from src.models.audit import AuditLog
from src.models.user import User
from src.schemas import UserRead, UserRoleUpdate, UserStatusUpdate, GenericMessageResponse
from src.services.auth_service import request_password_reset
from src.services.audit_service import verify_audit_chain, flush_stale_suppressed
from src.services.email_service import send_reset_email

router = APIRouter(prefix="/api/admin", tags=["admin"])
# Deliberately NO password or email endpoints, and no document-content endpoints.
admin_only = require_role("admin")

async def _target(db, user_id: uuid.UUID) -> User:
    u = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not u:
        raise HTTPException(404, "User not found")
    return u

@router.get("/users", response_model=list[UserRead])
async def list_users(ctx: AuthContext = Depends(admin_only), db: AsyncSession = Depends(get_db)):
    return (await db.execute(select(User).order_by(User.created_at))).scalars().all()

@router.post("/users/{user_id}/role", response_model=UserRead)
async def change_role(user_id: uuid.UUID, body: UserRoleUpdate, request: Request,
                      ctx: AuthContext = Depends(admin_only), db: AsyncSession = Depends(get_db)):
    u = await _target(db, user_id)
    if u.id == ctx.user_id:
        raise HTTPException(400, "Admins cannot change their own role")
    old = u.role
    u.role = body.role.value
    u.security_version += 1                      # kills the target's sessions immediately
    await audit(db, ctx, request, "ADMIN_ROLE_CHANGED", "user", u.id, target_user_id=str(u.id),
                old_role=old, new_role=u.role)
    await db.commit()
    return u

@router.post("/users/{user_id}/status", response_model=UserRead)
async def set_status(user_id: uuid.UUID, body: UserStatusUpdate, request: Request,
                     ctx: AuthContext = Depends(admin_only), db: AsyncSession = Depends(get_db)):
    u = await _target(db, user_id)
    if u.id == ctx.user_id:
        raise HTTPException(400, "Admins cannot disable themselves")
    u.is_active = body.is_active
    u.security_version += 1
    await audit(db, ctx, request, "ADMIN_USER_STATUS_CHANGED", "user", u.id, target_user_id=str(u.id),
                is_active=u.is_active)
    await db.commit()
    return u

@router.post("/users/{user_id}/trigger-reset", response_model=GenericMessageResponse)
async def trigger_reset(user_id: uuid.UUID, request: Request, ctx: AuthContext = Depends(admin_only),
                        db: AsyncSession = Depends(get_db)):
    u = await _target(db, user_id)
    from src.api.deps import client_meta
    _, token = await request_password_reset(db, u.email, **client_meta(request))
    await audit(db, ctx, request, "ADMIN_PASSWORD_RESET_TRIGGERED", "user", u.id, target_user_id=str(u.id))
    await db.commit()
    if token:
        await send_reset_email(u.email, token)          # token goes to the user's inbox only, never to the admin
    return GenericMessageResponse(message="Password reset triggered; instructions sent to the user's email")

@router.get("/audit")
async def view_audit(request: Request, page: int = Query(1, ge=1), limit: int = Query(50, ge=1, le=200),
                     ctx: AuthContext = Depends(admin_only), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(AuditLog).order_by(AuditLog.sequence_number.desc())
                             .offset((page - 1) * limit).limit(limit))).scalars().all()
    await audit(db, ctx, request, "AUDIT_LOG_VIEW", "audit", page=page, limit=limit)   # viewing is itself audited
    await db.commit()
    return [{"sequence_number": r.sequence_number, "timestamp": r.timestamp, "actor_id": r.actor_id,
             "action": r.action, "status": r.status, "reason": r.reason, "resource_type": r.resource_type,
             "resource_id": r.resource_id, "metadata": r.metadata_json} for r in rows]

@router.post("/audit/verify")
async def verify_chain(request: Request, ctx: AuthContext = Depends(admin_only), db: AsyncSession = Depends(get_db)):
    ok, total, broken = await verify_audit_chain(db)
    last = (await db.execute(select(AuditLog.row_hash).order_by(AuditLog.sequence_number.desc()).limit(1))).scalar()
    await audit(db, ctx, request, "AUDIT_CHAIN_VERIFY", "audit", status="VALID" if ok else "CORRUPTED")
    await db.commit()
    return ({"status": "VALID", "total_records": total, "last_hash": last} if ok
            else {"status": "CORRUPTED", "broken_sequence": broken})

@router.get("/dashboard")
async def dashboard(request: Request, ctx: AuthContext = Depends(admin_only), db: AsyncSession = Depends(get_db)):
    await flush_stale_suppressed(db)
    await db.commit()
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    rows = (await db.execute(select(AuditLog).where(AuditLog.timestamp >= since))).scalars().all()
    refused = Counter(f"user:{r.actor_id}" if r.actor_id else f"ip:{r.ip_address}"
                      for r in rows if r.action == "ACCESS_REFUSED")
    counts = Counter(r.action for r in rows)
    out = {"window_hours": 24,
           "repeated_refusals": [{"subject": k, "count": v} for k, v in refused.items() if v >= 3],
           "role_changes": counts["ADMIN_ROLE_CHANGED"],
           "admin_triggered_resets": counts["ADMIN_PASSWORD_RESET_TRIGGERED"],
           "failed_audit_verifications": sum(1 for r in rows if r.action == "AUDIT_CHAIN_VERIFY"
                                             and (r.metadata_json or {}).get("status") == "CORRUPTED"),
           "login_failures": counts["AUTH_LOGIN_FAILURE"]}
    await audit(db, ctx, request, "ADMIN_DASHBOARD_VIEW", "audit")
    await db.commit()
    return out
