"""The single authorisation kernel. Routes never decide permissions themselves."""
import enum, uuid
from typing import Optional, Tuple
from fastapi import HTTPException, Request
from sqlalchemy import select, or_, func
from sqlalchemy.ext.asyncio import AsyncSession
import src.db.session as db_module
from src.models.document import Document, Grant
from src.models.session import Session
from src.models.user import User
from src.services.audit_service import log_refusal, log_refusal_status

class Action(str, enum.Enum):
    READ = "read"; DOWNLOAD = "download"; EDIT = "edit"
    DELETE = "delete"; RESTORE = "restore"; ACCESS_LIST = "access_list"
    GRANT = "grant"; REVOKE = "revoke"; TRANSFER = "transfer"; TRANSFER_CANCEL = "transfer_cancel"
    TRANSFER_ACCEPT = "transfer_accept"; TRANSFER_REJECT = "transfer_reject"; AI_SUGGEST = "ai_suggest"

LEVEL_ACTIONS = {"read": {Action.READ, Action.DOWNLOAD}, "edit": {Action.READ, Action.DOWNLOAD, Action.EDIT}}
NOT_FOUND = HTTPException(404, "Document not found")

async def decide(db: AsyncSession, uid: uuid.UUID, doc_id: uuid.UUID, action: Action) -> Tuple[Optional[Document], str]:
    """Missing and ungranted documents run the SAME query and both come back 'notfound'.
    Admins get no special treatment: document access comes only from ownership or a live grant."""
    active = (select(Grant.level).where(
        Grant.document_id == Document.id, Grant.grantee_user_id == uid, Grant.revoked_at.is_(None),
        or_(Grant.expires_at.is_(None), Grant.expires_at > func.now()))
        .order_by(Grant.level.asc()).limit(1).scalar_subquery())          # 'edit' sorts before 'read'
    row = (await db.execute(select(Document, active.label("lvl")).where(
        Document.id == doc_id, or_(Document.owner_id == uid, active.is_not(None))))).first()
    if row is None:
        return None, "notfound"
    doc, lvl = row[0], row[1]
    rel = "owner" if doc.owner_id == uid else lvl
    if doc.is_deleted:                                    # grantees never see deleted docs; only the owner can restore
        return (doc, "allow") if (rel == "owner" and action == Action.RESTORE) else (None, "notfound")
    if action == Action.RESTORE:
        return None, "notfound"
    if rel == "owner":
        return doc, "allow"
    return (doc, "allow") if action in LEVEL_ACTIONS.get(rel, set()) else (doc, "forbid")

async def _refuse(db, ctx, request: Request, doc_id, action: Action, status: int, reason: str):
    from src.api.deps import client_meta
    actor = dict(actor_id=ctx.user_id, actor_username=ctx.username, actor_role=ctx.role)
    meta = client_meta(request)
    await db.rollback()                                   # release locks BEFORE the isolated refusal write
    _, retry = await log_refusal_status(action="ACCESS_REFUSED", resource_type="document", resource_id=str(doc_id)[:64],
                                        reason=reason, metadata={"action": action.value}, **actor, **meta)
    if retry:   # probing: same 429 whether or not the id exists, so it is not an existence oracle
        raise HTTPException(429, "Too many refused requests. Try again later.", headers={"Retry-After": str(retry)})
    if status == 404:
        raise HTTPException(404, "Document not found")
    raise HTTPException(403, "Insufficient permissions")

async def authorize(db, ctx, request: Request, doc_id: uuid.UUID, action: Action) -> Document:
    try:
        if action in (Action.TRANSFER_ACCEPT, Action.TRANSFER_REJECT):
            return await _authorize_pending(db, ctx, request, doc_id, action)
        doc, outcome = await decide(db, ctx.user_id, doc_id, action)
    except HTTPException:
        raise
    except Exception:                                      # deny by default
        await _refuse(db, ctx, request, doc_id, action, 404, "AUTHORIZATION_ERROR")
    if outcome == "allow":
        return doc
    await _refuse(db, ctx, request, doc_id, action,
                  404 if outcome == "notfound" else 403,
                  "NOT_FOUND_OR_UNGRANTED" if outcome == "notfound" else "INSUFFICIENT_PRIVILEGE")

async def _authorize_pending(db, ctx, request, doc_id, action):
    doc = (await db.execute(select(Document).where(Document.id == doc_id))).scalar_one_or_none()
    if doc is None:
        await _refuse(db, ctx, request, doc_id, action, 404, "NOT_FOUND_OR_UNGRANTED")
    if doc.pending_owner_id != ctx.user_id:
        # 404, not 403: a 403 here would tell ANY logged-in user that this document id exists.
        await _refuse(db, ctx, request, doc_id, action, 404, "NOT_PENDING_RECIPIENT")
    return doc

async def still_authorized(fresh: AsyncSession, uid, session_id, doc_id, action: Action) -> bool:
    """Live re-check on a fresh connection: user still active, session still valid, grant still live."""
    user = (await fresh.execute(select(User).where(User.id == uid))).scalar_one_or_none()
    sess = (await fresh.execute(select(Session).where(Session.id == session_id))).scalar_one_or_none()
    if not user or not user.is_active or not sess or sess.revoked_at is not None \
            or sess.user_security_version != user.security_version:
        return False
    _, outcome = await decide(fresh, uid, doc_id, action)
    return outcome == "allow"
