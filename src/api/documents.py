import asyncio, os, uuid
from datetime import date, datetime, time, timedelta, timezone
from typing import Literal, Optional
from urllib.parse import quote
from cryptography.exceptions import InvalidTag
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, Response, UploadFile
from sqlalchemy import select, or_, func, update
from sqlalchemy.ext.asyncio import AsyncSession
import src.db.session as db_module
from src.api.deps import AuthContext, current_auth, audit, client_meta
from src.core import crypto, uploads
from src.core.config import settings
from src.db.session import get_db
from src.models.document import Document, DocumentVersion, Grant
from src.models.user import User
from src.schemas.document import GrantCreate, GrantRead, TransferRequest
from src.services import ai_service
from src.services.audit_service import log_refusal
from src.services.authz import Action, authorize, still_authorized
from src.services.rate_limiter import enforce_rate_limit

router = APIRouter(prefix="/api/documents", tags=["documents"])
_decrypt_sem = asyncio.Semaphore(settings.MAX_CONCURRENT_DECRYPTS)

# ---------------- helpers ----------------
async def _read_upload(file: UploadFile):
    data = await file.read(settings.MAX_UPLOAD_BYTES + 1)
    if len(data) > settings.MAX_UPLOAD_BYTES:
        raise HTTPException(413, "File exceeds the 25MB limit")
    name = uploads.safe_filename(file.filename or "file")
    if (err := uploads.validate_upload(name, data)):
        raise HTTPException(400, err)
    return data, name

async def _add_version(db, doc, user_id, name, data, number) -> DocumentVersion:
    ver_id = uuid.uuid4()
    enc = crypto.encrypt_file(data, doc.id, ver_id)
    path = crypto.storage_path(doc.id, ver_id)
    crypto.write_blob(path, enc.pop("ciphertext"))
    ver = DocumentVersion(id=ver_id, document_id=doc.id, version_number=number, original_filename=name,
                          mime_type=uploads.MIME[os.path.splitext(name.lower())[1]], file_size_bytes=len(data),
                          storage_path=path, uploaded_by=user_id, **enc)
    db.add(ver)
    return ver

async def _commit_or_cleanup(db, *paths):
    try:
        await db.commit()
    except Exception:
        for p in paths:
            if os.path.exists(p): os.remove(p)
        raise

async def _latest(db, doc_id) -> DocumentVersion:
    return (await db.execute(select(DocumentVersion).where(DocumentVersion.document_id == doc_id)
                             .order_by(DocumentVersion.version_number.desc()).limit(1))).scalar_one()

async def _user_by_email(db, email: str):
    return (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()   # exact match only

# ---------------- upload / list / view ----------------
@router.post("", status_code=201)
async def upload_document(request: Request, title: str = Form(..., min_length=1, max_length=200),
                          category: str = Form("", max_length=100), file: UploadFile = File(...),
                          ctx: AuthContext = Depends(current_auth), db: AsyncSession = Depends(get_db)):
    if ctx.role != "owner":
        await log_refusal(action="ACCESS_REFUSED", resource_type="document", actor_id=ctx.user_id,
                          actor_username=ctx.username, actor_role=ctx.role, reason="ROLE_REQUIRED",
                          metadata={"action": "upload"}, **client_meta(request))
        raise HTTPException(403, "Requires 'owner' role")
    data, name = await _read_upload(file)
    doc = Document(owner_id=ctx.user_id, title=title, category=category)
    db.add(doc); await db.flush()
    ver = await _add_version(db, doc, ctx.user_id, name, data, 1)
    await audit(db, ctx, request, "DOCUMENT_UPLOAD", "document", doc.id, document_id=str(doc.id),
                version_id=str(ver.id), version_number=1)
    await _commit_or_cleanup(db, ver.storage_path)
    return {"id": str(doc.id), "version_id": str(ver.id), "version_number": 1}

def _like_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

@router.get("")
async def list_documents(request: Request, q: str = Query("", max_length=100), owner: str = Query("", max_length=64),
                         category: str = Query("", max_length=100), created_from: Optional[date] = None,
                         created_to: Optional[date] = None,
                         sort: Literal["created_at", "updated_at", "file_size_bytes"] = "created_at",
                         order: Literal["asc", "desc"] = "desc", page: int = Query(1, ge=1),
                         limit: int = Query(20, ge=1, le=100),
                         ctx: AuthContext = Depends(current_auth), db: AsyncSession = Depends(get_db)):
    """Search runs ONLY over documents the caller may read: the permission predicate is part of every query
    (results, total, pagination and facets), so none of them can leak the existence of other documents."""
    active = select(Grant.document_id).where(
        Grant.grantee_user_id == ctx.user_id, Grant.revoked_at.is_(None),
        or_(Grant.expires_at.is_(None), Grant.expires_at > func.now()))
    visible = [Document.is_deleted.is_(False), or_(Document.owner_id == ctx.user_id, Document.id.in_(active))]
    filters = []
    if q:
        filters.append(Document.title.ilike(f"%{_like_escape(q)}%", escape="\\"))
    if owner:
        filters.append(Document.owner_id.in_(select(User.id).where(User.username == owner)))
    if created_from:
        filters.append(Document.created_at >= datetime.combine(created_from, time.min, tzinfo=timezone.utc))
    if created_to:
        filters.append(Document.created_at < datetime.combine(created_to + timedelta(days=1), time.min, tzinfo=timezone.utc))
    with_category = filters + ([Document.category == category] if category else [])
    size = (select(DocumentVersion.file_size_bytes).where(DocumentVersion.document_id == Document.id)
            .order_by(DocumentVersion.version_number.desc()).limit(1).scalar_subquery())
    col = size if sort == "file_size_bytes" else getattr(Document, sort)
    total = (await db.execute(select(func.count()).select_from(Document).where(*visible, *with_category))).scalar_one()
    rows = (await db.execute(
        select(Document, size.label("size"), User.username).join(User, User.id == Document.owner_id)
        .where(*visible, *with_category).order_by(col.asc() if order == "asc" else col.desc(), Document.id)
        .offset((page - 1) * limit).limit(limit))).all()
    facets = (await db.execute(select(Document.category, func.count()).where(*visible, *filters)
                               .group_by(Document.category))).all()      # same visibility predicate
    await audit(db, ctx, request, "SEARCH_QUERY", "document", page=page, limit=limit, count=len(rows))
    await db.commit()
    return {"total": total, "page": page, "limit": limit,
            "facets": {"category": {c or "": n for c, n in facets}},
            "items": [{"id": str(d.id), "title": d.title, "category": d.category, "owner": uname,
                       "file_size_bytes": sz, "created_at": d.created_at} for d, sz, uname in rows]}

@router.get("/pending-transfers")
async def pending_transfers(ctx: AuthContext = Depends(current_auth), db: AsyncSession = Depends(get_db)):
    if ctx.role != "owner":
        raise HTTPException(403, "Requires 'owner' role")
    rows = (await db.execute(select(Document.id, Document.category, User.username)
            .join(User, User.id == Document.owner_id)
            .where(Document.pending_owner_id == ctx.user_id, Document.is_deleted.is_(False)))).all()
    # Deliberately minimal: no title, versions or file access before acceptance.
    return [{"document_id": str(i), "category": c, "from_username": u} for i, c, u in rows]

@router.get("/{doc_id}")
async def get_document(doc_id: uuid.UUID, request: Request, ctx: AuthContext = Depends(current_auth),
                       db: AsyncSession = Depends(get_db)):
    doc = await authorize(db, ctx, request, doc_id, Action.READ)
    count = (await db.execute(select(func.count()).select_from(DocumentVersion)
                              .where(DocumentVersion.document_id == doc.id))).scalar_one()
    out = {"id": str(doc.id), "title": doc.title, "category": doc.category,
           "versions": count, "created_at": doc.created_at}
    await audit(db, ctx, request, "DOCUMENT_VIEW", "document", doc.id, document_id=str(doc.id))
    await db.commit()
    return out

# ---------------- download (in-memory decrypt + pre-send re-check) ----------------
async def _release(db, ctx, request, doc, ver) -> Response:
    """The one place payload bytes leave the server: decrypt in memory, verify the GCM tag, re-check access on a
    fresh connection, audit 'released', respond. Used by every download route."""
    did, vid, fname, path = doc.id, ver.id, ver.original_filename, ver.storage_path
    async with _decrypt_sem:
        with open(path, "rb") as f:
            blob = f.read()
        try:
            plain = crypto.decrypt_file(blob, ver, did)                  # GCM tag verified here
        except InvalidTag:
            await db.rollback()
            await log_refusal(action="DOCUMENT_INTEGRITY_FAILURE", resource_type="document",
                              resource_id=str(did), actor_id=ctx.user_id, actor_username=ctx.username,
                              actor_role=ctx.role, reason="GCM_TAG_MISMATCH", metadata={"version_id": str(vid)},
                              **client_meta(request))
            raise HTTPException(500, "Stored file failed integrity verification")
        async with db_module.AsyncSessionLocal() as fresh:               # live re-check right before release
            ok = await still_authorized(fresh, ctx.user_id, ctx.session_id, did, Action.DOWNLOAD)
        if not ok:
            await db.rollback()
            await log_refusal(action="ACCESS_REFUSED", resource_type="document", resource_id=str(did),
                              actor_id=ctx.user_id, actor_username=ctx.username, actor_role=ctx.role,
                              reason="REVOKED_DURING_DOWNLOAD", metadata={"action": "download"},
                              **client_meta(request))
            raise HTTPException(404, "Document not found")               # zero payload bytes released
        await audit(db, ctx, request, "DOCUMENT_DOWNLOAD", "document", did,
                    document_id=str(did), version_id=str(vid))            # = payload released by server
        await db.commit()
    return Response(plain, media_type="application/octet-stream", headers={
        "Content-Disposition": f'attachment; filename="{fname}"; filename*=UTF-8\'\'{quote(fname)}',
        "X-Content-Type-Options": "nosniff", "Content-Security-Policy": "default-src 'none'; sandbox",
        "Cache-Control": "no-store"})

@router.get("/{doc_id}/download")
async def download_document(doc_id: uuid.UUID, request: Request, ctx: AuthContext = Depends(current_auth),
                            db: AsyncSession = Depends(get_db)):
    doc = await authorize(db, ctx, request, doc_id, Action.DOWNLOAD)
    return await _release(db, ctx, request, doc, await _latest(db, doc.id))

@router.get("/{doc_id}/versions")
async def list_versions(doc_id: uuid.UUID, request: Request, ctx: AuthContext = Depends(current_auth),
                        db: AsyncSession = Depends(get_db)):
    doc = await authorize(db, ctx, request, doc_id, Action.READ)
    rows = (await db.execute(select(DocumentVersion).where(DocumentVersion.document_id == doc.id)
                             .order_by(DocumentVersion.version_number.desc()))).scalars().all()
    out = [{"version_number": v.version_number, "id": str(v.id), "filename": v.original_filename,
            "file_size_bytes": v.file_size_bytes, "created_at": v.created_at} for v in rows]
    await audit(db, ctx, request, "DOCUMENT_VERSIONS_VIEW", "document", doc.id, document_id=str(doc.id), count=len(out))
    await db.commit()
    return out

@router.get("/{doc_id}/versions/{version_number}/download")
async def download_version(doc_id: uuid.UUID, version_number: int, request: Request,
                           ctx: AuthContext = Depends(current_auth), db: AsyncSession = Depends(get_db)):
    doc = await authorize(db, ctx, request, doc_id, Action.DOWNLOAD)     # same gate as the latest version
    ver = (await db.execute(select(DocumentVersion).where(DocumentVersion.document_id == doc.id,
                                                          DocumentVersion.version_number == version_number))).scalar_one_or_none()
    if ver is None:
        raise HTTPException(404, "Version not found")
    return await _release(db, ctx, request, doc, ver)

# ---------------- versions / delete / restore ----------------
@router.post("/{doc_id}/versions", status_code=201)
async def upload_version(doc_id: uuid.UUID, request: Request, file: UploadFile = File(...),
                         ctx: AuthContext = Depends(current_auth), db: AsyncSession = Depends(get_db)):
    doc = await authorize(db, ctx, request, doc_id, Action.EDIT)
    data, name = await _read_upload(file)
    await db.execute(select(Document).where(Document.id == doc.id).with_for_update())   # serialise numbering
    last = (await db.execute(select(func.max(DocumentVersion.version_number))
                             .where(DocumentVersion.document_id == doc.id))).scalar_one()
    ver = await _add_version(db, doc, ctx.user_id, name, data, (last or 0) + 1)
    doc.updated_at = datetime.now(timezone.utc)
    await audit(db, ctx, request, "DOCUMENT_VERSION_UPLOAD", "document", doc.id, document_id=str(doc.id),
                version_id=str(ver.id), version_number=ver.version_number)
    await _commit_or_cleanup(db, ver.storage_path)
    return {"version_id": str(ver.id), "version_number": ver.version_number}

@router.delete("/{doc_id}")
async def delete_document(doc_id: uuid.UUID, request: Request, ctx: AuthContext = Depends(current_auth),
                          db: AsyncSession = Depends(get_db)):
    doc = await authorize(db, ctx, request, doc_id, Action.DELETE)
    doc.is_deleted, doc.deleted_at, doc.pending_owner_id = True, datetime.now(timezone.utc), None
    await audit(db, ctx, request, "DOCUMENT_DELETE", "document", doc.id, document_id=str(doc.id))
    await db.commit()
    return {"message": "Document deleted"}

@router.post("/{doc_id}/restore")
async def restore_document(doc_id: uuid.UUID, request: Request, ctx: AuthContext = Depends(current_auth),
                           db: AsyncSession = Depends(get_db)):
    doc = await authorize(db, ctx, request, doc_id, Action.RESTORE)
    doc.is_deleted, doc.deleted_at = False, None       # unrevoked + unexpired grants are live again
    await audit(db, ctx, request, "DOCUMENT_RESTORE", "document", doc.id, document_id=str(doc.id))
    await db.commit()
    return {"message": "Document restored"}

# ---------------- grants ----------------
@router.get("/{doc_id}/grants", response_model=list[GrantRead])
async def list_grants(doc_id: uuid.UUID, request: Request, ctx: AuthContext = Depends(current_auth),
                      db: AsyncSession = Depends(get_db)):
    doc = await authorize(db, ctx, request, doc_id, Action.ACCESS_LIST)
    rows = (await db.execute(select(Grant).where(Grant.document_id == doc.id)
                             .order_by(Grant.granted_at))).scalars().all()
    await audit(db, ctx, request, "DOCUMENT_ACCESS_LIST_VIEW", "document", doc.id, document_id=str(doc.id))
    await db.commit()
    return rows

@router.post("/{doc_id}/grants", status_code=201)
async def create_grant(doc_id: uuid.UUID, body: GrantCreate, request: Request,
                       ctx: AuthContext = Depends(current_auth), db: AsyncSession = Depends(get_db)):
    doc = await authorize(db, ctx, request, doc_id, Action.GRANT)
    await enforce_rate_limit(db, request, "grant", settings.RATE_LIMIT_GRANTS_PER_MIN, identifier=str(ctx.user_id))
    target = await _user_by_email(db, body.grantee_email)
    if target is None or not target.is_active:
        await audit(db, ctx, request, "PERMISSION_GRANT_FAILED", "document", doc.id, document_id=str(doc.id))
        await db.commit()
        raise HTTPException(404, "Target user not found")
    if target.id == ctx.user_id:
        raise HTTPException(400, "You cannot grant access to yourself")
    exp = body.expires_at
    if exp is not None:
        exp = exp if exp.tzinfo else exp.replace(tzinfo=timezone.utc)
        if exp <= datetime.now(timezone.utc):
            raise HTTPException(400, "expires_at must be in the future")
    now = datetime.now(timezone.utc)
    await db.execute(update(Grant).where(Grant.document_id == doc.id, Grant.grantee_user_id == target.id,
                                         Grant.revoked_at.is_(None)).values(revoked_at=now))  # one live grant per user
    g = Grant(document_id=doc.id, grantee_user_id=target.id, level=body.level, granted_by=ctx.user_id, expires_at=exp)
    db.add(g); await db.flush()
    await audit(db, ctx, request, "PERMISSION_GRANT", "document", doc.id, document_id=str(doc.id),
                grantee_user_id=str(target.id), grant_id=str(g.id), level=body.level)
    await db.commit()
    return {"grant_id": str(g.id), "level": g.level}

@router.post("/{doc_id}/grants/{grant_id}/revoke")
async def revoke_grant(doc_id: uuid.UUID, grant_id: uuid.UUID, request: Request,
                       ctx: AuthContext = Depends(current_auth), db: AsyncSession = Depends(get_db)):
    doc = await authorize(db, ctx, request, doc_id, Action.REVOKE)
    g = (await db.execute(select(Grant).where(Grant.id == grant_id, Grant.document_id == doc.id,
                                              Grant.revoked_at.is_(None)))).scalar_one_or_none()
    if g is None:
        raise HTTPException(404, "Grant not found")
    g.revoked_at = datetime.now(timezone.utc)
    await audit(db, ctx, request, "PERMISSION_REVOKE", "document", doc.id, document_id=str(doc.id),
                grant_id=str(g.id), grantee_user_id=str(g.grantee_user_id))
    await db.commit()                                   # downloads in flight see this at their pre-send re-check
    return {"message": "Grant revoked"}

# ---------------- two-step ownership transfer ----------------
@router.post("/{doc_id}/transfer-request")
async def transfer_request(doc_id: uuid.UUID, body: TransferRequest, request: Request,
                           ctx: AuthContext = Depends(current_auth), db: AsyncSession = Depends(get_db)):
    doc = await authorize(db, ctx, request, doc_id, Action.TRANSFER)
    await enforce_rate_limit(db, request, "grant", settings.RATE_LIMIT_GRANTS_PER_MIN, identifier=str(ctx.user_id))
    target = await _user_by_email(db, body.target_email)
    if target is None or not target.is_active:
        raise HTTPException(404, "Target user not found")
    if target.id == ctx.user_id:
        raise HTTPException(400, "Document is already yours")
    if target.role != "owner":
        raise HTTPException(400, "Recipient must have the 'owner' system role")
    doc.pending_owner_id = target.id                    # current owner keeps full control while pending
    await audit(db, ctx, request, "OWNERSHIP_TRANSFER_REQUESTED", "document", doc.id,
                document_id=str(doc.id), target_user_id=str(target.id))
    await db.commit()
    return {"message": "Transfer requested"}

@router.post("/{doc_id}/transfer-accept")
async def transfer_accept(doc_id: uuid.UUID, request: Request, ctx: AuthContext = Depends(current_auth),
                          db: AsyncSession = Depends(get_db)):
    doc = await authorize(db, ctx, request, doc_id, Action.TRANSFER_ACCEPT)
    if doc.is_deleted or ctx.role != "owner":
        raise HTTPException(400, "Transfer can no longer be accepted")
    previous = doc.owner_id
    await db.execute(update(Grant).where(Grant.document_id == doc.id, Grant.grantee_user_id == ctx.user_id,
                                         Grant.revoked_at.is_(None)).values(revoked_at=datetime.now(timezone.utc)))
    doc.owner_id, doc.pending_owner_id = ctx.user_id, None      # atomic; old owner keeps nothing; other grants stay
    await audit(db, ctx, request, "OWNERSHIP_TRANSFER_ACCEPTED", "document", doc.id, document_id=str(doc.id),
                previous_owner_id=str(previous), new_owner_id=str(ctx.user_id))
    await db.commit()
    return {"message": "Ownership accepted"}

@router.post("/{doc_id}/transfer-reject")
async def transfer_reject(doc_id: uuid.UUID, request: Request, ctx: AuthContext = Depends(current_auth),
                          db: AsyncSession = Depends(get_db)):
    doc = await authorize(db, ctx, request, doc_id, Action.TRANSFER_REJECT)
    doc.pending_owner_id = None
    await audit(db, ctx, request, "OWNERSHIP_TRANSFER_REJECTED", "document", doc.id, document_id=str(doc.id),
                rejected_by_user_id=str(ctx.user_id))
    await db.commit()
    return {"message": "Transfer rejected"}

@router.post("/{doc_id}/transfer-cancel")
async def transfer_cancel(doc_id: uuid.UUID, request: Request, ctx: AuthContext = Depends(current_auth),
                          db: AsyncSession = Depends(get_db)):
    doc = await authorize(db, ctx, request, doc_id, Action.TRANSFER_CANCEL)
    doc.pending_owner_id = None
    await audit(db, ctx, request, "OWNERSHIP_TRANSFER_CANCELLED", "document", doc.id, document_id=str(doc.id))
    await db.commit()
    return {"message": "Transfer cancelled"}

# ---------------- advisory AI ----------------
@router.post("/{doc_id}/grantee-suggestions")
async def grantee_suggestions(doc_id: uuid.UUID, request: Request, ctx: AuthContext = Depends(current_auth),
                              db: AsyncSession = Depends(get_db)):
    doc = await authorize(db, ctx, request, doc_id, Action.AI_SUGGEST)
    if not settings.ANTHROPIC_API_KEY:
        raise HTTPException(503, "AI suggestions are not configured")
    suggestions = await ai_service.suggest_grantees(db, doc, ctx.user_id)
    await audit(db, ctx, request, "AI_GRANTEE_SUGGESTION", "document", doc.id, document_id=str(doc.id),
                count=len(suggestions))
    await db.commit()
    return {"advisory_only": True, "suggestions": suggestions}   # owner must still confirm via POST /grants
