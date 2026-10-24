from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession
from src.api.deps import AuthContext, current_auth, client_meta
from src.core.config import settings
from src.db.session import get_db
from src.schemas import (UserCreate, UserRead, LoginRequest, LoginResponse, ForgotPasswordRequest,
                         ResetPasswordRequest, ChangePasswordRequest, EmailChangeRequest,
                         EmailChangeConfirmRequest, GenericMessageResponse)
from src.services import auth_service as svc
from src.services.email_service import send_reset_email, send_email_change_email
from src.core.security import generate_token, hash_token
from src.services.rate_limiter import enforce_rate_limit

router = APIRouter(prefix="/api/auth", tags=["auth"])

@router.post("/register", response_model=UserRead, status_code=201)
async def register(body: UserCreate, request: Request, db: AsyncSession = Depends(get_db)):
    await enforce_rate_limit(db, request, "register", settings.RATE_LIMIT_REGISTER_PER_MIN)
    return await svc.register_user(db, body, **client_meta(request))

@router.post("/login", response_model=LoginResponse)
async def login(body: LoginRequest, request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    await enforce_rate_limit(db, request, "login", settings.RATE_LIMIT_LOGIN_PER_MIN)  # before any hashing
    user, _, raw_session, raw_csrf = await svc.authenticate_user(db, body, **client_meta(request))
    response.headers.append("set-cookie", (
        f"{settings.SESSION_COOKIE_NAME}={raw_session}; HttpOnly; {'Secure; ' if settings.COOKIE_SECURE else ''}SameSite=Strict; Path=/; "
        f"Max-Age={settings.SESSION_ABSOLUTE_TIMEOUT_HOURS * 3600}"))
    return LoginResponse(user=UserRead.model_validate(user), csrf_token=raw_csrf)

@router.post("/logout", response_model=GenericMessageResponse)
async def logout(request: Request, response: Response, ctx: AuthContext = Depends(current_auth),
                 db: AsyncSession = Depends(get_db)):
    await svc.logout_session(db, ctx.session, ctx.user, **client_meta(request))
    response.delete_cookie(settings.SESSION_COOKIE_NAME, path="/")
    return GenericMessageResponse(message="Logged out")

class MeResponse(UserRead):
    csrf_token: str

@router.get("/me", response_model=MeResponse)
async def me(ctx: AuthContext = Depends(current_auth), db: AsyncSession = Depends(get_db)):
    raw = generate_token(32)                      # fresh CSRF token for this page load (API.md); old one stops working
    ctx.session.csrf_token_hash = hash_token(raw)
    await db.commit()
    return MeResponse(**UserRead.model_validate(ctx.user).model_dump(), csrf_token=raw)

@router.post("/forgot-password", response_model=GenericMessageResponse)
async def forgot_password(body: ForgotPasswordRequest, request: Request, db: AsyncSession = Depends(get_db)):
    # API.md: 3 requests/hour per IP AND per email. The email limit applies to any address equally, so it reveals nothing.
    await enforce_rate_limit(db, request, "forgot_ip", settings.RATE_LIMIT_FORGOT_PER_HOUR, window_seconds=3600)
    await enforce_rate_limit(db, request, "forgot_email", settings.RATE_LIMIT_FORGOT_PER_HOUR, window_seconds=3600,
                             identifier=hash_token(body.email.lower())[:32])
    msg, token = await svc.request_password_reset(db, body.email, **client_meta(request))
    if token:
        await send_reset_email(body.email, token)       # the token only ever travels by email
    return GenericMessageResponse(message=msg)

@router.post("/reset-password", response_model=GenericMessageResponse)
async def reset_password(body: ResetPasswordRequest, request: Request, db: AsyncSession = Depends(get_db)):
    await enforce_rate_limit(db, request, "reset", settings.RATE_LIMIT_LOGIN_PER_MIN)
    await svc.reset_password(db, body.token, body.new_password, **client_meta(request))
    return GenericMessageResponse(message="Password has been reset")

@router.post("/change-password", response_model=GenericMessageResponse)
async def change_password(body: ChangePasswordRequest, request: Request,
                          ctx: AuthContext = Depends(current_auth), db: AsyncSession = Depends(get_db)):
    await svc.change_password(db, ctx.user, body.current_password, body.new_password, **client_meta(request))
    return GenericMessageResponse(message="Password changed")

@router.post("/email-change-request", response_model=GenericMessageResponse)
async def email_change_request(body: EmailChangeRequest, request: Request,
                               ctx: AuthContext = Depends(current_auth), db: AsyncSession = Depends(get_db)):
    old_email = ctx.user.email
    token = await svc.request_email_change(db, ctx.user, body.current_password, body.new_email, **client_meta(request))
    await send_email_change_email(old_email, token, body.new_email)   # to the OLD address, per API.md
    return GenericMessageResponse(message="Confirmation sent to your current email address")

@router.post("/email-change-confirm", response_model=GenericMessageResponse)
async def email_change_confirm(body: EmailChangeConfirmRequest, request: Request, db: AsyncSession = Depends(get_db)):
    await enforce_rate_limit(db, request, "emailconfirm", settings.RATE_LIMIT_LOGIN_PER_MIN)
    await svc.confirm_email_change(db, body.token, **client_meta(request))
    return GenericMessageResponse(message="Email address updated")
