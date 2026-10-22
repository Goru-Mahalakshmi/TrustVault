import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple
from fastapi import HTTPException, status
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from src.core.config import settings
from src.core.security import (
    hash_password,
    verify_password,
    generate_token,
    hash_token,
)
from src.models.user import User
from src.models.session import Session
from src.models.auth_tokens import PasswordResetToken, EmailChangeToken
from src.schemas.user import UserCreate
from src.schemas.auth import LoginRequest
from src.services.audit_service import log_event, log_refusal


async def register_user(
    db: AsyncSession,
    user_in: UserCreate,
    ip_address: str = "127.0.0.1",
    user_agent: str = "internal",
) -> User:
    """Register a new user account with default role 'owner'."""
    # Check if username or email is already taken
    existing_user_query = select(User).where(
        (User.username == user_in.username) | (User.email == user_in.email)
    )
    result = await db.execute(existing_user_query)
    existing_user = result.scalar_one_or_none()

    if existing_user:
        await log_refusal(
            action="AUTH_REGISTER_FAILURE",
            resource_type="user",
            ip_address=ip_address,
            user_agent=user_agent,
            reason="USERNAME_OR_EMAIL_TAKEN",
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email is already registered",
        )

    # Hash password with Argon2id
    pwd_hash = hash_password(user_in.password)

    new_user = User(
        username=user_in.username,
        email=user_in.email,
        password_hash=pwd_hash,
        role="owner",
        is_active=True,
        security_version=1,
        failed_login_attempts=0,
    )
    db.add(new_user)
    await db.flush()

    await log_event(
        db=db,
        action="AUTH_REGISTER",
        resource_type="user",
        resource_id=str(new_user.id),
        actor_id=new_user.id,
        actor_username=new_user.username,
        actor_role=new_user.role,
        ip_address=ip_address,
        user_agent=user_agent,
        status="SUCCESS",
        metadata={"user_id": str(new_user.id)},
    )

    await db.commit()
    await db.refresh(new_user)
    return new_user


async def authenticate_user(
    db: AsyncSession,
    login_data: LoginRequest,
    ip_address: str = "127.0.0.1",
    user_agent: str = "internal",
) -> Tuple[User, Session, str, str]:
    """Authenticate user, check lockouts, rotate sessions, and issue tokens."""
    now = datetime.now(timezone.utc)

    # Look up user by username
    result = await db.execute(select(User).where(User.username == login_data.username))
    user = result.scalar_one_or_none()

    if not user:
        # Constant-time dummy verification
        verify_password(login_data.password, None)
        await log_refusal(
            action="AUTH_LOGIN_FAILURE",
            resource_type="user",
            ip_address=ip_address,
            user_agent=user_agent,
            reason="USER_NOT_FOUND",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # Check account lockout
    if user.locked_until:
        locked_until_dt = user.locked_until
        if locked_until_dt.tzinfo is None:
            locked_until_dt = locked_until_dt.replace(tzinfo=timezone.utc)

        if locked_until_dt > now:
            await log_refusal(
                action="AUTH_LOGIN_LOCKED",
                resource_type="user",
                resource_id=str(user.id),
                actor_id=user.id,
                actor_username=user.username,
                actor_role=user.role,
                ip_address=ip_address,
                user_agent=user_agent,
                reason="ACCOUNT_LOCKED",
                metadata={"user_id": str(user.id)},
            )
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail="Account temporarily locked due to repeated failed attempts. Try again later.",
            )

    # Verify password with Argon2id
    is_valid = verify_password(login_data.password, user.password_hash)

    if not is_valid:
        # Atomic increment: parallel guesses cannot lose updates and sneak under the lockout threshold.
        attempts = (await db.execute(
            update(User).where(User.id == user.id)
            .values(failed_login_attempts=User.failed_login_attempts + 1)
            .returning(User.failed_login_attempts))).scalar_one()
        if attempts >= settings.MAX_FAILED_LOGIN_ATTEMPTS:
            await db.execute(update(User).where(User.id == user.id)
                             .values(locked_until=now + timedelta(minutes=settings.LOCKOUT_DURATION_MINUTES)))
        await db.commit()

        await log_refusal(
            action="AUTH_LOGIN_FAILURE",
            resource_type="user",
            resource_id=str(user.id),
            actor_id=user.id,
            actor_username=user.username,
            actor_role=user.role,
            ip_address=ip_address,
            user_agent=user_agent,
            reason="INVALID_PASSWORD",
            metadata={"user_id": str(user.id)},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # Disabled-account check comes AFTER the password check: only someone holding the right password learns the
    # account is disabled (before, anyone who knew a username could probe account state).
    # Check if user is disabled
    if not user.is_active:
        await log_refusal(
            action="AUTH_LOGIN_FAILURE",
            resource_type="user",
            resource_id=str(user.id),
            actor_id=user.id,
            actor_username=user.username,
            actor_role=user.role,
            ip_address=ip_address,
            user_agent=user_agent,
            reason="ACCOUNT_DISABLED",
            metadata={"user_id": str(user.id)},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is disabled",
        )

    # Successful login: reset failed counters
    user.failed_login_attempts = 0
    user.locked_until = None

    # Rotate/revoke previous sessions for this user
    await db.execute(
        update(Session)
        .where((Session.user_id == user.id) & (Session.revoked_at.is_(None)))
        .values(revoked_at=now)
    )

    # Issue fresh 256-bit session token and CSRF token
    raw_session_token = generate_token(32)
    session_token_hash = hash_token(raw_session_token)

    raw_csrf_token = generate_token(32)
    csrf_token_hash = hash_token(raw_csrf_token)

    abs_expiry = now + timedelta(hours=settings.SESSION_ABSOLUTE_TIMEOUT_HOURS)

    new_session = Session(
        session_token_hash=session_token_hash,
        user_id=user.id,
        user_security_version=user.security_version,
        csrf_token_hash=csrf_token_hash,
        ip_address=ip_address,
        user_agent=user_agent[:512],
        created_at=now,
        last_active_at=now,
        expires_at=abs_expiry,
    )
    db.add(new_session)
    await db.flush()

    await log_event(
        db=db,
        action="AUTH_LOGIN_SUCCESS",
        resource_type="session",
        resource_id=str(new_session.id),
        actor_id=user.id,
        actor_username=user.username,
        actor_role=user.role,
        ip_address=ip_address,
        user_agent=user_agent,
        status="SUCCESS",
        metadata={"user_id": str(user.id), "session_id": str(new_session.id)},
    )

    await db.commit()
    await db.refresh(new_session)
    return user, new_session, raw_session_token, raw_csrf_token


async def logout_session(
    db: AsyncSession,
    session: Session,
    user: User,
    ip_address: str = "127.0.0.1",
    user_agent: str = "internal",
):
    """Revoke active session and record audit event."""
    now = datetime.now(timezone.utc)
    session.revoked_at = now

    await log_event(
        db=db,
        action="AUTH_LOGOUT",
        resource_type="session",
        resource_id=str(session.id),
        actor_id=user.id,
        actor_username=user.username,
        actor_role=user.role,
        ip_address=ip_address,
        user_agent=user_agent,
        status="SUCCESS",
        metadata={"session_id": str(session.id)},
    )
    await db.commit()


async def request_password_reset(
    db: AsyncSession,
    email: str,
    ip_address: str = "127.0.0.1",
    user_agent: str = "internal",
) -> Tuple[str, Optional[str]]:
    """Generate single-use password reset token. Returns generic message and optional raw token (for dev/test)."""
    now = datetime.now(timezone.utc)
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    generic_msg = "If an account exists for that email, password reset instructions have been sent."

    if not user or not user.is_active:
        return generic_msg, None

    raw_token = generate_token(32)
    token_hash = hash_token(raw_token)
    expiry = now + timedelta(minutes=settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES)

    reset_token_record = PasswordResetToken(
        token_hash=token_hash,
        user_id=user.id,
        expires_at=expiry,
        created_at=now,
    )
    db.add(reset_token_record)

    await log_event(
        db=db,
        action="AUTH_RESET_REQUESTED",
        resource_type="user",
        resource_id=str(user.id),
        actor_id=user.id,
        actor_username=user.username,
        actor_role=user.role,
        ip_address=ip_address,
        user_agent=user_agent,
        status="SUCCESS",
        metadata={"user_id": str(user.id)},
    )

    await db.commit()
    return generic_msg, raw_token


async def reset_password(
    db: AsyncSession,
    token_str: str,
    new_password: str,
    ip_address: str = "127.0.0.1",
    user_agent: str = "internal",
):
    """Consume single-use reset token and increment security_version."""
    now = datetime.now(timezone.utc)
    token_hash = hash_token(token_str)

    result = await db.execute(
        select(PasswordResetToken).where(PasswordResetToken.token_hash == token_hash)
    )
    reset_record = result.scalar_one_or_none()

    if not reset_record or reset_record.used_at is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token",
        )

    expires_at = reset_record.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at < now:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token",
        )

    # Get user
    user_res = await db.execute(select(User).where(User.id == reset_record.user_id))
    user = user_res.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token",
        )

    # Hash new password
    user.password_hash = hash_password(new_password)
    user.security_version += 1  # Invalidate all active sessions immediately
    user.failed_login_attempts = 0
    user.locked_until = None

    reset_record.used_at = now

    await log_event(
        db=db,
        action="AUTH_RESET_COMPLETED",
        resource_type="user",
        resource_id=str(user.id),
        actor_id=user.id,
        actor_username=user.username,
        actor_role=user.role,
        ip_address=ip_address,
        user_agent=user_agent,
        status="SUCCESS",
        metadata={"user_id": str(user.id)},
    )

    await db.commit()


async def change_password(
    db: AsyncSession,
    user: User,
    current_password: str,
    new_password: str,
    ip_address: str = "127.0.0.1",
    user_agent: str = "internal",
):
    """User changes their own password with current password verification."""
    if not verify_password(current_password, user.password_hash):
        await log_refusal(
            action="AUTH_PASSWORD_CHANGE_FAILURE",
            resource_type="user",
            resource_id=str(user.id),
            actor_id=user.id,
            actor_username=user.username,
            actor_role=user.role,
            ip_address=ip_address,
            user_agent=user_agent,
            reason="INVALID_CURRENT_PASSWORD",
            metadata={"user_id": str(user.id)},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )

    user.password_hash = hash_password(new_password)
    user.security_version += 1  # Invalidate all active sessions

    await log_event(
        db=db,
        action="AUTH_PASSWORD_CHANGED",
        resource_type="user",
        resource_id=str(user.id),
        actor_id=user.id,
        actor_username=user.username,
        actor_role=user.role,
        ip_address=ip_address,
        user_agent=user_agent,
        status="SUCCESS",
        metadata={"user_id": str(user.id)},
    )

    await db.commit()


async def request_email_change(
    db: AsyncSession,
    user: User,
    current_password: str,
    new_email: str,
    ip_address: str = "127.0.0.1",
    user_agent: str = "internal",
) -> str:
    """Initiate email change requiring current password; returns token sent to old email."""
    now = datetime.now(timezone.utc)

    if not verify_password(current_password, user.password_hash):
        await log_refusal(
            action="AUTH_EMAIL_CHANGE_FAILURE",
            resource_type="user",
            resource_id=str(user.id),
            actor_id=user.id,
            actor_username=user.username,
            actor_role=user.role,
            ip_address=ip_address,
            user_agent=user_agent,
            reason="INVALID_CURRENT_PASSWORD",
            metadata={"user_id": str(user.id)},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )

    # Check if new email is already in use
    existing_res = await db.execute(select(User).where(User.email == new_email))
    if existing_res.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email address is already in use",
        )

    raw_token = generate_token(32)
    token_hash = hash_token(raw_token)
    expiry = now + timedelta(minutes=settings.EMAIL_CHANGE_TOKEN_EXPIRE_MINUTES)

    change_record = EmailChangeToken(
        token_hash=token_hash,
        user_id=user.id,
        new_email=new_email,
        expires_at=expiry,
        created_at=now,
    )
    db.add(change_record)

    await log_event(
        db=db,
        action="AUTH_EMAIL_CHANGE_REQUESTED",
        resource_type="user",
        resource_id=str(user.id),
        actor_id=user.id,
        actor_username=user.username,
        actor_role=user.role,
        ip_address=ip_address,
        user_agent=user_agent,
        status="SUCCESS",
        metadata={"user_id": str(user.id)},
    )

    await db.commit()
    return raw_token


async def confirm_email_change(
    db: AsyncSession,
    token_str: str,
    ip_address: str = "127.0.0.1",
    user_agent: str = "internal",
):
    """Confirm email change using token sent to old address."""
    now = datetime.now(timezone.utc)
    token_hash = hash_token(token_str)

    result = await db.execute(
        select(EmailChangeToken).where(EmailChangeToken.token_hash == token_hash)
    )
    change_record = result.scalar_one_or_none()

    if not change_record or change_record.used_at is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired email change token",
        )

    expires_at = change_record.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at < now:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired email change token",
        )

    user_res = await db.execute(select(User).where(User.id == change_record.user_id))
    user = user_res.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired token",
        )

    user.email = change_record.new_email
    user.security_version += 1  # Invalidate sessions
    change_record.used_at = now

    await log_event(
        db=db,
        action="AUTH_EMAIL_CHANGED",
        resource_type="user",
        resource_id=str(user.id),
        actor_id=user.id,
        actor_username=user.username,
        actor_role=user.role,
        ip_address=ip_address,
        user_agent=user_agent,
        status="SUCCESS",
        metadata={"user_id": str(user.id)},
    )

    await db.commit()
