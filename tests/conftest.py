import asyncio
import os
from datetime import datetime, timezone, timedelta
from typing import AsyncGenerator, Tuple
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.pool import NullPool
from scripts.init_db import init as init_db
from src.core.config import settings
from src.db.base import Base
import src.db.session as session_module
from src.db.session import get_db
from src.main import app
from src.models.user import User
from src.core.security import hash_password, generate_token, hash_token
from src.models.session import Session

OWNER_URL = os.getenv("TEST_OWNER_DATABASE_URL",
                      "postgresql+asyncpg://trustvault_owner:owner_dev_pw@localhost:5433/trustvault_test")
TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL",
                              "postgresql+asyncpg://trustvault_app:app_dev_pw@localhost:5433/trustvault_test")

if TEST_DATABASE_URL.startswith("sqlite") and os.getenv("TV_ALLOW_SQLITE") != "1":
    pytest.exit("Tests must run on PostgreSQL (audit trigger, role grants and advisory locks cannot be tested on "
                "SQLite). Run: docker compose up -d   (set TV_ALLOW_SQLITE=1 only for a quick, NON-authoritative run)",
                returncode=2)

os.environ["ENVIRONMENT"] = "testing"

# TEST-ONLY speed-up: cheap Argon2 parameters (production keeps the library defaults). Hashes embed their own
# parameters, so verification logic is exercised exactly as in production.
import argon2
import src.core.security as _security
_security._ph = argon2.PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
settings.DATABASE_URL = TEST_DATABASE_URL

# NullPool: pytest-asyncio gives every test its own event loop, so pooled connections would cross loops.
test_engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)    # the restricted APP role
owner_engine = create_async_engine(OWNER_URL, poolclass=NullPool)           # schema owner, used only for setup/tamper tests

TestingSessionLocal = async_sessionmaker(bind=test_engine, class_=AsyncSession, expire_on_commit=False, autoflush=False)

# Bind session_module so background/isolated log_refusal uses the test engine
session_module.engine = test_engine
session_module.AsyncSessionLocal = TestingSessionLocal


@pytest.fixture(scope="session", autouse=True)
def _require_database():
    async def ping():
        try:
            async with owner_engine.connect() as c:
                await c.execute(text("select 1"))
        except Exception as e:  # noqa: BLE001
            pytest.exit(f"Cannot reach the test database ({type(e).__name__}). Start it with: docker compose up -d", returncode=2)
    asyncio.run(ping())


_schema_ready = False

@pytest_asyncio.fixture(scope="function")
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    global _schema_ready
    if not _schema_ready:                           # real setup path once per run: schema + grants + immutability trigger
        await init_db(OWNER_URL, drop_first=True)
        _schema_ready = True
    else:                                           # per test: empty every table as OWNER, then re-apply grants/trigger
        tables = ", ".join(f'"{t.name}"' for t in Base.metadata.sorted_tables)
        async with owner_engine.begin() as c:
            await c.execute(text("ALTER TABLE audit_logs DISABLE TRIGGER USER"))
            await c.execute(text(f"TRUNCATE {tables} RESTART IDENTITY CASCADE"))
        await init_db(OWNER_URL, drop_first=False)  # re-enables the trigger; idempotent
    async with TestingSessionLocal() as session:
        yield session


@pytest_asyncio.fixture
async def as_owner():
    """Run SQL as the schema OWNER (models a DBA / compromised migration credential). Never the app role."""
    async def _run(sql: str):
        async with owner_engine.begin() as c:
            await c.execute(text(sql))
    return _run


@pytest_asyncio.fixture(scope="function")
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def create_user(db_session: AsyncSession):
    async def _create(
        username: str = "testuser",
        email: str = None,
        password: str = "Str0ngP@ssw0rd!",
        role: str = "owner",
        is_active: bool = True,
    ) -> Tuple[User, str]:
        actual_email = email or f"{username}@example.com"
        user = User(
            username=username,
            email=actual_email,
            password_hash=hash_password(password),
            role=role,
            is_active=is_active,
            security_version=1,
            failed_login_attempts=0,
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)
        return user, password

    return _create


@pytest_asyncio.fixture
async def auth_session(db_session: AsyncSession):
    async def _auth(user: User) -> Tuple[str, str]:
        now = datetime.now(timezone.utc)
        raw_session_token = generate_token(32)
        raw_csrf_token = generate_token(32)

        session = Session(
            session_token_hash=hash_token(raw_session_token),
            user_id=user.id,
            user_security_version=user.security_version,
            csrf_token_hash=hash_token(raw_csrf_token),
            ip_address="127.0.0.1",
            user_agent="pytest-client",
            created_at=now,
            last_active_at=now,
            expires_at=now + timedelta(hours=12),
        )
        db_session.add(session)
        await db_session.commit()
        return raw_session_token, raw_csrf_token

    return _auth


@pytest.fixture(autouse=True)
def _clean_ai_settings(monkeypatch):
    """Every test starts with AI switched OFF, whatever is in the developer's shell or .env
    (for example a real Groq key). Tests that need AI turn it on themselves, after this runs."""
    for name in ("AI_PROVIDER", "ANTHROPIC_API_KEY", "AI_API_KEY", "AI_BASE_URL", "AI_MODEL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(settings, "AI_PROVIDER", "anthropic")
    for name in ("ANTHROPIC_API_KEY", "AI_API_KEY", "AI_BASE_URL", "AI_MODEL"):
        monkeypatch.setattr(settings, name, "")