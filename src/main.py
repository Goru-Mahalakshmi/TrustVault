from contextlib import asynccontextmanager
import os
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from src.api import auth, admin, documents
from src.db.base import Base
import src.db.session as db
import src.models  # noqa: F401  (register tables)

@asynccontextmanager
async def lifespan(app):
    if db.engine.dialect.name == "sqlite":      # quick local dev only. On PostgreSQL the schema is created by
        async with db.engine.begin() as conn:   # `python -m scripts.init_db` as the OWNER role; the app role cannot CREATE.
            await conn.run_sync(Base.metadata.create_all)
    yield

from src.core.config import settings
app = FastAPI(title="TrustVault", lifespan=lifespan,
              docs_url="/docs" if settings.docs_enabled else None, redoc_url=None,
              openapi_url="/openapi.json" if settings.docs_enabled else None)
app.include_router(auth.router)
app.include_router(admin.router)
app.include_router(documents.router)

@app.middleware("http")
async def security_headers(request: Request, call_next):
    r = await call_next(request)
    r.headers.setdefault("X-Content-Type-Options", "nosniff")
    r.headers.setdefault("X-Frame-Options", "DENY")
    r.headers.setdefault("Cache-Control", "no-store")
    if settings.ENVIRONMENT == "production":
        r.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    if request.url.path == "/" or request.url.path.startswith("/static"):
        r.headers.setdefault("Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
    return r

_STATIC = os.path.join(os.path.dirname(__file__), "static")   # app's own UI only; uploads are never served from here
app.mount("/static", StaticFiles(directory=_STATIC), name="static")

@app.get("/", include_in_schema=False)
async def index():
    return FileResponse(os.path.join(_STATIC, "index.html"))

@app.get("/healthz", include_in_schema=False)
async def healthz():
    return {"status": "ok"}      # liveness only: no database access, no data
