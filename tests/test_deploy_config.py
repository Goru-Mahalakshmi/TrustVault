import base64, pytest
from pydantic import ValidationError
from starlette.requests import Request
from src.core.config import Settings, settings
from src.services.rate_limiter import get_client_ip

GOOD = dict(ENVIRONMENT="production", AUDIT_HMAC_KEY="k" * 40, MASTER_KEY_B64=base64.b64encode(b"m" * 32).decode(),
            DATABASE_URL="postgresql+asyncpg://u:p@db/x")

def test_production_refuses_to_start_with_development_defaults():
    Settings(_env_file=None, **GOOD)                                  # a proper config is accepted
    for bad in ({"AUDIT_HMAC_KEY": "dev-only-change-me"}, {"AUDIT_HMAC_KEY": "short"}, {"MASTER_KEY_B64": ""},
                {"MASTER_KEY_B64": base64.b64encode(b"x" * 16).decode()}, {"COOKIE_SECURE": False},
                {"DATABASE_URL": "sqlite+aiosqlite:///x.db"}):
        with pytest.raises(ValidationError):
            Settings(_env_file=None, **{**GOOD, **bad})

def test_docs_are_off_in_production_and_on_in_development():
    assert Settings(_env_file=None, **GOOD).docs_enabled is False
    assert Settings(_env_file=None, ENVIRONMENT="development").docs_enabled is True

def _req(peer, xff=None):
    h = [(b"x-forwarded-for", xff.encode())] if xff else []
    return Request({"type": "http", "headers": h, "client": (peer, 1), "method": "GET", "path": "/"})

def test_trusted_proxy_can_be_a_cidr_range(monkeypatch):
    monkeypatch.setattr(settings, "TRUSTED_PROXIES", ["172.16.0.0/12"])           # e.g. the Docker network
    assert get_client_ip(_req("172.18.0.5", "6.6.6.6, 203.0.113.9")) == "203.0.113.9"
    assert get_client_ip(_req("172.18.0.5", "6.6.6.6, 203.0.113.9, 172.18.0.2")) == "203.0.113.9"
    assert get_client_ip(_req("8.8.8.8", "1.2.3.4")) == "8.8.8.8"                   # untrusted peer: header ignored
    assert get_client_ip(_req("not-an-ip", "1.2.3.4")) == "not-an-ip"

async def test_healthz_is_public_and_leaks_nothing(client):
    r = await client.get("/healthz")
    assert r.status_code == 200 and r.json() == {"status": "ok"}

async def test_hsts_is_sent_only_in_production(client, monkeypatch):
    assert "strict-transport-security" not in (await client.get("/healthz")).headers
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    assert "max-age=31536000" in (await client.get("/healthz")).headers["strict-transport-security"]
