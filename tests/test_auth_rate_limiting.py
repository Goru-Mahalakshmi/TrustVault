import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from src.core.config import settings
from src.models.audit import AuditLog
from src.services.audit_service import log_refusal


@pytest.mark.asyncio
async def test_login_rate_limiting(client: AsyncClient):
    # Send 5 attempts (allowed)
    for i in range(5):
        resp = await client.post(
            "/api/auth/login",
            json={"username": f"user_probe_{i}", "password": "WrongPassword!123"},
        )
        assert resp.status_code == 401

    # 6th attempt should be blocked by rate limiter with 429
    resp_rate_limited = await client.post(
        "/api/auth/login",
        json={"username": "user_probe_final", "password": "WrongPassword!123"},
    )
    assert resp_rate_limited.status_code == 429
    assert "Rate limit exceeded" in resp_rate_limited.json()["detail"]
    assert "Retry-After" in resp_rate_limited.headers


@pytest.mark.asyncio
async def test_trusted_proxy_ip_resolution(client: AsyncClient):
    # By default, client connects from testserver (127.0.0.1 which is in TRUSTED_PROXIES)
    # Header X-Forwarded-For should be respected
    resp1 = await client.post(
        "/api/auth/login",
        json={"username": "ip_test_user", "password": "WrongPassword!123"},
        headers={"X-Forwarded-For": "203.0.113.195, 127.0.0.1"},
    )
    assert resp1.status_code == 401


@pytest.mark.asyncio
async def test_refusal_rate_limiting_and_aggregation(db_session: AsyncSession):
    from src.services.audit_service import _suppressed_refusals
    _suppressed_refusals.clear()

    test_ip = "198.51.100.42"

    # Log 20 refusals (within limit)
    for i in range(20):
        entry = await log_refusal(
            action="TEST_REFUSAL",
            resource_type="document",
            ip_address=test_ip,
            reason="PROBING_ATTEMPT",
        )
        assert entry is not None

    # 21st refusal should be suppressed
    entry_suppressed = await log_refusal(
        action="TEST_REFUSAL",
        resource_type="document",
        ip_address=test_ip,
        reason="PROBING_ATTEMPT",
    )
    assert entry_suppressed is None

    # Next attempt flushes the aggregate event
    # Let's verify that audit_logs contains rows
    from src.services.audit_service import verify_audit_chain
    is_valid, count, broken_seq = await verify_audit_chain(db_session)
    assert is_valid is True
    assert count >= 20
