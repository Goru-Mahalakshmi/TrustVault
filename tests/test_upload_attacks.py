import os
import pytest
from src.core.config import settings
from tests.test_documents import actor, storage, PDF  # noqa: F401

@pytest.mark.parametrize("name,data", [
    ("a.pdf\x00.exe", PDF),                       # null-byte extension trick
    ("report\u202egpj.exe", b"MZ" + b"\x00" * 60),  # right-to-left override disguising an .exe
    ("invoice.pdf.exe", PDF),                     # double extension
    ("x.pdf", b"\x89PNG\r\n\x1a\n" + b"0" * 20),  # PNG bytes claiming to be a PDF
    ("x.pdf", b""),                               # empty file
    ("x.pdf", b"#!/bin/sh\nrm -rf /"),            # script with a document extension
    ("x.png", b"<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'/>"),
    ("x.txt", b"<script>alert(1)</script>"),
    ("x.csv", b"id,name\n\x00\x01\x02"),          # binary pretending to be text
    ("x.exe", PDF), ("x.php", PDF), ("x.html", b"<html>"), ("x.svg", b"<svg/>"), ("x.js", b"alert(1)"),
])
async def test_dangerous_uploads_are_rejected(actor, name, data):
    a = await actor("alice")
    r = await a.upload(data, name)
    assert r.status_code == 400, (name, r.status_code, r.text)

async def test_oversize_upload_is_rejected_with_413(actor):
    a = await actor("alice")
    r = await a.upload(b"%PDF-" + b"0" * settings.MAX_UPLOAD_BYTES, "big.pdf")
    assert r.status_code == 413

async def test_hostile_filename_never_reaches_disk_or_headers(actor, storage):
    a = await actor("alice")
    doc = (await a.upload(PDF, '../../etc/passwd"; x=y\r\nSet-Cookie: pwn=1.pdf')).json()["id"]
    names = os.listdir(storage)
    assert len(names) == 1 and len(names[0]) == 36 + 1 + 36 + 4 and names[0].endswith(".enc")   # uuid_uuid.enc only
    r = await a.req("GET", f"/api/documents/{doc}/download")
    assert "set-cookie" not in r.headers and "\r" not in r.headers["content-disposition"] and ".." not in r.headers["content-disposition"]

async def test_php_named_pdf_is_stored_inert_and_served_as_an_attachment(actor):
    a = await actor("alice")
    doc = (await a.upload(PDF + b"<?php system($_GET[0]); ?>", "payload.php.pdf")).json()["id"]
    r = await a.req("GET", f"/api/documents/{doc}/download")
    assert r.headers["content-type"] == "application/octet-stream" and r.headers["content-disposition"].startswith("attachment")
    assert r.headers["x-content-type-options"] == "nosniff" and "sandbox" in r.headers["content-security-policy"]

@pytest.mark.parametrize("hostile", ['a"b.pdf', "a;b=c.pdf", "a b'c.pdf", "a\\b.pdf", "a<b>.pdf", "a:b|c?.pdf", "é€名.pdf"])
async def test_stored_filename_contains_only_safe_characters(actor, hostile):
    """Quotes, semicolons and spaces in a filename could break out of Content-Disposition; the sanitiser itself must
    neutralise them (not rely on later steps)."""
    import re
    from sqlalchemy import select
    a = await actor("alice")
    doc = (await a.upload(PDF, hostile)).json()["id"]
    cd = (await a.req("GET", f"/api/documents/{doc}/download")).headers["content-disposition"]
    name = re.search(r'filename="([^"]*)"', cd).group(1)
    assert re.fullmatch(r"[A-Za-z0-9._-]+", name), name
    assert cd.count('"') == 2 and cd.count(";") == 2          # attachment; filename="x"; filename*=UTF-8''x

async def test_download_security_headers_are_set_by_the_route_itself(actor, db_session):
    """The app-wide middleware also adds nosniff. Serve the router WITHOUT the middleware so deleting the route's own
    headers cannot hide behind it."""
    import httpx
    from fastapi import FastAPI
    from src.api import documents
    from src.db.session import get_db
    from tests.conftest import TestingSessionLocal
    from tests.test_documents import Actor
    a = await actor("alice")
    doc = (await a.upload()).json()["id"]
    bare = FastAPI(); bare.include_router(documents.router)
    async def fresh():
        async with TestingSessionLocal() as s:
            yield s
    bare.dependency_overrides[get_db] = fresh
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=bare), base_url="http://t") as c:
        t = Actor.__new__(Actor); t.c, t.user, t.cookies, t.h = c, a.user, a.cookies, a.h
        r = await t.req("GET", f"/api/documents/{doc}/download")
    assert r.status_code == 200
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["content-disposition"].startswith("attachment;")
    assert "sandbox" in r.headers["content-security-policy"] and r.headers["cache-control"] == "no-store"
