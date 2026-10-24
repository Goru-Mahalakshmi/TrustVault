"""Mutation check for authorisation: break ONE security check at a time and confirm the test suite fails.
A mutant that SURVIVES means a judge could delete that check and your tests would still pass.

    python -m scripts.mutation_check            # run everything (several minutes)
    python -m scripts.mutation_check --list     # show the mutants and check each one applies
    python -m scripts.mutation_check -k grant   # only mutants whose name contains 'grant'
"""
import pathlib, re, subprocess, sys, time

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOCS = "src/api/documents.py"
BYPASS = '\n\nasync def _bypass(db, doc_id):  # MUTANT: authorize() removed\n    d = (await db.execute(select(Document).where(Document.id == doc_id))).scalar_one_or_none()\n    if d is None:\n        raise HTTPException(404, "Document not found")\n    return d\n'
CALL = re.compile(r"await authorize\(db, ctx, request, doc_id, Action\.(\w+)\)")

# (name, file, old, new)
STATIC = [
    ("authz: grantee may do anything (level ignored)", "src/services/authz.py",
     'return (doc, "allow") if action in LEVEL_ACTIONS.get(rel, set()) else (doc, "forbid")', 'return doc, "allow"'),
    ("authz: read grant also allows edit", "src/services/authz.py",
     '"read": {Action.READ, Action.DOWNLOAD}', '"read": {Action.READ, Action.DOWNLOAD, Action.EDIT}'),
    ("authz: revoked grants still work", "src/services/authz.py",
     "Grant.grantee_user_id == uid, Grant.revoked_at.is_(None),", "Grant.grantee_user_id == uid,"),
    ("authz: expired grants still work", "src/services/authz.py",
     "or_(Grant.expires_at.is_(None), Grant.expires_at > func.now()))", "or_(Grant.expires_at.is_(None), Grant.expires_at.is_not(None)))"),
    ("authz: deleted documents stay reachable", "src/services/authz.py", "    if doc.is_deleted:", "    if False:"),
    ("authz: anyone may restore a non-deleted doc", "src/services/authz.py",
     "    if action == Action.RESTORE:\n        return None, \"notfound\"", "    if False:\n        return None, \"notfound\""),
    ("authz: ownership/grant predicate removed (everyone sees everything)", "src/services/authz.py",
     "Document.id == doc_id, or_(Document.owner_id == uid, active.is_not(None))", "Document.id == doc_id"),
    ("authz: transfer-accept open to non-recipients", "src/services/authz.py", "    if doc.pending_owner_id != ctx.user_id:", "    if False:"),
    ("authz: pre-send re-check always passes", "src/services/authz.py", 'return outcome == "allow"', "return True"),
    ("authz: refusal not audited", "src/services/authz.py", "    _, retry = await log_refusal_status(", "    _, retry = (None, 0), 0\n    _unused = (lambda **k: None)("),
    ("download: revocation re-check ignored", DOCS, "        if not ok:\n            await db.rollback()", "        if False:\n            await db.rollback()"),
    ("grants: expiry in the past accepted", DOCS, "if exp <= datetime.now(timezone.utc):", "if False:"),
    ("upload: any role may upload", DOCS, 'if ctx.role != "owner":', "if False:"),
    ("transfer: recipient need not be an owner", DOCS, 'if target.role != "owner":', "if False:"),
    ("transfer: accept ignores recipient role", DOCS, 'if doc.is_deleted or ctx.role != "owner":', "if False:"),
    ("transfer: can transfer to yourself", DOCS, "if target.id == ctx.user_id:\n        raise HTTPException(400, \"Document is already yours\")", "if False:\n        raise HTTPException(400, \"Document is already yours\")"),
    ("grants: can grant to yourself", DOCS, "if target.id == ctx.user_id:\n        raise HTTPException(400, \"You cannot grant access to yourself\")", "if False:\n        raise HTTPException(400, \"You cannot grant access to yourself\")"),
    ("search: permission predicate dropped from results", DOCS, "    visible = [Document.is_deleted.is_(False), or_(Document.owner_id == ctx.user_id, Document.id.in_(active))]", "    visible = [Document.is_deleted.is_(False)]"),
    ("search: deleted docs listed", DOCS, "    visible = [Document.is_deleted.is_(False), ", "    visible = ["),
    ("search: facets ignore visibility", DOCS, "select(Document.category, func.count()).where(*visible, *filters)", "select(Document.category, func.count()).where(*filters)"),
    ("search: grants never expire in listings", DOCS, "        or_(Grant.expires_at.is_(None), Grant.expires_at > func.now()))\n    visible", "        or_(Grant.expires_at.is_(None), Grant.expires_at.is_not(None)))\n    visible"),
    ("upload: magic-byte check removed", "src/core/uploads.py", "    if not ok:\n        return \"File content does not match its extension\"", "    if False:\n        return \"File content does not match its extension\""),
    ("upload: extension allowlist removed", "src/core/uploads.py", "    if ext not in ALLOWED:", "    if False:"),
    ("upload: executable signatures allowed", "src/core/uploads.py", "    if head.startswith(_BAD_START) or head.lstrip().lower().startswith(_BAD_TEXT):", "    if False:"),
    ("upload: size limit removed", DOCS, "if len(data) > settings.MAX_UPLOAD_BYTES:", "if False:"),
    ("upload: decompression-bomb guard removed", "src/core/uploads.py", "        if total > 100 * 1024 * 1024 or total > 100 * max(len(data), 1):", "        if False:"),
    ("upload: filename not sanitised", "src/core/uploads.py", 'return re.sub(r"[^A-Za-z0-9._-]", "_", name).lstrip(".")[:100] or "file"', "return name or 'file'"),
    ("download: attachment header removed", DOCS, '"Content-Disposition": f\'attachment;', '"X-Disabled": f\'attachment;'),
    ("download: nosniff removed", DOCS, '"X-Content-Type-Options": "nosniff", "Content-Security-Policy"', '"X-Disabled2": "nosniff", "Content-Security-Policy"'),
    ("auth: CSRF check removed", "src/api/deps.py", "        if not hmac.compare_digest(hash_token(sent), sess.csrf_token_hash):", "        if False:"),
    ("auth: CSRF header may be missing", "src/api/deps.py", "        if not sent:", "        if False:"),
    ("auth: security_version ignored (role change/disable/reset do not kill sessions)", "src/api/deps.py", "or user.security_version != sess.user_security_version", ""),
    ("auth: revoked sessions accepted (logout/rotation do nothing)", "src/api/deps.py", "if not sess or sess.revoked_at is not None:", "if not sess:"),
    ("auth: idle timeout removed", "src/api/deps.py", "    if now - _utc(sess.last_active_at) > timedelta(", "    if False and now - _utc(sess.last_active_at) > timedelta("),
    ("auth: absolute timeout removed", "src/api/deps.py", "    if _utc(sess.expires_at) <= now:", "    if False:"),
    ("auth: disabled user's session accepted", "src/api/deps.py", "or not user.is_active", ""),
    ("auth: role check removed (any user is admin)", "src/api/deps.py", "        if ctx.user.role != role:", "        if False:"),
    ("admin: can demote self", "src/api/admin.py", "    if u.id == ctx.user_id:\n        raise HTTPException(400, \"Admins cannot change their own role\")", "    if False:\n        raise HTTPException(400, \"Admins cannot change their own role\")"),
    ("admin: role change does not end sessions", "src/api/admin.py", "    u.role = body.role.value\n    u.security_version += 1", "    u.role = body.role.value"),
    ("admin: disable does not end sessions", "src/api/admin.py", "    u.is_active = body.is_active\n    u.security_version += 1", "    u.is_active = body.is_active"),
    ("auth: password change does not end sessions", "src/services/auth_service.py", "user.security_version += 1", "pass"),
    ("login: lockout never engages", "src/services/auth_service.py", "if attempts >= settings.MAX_FAILED_LOGIN_ATTEMPTS:", "if False:"),
    ("rate limit: never blocks", "src/services/rate_limiter.py", "    if count <= limit:", "    if True:"),
    ("ip: trusts leftmost X-Forwarded-For", "src/services/rate_limiter.py", "for hop in reversed([h.strip()", "for hop in ([h.strip()"),
    ("deploy: production guard rails removed", "src/core/config.py", '        if self.ENVIRONMENT != "production":\n            return self', "        if True:\n            return self"),
    ("deploy: forwarded headers trusted from any peer", "src/services/rate_limiter.py", "    if not _is_trusted_proxy(direct_ip):\n        return direct_ip", "    if False:\n        return direct_ip"),
    ("deploy: interactive docs enabled in production", "src/core/config.py", 'return self.ENABLE_DOCS if self.ENABLE_DOCS is not None else self.ENVIRONMENT != "production"', "return True"),
    ("deploy: HSTS header removed", "src/main.py", 'if settings.ENVIRONMENT == "production":\n        r.headers.setdefault("Strict-Transport-Security"', 'if False:\n        r.headers.setdefault("Strict-Transport-Security"'),
    ("ai: model-suggested ids not validated against candidates", "src/services/ai_service.py", "        if uid in cands and uid not in seen:", "        if True:"),
    ("ai: document text can break out of the prompt delimiters", "src/services/ai_service.py", '.replace("<", "\\\\u003c").replace(">", "\\\\u003e")', ""),
    ("ai: a suggestion can be decided twice", DOCS, 'if item["status"] != "pending":', "if False:"),
    ("ai: rejecting also grants access", DOCS, 'if body.action == "reject":', "if False:"),
    ("ai: decision may name a person who was never suggested", DOCS, "if rec is None or item is None:", "if rec is None:"),
    ("ai: suggestion not bound to this owner and document", DOCS, "AiSuggestion.id == suggestion_id, AiSuggestion.document_id == doc.id, AiSuggestion.owner_id == ctx.user_id)", "AiSuggestion.id == suggestion_id)"),
    ("ai: modified decision recorded as accepted", DOCS, 'label = "accepted" if (body.level == "read" and body.expires_at is None) else "modified"', 'label = "accepted"'),
    ("ai: suggested people not audited", DOCS, "    for x in suggestions:                                    # the suggestions themselves", "    for x in []:                                    # the suggestions themselves"),
    ("ai: rejection not audited", DOCS, 'await audit(db, ctx, request, "AI_SUGGESTION_REJECTED"', 'await audit(db, ctx, request, "UNLOGGED_REJECTED"'),
    ("ai: expiry dropped from the AI-assisted grant", DOCS, "g = await _issue_grant(db, ctx, request, doc, target, body.level, body.expires_at)\n        grant_id", "g = await _issue_grant(db, ctx, request, doc, target, body.level, None)\n        grant_id"),
    ("ai: suggestions auto-applied as grants", DOCS, '    return {"advisory_only": True, "suggestion_id"', '    for x in suggestions:\n        db.add(Grant(document_id=doc.id, grantee_user_id=uuid.UUID(x["user_id"]), level="read", granted_by=ctx.user_id))\n    await db.commit()\n    return {"advisory_only": True, "suggestion_id"'),
    ("req: edit grantees may relabel documents", "src/services/authz.py", '"edit": {Action.READ, Action.DOWNLOAD, Action.EDIT}', '"edit": {Action.READ, Action.DOWNLOAD, Action.EDIT, Action.UPDATE_METADATA}'),
    ("req: edit grantees may read the document's audit history", "src/services/authz.py", '"edit": {Action.READ, Action.DOWNLOAD, Action.EDIT}', '"edit": {Action.READ, Action.DOWNLOAD, Action.EDIT, Action.AUDIT_VIEW}'),
    ("req: trash lists other people's deleted documents", DOCS, "Document.owner_id == ctx.user_id, Document.is_deleted.is_(True)", "Document.is_deleted.is_(True)"),
    ("req: document history includes other documents' events", DOCS, 'AuditLog.resource_type == "document", AuditLog.resource_id == str(doc.id)', 'AuditLog.resource_type == "document"'),
    ("req: metadata edit not audited", DOCS, '"DOCUMENT_METADATA_UPDATE"', '"UNLOGGED_UPDATE"'),
    ("req: document history view not audited", DOCS, '"DOCUMENT_AUDIT_VIEW"', '"UNLOGGED_VIEW"'),
    ("req: upload rate limit removed (new document)", DOCS, 'await enforce_rate_limit(db, request, "upload", settings.RATE_LIMIT_UPLOADS_PER_MIN, identifier=str(ctx.user_id))\n    data, name = await _read_upload(file)\n    doc = Document(', '0 and await enforce_rate_limit(db, request, "upload", settings.RATE_LIMIT_UPLOADS_PER_MIN, identifier=str(ctx.user_id))\n    data, name = await _read_upload(file)\n    doc = Document('),
    ("req: upload rate limit removed (new version)", DOCS, 'await enforce_rate_limit(db, request, "upload", settings.RATE_LIMIT_UPLOADS_PER_MIN, identifier=str(ctx.user_id))\n    data, name = await _read_upload(file)\n    await db.execute', '0 and await enforce_rate_limit(db, request, "upload", settings.RATE_LIMIT_UPLOADS_PER_MIN, identifier=str(ctx.user_id))\n    data, name = await _read_upload(file)\n    await db.execute'),
    ("req: admin activity kind filter ignored", "src/api/admin.py", "    if kind:\n        conds.append", "    if False:\n        conds.append"),
    ("req: admin activity status filter ignored", "src/api/admin.py", "    if status:\n        conds.append", "    if False:\n        conds.append"),
    ("req: admin activity actor filter ignored", "src/api/admin.py", "    if actor:\n        conds.append", "    if False:\n        conds.append"),
    ("req: admin activity resource filter ignored", "src/api/admin.py", "    if resource_id:\n        conds.append", "    if False:\n        conds.append"),
    ("req: admin activity view not audited", "src/api/admin.py", '"AUDIT_LOG_VIEW"', '"UNLOGGED_AUDIT_VIEW"'),
    ("req: forgot-password per-IP limit removed", "src/api/auth.py", '"forgot_ip", settings.RATE_LIMIT_FORGOT_PER_HOUR', '"forgot_ip", 10**6'),
    ("req: forgot-password per-email limit removed", "src/api/auth.py", '"forgot_email", settings.RATE_LIMIT_FORGOT_PER_HOUR', '"forgot_email", 10**6'),
    ("req: reset links live too long", "src/core/config.py", "PASSWORD_RESET_TOKEN_EXPIRE_MINUTES: int = 15", "PASSWORD_RESET_TOKEN_EXPIRE_MINUTES: int = 1500"),
    ("req: email-change links live too long", "src/core/config.py", "EMAIL_CHANGE_TOKEN_EXPIRE_MINUTES: int = 15", "EMAIL_CHANGE_TOKEN_EXPIRE_MINUTES: int = 1500"),
    ("req: registration limit raised", "src/core/config.py", "RATE_LIMIT_REGISTER_PER_MIN: int = 5", "RATE_LIMIT_REGISTER_PER_MIN: int = 500"),
    ("ai: provider call sends no credentials", "src/services/ai_service.py", 'headers={"Authorization": f"Bearer {settings.AI_API_KEY}"}', "headers={}"),
    ("ai: unconfigured provider no longer refused", DOCS, "    if not settings.ai_configured:\n        raise HTTPException(503", "    if False:\n        raise HTTPException(503"),
    ("ai: provider reply not tolerant of code fences", "src/services/ai_service.py", '        if i != -1 and j > i:\n            return json.loads(text[i:j + 1])', '        if False:\n            return json.loads(text[i:j + 1])'),
    ("audit: chain not linked to previous hash", "src/services/audit_service.py", "            prev_hash = last_row[1]", "            prev_hash = GENESIS_HASH"),
    ("audit: verification always passes", "src/services/audit_service.py", "        if not hmac.compare_digest(row.row_hash, computed_hash):", "        if False:"),
]

def quick_for(endpoint_name):
    """Fast first phase for a call-site mutant: the isolation test of exactly that route (plus the AI decision tests)."""
    sys.path.insert(0, str(ROOT))
    from src.main import app
    from scripts.route_inventory import all_api_routes
    for r in all_api_routes(app):
        if r.endpoint.__name__ == endpoint_name:
            for m in sorted(r.methods - {"HEAD"}):
                rid = f"{m} {r.path.replace('/api/documents/', '')}"
                return ["tests/test_isolation.py::test_user_b_cannot_reach_user_a_document_on_any_route[" + rid + "]",
                        "tests/test_ai_decisions.py"]
    return None

def known_killers():
    """name -> test id that killed the mutant in the previous report: tried FIRST (a failure is a genuine kill; if it does not
    fail, the mutant still faces the whole suite)."""
    report, out = ROOT / "MUTATION_REPORT.md", {}
    if report.exists():
        for line in report.read_text(encoding="utf-8").splitlines():
            m = re.match(r"- KILLED  : (.*?)  \(first failing test: `(\S+::test_\w+)(\[[^\]]*\])?`\)$", line)
            if m:                                    # truncated parametrised ids do not match the pattern, so they are skipped
                out[m.group(1)] = m.group(2) + (m.group(3) or "")
    return out

def mutants():
    docs = (ROOT / DOCS).read_text(encoding="utf-8")
    for i, m in enumerate(CALL.finditer(docs)):
        old = m.group(0)
        n = docs[: m.start()].count(old)        # which occurrence of this exact text
        fn = re.findall(r"async def (\w+)\(", docs[: m.start()])[-1]            # endpoint that contains this call site
        yield (f"authorize() call site #{i+1} removed: Action.{m.group(1)} (line {docs[:m.start()].count(chr(10))+1})",
               DOCS, old, "await _bypass(db, doc_id)", n, BYPASS, quick_for(fn))
    for name, f, old, new in STATIC:
        yield name, f, old, new, None, "", ([KILLERS[name]] if name in KILLERS else None)

PRIORITY = ["test_requirements.py", "test_email_and_frontend.py", "test_ai_decisions.py", "test_deploy_config.py", "test_documents.py", "test_search_and_versions.py",
            "test_upload_attacks.py", "test_phase1_attacks.py", "test_isolation.py"]

def test_files():
    """Every test file EXPLICITLY, likely killers first (pytest ignores the order when a directory is also given), so a
    kill is found quickly. test_docs_current.py is excluded: it fails on any source edit and must not count as a kill."""
    names = [f.name for f in sorted((ROOT / "tests").glob("test_*.py")) if f.name != "test_docs_current.py"]
    first = [n for n in PRIORITY if n in names]
    return [f"tests/{n}" for n in first + [n for n in names if n not in first]]

def apply(text, old, new, nth, extra, *_):
    if old not in text:
        return None
    if nth is None:
        out = text.replace(old, new)
    else:
        idx = -1
        for _ in range(nth + 1):
            idx = text.index(old, idx + 1)
        out = text[:idx] + new + text[idx + len(old):]
    return out + extra

BACKUP = ROOT / ".mutation_backup"
KILLERS = None

def restore_stale_backup():
    """A killed run can leave a mutated file behind. Originals are saved before the first mutation; put them back."""
    if BACKUP.exists():
        for saved in BACKUP.rglob("*"):
            if saved.is_file():
                target = ROOT / saved.relative_to(BACKUP)
                target.write_text(saved.read_text(encoding="utf-8"), encoding="utf-8")
                print("restored", target.relative_to(ROOT))
        import shutil; shutil.rmtree(BACKUP)

def save_backup(files):
    for f in files:
        dst = BACKUP / f
        dst.parent.mkdir(parents=True, exist_ok=True)
        if not dst.exists():
            dst.write_text((ROOT / f).read_text(encoding="utf-8"), encoding="utf-8")

def main(argv):
    global KILLERS
    KILLERS = known_killers()
    restore_stale_backup()
    if "--restore" in argv:
        return
    only = argv[argv.index("-k") + 1] if "-k" in argv else None
    items = [m for m in mutants() if not only or only.lower() in m[0].lower()]
    if "--file" in argv:
        items = [m for m in items if m[1] == argv[argv.index("--file") + 1] and not m[0].startswith("authorize() call site")]
    lo = int(argv[argv.index("--from") + 1]) if "--from" in argv else 1
    hi = int(argv[argv.index("--to") + 1]) if "--to" in argv else len(items)
    if "--report" in argv:
        return write_report(items)
    numbered = list(enumerate(items, 1))
    items_run = [(n, m) for n, m in numbered if lo <= n <= hi]
    if "--resume" in argv and (ROOT / ".mutation_results.jsonl").exists():
        rows = [__import__("json").loads(l) for l in (ROOT / ".mutation_results.jsonl").read_text(encoding="utf-8").splitlines()]
        done = {r["name"] for r in rows if r["verdict"] == "killed"}   # survivors are re-run after the tests improve
        items_run = [(n, m) for n, m in items_run if m[0] not in done]
    if "--list" in argv:
        bad = 0
        for name, f, old, new, nth, extra, quick in items:
            ok = apply((ROOT / f).read_text(encoding="utf-8"), old, new, nth, extra) is not None
            bad += not ok
            print(("ok   " if ok else "MISSING ") + name)
        sys.exit(1 if bad else 0)
    save_backup({m[1] for _, m in items_run})
    results = []
    for n, (name, f, old, new, nth, extra, quick) in items_run:
        path = ROOT / f
        original = path.read_text(encoding="utf-8")
        mutated = apply(original, old, new, nth, extra)
        if mutated is None:
            results.append((name, "NOT APPLICABLE (source changed; fix the mutant)")); print(f"[{n}/{len(items)}] N/A       {name}", flush=True); continue
        t = time.time()
        try:
            path.write_text(mutated, encoding="utf-8")
            try:
                verdict, killer = None, ""
                if quick:                                   # phase 1: only the tests that should catch THIS mutant
                    q = subprocess.run([sys.executable, "-m", "pytest", "-x", "-q", "--timeout=120", "-p", "no:cacheprovider", *quick],
                                       cwd=ROOT, capture_output=True, text=True, timeout=300)
                    if q.returncode == 1:                   # 1 = tests failed (2..5 = infrastructure trouble: do not trust it)
                        mm = re.search(r"FAILED (\S+)", q.stdout)
                        verdict, killer = "killed", (mm.group(1) if mm else "quick phase")
                if verdict is None:                         # phase 2 (all mutants without a quick selector, and every survivor of phase 1)
                    p = subprocess.run([sys.executable, "-m", "pytest", "-x", "-q", "--timeout=120", "-p", "no:cacheprovider", *test_files()],
                                       cwd=ROOT, capture_output=True, text=True, timeout=900)
                    verdict = "SURVIVED" if p.returncode == 0 else "killed"
                    if p.returncode != 0:
                        mm = re.search(r"FAILED (\S+)", p.stdout)
                        killer = mm.group(1) if mm else ("error" if "ERROR" in p.stdout else "")
            except subprocess.TimeoutExpired:
                verdict, killer = "killed", "timeout"
        finally:
            path.write_text(original, encoding="utf-8")        # ALWAYS restore
        results.append((name, verdict, killer))
        with open(ROOT / ".mutation_results.jsonl", "a", encoding="utf-8") as fh:
            fh.write(__import__("json").dumps({"name": name, "verdict": verdict, "killer": killer}) + "\n")
        print(f"[{n}/{len(items)}] {verdict:9} {time.time()-t:5.1f}s  {name}  {('<- ' + killer) if killer else ''}", flush=True)
    import shutil; shutil.rmtree(BACKUP, ignore_errors=True)       # clean finish: originals are already back in place
    survivors = [r for r in results if r[1] != "killed"]
    print(f"\nchunk done: {len(results)-len(survivors)}/{len(results)} killed; survivors: {len(survivors)}")
    sys.exit(1 if survivors else 0)

def write_report(items):
    import json
    latest = {}
    for line in (ROOT / ".mutation_results.jsonl").read_text(encoding="utf-8").splitlines():
        r = json.loads(line); latest[r["name"]] = r
    names = [m[0] for m in items]
    done = [latest[n] for n in names if n in latest]
    surv = [r for r in done if r["verdict"] != "killed"]
    lines = ["# Mutation check report", "",
             f"{len(done) - len(surv)} of {len(names)} mutants killed ({len(names) - len(done)} not yet run). "
             "A mutant is one deleted or weakened security check; 'killed' means a test failed.", ""]
    lines += [f"- {'KILLED  ' if r['verdict']=='killed' else '**SURVIVED**'}: {r['name']}"
              + (f"  (first failing test: `{r['killer']}`)" if r["killer"] else "") for r in done]
    (ROOT / "MUTATION_REPORT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[:3])); print("survivors:", [r["name"] for r in surv])

if __name__ == "__main__":
    main(sys.argv[1:])
