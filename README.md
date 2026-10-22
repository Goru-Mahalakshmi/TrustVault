# TrustVault

Secure document sharing: per-document grants, instant revocation, envelope encryption, HMAC-chained audit trail.

## Run (Windows Command Prompt)
    python -m venv .venv
    .venv\Scripts\activate.bat
    pip install -r requirements.txt
    docker compose up -d                       # PostgreSQL 16 on localhost:5433 (roles + databases created automatically)
    copy .env.example .env                     # then fill MASTER_KEY_B64 and AUDIT_HMAC_KEY
    python -m pytest -q                        # 129 tests, all on PostgreSQL (refuses to run on SQLite)
    set OWNER_DATABASE_URL=postgresql+asyncpg://trustvault_owner:owner_dev_pw@localhost:5433/trustvault
    python -m scripts.init_db                  # schema + grants + audit immutability trigger (as OWNER role)
    uvicorn src.main:app --reload              # UI at http://127.0.0.1:8000
    python -m scripts.make_admin <username>    # first admin (no public way to become admin)

No Docker? Install PostgreSQL 16 locally, set its port to 5433, and run docker\initdb\01_roles.sql once as the postgres
superuser. A quick NON-authoritative run on SQLite is possible with TV_ALLOW_SQLITE=1 and TEST_DATABASE_URL=sqlite+aiosqlite:///t.db
(audit trigger / grant tests will fail there by design).

## Demo accounts (after `python -m scripts.seed`; PUBLIC demo passwords, see DEPLOY.md to change them)
| User | Password | Role |
|---|---|---|
| `admin_demo` | `Admin!Demo-2026` | admin |
| `owner_demo` | `Owner!Demo-2026` | owner |
| `owner_two` | `Owner2!Demo-2026` | owner |
| `viewer_demo` | `Viewer!Demo-2026` | viewer (can reach exactly one document) |

## Deploy
See **DEPLOY.md** (Docker Compose + Caddy HTTPS, clean clone to live URL, with a verification checklist).

## Mutation check (does the test suite really guard authorisation?)
    python -m scripts.mutation_check            # ~25 min: removes/weakens 61 security checks ONE at a time, reruns the tests
    python -m scripts.mutation_check --list     # confirm every mutant still applies to the source
    python -m scripts.mutation_check --resume   # continue after an interruption (originals are always restored first)
A mutant that SURVIVES = a check someone could delete without any test failing. Current result: MUTATION_REPORT.md.

## Two database roles (why)
`trustvault_owner` creates the schema and the audit trigger. The API connects as `trustvault_app`, which cannot create
tables, cannot drop the trigger, and has INSERT + SELECT only on `audit_logs`. Tests prove: the app role is refused
UPDATE/DELETE/TRUNCATE; the trigger blocks even the owner; a DBA who disables the trigger and edits history still breaks the HMAC chain.

## Email
EMAIL_BACKEND=console (default) prints reset / email-change links in the server terminal. For real delivery set
EMAIL_BACKEND=smtp plus SMTP_HOST/PORT/USER/PASSWORD/FROM and APP_BASE_URL.

## Layout
src/api | src/services (authz kernel, audit, auth, rate limit, AI) | src/core | src/static (UI) | db/hardening.sql |
docker-compose.yml | scripts/ (init_db, make_admin, anchor_audit) | tests/ | THREATS.md

## Decisions taken without being asked (reverse any of them)
- `transfer-accept` / `transfer-reject` by anyone who is not the pending recipient return 404, not 403 (ROLES.md/API.md still say 403: update them).
- Disabled-account status is revealed only after the correct password; locked accounts return 423 for any password.
- X-Forwarded-For: rightmost entry that is not a trusted proxy.

- Anyone who can read a document can read its WHOLE version history (grants are per document, not per version).
- Search by owner is by exact username and runs only over documents the caller may already read.

## Known limits
- Tests run on PostgreSQL 16; anchoring (scripts/anchor_audit.py) works but is not scheduled by this repo.
- No Alembic migrations yet (scripts/init_db.py uses create_all + db/hardening.sql).
- Identical response *timing* for missing vs ungranted documents is designed, not measured.
- The UI keeps the CSRF token in sessionStorage; strict CSP limits XSS risk but does not remove it.
- The web UI does not expose the new search filters, facets or version history yet (the API does).
- AI decisions (accept/reject) are not yet audited; AI requests are, with a count only.
- Mutants are chosen by me: passing them is evidence, not proof. A judge may break a check I did not think of.
