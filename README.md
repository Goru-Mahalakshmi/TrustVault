# TrustVault

Secure document sharing where the wrong person cannot reach a file and the record shows who did, including refused attempts.
FastAPI + PostgreSQL, server-side sessions, per-document grants, AES-256-GCM encryption at rest, an HMAC-chained audit trail.

**Live demo:** _add your URL here after deploying (see DEPLOY.md)_  |  **API reference:** `docs/API_REFERENCE.md` (generated from the code, with who may call each endpoint)

## Demo accounts (public demo passwords; created by `python -m scripts.seed`)
| User | Password | Role | Try this |
|---|---|---|---|
| `admin_demo` | `Admin!Demo-2026` | admin | audit log with filters, dashboard, **Audit trail -> Verify integrity**, **Users** page (roles, enable/disable, reset). Cannot open any document. |
| `owner_demo` | `Owner!Demo-2026` | owner | owns 3 documents; **Share** button / **Sharing & access** tab (grant, revoke, expiry); **Activity** tab (who accessed it); AI suggestions (needs `ANTHROPIC_API_KEY`) |
| `owner_two` | `Owner2!Demo-2026` | owner | owns "Site drawings" (2 versions); can read "Board minutes Q3" |
| `viewer_demo` | `Viewer!Demo-2026` | viewer | sees exactly one document; "Contract - Acme Ltd" is shared with nobody |

## Using the interface
- **Roles:** anyone who registers is an **owner**; an admin can change a role under **Users**; admins are created only with `python -m scripts.make_admin <username>`.
- **Share a document:** Documents -> **Share** -> exact email + *Can read* / *Can edit* (+ optional expiry). **Revoke** takes effect immediately.
- **Audit:** owners see the history of their own documents (Document -> **Activity**, or **Audit trail** -> pick a document). Admins see all events as ids only, with filters and **Verify integrity**.
- **Look:** cream light theme with a dark-mode toggle; responsive on phone, tablet and desktop. The front end is plain JS in `src/static/` and works under the strict CSP (no inline scripts or styles, no third-party resources).

## What it does (the brief's requirements)
| Requirement | Where |
|---|---|
| 3 roles: admin / owner / viewer | `src/api/deps.py`, `docs/ROLES.md`; admins have **no** document access |
| Upload, organise, search, manage | upload + versions, edit title/category, soft delete + trash + restore, search by name/owner/category/date with facets |
| Per-document read/edit grants to named people; owners grant and revoke | `POST /api/documents/{id}/grants`, revoke is instant (no tokens or links to expire) |
| Non-granted users cannot read, download, change, delete | one function, `authorize()` in `src/services/authz.py`; missing and ungranted documents both answer `404 Document not found` |
| Audit of uploads, downloads, changes, deletions, permission changes, **and refusals** | HMAC hash chain in `audit_logs`; owners see their document's history, admins see everything (ids only) |
| Upload validation | extension allowlist, magic bytes, executable/script/HTML/SVG rejection, zip-bomb guard, filename sanitising, 25 MB cap, upload rate limit |
| Admin view of document activity and permission changes | **Audit trail** page (admin): filter by kind / actor / result / resource; viewing it is itself audited |
| Tests that one user cannot reach another's documents | `tests/test_isolation.py` attacks every document route (auto-discovered) as another owner, a viewer and an admin, after revoke, expiry, delete and role change |
| AI that only suggests | owner asks, gets suggestions, decides per person; request, suggestions and decisions are audited (`tests/test_ai_decisions.py`). Works with Anthropic **or any OpenAI-compatible API** (several have free tiers): see DEPLOY.md "AI suggestions" |

## Run locally (Windows Command Prompt)
    python -m venv .venv
    .venv\Scripts\activate.bat
    pip install -r requirements.txt
    docker compose up -d                       # PostgreSQL 16 on localhost:5433 (two roles + databases created automatically)
    copy .env.example .env                     # then fill MASTER_KEY_B64 and AUDIT_HMAC_KEY
    python -m pytest -q                        # all tests run on PostgreSQL; refuses to run on SQLite
    set OWNER_DATABASE_URL=postgresql+asyncpg://trustvault_owner:owner_dev_pw@localhost:5433/trustvault
    python -m scripts.init_db                  # schema + grants + audit immutability trigger (OWNER role)
    python -m scripts.seed                     # demo accounts and documents
    uvicorn src.main:app --reload              # http://127.0.0.1:8000
    python -m scripts.make_admin <username>    # promote a real user (there is deliberately no public way to become admin)

No Docker? Install PostgreSQL 16, set its port to 5433 and run `docker/initdb/01_roles.sql` once as the postgres superuser.
`TV_ALLOW_SQLITE=1` + `TEST_DATABASE_URL=sqlite+aiosqlite:///t.db` gives a quick **non-authoritative** run (audit-trigger/grant tests fail there by design).

## The permission model in short
A document is reachable by its **owner** and by people with a live **grant** (`read` or `edit`, optional expiry, revocable). There is no folder or group
inheritance and categories are labels only. Administrators manage accounts and read the audit log but have no access to contents unless an owner
grants it like to anyone else. Every request is checked on the server against the database at that moment, so revoking, disabling a user or changing a
role takes effect on the next request (sessions carry a `security_version` that those actions bump). Downloads are checked twice: before any file is read,
and again on a fresh connection just before the bytes are released.

## What stops the audit trail being quietly altered
(1) the app's database role can only INSERT and SELECT on `audit_logs`; (2) a trigger rejects UPDATE/DELETE/TRUNCATE even for the table owner;
(3) every row is `HMAC-SHA256(key, previous_hash || row)` with the key held **outside** the database, so editing history breaks the chain
(`POST /api/admin/audit/verify`); (4) `scripts/anchor_audit.py` publishes the latest hash outside the system (you schedule it; see DEPLOY.md).
Honest limits are in `THREATS.md` (for example: someone holding both the database owner role and the HMAC key could rewrite history; anchoring only
detects tampering back to the last anchor).

## Tests and the "remove one check" attack
- `python -m pytest -q`: all tests (PostgreSQL). Documentation is tested too: `docs/API_REFERENCE.md` and `db/schema.sql` are generated and a test fails if stale; every
  test and file cited in THREATS.md / README.md / DEPLOY.md must exist.
- `python -m scripts.mutation_check` removes or weakens each security check one at a time (every `authorize()` call site plus many others) and reruns the tests; a
  survivor means a check could be deleted unnoticed. Current result: `MUTATION_REPORT.md`. Mutants are my own list; passing them is strong evidence, not proof.

## Documents
Design documents (unchanged): `docs/ARCHITECTURE.md`, `docs/API.md`, `docs/ROLES.md`, `docs/AI_CONTEXT.md`; what differs from them: `docs/DESIGN_VS_IMPLEMENTATION.md`. `THREATS.md` (attacks, defences, tests, residual risk, what I knowingly accepted) | `docs/API_REFERENCE.md` | `db/schema.sql` + `db/hardening.sql` |
`DEPLOY.md` (Render free tier, or your own server with Docker + Caddy) | `docs/WALKTHROUGH.md` (how authorisation works, for the interview) | `DEMO.md` | `WRITEUP.md` | `PROMPTS.md`

## Decisions and known limits (what is NOT built or NOT proven)
- `transfer-accept`/`transfer-reject` by anyone but the pending recipient return **404** (not 403), so they cannot be used to probe whether a document id exists.
- Anyone who can read a document can read its whole version history (grants are per document, not per version).
- The AI sees only a document's title and category plus names and past categories of people the owner already shared with; never file contents, so there is no content opt-in.
- **Deployment is not proven here:** Docker images, Caddy and Render were written but not built in the authoring environment (`DEPLOY.md` says exactly what was and was not run).
- No Alembic migrations: the schema is created by `scripts/init_db.py` (`db/schema.sql` is the readable copy).
- No email verification at sign-up, no MFA, email defaults to console output (reset links appear in the server log) unless SMTP is configured.
- No per-user storage quota; upload validation of `.docx/.xlsx` is a ZIP-header + bomb check, not full structure, and there is no antivirus.
- Response *timing* equality between "missing" and "ungranted" documents is by construction (same query) but not measured.
- The UI keeps the CSRF token in `sessionStorage` (strict CSP, no `innerHTML`); a successful XSS would still be serious.
- Most tests share one database session between requests; the attack tests in `tests/test_phase1_attacks.py` use independent sessions for real concurrency.
- Without a persistent disk, files are stored encrypted in PostgreSQL (`STORAGE_BACKEND=db`); on single-user hosts the audit table is protected by the trigger only.
