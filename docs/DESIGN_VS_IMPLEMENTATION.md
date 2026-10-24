# Design documents vs what is built

`ARCHITECTURE.md`, `API.md`, `ROLES.md` and `AI_CONTEXT.md` in this folder are the **original design documents**, kept unchanged. Where the finished system
differs, this file says how. **`API_REFERENCE.md` (generated from the code) is the authority on what exists today.**

## Differences (deliberate, with reasons)
| Design says | Implemented | Why |
|---|---|---|
| `transfer-accept` / `transfer-reject` by anyone other than the recipient: `403` (ROLES.md matrix, API.md) | `404 Document not found` | a 403 would let any signed-in user tell whether a document id exists |
| Global cap on concurrent decrypts | a cap **per server process** (`MAX_CONCURRENT_DECRYPTS`, default 10) | in-process semaphore; with N workers the real ceiling is N times higher |
| Files on disk in `STORAGE_DIR` | `disk` **or** `db` (encrypted blob in PostgreSQL, `STORAGE_BACKEND=db`) | hosts without a persistent disk (Render free tier) |
| Separate owner and app database roles | two roles by default; **single-role mode** on hosts that give one user | on that mode only the trigger (not role grants) protects the audit table |
| Scheduled external anchoring of the audit hash | `scripts/anchor_audit.py` exists and works; **scheduling it is the operator's job** (cron example in DEPLOY.md) | not run automatically by the app |
| Admin "suspicious activity" dashboard | a deliberately small rule set: repeated refusals by one user/IP, role changes, admin-triggered resets, login failures, failed chain verifications | enough to be useful, not a detection engine |
| Alembic migrations | not used: `scripts/init_db.py` creates the schema; `db/schema.sql` is the readable copy | scope of a one-week build |

## Added beyond the design documents
`GET /api/documents/trash`, `PATCH /api/documents/{id}` (owner edits title/category), `GET /api/documents/{id}/audit` (owner sees who touched a document, including
refusals), `GET /api/documents/{id}/versions` and `.../versions/{n}/download`, search filters and facets, the AI decision endpoint
`POST /api/documents/{id}/grantee-suggestions/{suggestion_id}/decisions`, filtered admin activity view, `GET /healthz`, upload rate limit.

## Brought in line with the design while building
Register 5/min per IP; forgot-password 3/hour per IP and per email; reset and email-change links valid 15 minutes; refusals rate-limited per IP and per user with an
aggregate audit event; audit hash is HMAC-SHA256 with the key outside the database.
